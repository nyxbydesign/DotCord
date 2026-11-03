import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { snowflake, type BridgeConfig } from "./config.js";
import { callbackUrl, equal, signature, signingKey, type BridgeResponse, type CallbackPost, type ReplySend } from "./networking.js";
import type { BridgeRecords } from "./storage.js";
import { DiscordTyping, type TypingRequest } from "./typing.js";
import { AttachmentError, IMAGE_READ_TIMEOUT_MS, imageAttachments, type AttachmentBinding, type AttachmentImage, type AttachmentReader, type ImageAttachment } from "./attachments.js";

export const EVENT_NAME = "discord.message.created";
export const DAY = 86_400_000;
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const incomingSchema = z.object({
  id: snowflake, channel_id: snowflake, guild_id: snowflake.optional(),
  author: z.object({ id: snowflake, bot: z.boolean().optional() }), webhook_id: z.string().optional(),
  content: z.string().max(16_000), timestamp: z.iso.datetime({ offset: true }),
  mentions: z.array(z.object({ id: snowflake })).max(100).optional(),
  referenced_message: z.object({ author: z.object({ id: snowflake }).optional(), channel_id: snowflake.optional() }).nullish(),
  type: z.number().optional(), attachments: z.array(z.unknown()).max(10).optional()
});
export type IncomingMessage = z.infer<typeof incomingSchema>;
export type EventPayload = {
  author_id: string; author_role: "owner" | "other"; conversation_id: string;
  channel_id: string; guild_id: string | null; participant_ids: string[]; message_id: string; text: string; attachments?: ImageAttachment[];
};
type Event = { eventId: string; name: string; timestamp: string; data: EventPayload; cursor: null };
export type MessageRecord = {
  event: Event; expires: number; principal: string; generation: string; authority?: string;
  delivery: { status: "queued" | "receipt" | "failed"; attempts: number; next: number };
  reply?: { status: "pending" | "sent"; hash: string; messageId?: string; text?: string; messageIds?: string[] };
  timing?: { trace: string; receivedAt: number; admittedAt: number; dispatchAt?: number; receiptAt?: number;
    firstToolAt?: number; replyRequestedAt?: number; replyDispatchAt?: number; replySentAt?: number };
};
type ConversationRecord = {
  author: string; channel: string; participants: string[]; expires: number; generation: string;
  turns: Array<{ message_id: string; role: "user" | "assistant"; text: string; timestamp: string; image_message?: true }>;
};
export type Subscription = {
  id: string; principal: string; url: string; secret: string; expires: number; authorizedUntil: number;
  active: boolean; verifiedUntil: number; generation: string; authority?: string; oldSecret?: string; rotateUntil?: number;
  audience: BridgeConfig["audience"];
};
const subscriptionSchema = z.object({
  name: z.literal(EVENT_NAME), arguments: z.object({ audience: z.enum(["owner-dm", "directed"]) }).strict(),
  delivery: z.object({ mode: z.literal("webhook"), url: z.string().max(4096), secret: z.string().max(128).optional() }).strict(),
  ttlMs: z.number().int().positive().nullable().optional(), cursor: z.null().optional()
}).strict();
const replySchema = z.object({ message_id: snowflake, conversation_id: z.string().regex(/^conv_[a-f0-9]{64}$/), text: z.string().trim().min(1).max(2000) }).strict();

export class BridgeError extends Error {
  constructor(readonly code: number, message: string, readonly reason = message) { super(message); }
}
export type AccessCheck = (principal: string, authority?: string) => Promise<boolean>;

export class DiscordEventsBridge {
  private tail: Promise<unknown> = Promise.resolve();
  private deliveryTail: Promise<unknown> = Promise.resolve();
  private deliveries = 0;
  private readonly writes = new Set<Promise<unknown>>();
  private readonly imageReads = new Set<Promise<unknown>>();
  private readonly imageAbort = new AbortController();
  private readonly replyLanes = new Map<string, Promise<unknown>>();
  private pending = 0;
  private healthy = true;
  private stopped = false;
  private readonly startedAt: number;
  private readonly typing?: DiscordTyping;
  constructor(
    readonly config: BridgeConfig, private readonly records: BridgeRecords,
    private readonly post: CallbackPost, private readonly send: ReplySend,
    private readonly access: AccessCheck, private readonly log: (code: string) => void,
    private readonly now = Date.now, typing?: TypingRequest, private readonly readImage?: AttachmentReader,
    private readonly controls: BridgeRecords = records, private readonly intakeAllowed: () => boolean = () => true
  ) {
    this.startedAt = now();
    if (typing) this.typing = new DiscordTyping(typing, async () => {
      const sub = (await this.controls.get<Subscription>("subscription", "dot"))?.value;
      return this.config.enabled && this.healthy && !this.stopped && Boolean(sub?.active
        && sub.audience === this.config.audience && sub.expires > this.now() && sub.authorizedUntil > this.now()
        && this.intakeAllowed() && await this.access(sub.principal, sub.authority));
    }, log, now);
  }

  status() { return { enabled: this.config.enabled, intakeEnabled:this.intakeAllowed(), healthy: this.healthy, stopped: this.stopped, audience: this.config.audience,
    queuedOperations: this.pending, pendingDeliveries: this.deliveries, pendingReplies: this.writes.size, pendingAttachmentReads: this.imageReads.size }; }
  stop() { this.stopped = true; this.typing?.close(); this.imageAbort.abort(); }
  async drain() {
    for (;;) {
      const tail = this.tail, delivery = this.deliveryTail;
      await Promise.allSettled([tail, delivery, ...this.writes, ...this.imageReads]);
      if (tail === this.tail && delivery === this.deliveryTail && !this.writes.size && !this.imageReads.size) break;
    }
    await this.typing?.drain();
  }
  private track<T>(run: () => Promise<T>): Promise<T> {
    const work = run(); this.writes.add(work);
    void work.then(() => this.writes.delete(work), () => this.writes.delete(work));
    return work;
  }
  private sendInOrder<T>(channel: string, send: () => Promise<T>): Promise<T> {
    const work = (this.replyLanes.get(channel) ?? Promise.resolve()).catch(() => undefined).then(send);
    this.replyLanes.set(channel, work);
    const release = () => { if (this.replyLanes.get(channel) === work) this.replyLanes.delete(channel); };
    void work.then(release, release);
    return work;
  }
  private trace(message: MessageRecord, stage: string) {
    const t = message.timing;
    if (!t) return;
    const elapsed = (end: number | undefined, start: number | undefined) => end !== undefined && start !== undefined
      && Number.isFinite(end - start) && end >= start ? end - start : null;
    this.log("event_latency " + JSON.stringify({ trace: t.trace, stage,
      ingressMs: elapsed(t.receivedAt, Date.parse(message.event.timestamp)), intakeMs: elapsed(t.admittedAt, t.receivedAt),
      dispatchWaitMs: elapsed(t.dispatchAt, t.admittedAt), callbackMs: elapsed(t.receiptAt, t.dispatchAt),
      nativeWaitMs: elapsed(t.firstToolAt, t.receiptAt), toolToReplyMs: elapsed(t.replyRequestedAt, t.firstToolAt),
      replyWaitMs: elapsed(t.replyDispatchAt, t.replyRequestedAt), replyMs: elapsed(t.replySentAt, t.replyDispatchAt),
      totalMs: elapsed(t.replySentAt, t.receivedAt) }));
  }
  private serial<T>(run: () => Promise<T>): Promise<T> {
    if (this.pending >= 128) return Promise.reject(new BridgeError(-32000, "busy"));
    this.pending++;
    const work = this.tail.then(run).finally(() => { this.pending--; });
    this.tail = work.catch(() => undefined);
    return work;
  }
  private async put<T>(type: string, key: string, value: T, etag: string | null, expires?: number) {
    try { return await (type === "subscription" ? this.controls : this.records).put(type, key, value, etag, expires); }
    catch { this.healthy = false; this.typing?.clear(); throw new BridgeError(-32603, "storage_uncertain_stop_and_reconcile"); }
  }
  private async authorize(principal: string, authority?: string): Promise<void> {
    if (!this.config.enabled || !this.healthy || this.stopped || !await this.access(principal, authority)) throw new BridgeError(-32024, "forbidden");
  }
  private identity(input: unknown) {
    const parsed = subscriptionSchema.safeParse(input);
    if (!parsed.success || parsed.data.arguments.audience !== this.config.audience) throw new BridgeError(-32602, "invalid_parameters");
    const params = parsed.data;
    try { if (callbackUrl(params.delivery.url, this.config.callbackHosts).toString() !== this.config.callbackUrl) throw new Error(); }
    catch { throw new BridgeError(-32015, "unsafe_callback"); }
    return params;
  }
  private headers(sub: Subscription, id: string, body: string) {
    const timestamp = String(Math.floor(this.now() / 1000));
    const keys = [sub.secret];
    if (sub.oldSecret && (sub.rotateUntil ?? 0) > this.now()) keys.push(sub.oldSecret);
    return { "webhook-id": id, "webhook-timestamp": timestamp, "webhook-signature": keys.map((key) => signature(key, id, timestamp, body)).join(" "), "X-MCP-Subscription-Id": sub.id };
  }
  subscribe(principal: string, input: unknown, authorizedUntil: number, authority?: string) { return this.serial(async () => {
    await this.authorize(principal, authority);
    const params = this.identity(input);
    if (!params.delivery.secret || !Number.isFinite(authorizedUntil) || authorizedUntil <= this.now()) throw new BridgeError(-32602, "invalid_parameters");
    try { signingKey(params.delivery.secret); } catch { throw new BridgeError(-32602, "invalid_signing_secret"); }
    const id = "sub_" + hash(JSON.stringify([principal, params.delivery.url, EVENT_NAME, { audience: params.arguments.audience }]));
    const old = await this.controls.get<Subscription>("subscription", "dot");
    // An unsubscribe retains the destination binding. Moving dots requires an explicit operator migration.
    if (old && (old.value.principal !== principal || old.value.url !== params.delivery.url
      || old.value.active && old.value.id !== id)) throw new BridgeError(-32024, "different_dot_binding");
    const previous = old?.value;
    const sub: Subscription = {
      id, principal, authority, audience: this.config.audience, url: params.delivery.url, secret: params.delivery.secret, authorizedUntil,
      expires: Math.min(this.now() + Math.min(params.ttlMs ?? DAY, DAY), authorizedUntil), active: true,
      verifiedUntil: previous?.authority === authority ? previous?.verifiedUntil ?? 0 : 0,
      generation: previous?.active && previous.expires > this.now() && previous.authority === authority ? previous.generation : randomBytes(16).toString("hex")
    };
    if (previous && previous.secret !== sub.secret) { sub.oldSecret = previous.secret; sub.rotateUntil = this.now() + 300_000; }
    else if (previous?.oldSecret && (previous.rotateUntil ?? 0) > this.now()) { sub.oldSecret = previous.oldSecret; sub.rotateUntil = previous.rotateUntil; }
    if (!previous?.active || previous.secret !== sub.secret || sub.verifiedUntil <= this.now()) {
      const challenge = randomBytes(32).toString("base64url");
      const body = JSON.stringify({ type: "verification", challenge });
      try {
        const response = await this.post(sub.url, body, this.headers(sub, "verification_" + randomBytes(16).toString("hex"), body));
        const echoed: unknown = JSON.parse(response.body);
        if (response.status < 200 || response.status >= 300 || !echoed || typeof echoed !== "object"
          || !("challenge" in echoed) || typeof echoed.challenge !== "string" || !equal(echoed.challenge, challenge)) throw new Error();
      } catch { throw new BridgeError(-32015, "challenge_failed"); }
      sub.verifiedUntil = this.now() + 300_000;
    }
    await this.authorize(principal, authority);
    await this.put("subscription", "dot", sub, old?.etag ?? null);
    if (previous?.generation !== sub.generation) this.typing?.clear();
    this.log("subscription_active");
    return { id, refreshBefore: new Date(sub.expires).toISOString(), cursor: null, truncated: false };
  }); }
  unsubscribe(principal: string, input: unknown) { return this.serial(async () => {
    await this.authorize(principal);
    const params = this.identity(input);
    const old = await this.controls.get<Subscription>("subscription", "dot");
    if (old && (old.value.principal !== principal || old.value.url !== params.delivery.url)) throw new BridgeError(-32024, "forbidden");
    if (old) await this.put("subscription", "dot", { ...old.value, active: false, secret: "", oldSecret: undefined }, old.etag);
    this.typing?.clear();
    this.log("subscription_stopped");
    return {};
  }); }
  private async rate(kind: string, author: string, senderLimit: number, globalLimit: number): Promise<boolean> {
    const keys = [`${kind}:global`, `${kind}:${author}`];
    const limits = [globalLimit, senderLimit];
    const buckets = [];
    for (const key of keys) buckets.push(await this.records.get<{ start: number; count: number }>("rate", key));
    for (let i = 0; i < keys.length; i++) {
      const bucket = buckets[i]?.value;
      if (bucket && bucket.start > this.now() - 60_000 && bucket.count >= limits[i]!) return false;
    }
    for (let i = 0; i < keys.length; i++) {
      const old = buckets[i];
      const next = old && old.value.start > this.now() - 60_000 ? { ...old.value, count: old.value.count + 1 } : { start: this.now(), count: 1 };
      await this.put("rate", keys[i]!, next, old?.etag ?? null, next.start + 60_000);
    }
    return true;
  }
  async receive(input: unknown) {
    const accepted = await this.ingest(input);
    if (accepted) await this.pump(false);
    return accepted;
  }
  ingest(input: unknown) {
    const receivedAt = this.now();
    return this.serial(async () => {
      const parsed = incomingSchema.safeParse(input);
      if (!parsed.success || !this.config.enabled || !this.healthy || this.stopped || !this.intakeAllowed()) return false;
      const m = parsed.data;
      if (m.author.id !== this.config.senderUserId) return false;
      if (m.webhook_id !== undefined || m.author.bot || m.author.id === this.config.botUserId || (m.type !== undefined && ![0, 19].includes(m.type))) return false;
      if (this.config.audience === "owner-dm" && (m.author.id !== this.config.ownerUserId || m.guild_id || m.channel_id !== this.config.ownerChannelId)) return false;
      if (m.guild_id && !m.mentions?.some(({ id }) => id === this.config.botUserId)
        && !(m.referenced_message?.author?.id === this.config.botUserId && m.referenced_message.channel_id === m.channel_id)) return false;
      const occurred = Date.parse(m.timestamp);
      const attachments = imageAttachments(m.attachments ?? []);
      if (occurred < Math.max(this.startedAt, this.now() - 60_000) || occurred > this.now() + 60_000 || (!m.content.trim() && !attachments.length)) return false;
      const sub = await this.controls.get<Subscription>("subscription", "dot");
      if (!sub?.value.active || sub.value.audience !== this.config.audience || sub.value.expires <= this.now() || sub.value.authorizedUntil <= this.now()) return false;
      await this.authorize(sub.value.principal, sub.value.authority);
      if (await this.records.get("message", m.id)) return false;
      const messages = await this.records.list("message", 1000);
      if (messages.length >= 1000 || messages.filter(({ queued }) => queued).length >= 100) throw new BridgeError(-32000, "capacity_reached");
      if (!await this.rate("in", m.author.id, 10, 60)) { this.log("inbound_rate_limited"); return false; }
      const participants = [m.author.id, this.config.botUserId].sort();
      const conversation = "conv_" + hash(JSON.stringify([m.guild_id ?? null, m.channel_id, participants]));
      if (!await this.records.get("conversation", conversation) && (await this.records.list("conversation", 1000)).length >= 1000) throw new BridgeError(-32000, "conversation_capacity_reached");
      const value: MessageRecord = {
        principal: sub.value.principal, generation: sub.value.generation, authority: sub.value.authority, expires: this.now() + DAY,
        timing: { trace: randomBytes(12).toString("hex"), receivedAt, admittedAt: this.now() },
        delivery: { status: "queued", attempts: 0, next: this.now() },
        event: { eventId: "discord_" + m.id, name: EVENT_NAME, timestamp: new Date(occurred).toISOString(), cursor: null,
          data: { author_id: m.author.id, author_role: m.author.id === this.config.ownerUserId ? "owner" : "other", conversation_id: conversation,
            channel_id: m.channel_id, guild_id: m.guild_id ?? null, participant_ids: participants, message_id: m.id, text: m.content.slice(0, 4000), ...(attachments.length ? { attachments } : {}) } }
      };
      await this.put("message", m.id, value, null, value.expires);
      await this.appendConversation(value, "user", m.id, value.event.data.text, value.event.timestamp);
      this.log("human_message_queued");
      this.trace(value, "accepted");
      this.typing?.start(m.id, m.channel_id);
      return true;
    });
  }
  pump(prune = true) {
    if (this.deliveries >= 128) return Promise.reject(new BridgeError(-32000, "busy"));
    this.deliveries++;
    const work = this.deliveryTail.then(() => this.deliver(prune)).finally(() => { this.deliveries--; });
    this.deliveryTail = work.catch(() => undefined);
    return work;
  }
  private async deliver(prune: boolean) {
    const job = await this.serial(async () => {
      if (!this.config.enabled || !this.healthy || this.stopped || !this.intakeAllowed()) { this.typing?.clear(); return; }
      const messages = await this.records.list("message", 1000);
      if (prune) for (const record of messages) if ((record.expires ?? Infinity) <= this.now()) await this.records.delete("message", record.key);
      if (prune) for (const type of ["rate", "conversation"]) {
        for (const record of await this.records.list(type, 1000)) if ((record.expires ?? Infinity) <= this.now()) await this.records.delete(type, record.key);
      }
      let storedSub = await this.controls.get<Subscription>("subscription", "dot");
      let sub = storedSub?.value;
      if (!sub?.active) { this.typing?.clear(); return; }
      if (sub.oldSecret && (sub.rotateUntil ?? 0) <= this.now()) {
        storedSub = await this.put("subscription", "dot", { ...sub, oldSecret: undefined, rotateUntil: undefined }, storedSub!.etag);
        sub = storedSub.value;
      }
      if (sub.audience !== this.config.audience || sub.expires <= this.now() || sub.authorizedUntil <= this.now() || !await this.access(sub.principal, sub.authority)) {
        await this.put("subscription", "dot", { ...sub, active: false, secret: "", oldSecret: undefined }, storedSub!.etag);
        this.typing?.clear();
        this.log("subscription_expired_or_revoked"); return;
      }
      const ordered = messages.filter(record => (record.expires ?? 0) > this.now() && record.queued)
        .sort((a, b) => a.key.length - b.key.length || a.key.localeCompare(b.key));
      const blocked = new Set<string>();
      let summary: (typeof ordered)[number] | undefined;
      for (const candidate of ordered) {
        const item = await this.records.get<MessageRecord>("message", candidate.key);
        if (!item) continue;
        const conversation = item.value.event.data.conversation_id;
        if (blocked.has(conversation)) continue;
        blocked.add(conversation);
        if ((candidate.next ?? Infinity) <= this.now()) { summary = candidate; break; }
      }
      if (!summary) return;
      const storedMessage = await this.records.get<MessageRecord>("message", summary.key);
      if (!storedMessage) return;
      const value = structuredClone(storedMessage.value);
      if (value.generation !== sub.generation || value.authority !== sub.authority || value.principal !== sub.principal || value.delivery.attempts >= 5) {
        value.delivery.status = "failed";
        this.typing?.stop(summary.key);
        await this.put("message", summary.key, value, storedMessage.etag, value.expires); return;
      }
      value.delivery.attempts++;
      value.delivery.next = this.now() + Math.min(60_000, 1000 * 2 ** value.delivery.attempts);
      if (value.timing) value.timing.dispatchAt = this.now();
      await this.put("message", summary.key, value, storedMessage.etag, value.expires);
      return { key: summary.key, value, sub };
    });
    if (!job || this.stopped || !this.healthy || !await this.access(job.sub.principal, job.sub.authority)) return;
    const { value, sub } = job;
    const body = JSON.stringify(value.event);
    this.trace(value, "dispatch");
    let response: BridgeResponse = { status: 0, body: "" };
    try { response = await this.post(sub.url, body, this.headers(sub, value.event.eventId, body)); } catch { /* Bounded idempotent webhook retry. */ }
    if (response.status >= 200 && response.status < 300) value.delivery.status = "receipt";
    else if (response.status >= 300 && response.status < 500 && ![408, 429].includes(response.status) || value.delivery.attempts >= 5) value.delivery.status = "failed";
    if (response.retryAfter) {
      const delay = /^\d+(\.\d+)?$/.test(response.retryAfter) ? Number(response.retryAfter) * 1000 : Date.parse(response.retryAfter) - this.now();
      if (Number.isFinite(delay) && delay > 0) value.delivery.next = Math.max(value.delivery.next, this.now() + Math.min(delay, DAY));
    }
    const receiptAt = this.now();
    await this.serial(async () => {
      const current = await this.records.get<MessageRecord>("message", job.key);
      if (!current || current.value.generation !== value.generation || current.value.delivery.attempts !== value.delivery.attempts) return;
      const merged = { ...current.value, delivery: value.delivery };
      if (merged.timing && value.delivery.status === "receipt") merged.timing.receiptAt = receiptAt;
      if (response.status === 410) {
        const active = await this.controls.get<Subscription>("subscription", "dot");
        if (active?.value.generation === sub.generation && active.value.id === sub.id) {
          await this.put("subscription", "dot", { ...active.value, active: false, secret: "", oldSecret: undefined }, active.etag);
          this.typing?.clear();
        }
      }
      await this.put("message", job.key, merged, current.etag, merged.expires);
      if (merged.delivery.status === "failed") this.typing?.stop(job.key);
      this.log(merged.delivery.status === "receipt" ? "event_receipt_acknowledged" : merged.delivery.status === "failed" ? "event_delivery_failed" : "event_retry_scheduled");
      this.trace(merged, "callback");
    });
  }
  reply(principal: string, input: unknown) {
    const parsed = replySchema.safeParse(input);
    if (!parsed.success) return Promise.reject(new BridgeError(-32602, "invalid_parameters"));
    const { text, ...anchor } = parsed.data;
    return this.replyBatch(principal, { ...anchor, texts: [text] }).then(result => ({ message_id: result.message_ids[0]!, duplicate: result.duplicate }));
  }
  replyBatch(principal: string, input: unknown) {
    if (!this.intakeAllowed()) return Promise.reject(new BridgeError(-32024,"intake_disabled"));
    const parsed = replySchema.omit({ text: true }).extend({ texts: z.array(z.string().trim().min(1).max(2000)).min(1).max(4) }).safeParse(input);
    if (!parsed.success) return Promise.reject(new BridgeError(-32602,"invalid_parameters"));
    const p = parsed.data, requestedAt = this.now(), contentHash = hash(JSON.stringify(p.texts));
    type Barrier = { message_id: string; hash: string; message_ids: string[]; status: "pending" | "confirmed"; expires: number };
    return this.track(() => this.sendInOrder(p.conversation_id, async () => {
      const prepared = await this.serial(async () => {
        await this.authorize(principal);
        const record = await this.records.get<MessageRecord>("message",p.message_id);
        const sub = await this.controls.get<Subscription>("subscription","dot");
        const value = record?.value;
        if (!value || value.principal !== principal || value.event.data.author_id !== this.config.senderUserId
          || value.expires <= this.now() || value.event.data.conversation_id !== p.conversation_id
          || !sub?.value.active || sub.value.principal !== principal || sub.value.authorizedUntil <= this.now()
          || sub.value.audience !== this.config.audience || sub.value.expires <= this.now()
          || sub.value.generation !== value.generation || sub.value.authority !== value.authority || !await this.access(principal, value.authority) || value.delivery.attempts < 1) throw new BridgeError(-32024,"unknown_or_expired_message");
        if (value.reply) {
          if (value.reply.hash !== contentHash) throw new BridgeError(-32024,"reply_already_reserved");
          if (value.reply.status === "pending") throw new BridgeError(-32024,"reply_outcome_uncertain_no_resend");
          return {duplicate:true as const,message_ids:value.reply.messageIds ?? [value.reply.messageId!]};
        }
        const previous = await this.records.get<Barrier>("send-lane",p.conversation_id);
        if (previous?.value.status === "pending" && previous.value.expires > this.now()) throw new BridgeError(-32024,"conversation_send_uncertain_no_resend");
        for (const _text of p.texts) if (!await this.rate("out",value.event.data.author_id,12,30)) throw new BridgeError(-32024,"reply_rate_limited");
        const barrier: Barrier = {message_id:p.message_id,hash:contentHash,message_ids:[],status:"pending",expires:value.expires};
        await this.put("send-lane",p.conversation_id,barrier,previous?.etag ?? null,value.expires);
        value.reply = {status:"pending",hash:contentHash,messageIds:[]};
        if (value.timing) {value.timing.firstToolAt ??= requestedAt;value.timing.replyRequestedAt=requestedAt;}
        await this.put("message",p.message_id,value,record!.etag,value.expires);
        return {value};
      });
      if (prepared.duplicate === true) return {message_ids:prepared.message_ids,duplicate:true};
      const {value}=prepared, messageIds: string[]=[];
      // The durable conversation barrier precedes all provider writes and is released only
      // after the complete batch and its final state/context have been durably confirmed.
      try {
        for (let index=0; index<p.texts.length; index++) {
          await this.serial(async () => {
            await this.authorize(principal, value.authority);
            const active=(await this.controls.get<Subscription>("subscription","dot"))?.value;
            if (!active?.active || active.principal !== principal || active.generation !== value.generation
              || active.audience !== this.config.audience || active.expires <= this.now()
              || active.authorizedUntil <= this.now() || value.expires <= this.now()) throw new BridgeError(-32024,"unknown_or_expired_message");
          });
          const id=snowflake.parse(await this.send(value.event.data.channel_id,p.message_id,p.texts[index]!,hash(`reply:${p.message_id}:${index}`).slice(0,24)));
          messageIds.push(id);
          await this.serial(async () => {
            const current=await this.records.get<MessageRecord>("message",p.message_id);
            const barrier=await this.records.get<Barrier>("send-lane",p.conversation_id);
            if (!current || current.value.generation !== value.generation || current.value.reply?.status !== "pending"
              || current.value.reply.hash !== contentHash || !barrier || barrier.value.status !== "pending"
              || barrier.value.message_id !== p.message_id || barrier.value.hash !== contentHash) throw new BridgeError(-32024,"reply_outcome_uncertain_no_resend");
            barrier.value.message_ids=[...messageIds];
            await this.put("send-lane",p.conversation_id,barrier.value,barrier.etag,barrier.value.expires);
            current.value.reply.messageIds=[...messageIds];
            await this.put("message",p.message_id,current.value,current.etag,current.value.expires);
          });
        }
        const sentAt=this.now();
        await this.serial(async () => {
          const current=await this.records.get<MessageRecord>("message",p.message_id);
          const barrier=await this.records.get<Barrier>("send-lane",p.conversation_id);
          if (!current || current.value.generation !== value.generation || current.value.reply?.status !== "pending"
            || current.value.reply.hash !== contentHash || !barrier || barrier.value.status !== "pending"
            || barrier.value.message_id !== p.message_id || barrier.value.hash !== contentHash
            || JSON.stringify(barrier.value.message_ids) !== JSON.stringify(messageIds)) throw new BridgeError(-32024,"reply_outcome_uncertain_no_resend");
          const merged=current.value;
          merged.reply={status:"sent",hash:contentHash,messageId:messageIds[0],messageIds,text:p.texts.join("\n")};
          if (merged.timing) merged.timing.replySentAt=sentAt;
          await this.put("message",p.message_id,merged,current.etag,merged.expires);
          for (let index=0;index<messageIds.length;index++) await this.appendConversation(merged,"assistant",messageIds[index]!,p.texts[index]!,new Date(sentAt).toISOString());
          barrier.value.status="confirmed";
          await this.put("send-lane",p.conversation_id,barrier.value,barrier.etag,barrier.value.expires);
          this.log("reply_batch_sent");
        });
      } catch {this.log("reply_outcome_uncertain");throw new BridgeError(-32024,"reply_outcome_uncertain_no_resend");}
      return {message_ids:messageIds,duplicate:false};
    }));
  }
  private async attachmentBinding(principal: string, p: { message_id: string; conversation_id: string; attachment_id: string }) {
    if (!this.intakeAllowed()) throw new BridgeError(-32024,"intake_disabled");
    await this.authorize(principal);
    const record = await this.records.get<MessageRecord>("message", p.message_id);
    const sub = (await this.controls.get<Subscription>("subscription", "dot"))?.value;
    const value = record?.value;
    if (!value || value.event.data.author_id !== this.config.senderUserId || value.principal !== principal || value.expires <= this.now() || value.event.data.conversation_id !== p.conversation_id
      || value.delivery.attempts < 1 || !sub?.active || sub.audience !== this.config.audience || sub.expires <= this.now()
      || sub.authorizedUntil <= this.now() || sub.generation !== value.generation || sub.authority !== value.authority || !await this.access(principal,value.authority) || sub.principal !== principal) {
      throw new BridgeError(-32024, "unknown_or_expired_message");
    }
    const attachment = value.event.data.attachments?.find(item => item.id === p.attachment_id);
    if (!attachment) throw new BridgeError(-32024, "unknown_or_expired_attachment");
    const binding: AttachmentBinding = { messageId: p.message_id, channelId: value.event.data.channel_id,
      guildId: value.event.data.guild_id, authorId: value.event.data.author_id, attachment };
    return { binding, record: record!, generation: value.generation };
  }
  attachment(principal: string, input: unknown): Promise<AttachmentImage> {
    if (this.imageReads.size >= 2) return Promise.reject(new BridgeError(-32000, "attachment_busy"));
    const requestedAt = this.now();
    const work = (async () => {
      try {
        const parsed = replySchema.omit({ text: true }).extend({ attachment_id: snowflake }).safeParse(input);
        if (!parsed.success) throw new BridgeError(-32602, "invalid_parameters");
        const prepared = await this.serial(async () => {
          const result = await this.attachmentBinding(principal, parsed.data);
          if (!this.readImage) throw new BridgeError(-32024, "attachment_unavailable");
          if (!await this.rate("image", result.binding.authorId, 5, 30)) throw new BridgeError(-32024, "attachment_rate_limited");
          if (result.record.value.timing && result.record.value.timing.firstToolAt === undefined) {
            result.record.value.timing.firstToolAt = requestedAt;
            await this.put("message", parsed.data.message_id, result.record.value, result.record.etag, result.record.value.expires);
            this.trace(result.record.value, "image");
          }
          return result;
        });
        const signal = AbortSignal.any([this.imageAbort.signal, AbortSignal.timeout(IMAGE_READ_TIMEOUT_MS)]);
        const image = await this.readImage!(prepared.binding, signal);
        await this.serial(async () => {
          const current = await this.attachmentBinding(principal, parsed.data);
          if (signal.aborted || current.generation !== prepared.generation
            || JSON.stringify(current.binding) !== JSON.stringify(prepared.binding)) throw new BridgeError(-32024, "unknown_or_expired_attachment");
        });
        return image;
      } catch (error) {
        if (error instanceof AttachmentError) throw new BridgeError(-32024, error.message);
        if (error instanceof BridgeError) throw error;
        throw new BridgeError(-32024, "attachment_unavailable");
      }
    })();
    this.imageReads.add(work);
    void work.then(() => this.imageReads.delete(work), () => this.imageReads.delete(work));
    return work;
  }
  private async appendConversation(message: MessageRecord, role: "user" | "assistant", id: string, text: string, timestamp: string) {
    const data = message.event.data;
    const old = await this.records.get<ConversationRecord>("conversation", data.conversation_id);
    const value: ConversationRecord = old && old.value.expires > this.now() && old.value.generation === message.generation ? old.value : {
      author: data.author_id, channel: data.channel_id, participants: data.participant_ids, expires: 0, generation:message.generation, turns: []
    };
    if (value.author !== data.author_id || value.channel !== data.channel_id) throw new BridgeError(-32024, "conversation_scope_mismatch");
    if (!value.turns.some((turn) => turn.message_id === id && turn.role === role)) value.turns.push({ message_id: id, role, text, timestamp, ...(role === "user" && data.attachments?.length ? { image_message: true as const } : {}) });
    value.turns = value.turns.filter((turn) => Date.parse(turn.timestamp) > this.now() - DAY).slice(-40);
    value.expires = this.now() + DAY;
    await this.put("conversation", data.conversation_id, value, old?.etag ?? null, value.expires);
  }
  conversation(principal: string, input: unknown) {
    if (!this.intakeAllowed()) return Promise.reject(new BridgeError(-32024,"intake_disabled"));
    const requestedAt = this.now();
    return this.serial(async () => {
      await this.authorize(principal);
      const parsed = replySchema.omit({ text: true }).safeParse(input);
      if (!parsed.success) throw new BridgeError(-32602, "invalid_parameters");
      const p = parsed.data;
      const anchor = await this.records.get<MessageRecord>("message", p.message_id);
      const sub = await this.controls.get<Subscription>("subscription", "dot");
      if (!anchor || anchor.value.event.data.author_id !== this.config.senderUserId || anchor.value.principal !== principal || anchor.value.expires <= this.now()
        || anchor.value.event.data.conversation_id !== p.conversation_id || !sub?.value.active
        || sub.value.audience !== this.config.audience || sub.value.expires <= this.now() || sub.value.authorizedUntil <= this.now()
        || anchor.value.generation !== sub.value.generation || anchor.value.authority !== sub.value.authority || !await this.access(principal,anchor.value.authority)) throw new BridgeError(-32024, "unknown_or_expired_message");
      if (anchor.value.timing && anchor.value.timing.firstToolAt === undefined) {
        anchor.value.timing.firstToolAt = requestedAt;
        await this.put("message", p.message_id, anchor.value, anchor.etag, anchor.value.expires);
        this.trace(anchor.value, "context");
      }
      const history = await this.records.get<ConversationRecord>("conversation", p.conversation_id);
      const value = history?.value;
      if (!value || value.expires <= this.now() || value.author !== anchor.value.event.data.author_id || value.channel !== anchor.value.event.data.channel_id) return { conversation_id: p.conversation_id, turns: [] };
      const turns = await Promise.all(value.turns.filter(turn => Date.parse(turn.timestamp) > this.now() - DAY).map(async turn => {
        const { image_message, ...text } = turn;
        if (!image_message || turn.role !== "user") return text;
        const image = (await this.records.get<MessageRecord>("message", turn.message_id))?.value;
        const attachments = image && image.expires > this.now() && image.principal === principal && image.generation === sub.value.generation
          && image.event.data.conversation_id === p.conversation_id && image.event.data.author_id === value.author
          && image.event.data.channel_id === value.channel ? image.event.data.attachments ?? [] : [];
        return { ...text, attachments };
      }));
      return { conversation_id: p.conversation_id, author_id: value.author, channel_id: value.channel, participant_ids: value.participants, turns };
    });
  }
}
