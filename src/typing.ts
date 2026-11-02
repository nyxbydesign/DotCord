import type { BridgeResponse } from "./networking.js";

export type TypingRequest = (channel: string) => Promise<BridgeResponse>;
const REQUESTS_PER_SECOND = 16;

/** Ephemeral feedback only; destinations come from accepted inbound messages. */
export class DiscordTyping {
  private readonly pending = new Map<string, { channel: string; expires: number }>();
  private readonly next = new Map<string, number>();
  private readonly work = new Map<string, Promise<unknown>>();
  private timer?: ReturnType<typeof setInterval>;
  private checking = false;
  private closed = false;
  private cooldown = 0;
  private budgetAt = 0;
  private budget = REQUESTS_PER_SECOND;
  constructor(private readonly request: TypingRequest, private readonly allowed: () => Promise<boolean>,
    private readonly log: (code: string) => void, private readonly now = Date.now) {}

  start(message: string, channel: string) {
    if (this.closed || this.pending.has(message) || this.pending.size >= 100) return;
    this.pending.set(message, { channel, expires: this.now() + 120_000 });
    this.timer ??= setInterval(() => { void this.tick(); }, 1000).unref();
    void this.tick();
  }
  stop(message: string) { this.pending.delete(message); }
  clear() {
    this.pending.clear(); this.next.clear();
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }
  close() { this.closed = true; this.clear(); }
  async drain() { await Promise.allSettled(this.work.values()); }
  reply<T>(channel: string, message: string, send: () => Promise<T>): Promise<T> {
    this.stop(message);
    // An in-flight typing POST must finish before the message clears the indicator.
    return this.queue(channel, send);
  }
  private queue<T>(channel: string, run: () => Promise<T>): Promise<T> {
    const operation = (this.work.get(channel) ?? Promise.resolve()).catch(() => {}).then(run);
    this.work.set(channel, operation);
    void operation.finally(() => { if (this.work.get(channel) === operation) this.work.delete(channel); }).catch(() => {});
    return operation;
  }
  private active(channel: string) {
    return !this.closed && [...this.pending.values()].some((entry) => entry.channel === channel && entry.expires > this.now());
  }
  private async tick() {
    if (this.closed || this.checking) return;
    this.checking = true;
    try {
      const now = this.now();
      for (const [id, entry] of this.pending) if (entry.expires <= now) this.pending.delete(id);
      if (!this.pending.size) { this.clear(); return; }
      if (now < this.cooldown) return;
      const channels = new Set([...this.pending.values()].map((entry) => entry.channel));
      for (const channel of this.next.keys()) if (!channels.has(channel)) this.next.delete(channel);
      const due = [...channels].filter((channel) => !this.work.has(channel) && (this.next.get(channel) ?? 0) <= now)
        .sort((left, right) => (this.next.get(left) ?? 0) - (this.next.get(right) ?? 0));
      if (!due.length) return;
      if (!await this.allowed()) { this.clear(); return; }
      if (this.closed || !this.pending.size) return;
      if (now - this.budgetAt >= 1000) { this.budgetAt = now; this.budget = REQUESTS_PER_SECOND; }
      for (const channel of due.slice(0, this.budget)) {
        this.budget--; this.next.set(channel, now + 7000);
        void this.queue(channel, async () => {
          if (!this.active(channel) || this.now() < this.cooldown) return;
          try {
            const response = await this.request(channel);
            if (response.status === 204) return;
            if (response.status === 429) {
              const retry = response.retryAfter ?? "";
              const delay = /^\d+(\.\d+)?$/.test(retry) ? Number(retry) * 1000 : Date.parse(retry) - this.now();
              this.cooldown = this.now() + (Number.isFinite(delay) && delay > 0 ? Math.min(delay, Number.MAX_SAFE_INTEGER - this.now()) : 10_000);
            } else if ([401, 403, 404].includes(response.status)) {
              for (const [id, entry] of this.pending) if (entry.channel === channel) this.pending.delete(id);
            } else this.next.set(channel, this.now() + 15_000);
            this.log("typing_indicator_unavailable");
          } catch { this.next.set(channel, this.now() + 15_000); this.log("typing_indicator_unavailable"); }
        });
      }
    } catch { this.clear(); this.log("typing_indicator_unavailable"); }
    finally { this.checking = false; }
  }
}
