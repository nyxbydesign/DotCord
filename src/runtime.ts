import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Config, BridgeConfig } from "./config.js";
import { callbackHosts } from "./config.js";
import { DiscordEventsBridge } from "./bridge.js";
import { DiscordGateway, gatewayUrl } from "./gateway.js";
import { createNetwork, equal } from "./networking.js";
import { EncryptedStore, isWithin, readPrivateFile } from "./storage.js";
import { createOAuth, type AuthTransport, type OAuthRuntime } from "./oauth.js";
import type { BridgeRecords } from "./storage.js";
import { deadlineActive, deadlineFrom } from "./deadline.js";

export type Network = ReturnType<typeof createNetwork>;
export type Runtime = Awaited<ReturnType<typeof createRuntime>>;
function secretText(path: string): string {
  const bytes = readPrivateFile(path);
  try { return bytes.toString("utf8").trim(); } finally { bytes.fill(0); }
}
export function bearerDigest(path: string): string {
  const bearer = secretText(path);
  if (!/^[A-Za-z0-9._~+\/=-]{32,4096}$/.test(bearer)) throw new Error("invalid_external_bearer");
  return createHash("sha256").update(bearer).digest("hex");
}
export async function verifyDiscordIdentity(network: Pick<Network,"discord">, config: Config) {
  const me = await network.discord("/users/@me"), application = await network.discord("/oauth2/applications/@me");
  const channel = await network.discord(`/channels/${config.ownerChannelId}`);
  const recipients = channel.recipients as Array<{id?:unknown;bot?:unknown}> | undefined;
  if (me.id !== config.botUserId || me.bot !== true || application.id !== config.applicationId || channel.id !== config.ownerChannelId
    || channel.type !== 1 || !Array.isArray(recipients) || recipients.length !== 1
    || recipients[0]?.id !== config.ownerUserId || recipients[0]?.bot === true) throw new Error("discord_identity_mismatch");
  const gateway = await network.discord("/gateway/bot");
  const remaining = (gateway.session_start_limit as {remaining?:unknown})?.remaining;
  if (typeof gateway.url !== "string" || !Number.isInteger(remaining) || (remaining as number) < 1) throw new Error("gateway_session_unavailable");
  return {url:gatewayUrl(gateway.url),identifyLimit:Math.min(8,remaining as number)};
}
/** Adapters are injectable only in-process; HTTP callers cannot replace providers or claim principals. */
export async function createRuntime(config: Config, createAdapter = createNetwork, log: (code: string) => void = () => {}, options: { authTransport?:AuthTransport } = {}) {
  const bridges = new Map<string, DiscordEventsBridge>();
  let store: EncryptedStore | undefined, network: Network | undefined, gateway: DiscordGateway | undefined;
  let oauth:OAuthRuntime|undefined;
  let timer: ReturnType<typeof setInterval> | undefined, maintenance: Promise<void> | undefined, stopped = false;
  const fingerprints = () => config.bindings.map(binding => bearerDigest(binding.bearerFile!));
  const access = (bindingId: string) => {
    if (stopped || !config.enabled) return false;
    const binding = config.bindings.find(item => item.id === bindingId);
    if (!binding || !deadlineActive(deadlineFrom(binding.authorizedUntil))) return false;
    try { const hashes = fingerprints(); return new Set(hashes).size === hashes.length; } catch { return false; }
  };
  const authenticate = (header: string | undefined) => {
    if (config.authEnabled) return oauth?.authenticate(header);
    if (!header?.startsWith("Bearer ") || header.length > 4103) return undefined;
    const digest = createHash("sha256").update(header.slice(7)).digest("hex");
    let hashes: string[];
    try { hashes = fingerprints(); } catch { return undefined; }
    if (new Set(hashes).size !== hashes.length) return undefined;
    return config.bindings.find((binding,index) => equal(hashes[index]!,digest) && access(binding.id));
  };
  const stop = async () => {
    if (stopped) return; stopped = true; clearInterval(timer); gateway?.stop();
    for (const bridge of bridges.values()) bridge.stop();
    await network?.close();
    await Promise.all([...bridges.values()].map(bridge => bridge.drain()));
    await maintenance; store?.prune(); store?.close();await oauth?.stop();
  };
  try {
    if (config.authEnabled) oauth=await createOAuth(config,log,options.authTransport);
    if (config.enabled) {
      const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)),"..");
      for (const path of [config.botTokenFile!,config.encryptionKeyFile!,...config.bindings.flatMap(item => item.bearerFile?[item.bearerFile]:[])]) {
        if (isWithin(path,packageDirectory) || isWithin(path,config.stateDirectory!)) throw new Error("credentials_must_remain_external");
      }
      const hashes = oauth ? [] : fingerprints();
      if (new Set(hashes).size !== hashes.length) throw new Error("sender_bearers_must_be_separate");
      const token = secretText(config.botTokenFile!);
      if (!/^[A-Za-z0-9._-]{20,4096}$/.test(token)) throw new Error("invalid_bot_token_reference");
      const encoded = secretText(config.encryptionKeyFile!), key = Buffer.from(encoded,"base64");
      if (key.length !== 32 || key.toString("base64") !== encoded) throw new Error("invalid_storage_key_reference");
      if ([token,encoded].some(value => hashes.includes(createHash("sha256").update(value).digest("hex")))) throw new Error("credential_roles_must_be_separate");
      if (oauth && key.equals(Buffer.from(readPrivateFile(config.oauth!.encryptionKeyFile).toString("utf8").trim(),"base64"))) throw new Error("credential_roles_must_be_separate");
      const scope = oauth ? JSON.stringify(["live-v2",config.oauth!.installationId,config.applicationId,config.botUserId,config.ownerUserId,config.ownerChannelId])
        : JSON.stringify([config.applicationId,config.botUserId,config.ownerUserId,config.ownerChannelId,config.bindings.map(({id,senderId,principal,callbackUrl}) => ({id,senderId,principal,callbackUrl}))]);
      store = new EncryptedStore(config.stateDirectory!,key,scope);
      store.prune();
      network = createAdapter(token,callbackHosts,config.sourceAddress!);
      const verified = await verifyDiscordIdentity(network,config);
      for (const binding of config.bindings) {
        const bridgeConfig: BridgeConfig = {enabled:true,botUserId:config.botUserId!,ownerUserId:config.ownerUserId!,senderUserId:binding.senderId,
          ownerChannelId:config.ownerChannelId!,audience:binding.audience,callbackHosts,callbackUrl:binding.callbackUrl??""};
        bridges.set(binding.id,new DiscordEventsBridge(bridgeConfig,store.records(binding.id),network.post,network.send,
          async (principal,authority) => principal === binding.principal && (oauth ? oauth.authorize(principal,authority) : access(binding.id)),log,Date.now,network.typing,network.readAttachment,
          oauth?.store.records(binding.id),()=>config.enabled));
      }
      const adapter = network;
      gateway = new DiscordGateway(token,config.botUserId!,verified.url,async input => {
        if (!input || typeof input !== "object" || !("author" in input)) return;
        const sender = (input.author as {id?:unknown})?.id;
        const binding = config.bindings.find(item => item.senderId === sender);
        if (binding && (oauth ? await oauth.authorize(binding.principal) : access(binding.id))) await bridges.get(binding.id)!.receive(input);
      },log,{...verified,applicationId:config.applicationId!,directed:config.bindings.some(binding => binding.audience === "directed"),
        guildMessageContent:config.guildMessageContent,factory:url => adapter.socket(url)});
      let pumping = false;
      timer = setInterval(() => {
        if (pumping || stopped) return; pumping = true;
        maintenance = (async () => {
          for (const bridge of bridges.values()) await bridge.pump();
          store?.prune();
        })().catch(() => { log("live_state_processing_failed"); gateway?.stop(); for (const bridge of bridges.values()) bridge.stop(); })
          .finally(() => { pumping = false; });
      },2000).unref();
      gateway.start();
    }
    if(oauth && !config.enabled) {
      const unavailable:BridgeRecords={get:async()=>{throw new Error("intake_disabled");},put:async()=>{throw new Error("intake_disabled");},list:async()=>[],delete:async()=>{throw new Error("intake_disabled");}};
      for(const binding of config.bindings) {
        const bridgeConfig:BridgeConfig={enabled:true,botUserId:config.botUserId!,ownerUserId:config.ownerUserId!,senderUserId:binding.senderId,ownerChannelId:config.ownerChannelId!,audience:binding.audience,callbackHosts,callbackUrl:binding.callbackUrl??""};
        bridges.set(binding.id,new DiscordEventsBridge(bridgeConfig,unavailable,oauth.network.post,async()=>{throw new Error("intake_disabled");},
          async(principal,authority)=>principal===binding.principal && oauth!.authorize(principal,authority),log,Date.now,undefined,undefined,oauth.store.records(binding.id),()=>false));
      }
    }
  } catch (error) { await stop(); throw error; }
  return {config,bridges,authenticate,oauth,stop,status:() => ({enabled:config.enabled,...(config.authEnabled?{authenticationEnabled:true}:{}),ready:!config.enabled || Boolean(gateway?.ready && [...bridges.values()].every(bridge => bridge.status().healthy && !bridge.status().stopped))})};
}
