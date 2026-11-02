import { createHmac, timingSafeEqual } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { setTimeout as delay } from "node:timers/promises";
import { Agent, WebSocket } from "undici";
import { snowflake } from "./config.js";
import { createAttachmentReader } from "./attachments.js";

export type BridgeResponse = { status: number; body: string; retryAfter?: string };
export type CallbackPost = (url: string, body: string, headers: Record<string, string>) => Promise<BridgeResponse>;
export type ReplySend = (channel: string, message: string, text: string, nonce: string) => Promise<string>;
export type NetworkResult = { status: number; url: string; bodyText: string; bodyBase64: string; headers: Record<string,string>; truncated: false };
export type NetworkRequest = (url: string, method: "GET" | "POST", body?: string, headers?: Record<string,string>, maxBytes?: number, timeout?: number, signal?: AbortSignal) => Promise<NetworkResult>;
export function equal(left: string, right: string): boolean {
  const a = Buffer.from(left), b = Buffer.from(right); return a.length === b.length && timingSafeEqual(a,b);
}
export function signingKey(secret: string): Buffer {
  if (!/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(secret)) throw new Error("invalid_signing_secret");
  const key = Buffer.from(secret.slice(6), "base64");
  if (key.length < 24 || key.length > 64 || key.toString("base64") !== secret.slice(6)) throw new Error("invalid_signing_secret");
  return key;
}
export function signature(secret: string, id: string, timestamp: string, body: string): string {
  return "v1," + createHmac("sha256", signingKey(secret)).update(`${id}.${timestamp}.${body}`).digest("base64");
}
export function callbackUrl(raw: string, hosts: string[]): URL {
  const url = new URL(raw);
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.port || !hosts.includes(url.hostname)) throw new Error("unsafe_callback");
  return url;
}
export function publicIPv4(address: string): boolean {
  if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(address)) return false;
  const [a,b,c] = address.split(".").map(Number) as [number,number,number,number];
  if (address.split(".").some(part => Number(part) > 255)) return false;
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31
    || a === 192 && (b === 168 || b === 0 && (c === 0 || c === 2)) || a === 100 && b >= 64 && b <= 127
    || a === 198 && (b === 18 || b === 19 || b === 51 && c === 100) || a === 203 && b === 0 && c === 113);
}
const providers = ["discord.com", "cdn.discordapp.com", "gateway.discord.gg", "chatgpt.com", "connectors.api.openai.com"];
export async function pinnedAddress(host: string, resolveIPv4: (host: string) => Promise<Array<{ address: string }>> = host => dnsLookup(host, { family: 4, all: true, verbatim: true })): Promise<string> {
  if (!providers.includes(host)) throw new Error("destination_denied");
  const records = await resolveIPv4(host);
  if (!records.length || records.some(item => !publicIPv4(item.address))) throw new Error("public_destination_required");
  return records[0]!.address;
}
function abortable<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new Error("network_stopped"));
  return new Promise((resolve,reject) => {
    const abort = () => reject(new Error("network_stopped"));
    signal.addEventListener("abort",abort,{once:true});
    void work.then(resolve,reject).finally(() => signal.removeEventListener("abort",abort));
  });
}
/** No proxy, redirect or write retries; IPv4 is validated and pinned to each TLS connection. */
export function createNetwork(token: string, hosts: string[], sourceAddress: string) {
  const stop = new AbortController();
  const budgets = new Map<string, number[]>();
  let waiting = 0;
  const budget = async (host: string, signal: AbortSignal) => {
    if (++waiting > 64) { waiting--; throw new Error("network_capacity_reached"); }
    try {
      const limit = host === "discord.com" ? 5 : host === "cdn.discordapp.com" ? 2 : 10;
      for (;;) {
        const now = Date.now(), recent = (budgets.get(host) ?? []).filter(time => now - time < 1000);
        budgets.set(host,recent);
        if (recent.length < limit) { recent.push(now); return; }
        await delay(Math.max(1,1000 - now + recent[0]!), undefined, { signal });
      }
    } finally { waiting--; }
  };
  const request: NetworkRequest = async (raw, method, body, headers = {}, maxBytes = 16384, timeout = 10000, outerSignal) => {
    const url = callbackUrl(raw, ["discord.com", "cdn.discordapp.com", ...hosts]);
    if (body && Buffer.byteLength(body) > 262144) throw new Error("request_too_large");
    const signal = AbortSignal.any([stop.signal, AbortSignal.timeout(Math.min(15000,Math.max(1,timeout))), ...(outerSignal ? [outerSignal] : [])]);
    await budget(url.hostname,signal);
    const address = await abortable(pinnedAddress(url.hostname),signal);
    if (signal.aborted) throw new Error("network_stopped");
    return await new Promise<NetworkResult>((resolve,reject) => {
      const req = httpsRequest(url, { method, agent: false, family: 4, rejectUnauthorized: true, localAddress: sourceAddress, servername: url.hostname, signal,
        lookup: (_hostname, _options, callback) => callback(null,address,4),
        headers: { "content-type": "application/json", ...(body ? {"content-length":String(Buffer.byteLength(body))} : {}), ...headers }
      }, response => {
        const chunks: Buffer[] = []; let length = 0;
        response.on("data", (chunk: Buffer) => {
          length += chunk.length;
          if (length > maxBytes) { req.destroy(new Error("response_too_large")); return; }
          chunks.push(chunk);
        });
        response.on("error",reject);
        response.on("end", () => {
          const bytes = Buffer.concat(chunks), returned: Record<string,string> = {};
          for (const [key,value] of Object.entries(response.headers)) if (typeof value === "string") returned[key] = value;
          resolve({ status: response.statusCode ?? 0, url: raw, headers: returned, bodyText: bytes.toString("utf8"), bodyBase64: bytes.toString("base64"), truncated: false });
        });
      });
      req.on("error", () => reject(new Error("network_request_failed")));
      req.end(body);
    });
  };
  const discord = async (path: string, method: "GET" | "POST" = "GET", body?: string): Promise<Record<string,unknown>> => {
    if (!/^\/(users\/@me|oauth2\/applications\/@me|gateway\/bot|channels\/[0-9]{17,20}(\/(messages(\/[0-9]{17,20})?|typing))?)$/.test(path)) throw new Error("discord_path_denied");
    const response = await request(`https://discord.com/api/v10${path}`, method, body, {Authorization:`Bot ${token}`},65536);
    if (response.status < 200 || response.status >= 300) throw new Error("discord_request_failed_reconcile_writes");
    if (response.status === 204) return {};
    const parsed: unknown = JSON.parse(response.bodyText);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("discord_response_rejected");
    return parsed as Record<string,unknown>;
  };
  const post: CallbackPost = async (url,body,headers) => {
    callbackUrl(url,hosts);
    const response = await request(url,"POST",body,headers);
    return {status:response.status,body:response.bodyText,retryAfter:response.headers["retry-after"]};
  };
  const send: ReplySend = async (channel,message,text,nonce) => {
    snowflake.parse(channel); snowflake.parse(message);
    const result = await discord(`/channels/${channel}/messages`,"POST",JSON.stringify({content:text,nonce,enforce_nonce:true,
      allowed_mentions:{parse:[],replied_user:false},message_reference:{message_id:message,channel_id:channel,fail_if_not_exists:true}}));
    if (result.channel_id !== channel) throw new Error("discord_reply_binding_mismatch");
    return snowflake.parse(result.id);
  };
  const dispatcher = new Agent({ connect: { family: 4, rejectUnauthorized: true, localAddress: sourceAddress, timeout: 10000,
    lookup: (hostname, _options, callback) => { void pinnedAddress(hostname).then(address => callback(null,address,4), () => callback(new Error("gateway_destination_denied"),"",4)); }
  } });
  const typing = async (channel: string): Promise<BridgeResponse> => {
    const response = await request(`https://discord.com/api/v10/channels/${snowflake.parse(channel)}/typing`,"POST",undefined,{Authorization:`Bot ${token}`},16384,2000);
    return {status:response.status,body:response.bodyText,retryAfter:response.headers["retry-after"]};
  };
  return { post, send, discord, request, typing, readAttachment:createAttachmentReader(request,token),
    socket: (url: string) => new WebSocket(url,{dispatcher}),
    close: async () => { stop.abort(); await dispatcher.destroy(); }
  };
}
