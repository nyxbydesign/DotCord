import { isAbsolute, resolve } from "node:path";
import { isIP } from "node:net";
import { z } from "zod";

export const snowflake = z.string().regex(/^[0-9]{17,20}$/);
export const callbackHosts = ["chatgpt.com", "connectors.api.openai.com"];
export type BridgeConfig = {
  enabled: boolean; botUserId: string; ownerUserId: string; senderUserId: string;
  ownerChannelId: string; audience: "owner-dm" | "directed"; callbackHosts: string[]; callbackUrl: string;
};
const externalFile = z.string().min(1).refine(isAbsolute, "credential reference must be absolute");
const binding = z.object({
  id: z.string().regex(/^[a-z0-9-]{1,48}$/), senderId: snowflake,
  principal: z.string().min(1).max(200), bearerFile: externalFile,
  authorizedUntil: z.iso.datetime({ offset: true }), callbackUrl: z.url(),
  audience: z.enum(["owner-dm", "directed"]).default("owner-dm")
}).strict();
const schema = z.object({
  port: z.number().int().min(1).max(65535).default(9294),
  publicOrigin: z.url().optional(), stateDirectory: externalFile.optional(),
  botUserId: snowflake.optional(), applicationId: snowflake.optional(), ownerUserId: snowflake.optional(), ownerChannelId: snowflake.optional(),
  botTokenFile: externalFile.optional(), encryptionKeyFile: externalFile.optional(),
  sourceAddress: z.string().refine(value => isIP(value) === 4 && value !== "0.0.0.0").optional(),
  guildMessageContent: z.boolean().default(false), bindings: z.array(binding).max(32).default([])
}).strict();
export type Config = z.infer<typeof schema> & { enabled: boolean };
export function parseConfig(input: unknown, enabled = false): Config {
  const config = { ...schema.parse(input), enabled };
  if (config.publicOrigin) {
    const url = new URL(config.publicOrigin);
    if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash || url.port) throw new Error("invalid_public_origin");
  }
  if (!enabled) return config;
  if (!config.botUserId || !config.applicationId || !config.ownerUserId || !config.ownerChannelId || !config.sourceAddress
    || !config.botTokenFile || !config.encryptionKeyFile || !config.stateDirectory || !config.bindings.length) throw new Error("enabled_configuration_incomplete");
  if (config.botUserId === config.ownerUserId) throw new Error("identity_mismatch");
  for (const key of ["id", "senderId", "principal", "bearerFile", "callbackUrl"] as const) {
    if (new Set(config.bindings.map(item => item[key])).size !== config.bindings.length) throw new Error("sender_bindings_must_be_separate");
  }
  const references = [config.botTokenFile, config.encryptionKeyFile, ...config.bindings.map(item => item.bearerFile)].map(item => resolve(item));
  if (new Set(references).size !== references.length) throw new Error("credential_references_must_be_separate");
  for (const item of config.bindings) {
    const url = new URL(item.callbackUrl);
    if (url.protocol !== "https:" || !callbackHosts.includes(url.hostname) || url.port || url.username || url.password || url.hash) throw new Error("unsafe_callback");
    item.callbackUrl = url.toString();
    if (item.audience === "owner-dm" && item.senderId !== config.ownerUserId) throw new Error("owner_binding_mismatch");
    if (Date.parse(item.authorizedUntil) <= Date.now()) throw new Error("expired_consumer_authorization");
  }
  if (new Set(config.bindings.map(item => item.callbackUrl)).size !== config.bindings.length) throw new Error("sender_callbacks_must_be_separate");
  return config;
}
