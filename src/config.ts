import { isAbsolute, resolve } from "node:path";
import { isIP } from "node:net";
import { z } from "zod";

export const snowflake = z.string().regex(/^[0-9]{17,20}$/);
export const callbackHosts = ["chatgpt.com", "connectors.api.openai.com"];
export type BridgeConfig = {
  enabled: boolean; botUserId: string; ownerUserId: string; senderUserId: string;
  ownerChannelId: string; audience: "owner-dm" | "directed"; callbackHosts: string[]; callbackUrl: string;
};
export const oauthScopes = ["discord:status", "discord:context:read", "discord:attachments:read", "discord:reply", "discord:events:subscribe"] as const;
export type OAuthScope = (typeof oauthScopes)[number];
const externalFile = z.string().min(1).refine(isAbsolute, "credential reference must be absolute");
const binding = z.object({
  id: z.string().regex(/^[a-z0-9-]{1,48}$/), senderId: snowflake,
  principal: z.string().min(1).max(200), bearerFile: externalFile.optional(),
  authorizedUntil: z.iso.datetime({ offset: true }).nullable(), callbackUrl: z.url().optional(),
  callbackApprovalFile: externalFile.optional(), grantVersion: z.number().int().positive().default(1),
  scopes: z.array(z.enum(oauthScopes)).min(1).max(5).default([...oauthScopes]),
  audience: z.enum(["owner-dm", "directed"]).default("owner-dm")
}).strict();
const oauthSchema = z.object({
  installationId: z.string().regex(/^[A-Za-z0-9-]{16,64}$/),
  stateDirectory: externalFile, encryptionKeyFile: externalFile, signingKeyFile: externalFile, cookieKeyFile: externalFile,
  clientId: z.string().regex(/^[a-zA-Z0-9-]{1,100}$/), redirectUris: z.array(z.url()).min(1).max(2),
  discordClientId: snowflake, discordClientSecretFile: externalFile
}).strict();
const schema = z.object({
  port: z.number().int().min(1).max(65535).default(9294),
  publicOrigin: z.url().optional(), stateDirectory: externalFile.optional(),
  botUserId: snowflake.optional(), applicationId: snowflake.optional(), ownerUserId: snowflake.optional(), ownerChannelId: snowflake.optional(),
  botTokenFile: externalFile.optional(), encryptionKeyFile: externalFile.optional(),
  sourceAddress: z.string().refine(value => isIP(value) === 4 && value !== "0.0.0.0").optional(),
  guildMessageContent: z.boolean().default(false), bindings: z.array(binding).max(32).default([]), oauth: oauthSchema.optional()
}).strict();
export type Config = z.infer<typeof schema> & { enabled: boolean; authEnabled: boolean };
export type SenderBinding = Config["bindings"][number];
export function parseConfig(input: unknown, enabled = false, authEnabled = false): Config {
  const config = { ...schema.parse(input), enabled, authEnabled };
  if (config.publicOrigin) {
    const url = new URL(config.publicOrigin);
    if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash || url.port) throw new Error("invalid_public_origin");
  }
  if (!enabled && !authEnabled) return config;
  if (config.oauth && enabled && !authEnabled) throw new Error("oauth_authentication_not_enabled");
  if (authEnabled && (!config.oauth || !config.publicOrigin || !config.sourceAddress || !config.bindings.length)) throw new Error("oauth_configuration_incomplete");
  if (!config.botUserId || !config.applicationId || !config.ownerUserId || !config.ownerChannelId || !config.sourceAddress
    || enabled && (!config.botTokenFile || !config.encryptionKeyFile || !config.stateDirectory) || !config.bindings.length) throw new Error("enabled_configuration_incomplete");
  if (config.botUserId === config.ownerUserId) throw new Error("identity_mismatch");
  for (const key of ["id", "senderId", "principal", "bearerFile", "callbackUrl"] as const) {
    const values = config.bindings.map(item => item[key]).filter(value => value !== undefined);
    if (new Set(values).size !== values.length) throw new Error("sender_bindings_must_be_separate");
  }
  const references = [config.botTokenFile, config.encryptionKeyFile, ...config.bindings.flatMap(item => [item.bearerFile,item.callbackApprovalFile]),
    ...(config.oauth ? [config.oauth.encryptionKeyFile,config.oauth.signingKeyFile,config.oauth.cookieKeyFile,config.oauth.discordClientSecretFile] : [])]
    .filter((item): item is string => Boolean(item)).map(item => resolve(item));
  if (new Set(references).size !== references.length) throw new Error("credential_references_must_be_separate");
  for (const item of config.bindings) {
    if (item.callbackUrl) {
      const url = new URL(item.callbackUrl);
      if (url.protocol !== "https:" || !callbackHosts.includes(url.hostname) || url.port || url.username || url.password || url.hash) throw new Error("unsafe_callback");
      item.callbackUrl = url.toString();
    }
    if (authEnabled ? item.bearerFile !== undefined : !item.bearerFile || !item.callbackUrl) throw new Error("authentication_binding_mismatch");
    if (item.audience === "owner-dm" && item.senderId !== config.ownerUserId) throw new Error("owner_binding_mismatch");
    if (item.authorizedUntil===null ? !authEnabled || item.audience!=="owner-dm" : Date.parse(item.authorizedUntil) <= Date.now()) throw new Error("expired_or_unsupported_consumer_authorization");
  }
  if (config.oauth && authEnabled) {
    if (config.bindings.some(item => item.audience !== "owner-dm" || item.senderId !== config.ownerUserId)) throw new Error("oauth_pilot_owner_dm_only");
    for (const raw of config.oauth.redirectUris) {
      const url = new URL(raw);
      if (url.protocol !== "https:" || url.hostname !== "chatgpt.com" || url.port || url.username || url.password || url.search || url.hash
        || !/^\/(connector_platform_oauth_redirect|connector\/oauth\/[A-Za-z0-9_-]+)$/.test(url.pathname)) throw new Error("unsafe_oauth_redirect");
    }
    if (config.stateDirectory && resolve(config.stateDirectory) === resolve(config.oauth.stateDirectory)) throw new Error("auth_live_state_must_be_separate");
  }
  return config;
}
