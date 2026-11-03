# DotCord

DotCord is a standalone bridge for bringing **your [OpenAI dot](https://openai.com/index/introducing-dots/) into Discord**. It forwards new Discord messages to your dot through MCP Events and provides tools for your dot to read recent conversation context, view attached images and reply in the same Discord conversation.

## How the bridge works

1. A configured person sends the bot a Discord DM, or mentions or replies to it in a server.
2. DotCord delivers a `discord.message.created` event to that person's configured dot integration.
3. Your dot can read the accepted conversation's recent context and supported images, then send a reply back to its original Discord destination.

Each sender has a separate binding and encrypted live context. DotCord supplies the Discord connection; your dot supplies the assistant response. The receiving dot integration must keep each person's account, memory and tools isolated.

**Connection requirement:** ChatGPT connections use the self-hosted OAuth issuer described below. The legacy externally provisioned bearer configuration is available for separate compatible consumers; it is never a fallback after an OAuth failure. A configured and tested local issuer still requires a real account link, signed subscription challenge and Discord reply witness before the complete connection is ready. See the [OpenAI authentication documentation](https://developers.openai.com/plugins/build/auth).

## OAuth setup

Use [config.oauth.example.json](config.oauth.example.json) for an owner-DM connection. Configure the dedicated Discord login application's `identify` scope and redirect to `https://your-host/oauth/login/discord/callback`. Its client ID/secret are separate from both the existing Discord bot token and the public ChatGPT client. Register the exact ChatGPT OAuth redirect shown by the connection's management page; do not guess a callback ID or reuse an event webhook URL as the OAuth redirect.

Keep the auth-state AES key, session-cookie key and ES256/P-256 signing JWK or JWKS in separate private external files. AES/cookie files contain canonical base64 encoding of 32 bytes. The signing key must have an explicit unique `kid`; the first key is the current private signing key. Public JWKS responses omit private material. Credential files must satisfy the ownership and non-symlink rules below. There are no generated development keys or permissive login screens.

Start authentication without Discord intake:

```sh
DOTCORD_CONFIG=/etc/dotcord/config.json DOTCORD_AUTH_ENABLED=1 npm start
```

This opens only the authentication/control store. It does not read the bot token or message-state key, open the message database, call Discord's bot API, or start a Gateway. Discord login uses its separate bounded, source-bound HTTPS client. Enable `DOTCORD_NETWORK_ENABLED=1` separately only when the bot, sender, callback and message-state custody are ready.

The issuer is `<publicOrigin>/oauth`; discovery is `/oauth/.well-known/openid-configuration`. Protected-resource metadata is `/.well-known/oauth-protected-resource/mcp`, and access tokens target `<publicOrigin>/mcp`. The predefined ChatGPT public client uses authorization code with S256 PKCE and `token_endpoint_auth_method=none`. Dynamic registration, CIMD, password, implicit and client-credentials grants are disabled. The minimal OIDC identity contains only an opaque subject; verified-email workspace restrictions require a separate compatible identity configuration.

The five resource scopes are `discord:status`, `discord:context:read`, `discord:attachments:read`, `discord:reply` and `discord:events:subscribe`. Access tokens last at most five minutes. Sender authorization lasts at most 24 hours from consent and never beyond `authorizedUntil`. Refresh rotates without extending that cutoff; reuse revokes its grant. A new grant generation cannot replay old anchors or queued events or bypass an unresolved send barrier. Changing `grantVersion` is an explicit operator action, not an automatic renewal.

Event callbacks need separate exact-URL approval. A fixed `callbackUrl` may be configured in the binding. If the URL is learned during subscription, the request records a pending encrypted enrollment and returns `callback_approval_required` without sending a challenge or application data. The private `callbackApprovalFile` must contain `callbackUrl`, the current `grantId` and numeric `grantVersion`; keep it under the same private-file rules. Subscription creation then verifies its fresh signed challenge. OAuth redirect URLs and MCP Events callbacks are distinct.

Authorization state, codes, refresh families, enrollments and subscription secrets are encrypted in the separate auth store. Message/context/send-barrier state uses a stable `live-v2` installation identity and a different key. Existing nonmatching state refuses to open; do not delete it to force a migration. Keep database/key pairs together for recovery. Audit metadata contains only bounded operation codes and pseudonymous grant references and expires after seven days; request bodies and credentials are not logged.

## Quick start

Use Node.js 24 or later and a platform supported by `@napi-rs/canvas`.

```sh
npm ci --ignore-scripts
npm run build
npm test
npm start
```

Without `DOTCORD_NETWORK_ENABLED=1`, the process listens on `127.0.0.1:9294`, reports disabled status at `GET /health`, and returns `503` from `/mcp`. Disabled startup reads no credential references, opens no live-state database and starts no provider intake. Stop with SIGINT or SIGTERM.

For provider intake, configure an absolute `DOTCORD_CONFIG` path using [config.example.json](config.example.json):

```sh
DOTCORD_CONFIG=/etc/dotcord/config.json DOTCORD_NETWORK_ENABLED=1 npm start
```

The example contains synthetic IDs, placeholder file references and a documentation-only source address. Replace them before enabling intake.

## Configuration

| Field | Purpose |
| --- | --- |
| `port` | Loopback HTTP port; defaults to `9294`. |
| `publicOrigin` | HTTPS origin served by a reverse proxy on the standard TLS port. |
| `stateDirectory` | Dedicated live-state directory. One DotCord process may hold its local lock. |
| `sourceAddress` | Assigned local IPv4 address used for REST, callbacks and Gateway connections. Configure routing and DNS for that address on the host. |
| `botUserId`, `applicationId` | Discord bot and application identities verified at startup. |
| `ownerUserId`, `ownerChannelId` | Owner identity and exact one-to-one DM verified against Discord. |
| `botTokenFile` | Absolute path to the external bot credential. |
| `encryptionKeyFile` | Absolute path to a canonical base64 value decoding to 32 bytes. |
| `bindings` | Separate sender, consumer, bearer and callback settings. |
| `guildMessageContent` | Opt-in use of Discord's privileged Message Content intent. |

Credential files must remain outside the installation and state directories. Symlinked references are rejected. On POSIX, state and credential files must be private and owned by the service user. Windows deployments need equivalent ACL protection; the process does not enforce POSIX mode checks on Windows. Keep real credentials and local configuration out of Git.

Each binding contains `id`, immutable `senderId`, `principal`, `bearerFile`, finite `authorizedUntil`, exact `callbackUrl`, and `audience`:

- `owner-dm` accepts the configured owner in the exact verified DM channel.
- `directed` accepts human DMs or guild messages mentioning or replying to the bot.

Bots, webhooks, unrelated guild chatter, stale messages and unconfigured senders are ignored. Sender IDs, principals, bearer files, bearer values and callback URLs must be distinct. Changing or removing a bearer file revokes its old value; authorization is checked on requests and sensitive operations.

Each sender has a separate encrypted record namespace. Context, attachment and reply references cannot cross sender boundaries. The receiving application must also isolate its consumers: distinct callback URLs alone do not isolate another application's memory, accounts or tools.

## Context, images and replies

Live context is limited to **40 turns within 24 hours**, anchored to an accepted message and its exact conversation. There is no historical message backfill or archive/search/index API. Messages missed while stopped or without an active subscription are not recovered.

Up to four PNG or JPEG images may be read on demand from an accepted message. Each image is limited to 2 MiB, 10 million pixels and one frame. The adapter revalidates its message, sender, channel and attachment identity. Image bytes and signed CDN URLs are not persisted.

Replies use the destination and anchor from the accepted inbound record. Mentions are disabled. A reply is at most 2,000 characters; a batch contains one to four replies. A complete batch is reserved durably before sending, and concurrent batches remain ordered within their conversation.

Confirmed duplicates return the existing result. A timeout, partial batch or failure to persist final confirmation leaves a durable conversation barrier. The uncertain batch is not resent, and later batches in that conversation are refused across restart. Other conversations can continue unless storage itself fails. Reconcile actual Discord results and confirmed part IDs before intervening in an uncertain send.

## HTTP and MCP

The authenticated endpoint is `POST /mcp`, with `Authorization: Bearer <provisioned value>`. Bodies cannot select the authenticated principal or its expiry. Requests use MCP `2026-07-28`, matching `mcp-protocol-version` and `mcp-method` headers, and the `_meta` protocol version, client information and capabilities. Tool calls also require the matching `mcp-name` header.

Supported methods are `server/discover`, `ping`, `tools/list`, `tools/call`, `events/list`, `events/subscribe` and `events/unsubscribe`.

| Tool | Purpose |
| --- | --- |
| `discord_connection_status` | Report the authenticated binding and audience. |
| `discord_conversation_read` | Read its bounded live conversation context. |
| `discord_attachment_read` | Read one supported image using its accepted message, conversation and attachment IDs. |
| `discord_reply_to_message` | Send one destination-bound text reply. |
| `discord_reply_batch` | Send a contiguous batch of one to four replies. |

The event is `discord.message.created`. A subscription must use its binding's configured callback URL, a valid Standard Webhooks secret and a finite TTL of at most 24 hours. A signed callback challenge must succeed before delivery starts. Rotated signing secrets overlap for five minutes. Refresh subscriptions before both their authorization and subscription expiry.

Callbacks are restricted to `chatgpt.com` and `connectors.api.openai.com`. Attempts preserve the event ID and body, allow at most five attempts, and hold later events behind their queued conversation predecessor. Expiry, revoked access and terminal delivery failures stop the affected delivery. A `2xx` callback response acknowledges receipt; it does not establish that a consumer processed the message or that Discord received a reply. See the [MCP Events integration guide](https://developers.openai.com/plugins/build/mcp-events).

REST, CDN and Gateway adapters validate public IPv4 destinations, pin DNS results to TLS connections, verify TLS identities and bind `sourceAddress`. They do not follow redirects, use proxy environment variables or automatically retry Discord writes. Host routing and DNS policy must enforce the intended egress path.

## Live state and recovery

State uses AES-256-GCM encrypted SQLite records, synchronous durable writes and compare-and-put versions. Encryption binds each body to its namespace, record type and key. Record keys, types, versions and expiry remain metadata; message text, context, subscriptions and send-barrier state are encrypted.

Live receipts, context and uncertain-send barriers expire after 24 hours. Context also keeps at most 40 turns. Expired anchors cannot be replayed. Retention runs only while the service is active or shutting down; an offline process does not perform cleanup. Retention does not erase filesystem snapshots or guarantee secure deletion.

Keep the database and its referenced encryption key together. Changing installation identities, sender bindings, callbacks or the key fails closed. Verify the exact process before addressing a stale lock. Deleting the database or lock is not a recovery procedure, and the local lock does not fence another host or state directory.

## Deployment and rollback

1. Build a known revision and configure a dedicated service identity, private state, external credentials, source routing/DNS and an HTTPS reverse proxy to the loopback endpoint. Complete compatible authentication and per-sender callback provisioning before enabling intake.
2. Record the current consumer and recovery configuration. Stop its intake, reconcile in-flight callbacks and uncertain replies, and verify that its Gateway process cannot restart alongside DotCord.
3. Enable DotCord, verify the bot/application/owner-DM identities, and establish each isolated consumer's signed subscription challenge. Test a live message, scoped context/image read and ordered reply for every enabled audience. Check for duplicate consumers and uncertain sends.
4. To roll back, stop and drain DotCord, verify its process and Gateway are closed, and preserve its encrypted state. Reconcile uncertain sends before restoring the previous consumer through its normal supervisor. Do not replay pending replies into the restored consumer.

A cutover can miss messages because historical replay is unavailable. Local tests and a health response do not establish live subscription or reply delivery.

## Development

`npm run build` compiles only `src/`. `npm test` exercises synthetic HTTP/MCP, callback, storage, sender-isolation, attachment and ordered-reply boundaries. Provider and end-to-end consumer acceptance need separate live checks.

Runtime dependencies are `zod`, `undici` and `@napi-rs/canvas`; TypeScript and Node types are development dependencies. Exact versions and package integrity are recorded in `package-lock.json`. Third-party packages retain their own licenses; no dependency source or binaries are vendored here.

## License

Copyright (C) 2026 Nyx.

DotCord is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3 only (`GPL-3.0-only`), as published by the Free Software Foundation. No later version is granted.

DotCord is distributed without any warranty, including the implied warranties of merchantability or fitness for a particular purpose. See [LICENSE](LICENSE) for the full terms. Third-party dependencies retain their own licenses and notices.
