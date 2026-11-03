import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { bridgeProtocol } from "./protocol.js";
import type { Runtime } from "./runtime.js";
import { OAuthError, oauthChallenge, requiredScopes } from "./oauth.js";
const MAX_REQUEST = 65536;
function send(response: ServerResponse, status: number, body: unknown) {
  response.writeHead(status,{"content-type":"application/json","cache-control":"no-store","x-content-type-options":"nosniff"});
  response.end(JSON.stringify(body));
}
async function readBody(request: IncomingMessage): Promise<unknown> {
  if (request.headers["content-encoding"] || request.headers["content-type"]?.split(";",1)[0]?.trim() !== "application/json") throw new Error("invalid_body");
  const chunks: Buffer[] = []; let bytes=0;
  for await (const value of request) { const chunk = Buffer.from(value as Uint8Array); bytes += chunk.length; if (bytes>MAX_REQUEST) throw new Error("request_too_large"); chunks.push(chunk); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
export async function startHttpServer(runtime: Runtime, port = runtime.config.port) {
  let active = 0;
  const server = createServer(async (request,response) => {
    if (++active > 64) { active--; send(response,503,{error:"busy"}); return; }
    try {
      const local = `127.0.0.1:${(server.address() as {port:number}).port}`;
      const permittedHosts = [local,...(runtime.config.publicOrigin ? [new URL(runtime.config.publicOrigin).host] : [])];
      const origin = request.headers.origin;
      if (!permittedHosts.includes(request.headers.host ?? "") || origin && !["https://chatgpt.com","https://connectors.api.openai.com",runtime.config.publicOrigin ? new URL(runtime.config.publicOrigin).origin : undefined].includes(origin)) {
        send(response,403,{error:"origin_denied"}); return;
      }
      if (request.method === "GET" && request.url === "/health") { send(response,200,runtime.status()); return; }
      if (runtime.oauth && await runtime.oauth.handle(request,response)) return;
      if (request.url !== "/mcp" || request.method !== "POST") { send(response,404,{error:"not_found"}); return; }
      if (!runtime.config.enabled && !runtime.config.authEnabled) { send(response,503,{error:"disabled"}); return; }
      const binding = await runtime.authenticate(request.headers.authorization);
      if (!binding) { response.setHeader("www-authenticate",runtime.oauth?oauthChallenge(runtime.config,"invalid_token"):'Bearer realm="DotCord"'); send(response,401,{error:"unauthorized"}); return; }
      let rpc: unknown;
      try { rpc=await readBody(request); } catch { send(response,400,{error:"invalid_request"}); return; }
      const bridge=runtime.bridges.get(binding.id)!;
      if(runtime.oauth) {
        const call=rpc && typeof rpc==="object"?rpc as {method?:unknown;params?:{name?:unknown;delivery?:{url?:unknown}}}:undefined;
        const required=requiredScopes(typeof call?.method==="string"?call.method:"",typeof call?.params?.name==="string"?call.params.name:undefined);
        if(required.some(scope=>!binding.scopes.includes(scope))) {
          response.setHeader("www-authenticate",oauthChallenge(runtime.config,"insufficient_scope",required.join(" ")));send(response,403,{error:"insufficient_scope"});return;
        }
        if(call?.method==="events/subscribe" && typeof call.params?.delivery?.url==="string") {
          try {const enrolled=runtime.oauth.enroll(binding,call.params.delivery.url);bridge.config.callbackUrl=enrolled.url;}
          catch(error){if(error instanceof OAuthError){send(response,error.status,{error:error.code});return;}send(response,403,{error:"unsafe_callback"});return;}
        }
      }
      // Never trust body-supplied principals, expiry, headers or OAuth claims.
      const headers: Record<string,string>={};
      for (const name of ["mcp-protocol-version","mcp-method","mcp-name"]) if (typeof request.headers[name] === "string") headers[name]=request.headers[name];
      const result = await bridgeProtocol(bridge,{principal:binding.principal,authorizedUntil:Date.parse(binding.authorizedUntil),
        ...("authority" in binding?{authority:binding.authority}:{}),headers,rpc});
      send(response,result.status,result.body);
    } catch { if (!response.headersSent) send(response,500,{error:"internal_error"}); else response.destroy(); }
    finally { active--; }
  });
  server.requestTimeout=15000; server.headersTimeout=10000; server.keepAliveTimeout=5000; server.maxHeadersCount=32;
  await new Promise<void>((resolve,reject) => { server.once("error",reject); server.listen(port,"127.0.0.1",resolve); });
  return {server,stop:async () => { server.closeIdleConnections(); await new Promise<void>((resolve,reject) => server.close(error => error ? reject(error) : resolve())); }};
}
