import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { bridgeProtocol } from "./protocol.js";
import type { Runtime } from "./runtime.js";
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
      if (!permittedHosts.includes(request.headers.host ?? "") || origin && !["https://chatgpt.com","https://connectors.api.openai.com",runtime.config.publicOrigin].includes(origin)) {
        send(response,403,{error:"origin_denied"}); return;
      }
      if (request.method === "GET" && request.url === "/health") { send(response,200,runtime.status()); return; }
      if (request.url !== "/mcp" || request.method !== "POST") { send(response,404,{error:"not_found"}); return; }
      if (!runtime.config.enabled) { send(response,503,{error:"disabled"}); return; }
      const binding = runtime.authenticate(request.headers.authorization);
      if (!binding) { response.setHeader("www-authenticate",'Bearer realm="DotCord"'); send(response,401,{error:"unauthorized"}); return; }
      let rpc: unknown;
      try { rpc=await readBody(request); } catch { send(response,400,{error:"invalid_request"}); return; }
      // Never trust body-supplied principals, expiry, headers or OAuth claims.
      const headers: Record<string,string>={};
      for (const name of ["mcp-protocol-version","mcp-method","mcp-name"]) if (typeof request.headers[name] === "string") headers[name]=request.headers[name];
      const result = await bridgeProtocol(runtime.bridges.get(binding.id)!,{principal:binding.principal,authorizedUntil:Date.parse(binding.authorizedUntil),headers,rpc});
      send(response,result.status,result.body);
    } catch { if (!response.headersSent) send(response,500,{error:"internal_error"}); else response.destroy(); }
    finally { active--; }
  });
  server.requestTimeout=15000; server.headersTimeout=10000; server.keepAliveTimeout=5000; server.maxHeadersCount=32;
  await new Promise<void>((resolve,reject) => { server.once("error",reject); server.listen(port,"127.0.0.1",resolve); });
  return {server,stop:async () => { server.closeIdleConnections(); await new Promise<void>((resolve,reject) => server.close(error => error ? reject(error) : resolve())); }};
}
