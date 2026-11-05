import assert from "node:assert/strict";
import { test } from "node:test";
import { request as httpRequest } from "node:http";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { importJWK, SignJWT, decodeJwt } from "jose";
import { parseConfig, oauthScopes } from "../dist/config.js";
import { createRuntime } from "../dist/runtime.js";
import { startHttpServer } from "../dist/http.js";
import { AuthStore } from "../dist/auth-store.js";

// Public deterministic test key: P-256 generator point, private scalar one. Never a deployment credential.
const b64=hex=>Buffer.from(hex,"hex").toString("base64url");
const JWK={kty:"EC",crv:"P-256",kid:"synthetic-key",alg:"ES256",use:"sig",d:b64("00".repeat(31)+"01"),
  x:b64("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),y:b64("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")};
const OWNER="111111111111111111",BOT="222222222222222222",APP="888888888888888888",CHANNEL="333333333333333333";
const ORIGIN="https://dotcord.example.com",ISSUER=ORIGIN+"/oauth",RESOURCE=ORIGIN+"/mcp",REDIRECT="https://chatgpt.com/connector_platform_oauth_redirect";
const META={"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{name:"synthetic",version:"1"},"io.modelcontextprotocol/clientCapabilities":{}};
const SECRET="whsec_"+Buffer.alloc(32,7).toString("base64");
async function harness(t,{continuous=false}={}) {
  const directory=await mkdtemp(join(tmpdir(),"dotcord-oauth-")),external=join(directory,"external");await mkdir(external,{mode:0o700});
  const input={publicOrigin:ORIGIN+"/",sourceAddress:"127.0.0.1",botUserId:BOT,applicationId:APP,ownerUserId:OWNER,ownerChannelId:CHANNEL,
    botTokenFile:join(external,"must-not-read-bot"),encryptionKeyFile:join(external,"must-not-read-live-key"),stateDirectory:join(directory,"must-not-create-live"),
    oauth:{installationId:"synthetic-installation-01",stateDirectory:join(directory,"auth"),encryptionKeyFile:join(external,"auth-key"),signingKeyFile:join(external,"issuer-jwk"),cookieKeyFile:join(external,"cookie-key"),
      clientId:"dotcord-chatgpt-owner-v1",redirectUris:[REDIRECT],discordClientId:APP,discordClientSecretFile:join(external,"login-secret")},
    bindings:[{id:"owner",senderId:OWNER,principal:"owner-consumer",authorizedUntil:continuous?null:new Date(Date.now()+3600000).toISOString(),audience:"owner-dm",callbackApprovalFile:join(external,"callback-approval")}]};
  for(const[path,value]of[[input.oauth.encryptionKeyFile,Buffer.alloc(32,3).toString("base64")],[input.oauth.cookieKeyFile,Buffer.alloc(32,4).toString("base64")],[input.oauth.signingKeyFile,JSON.stringify(JWK)],[input.oauth.discordClientSecretFile,"synthetic_login_secret_0123456789"]])await writeFile(path,value,{mode:0o600});
  const calls=[],callbacks=[],logs=[],jar=new Map();let botCalls=0;
  const transport={request:async(url,method,body,headers)=>{
    calls.push({url,method});
    if(url==="https://discord.com/api/oauth2/token") {
      assert.equal(method,"POST");assert.equal(headers["content-type"],"application/x-www-form-urlencoded");assert.match(headers.authorization,/^Basic /);
      const p=new URLSearchParams(body);assert.equal(p.get("redirect_uri"),ISSUER+"/login/discord/callback");assert.ok(p.get("code_verifier"));
      return {status:200,bodyText:JSON.stringify({access_token:"synthetic-upstream-token",refresh_token:"discard-me",token_type:"Bearer",scope:"identify"})};
    }
    if(url==="https://discord.com/api/v10/users/@me") {assert.equal(headers.authorization,"Bearer synthetic-upstream-token");return {status:200,bodyText:JSON.stringify({id:OWNER,bot:false})};}
    throw new Error("unplanned_external_call");
  },post:async(url,body,headers)=>{callbacks.push({url,body,headers});const p=JSON.parse(body);assert.equal(p.type,"verification");return {status:200,body:JSON.stringify({challenge:p.challenge})};},close:async()=>{}};
  let runtime,http;
  const start=async()=>{runtime=await createRuntime(parseConfig(input,false,true),()=>{botCalls++;throw new Error("bot_adapter_must_not_start");},code=>logs.push(code),{authTransport:transport});http=await startHttpServer(runtime,0);};
  await start();
  t.after(async()=>{await http?.stop();await runtime?.stop();await rm(directory,{recursive:true,force:true});});
  const req=async(path,method="GET",body,extra={})=>{
    const logical=new URL(path,ORIGIN);assert.equal(logical.origin,ORIGIN,"synthetic browser cannot follow external destinations");
    const cookie=[...jar].filter(([,c])=>logical.pathname.startsWith(c.path)).map(([k,c])=>`${k}=${c.value}`).join("; ");
    return new Promise((resolve,reject)=>{const r=httpRequest({hostname:"127.0.0.1",port:http.server.address().port,path:logical.pathname+logical.search,method,headers:{host:new URL(ORIGIN).host,...(cookie?{cookie}:{}),...extra}},res=>{
      for(const item of res.headers["set-cookie"]??[]){const [kv,...attrs]=item.split(";");const index=kv.indexOf("="),name=kv.slice(0,index),value=kv.slice(index+1),path=attrs.find(s=>s.trim().toLowerCase().startsWith("path="))?.trim().slice(5)??"/";jar.set(name,{value,path});}
      const chunks=[];res.on("data",b=>chunks.push(b));res.on("end",()=>resolve({status:res.statusCode,headers:res.headers,url:logical.href,text:Buffer.concat(chunks).toString("utf8")}));res.on("error",reject);
    });r.on("error",reject);r.end(body);});
  };
  const walk=async(response)=>{for(let i=0;i<10&&[302,303].includes(response.status);i++){const next=new URL(response.headers.location,ORIGIN);if(next.origin!==ORIGIN)return {...response,destination:next};response=await req(next.href);}return response;};
  const login=async({checkConsentOrigins=false,forceLogin=false}={})=>{
    const verifier="synthetic_pkce_verifier_012345678901234567890123456789",challenge=(await import("node:crypto")).createHash("sha256").update(verifier).digest("base64url");
    const params=new URLSearchParams({client_id:input.oauth.clientId,response_type:"code",redirect_uri:REDIRECT,scope:"openid offline_access "+oauthScopes.join(" "),resource:RESOURCE,state:"synthetic-openai-state",code_challenge:challenge,code_challenge_method:"S256",prompt:forceLogin?"login consent":"consent"});
    let r=await walk(await req("/oauth/authorize?"+params));assert.equal(r.destination?.origin,"https://discord.com",r.text);
    assert.equal(r.destination.searchParams.get("scope"),"identify");assert.equal(r.destination.searchParams.get("code_challenge_method"),"S256");
    const ret=new URL(ISSUER+"/login/discord/callback");ret.searchParams.set("state",r.destination.searchParams.get("state"));ret.searchParams.set("code","synthetic-discord-code");ret.searchParams.set("iss","https://discord.com");
    const returned=await req(ret.href);assert.equal(returned.headers["referrer-policy"],"no-referrer");
    r=await walk(returned);assert.equal(r.status,200,r.text);assert.match(r.text,/Authorize DotCord/);assert.equal(r.headers["referrer-policy"],"same-origin");
    assert.match(r.text,input.bindings[0].authorizedUntil===null?/until you revoke this connection/:/at most 24 hours/);
    assert.equal(r.headers["content-security-policy"],`default-src 'none'; form-action 'self' ${REDIRECT}; frame-ancestors 'none'; base-uri 'none'`);
    const csrf=/name="csrf" value="([^"]+)"/.exec(r.text)?.[1];assert.ok(csrf,r.text);
    const consentPath=r.url;
    const consentBody=new URLSearchParams({csrf,action:"approve"}).toString();
    if(checkConsentOrigins) {
      const uid=new URL(consentPath).pathname.split("/").pop();
      for(const origin of ["null","https://chatgpt.com"]) {
        const denied=await req(consentPath,"POST",consentBody,{"content-type":"application/x-www-form-urlencoded",origin});
        assert.equal(denied.status,403,denied.text);assert.equal(runtime.oauth.store.get("consent",uid).value.consumed,undefined,"rejected origin cannot consume consent");assert.equal(runtime.oauth.grantFor("owner"),undefined);
      }
    }
    r=await walk(await req(consentPath,"POST",consentBody,{"content-type":"application/x-www-form-urlencoded",origin:ORIGIN}));
    assert.equal(r.destination?.origin,"https://chatgpt.com",r.text);assert.equal(r.destination.searchParams.get("iss"),ISSUER);assert.equal(r.destination.searchParams.get("state"),"synthetic-openai-state");
    const code=r.destination.searchParams.get("code");assert.ok(code);
    const exchange=async(overrides={})=>req("/oauth/token","POST",new URLSearchParams({client_id:input.oauth.clientId,grant_type:"authorization_code",redirect_uri:REDIRECT,resource:RESOURCE,code,code_verifier:verifier,...overrides}).toString(),{"content-type":"application/x-www-form-urlencoded"});
    return {code,verifier,exchange};
  };
  const rpc=async(token,method,params={})=>req("/mcp","POST",JSON.stringify({jsonrpc:"2.0",id:1,method,params:{...params,_meta:META}}),{"content-type":"application/json",authorization:"Bearer "+token,"mcp-protocol-version":"2026-07-28","mcp-method":method,...(method==="tools/call"?{"mcp-name":params.name}:{})});
  return {directory,input,req,login,rpc,callbacks,calls,logs,get runtime(){return runtime;},get botCalls(){return botCalls;},restart:async()=>{await http.stop();await runtime.stop();await start();},json:r=>JSON.parse(r.text)};
}

test("actual maintained issuer completes PKCE login and finite refresh; auth-only, token checks and callback isolation survive restart",async t=>{
  const f=await harness(t);
  const invalidCallback=await f.req("/oauth/login/discord/callback");assert.equal(invalidCallback.status,400);assert.equal(invalidCallback.headers["content-security-policy"],"default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");assert.equal(invalidCallback.headers["referrer-policy"],"no-referrer");
  const metadata=f.json(await f.req("/.well-known/oauth-protected-resource/mcp"));assert.equal(metadata.resource,RESOURCE);assert.deepEqual(metadata.authorization_servers,[ISSUER]);
  const discovery=f.json(await f.req("/oauth/.well-known/openid-configuration"));assert.equal(discovery.issuer,ISSUER);assert.deepEqual(discovery.code_challenge_methods_supported,["S256"]);assert.equal(discovery.authorization_response_iss_parameter_supported,true);assert.equal(discovery.registration_endpoint,undefined);
  assert.equal((await f.req("/mcp","POST","{}",{"content-type":"application/json"})).status,401);
  const login=await f.login({checkConsentOrigins:true}),issued=await login.exchange();assert.equal(issued.status,200,issued.text);const token=f.json(issued);assert.ok(token.access_token);assert.ok(token.refresh_token);assert.ok(token.expires_in<=300);
  const claims=decodeJwt(token.access_token);assert.equal(claims.aud,RESOURCE);assert.equal(claims.client_id,f.input.oauth.clientId);assert.ok(claims.grant_id);assert.equal(claims.grant_version,1);
  assert.equal((await f.rpc(token.access_token,"tools/call",{name:"discord_connection_status",arguments:{}})).status,200);
  const key=await importJWK(JWK,"ES256");
  for(const change of [{iss:"https://evil.example/oauth"},{aud:"https://evil.example/mcp"},{client_id:"foreign"},{exp:Math.floor(Date.now()/1000)-1}]){
    const bad=await new SignJWT({...claims,...change}).setProtectedHeader({alg:"ES256",kid:JWK.kid,typ:"at+jwt"}).sign(key);assert.equal((await f.rpc(bad,"ping")).status,401);
  }
  const restricted=await new SignJWT({...claims,scope:"discord:status"}).setProtectedHeader({alg:"ES256",kid:JWK.kid,typ:"at+jwt"}).sign(key);
  assert.equal((await f.rpc(restricted,"tools/call",{name:"discord_reply_to_message",arguments:{}})).status,403);
  const url="https://chatgpt.com/mcp-events/synthetic-owner",params={name:"discord.message.created",arguments:{audience:"owner-dm"},delivery:{mode:"webhook",url,secret:SECRET},ttlMs:3600000};
  const pending=await f.rpc(token.access_token,"events/subscribe",params);assert.equal(pending.status,403);assert.equal(f.callbacks.length,0);
  const grant=f.runtime.oauth.grantFor("owner");await writeFile(f.input.bindings[0].callbackApprovalFile,JSON.stringify({callbackUrl:url,grantId:grant.id,grantVersion:grant.version}),{mode:0o600});
  const sub=await f.rpc(token.access_token,"events/subscribe",params);assert.equal(f.json(sub).error,undefined,sub.text);assert.equal(f.callbacks.length,1);
  assert.equal((await f.rpc(token.access_token,"events/subscribe",{...params,delivery:{...params.delivery,url:"https://chatgpt.com/mcp-events/foreign"}})).status,403);
  const rotated=await f.rpc(token.access_token,"events/subscribe",{...params,delivery:{...params.delivery,secret:"whsec_"+Buffer.alloc(32,8).toString("base64")}});assert.equal(f.json(rotated).error,undefined,rotated.text);assert.equal(f.callbacks.length,2);assert.equal(f.callbacks[1].headers["webhook-signature"].split(" ").length,2);
  await f.restart();assert.ok(await f.runtime.oauth.authenticate("Bearer "+token.access_token));assert.equal(f.botCalls,0);await assert.rejects(readFile(f.input.encryptionKeyFile),/ENOENT/);await assert.rejects(readFile(join(f.input.stateDirectory,"dotcord.sqlite")),/ENOENT/);
  const refresh=()=>f.req("/oauth/token","POST",new URLSearchParams({grant_type:"refresh_token",refresh_token:token.refresh_token,client_id:f.input.oauth.clientId,resource:RESOURCE}).toString(),{"content-type":"application/x-www-form-urlencoded"});
  const renewed=await refresh();assert.equal(renewed.status,200,renewed.text);const next=f.json(renewed);assert.notEqual(next.refresh_token,token.refresh_token);assert.equal(decodeJwt(next.access_token).grant_id,claims.grant_id);
  assert.equal((await refresh()).status,400);assert.equal(await f.runtime.oauth.authenticate("Bearer "+next.access_token),undefined);
  assert.equal(f.botCalls,0);assert.ok(f.calls.every(c=>c.url.startsWith("https://discord.com/")));assert.ok(f.logs.every(c=>/^[a-z_]+$/.test(c)));
});

test("authorization code is single-use under concurrent actual token exchanges",async t=>{
  const f=await harness(t),login=await f.login(),results=await Promise.all([login.exchange(),login.exchange()]);
  assert.ok(results.every(x=>x.status===200||x.status===400));assert.ok(results.some(x=>x.status===400));assert.ok(results.filter(x=>x.status===200).length<=1,"a code cannot issue twice");
  for(const denied of results.filter(x=>x.status===400))assert.equal(f.json(denied).error,"invalid_grant",denied.text);
  assert.equal(f.runtime.oauth.grantFor("owner").revoked,true,"concurrent replay revokes its grant before further issuance");
  for(const issued of results.filter(x=>x.status===200))assert.equal(await f.runtime.oauth.authenticate("Bearer "+f.json(issued).access_token),undefined,"any issued token is revoked");
});

test("continuous real issuer survives nominal Grant and family age with rolling bounded refresh, restart and revocation",async t=>{
  const initial=Date.now(),DAY=86400000;t.mock.timers.enable({apis:["Date"],now:initial});
  const f=await harness(t,{continuous:true}),login=await f.login({checkConsentOrigins:true}),issued=await login.exchange();assert.equal(issued.status,200,issued.text);
  let token=f.json(issued),previous;const grant=f.runtime.oauth.grantFor("owner");assert.equal(grant.until,null);assert.ok(token.refresh_token);assert.ok(token.expires_in<=300);
  const provider=f.runtime.oauth.store.get("Grant",grant.providerGrantId);assert.equal(provider.expires,null);assert.equal(Object.hasOwn(provider.value,"exp"),false);
  await f.restart();assert.equal((await f.runtime.oauth.authenticate("Bearer "+token.access_token)).authorizedUntil,null);
  for(const days of [6,12,18]) {
    t.mock.timers.setTime(initial+days*DAY);f.runtime.oauth.store.prune();assert.equal(await f.runtime.oauth.authenticate("Bearer "+token.access_token),undefined);
    previous=token.refresh_token;
    const response=await f.req("/oauth/token","POST",new URLSearchParams({grant_type:"refresh_token",refresh_token:previous,client_id:f.input.oauth.clientId,resource:RESOURCE}).toString(),{"content-type":"application/x-www-form-urlencoded"});
    assert.equal(response.status,200,response.text);token=f.json(response);assert.notEqual(token.refresh_token,previous);assert.ok(token.expires_in<=300);assert.equal(decodeJwt(token.access_token).grant_id,grant.id);assert.ok(await f.runtime.oauth.authenticate("Bearer "+token.access_token));
    const row=f.runtime.oauth.store.get("RefreshToken",token.refresh_token);assert.ok(row.expires>Date.now()+6*DAY&&row.expires<=Date.now()+7*DAY);assert.equal(f.runtime.oauth.grantFor("owner").until,null);
  }
  const replay=await f.req("/oauth/token","POST",new URLSearchParams({grant_type:"refresh_token",refresh_token:previous,client_id:f.input.oauth.clientId,resource:RESOURCE}).toString(),{"content-type":"application/x-www-form-urlencoded"});
  assert.equal(replay.status,400);assert.equal(f.runtime.oauth.grantFor("owner").revoked,true);assert.equal(await f.runtime.oauth.authenticate("Bearer "+token.access_token),undefined);assert.equal(f.botCalls,0);
});

test("new continuous generation requires consent; old code, refresh and callback cannot revive or revoke it",async t=>{
  const f=await harness(t),firstLogin=await f.login(),first=f.json(await firstLogin.exchange()),old=f.runtime.oauth.grantFor("owner");
  const pendingCode=await f.login({forceLogin:true});
  f.input.bindings[0].authorizedUntil=null;await f.restart();assert.equal(f.runtime.oauth.grantFor("owner").until,old.until,"policy alone does not widen an existing finite grant");
  f.input.bindings[0].grantVersion=2;await f.restart();assert.equal(await f.runtime.oauth.authenticate("Bearer "+first.access_token),undefined);
  const newLogin=await f.login({forceLogin:true}),issued=await newLogin.exchange();assert.equal(issued.status,200,issued.text);const next=f.json(issued),current=f.runtime.oauth.grantFor("owner");
  assert.equal(current.version,2);assert.equal(current.until,null);assert.notEqual(current.id,old.id);
  const refresh=await f.req("/oauth/token","POST",new URLSearchParams({grant_type:"refresh_token",refresh_token:first.refresh_token,client_id:f.input.oauth.clientId,resource:RESOURCE}).toString(),{"content-type":"application/x-www-form-urlencoded"});assert.equal(refresh.status,400);
  assert.equal((await pendingCode.exchange()).status,400);await f.runtime.oauth.provider.RefreshToken.revokeByGrantId(old.providerGrantId);assert.equal(f.runtime.oauth.grantFor("owner").revoked,false);assert.ok(await f.runtime.oauth.authenticate("Bearer "+next.access_token));
  assert.equal(f.runtime.oauth.store.get("Grant",old.providerGrantId,true),undefined);assert.equal(f.runtime.oauth.store.get("provider-link",old.providerGrantId,true),undefined);
  const url="https://chatgpt.com/mcp-events/synthetic-owner",params={name:"discord.message.created",arguments:{audience:"owner-dm"},delivery:{mode:"webhook",url,secret:SECRET},ttlMs:null};
  await writeFile(f.input.bindings[0].callbackApprovalFile,JSON.stringify({callbackUrl:url,grantId:old.id,grantVersion:old.version}),{mode:0o600});assert.equal((await f.rpc(next.access_token,"events/subscribe",params)).status,403);assert.equal(f.callbacks.length,0);
  await writeFile(f.input.bindings[0].callbackApprovalFile,JSON.stringify({callbackUrl:url,grantId:current.id,grantVersion:current.version}),{mode:0o600});const sub=await f.rpc(next.access_token,"events/subscribe",params);assert.equal(f.json(sub).result.refreshBefore,null);assert.equal(f.callbacks.length,1);
  f.runtime.oauth.revoke("owner");assert.equal(await f.runtime.oauth.authenticate("Bearer "+next.access_token),undefined);assert.equal(await f.runtime.oauth.authorize("owner-consumer"),false);assert.equal(f.runtime.oauth.grantFor("owner").revoked,true);
});

test("changing continuous policy to a finite cutoff immediately denies the old continuous grant",async t=>{
  const f=await harness(t,{continuous:true}),login=await f.login(),response=await login.exchange();assert.equal(response.status,200,response.text);const token=f.json(response);
  f.input.bindings[0].authorizedUntil=new Date(Date.now()+3600000).toISOString();await f.restart();assert.equal(f.runtime.oauth.grantFor("owner").until,null);assert.equal(f.runtime.oauth.grantFor("owner").revoked,false);assert.equal(await f.runtime.oauth.authenticate("Bearer "+token.access_token),undefined);assert.equal(await f.runtime.oauth.authorize("owner-consumer"),false);
});

test("encrypted auth storage enforces expiry integrity, atomic consume and capacity for CAS inserts",async t=>{
  const directory=await mkdtemp(join(tmpdir(),"dotcord-auth-store-")),s=new AuthStore(directory,Buffer.alloc(32,6),"synthetic-installation");t.after(async()=>{s.close();await rm(directory,{recursive:true,force:true});});
  s.set("credential","one",{value:"synthetic"},Date.now()+60000);assert.equal(s.consume("credential","one"),true);assert.equal(s.consume("credential","one"),false);
  s.set("credential","expiry",{value:"synthetic"},Date.now()+60000);
  const db=new DatabaseSync(join(directory,"auth.sqlite"));db.prepare("UPDATE auth_v1 SET expires=expires+60000 WHERE ns='credential'").run();db.close();assert.throws(()=>s.get("credential","expiry"),/integrity/);
  s.atomic(()=>{for(let i=0;i<9997;i++)s.set("capacity",String(i),{n:i},Number.MAX_SAFE_INTEGER,null);});
  assert.throws(()=>s.set("capacity","new",{n:1},Number.MAX_SAFE_INTEGER,null),/capacity/);
  const old=s.get("capacity","0");s.set("capacity","0",{n:2},Number.MAX_SAFE_INTEGER,old.etag);assert.equal(s.get("capacity","0").value.n,2);
});
