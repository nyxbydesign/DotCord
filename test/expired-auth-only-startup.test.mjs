import assert from "node:assert/strict";
import { test } from "node:test";
import { createCipheriv, randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";
import { mkdtemp, mkdir, writeFile, readFile, chmod, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { importJWK, SignJWT } from "jose";
import { parseConfig, oauthScopes } from "../dist/config.js";
import { createRuntime } from "../dist/runtime.js";
import { startHttpServer } from "../dist/http.js";
import { authHash } from "../dist/auth-store.js";

const OWNER="111111111111111111",BOT="222222222222222222",APP="888888888888888888",CHANNEL="333333333333333333";
const ORIGIN="https://expired.dotcord.example",ISSUER=ORIGIN+"/oauth",RESOURCE=ORIGIN+"/mcp";
const EXPIRED=new Date(Date.now()-60000).toISOString(),AUTH_KEY=Buffer.alloc(32,3);
const b64=hex=>Buffer.from(hex,"hex").toString("base64url");
// Public synthetic P-256 key, scalar one; never a deployment credential.
const JWK={kty:"EC",crv:"P-256",kid:"synthetic-expired-key",alg:"ES256",use:"sig",d:b64("00".repeat(31)+"01"),
  x:b64("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),y:b64("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")};
function inputAt(directory) {
  const external=join(directory,"external");
  return {publicOrigin:ORIGIN+"/",sourceAddress:"127.0.0.1",botUserId:BOT,applicationId:APP,ownerUserId:OWNER,ownerChannelId:CHANNEL,
    botTokenFile:join(external,"must-not-read-bot"),encryptionKeyFile:join(external,"must-not-read-live-key"),stateDirectory:join(directory,"must-not-create-live"),
    oauth:{installationId:"synthetic-expired-auth-01",stateDirectory:join(directory,"auth"),encryptionKeyFile:join(external,"auth-key"),cookieKeyFile:join(external,"cookie-key"),signingKeyFile:join(external,"issuer-jwk"),discordClientSecretFile:join(external,"login-secret"),discordClientId:APP,clientId:"synthetic-owner-client",redirectUris:["https://chatgpt.com/connector_platform_oauth_redirect"]},
    bindings:[{id:"owner",senderId:OWNER,principal:"owner-consumer",authorizedUntil:EXPIRED,grantVersion:1,scopes:[...oauthScopes],audience:"owner-dm",callbackApprovalFile:join(external,"callback-approval")}]};
}
async function fixture(t,{withGrant=true}={}) {
  const directory=await mkdtemp(join(tmpdir(),"dotcord-expired-startup-")),input=inputAt(directory);let runtime,http,botCalls=0,requestCalls=0,postCalls=0;
  t.after(async()=>{await http?.stop();await runtime?.stop();await rm(directory,{recursive:true,force:true});});
  await mkdir(join(directory,"external"),{mode:0o700});await mkdir(input.oauth.stateDirectory,{mode:0o700});
  const keyFiles=[[input.oauth.encryptionKeyFile,AUTH_KEY.toString("base64")],[input.oauth.cookieKeyFile,Buffer.alloc(32,4).toString("base64")],[input.oauth.signingKeyFile,JSON.stringify(JWK)],[input.oauth.discordClientSecretFile,"synthetic_login_secret_0123456789"]];
  for(const[path,value]of keyFiles)await writeFile(path,value,{mode:0o600});
  const installation=JSON.stringify(["oauth-v1",input.oauth.installationId,ISSUER,APP,BOT,OWNER,CHANNEL]);
  const grant={id:"A".repeat(32),version:1,bindingId:"owner",subject:authHash(JSON.stringify([ISSUER,OWNER])),clientId:input.oauth.clientId,scopes:[...oauthScopes],started:Date.parse(EXPIRED)-3600000,until:Date.parse(EXPIRED),revoked:false,providerGrantId:"synthetic-expired-provider-grant"};
  const file=join(input.oauth.stateDirectory,"auth.sqlite"),legacy=new DatabaseSync(file);
  legacy.exec("CREATE TABLE auth_v1 (ns TEXT NOT NULL,id TEXT NOT NULL,etag TEXT NOT NULL,expires INTEGER NOT NULL,body BLOB NOT NULL,grant_ref TEXT,uid_ref TEXT,user_ref TEXT,PRIMARY KEY(ns,id)); CREATE INDEX auth_grant ON auth_v1(grant_ref); CREATE INDEX auth_uid ON auth_v1(ns,uid_ref);");
  const add=(ns,id,value,expires)=>{const iv=randomBytes(12),cipher=createCipheriv("aes-256-gcm",AUTH_KEY,iv);cipher.setAAD(Buffer.from(JSON.stringify(["auth-v1",installation,ns,authHash(id)])));const bytes=Buffer.concat([cipher.update(JSON.stringify({value,expires})),cipher.final()]);legacy.prepare("INSERT INTO auth_v1 VALUES (?,?,?,?,?,?,?,?)").run(ns,authHash(id),"synthetic-unchanged-etag",expires,Buffer.concat([iv,cipher.getAuthTag(),bytes]),typeof value.grantId==="string"?authHash(value.grantId):null,null,null);};
  add("installation","primary",{identity:installation},Number.MAX_SAFE_INTEGER);
  if(withGrant){
    add("authorization","owner",grant,Number.MAX_SAFE_INTEGER);add("provider-link",grant.providerGrantId,{bindingId:"owner"},Number.MAX_SAFE_INTEGER);
    const payload={accountId:grant.subject,clientId:grant.clientId,iat:Math.floor(grant.started/1000),exp:Math.floor(grant.until/1000)};
    add("Grant",grant.providerGrantId,{...payload,jti:grant.providerGrantId,kind:"Grant"},grant.until);
    add("RefreshToken","synthetic-expired-refresh",{...payload,jti:"synthetic-expired-refresh",kind:"RefreshToken",grantId:grant.providerGrantId,scope:"openid offline_access "+oauthScopes.join(" ")},grant.until);
  }
  const before=legacy.prepare("SELECT * FROM auth_v1 ORDER BY ns,id").all();legacy.close();await chmod(file,0o600);
  const keyBytes=await Promise.all(keyFiles.map(async([path])=>[path,await readFile(path)]));
  const config=parseConfig(input,false,true);assert.equal(config.bindings[0].authorizedUntil,EXPIRED);assert.equal(config.bindings[0].grantVersion,1);
  runtime=await createRuntime(config,()=>{botCalls++;throw Error("bot_adapter_must_not_start");},()=>{},{authTransport:{request:async()=>{requestCalls++;throw Error("upstream_must_not_be_called");},post:async()=>{postCalls++;throw Error("callback_must_not_be_called");},close:async()=>{}}});
  http=await startHttpServer(runtime,0);
  const rows=()=>{const db=new DatabaseSync(file,{readOnly:true});try{return db.prepare("SELECT * FROM auth_v1 ORDER BY ns,id").all();}finally{db.close();}};
  const preserved=async()=>{assert.deepEqual(rows(),before,"migration/startup and denied requests preserve encrypted bodies, numeric expiry, etags and refs");for(const[path,bytes]of keyBytes)assert.deepEqual(await readFile(path),bytes);assert.equal(botCalls,0);assert.equal(requestCalls,0);assert.equal(postCalls,0);await assert.rejects(readFile(input.botTokenFile),/ENOENT/);await assert.rejects(readFile(input.encryptionKeyFile),/ENOENT/);await assert.rejects(readFile(join(input.stateDirectory,"dotcord.sqlite")),/ENOENT/);};
  const req=(path,method="GET",body,headers={})=>new Promise((resolve,reject)=>{const r=httpRequest({hostname:"127.0.0.1",port:http.server.address().port,path,method,headers:{host:new URL(ORIGIN).host,...headers}},res=>{const chunks=[];res.on("data",b=>chunks.push(b));res.on("end",()=>resolve({status:res.statusCode,text:Buffer.concat(chunks).toString("utf8")}));res.on("error",reject);});r.on("error",reject);r.end(body);});
  await preserved();const inspect=new DatabaseSync(file,{readOnly:true});assert.equal(inspect.prepare("PRAGMA table_info(auth_v1)").all().find(c=>c.name==="expires").notnull,0);inspect.close();
  return {input,config,runtime,grant,req,preserved,rows};
}

test("expired finite auth-only startup migrates legacy rows and serves health while every authority path remains denied",async t=>{
  const f=await fixture(t);assert.deepEqual(JSON.parse((await f.req("/health")).text),{enabled:false,authenticationEnabled:true,ready:true});
  const discovery=await f.req("/oauth/.well-known/openid-configuration");assert.equal(discovery.status,200);assert.equal(JSON.parse(discovery.text).issuer,ISSUER);
  assert.deepEqual(f.runtime.oauth.grantFor("owner"),f.grant);assert.equal(await f.runtime.oauth.authorize("owner-consumer"),false);
  const now=Math.floor(Date.now()/1000),token=await new SignJWT({iss:ISSUER,aud:RESOURCE,sub:f.grant.subject,client_id:f.grant.clientId,grant_id:f.grant.id,grant_version:1,scope:oauthScopes.join(" "),iat:now,nbf:now,exp:now+300,jti:"synthetic-current-token"}).setProtectedHeader({alg:"ES256",kid:JWK.kid,typ:"at+jwt"}).sign(await importJWK(JWK,"ES256"));
  assert.equal(await f.runtime.authenticate("Bearer "+token),undefined,"even a correctly signed current token cannot revive expired authority");
  for(const method of ["events/subscribe","tools/call"]){const response=await f.req("/mcp","POST",JSON.stringify({jsonrpc:"2.0",id:1,method,params:{name:method==="tools/call"?"discord_reply_to_message":"discord.message.created"}}),{"content-type":"application/json",authorization:"Bearer "+token});assert.equal(response.status,401,response.text);}
  const refreshed=await f.req("/oauth/token","POST",new URLSearchParams({grant_type:"refresh_token",refresh_token:"synthetic-expired-refresh",client_id:f.input.oauth.clientId,resource:RESOURCE}).toString(),{"content-type":"application/x-www-form-urlencoded"});assert.equal(refreshed.status,400);assert.equal(JSON.parse(refreshed.text).error,"invalid_grant");
  assert.throws(()=>f.runtime.oauth.enroll(f.config.bindings[0],"https://chatgpt.com/mcp-events/synthetic-expired"),error=>error.status===403&&error.code==="grant_inactive");
  const consent=await f.req("/oauth/interaction/synthetic-expired","POST","csrf=synthetic&action=approve",{"content-type":"application/x-www-form-urlencoded",origin:ORIGIN});assert.equal(consent.status,400);
  assert.deepEqual(f.runtime.oauth.grantFor("owner"),f.grant);assert.equal(f.rows().some(row=>["consent","callback-pending","callback-enrollment","control:owner:subscription"].includes(row.ns)),false);await f.preserved();
});

test("cold expired auth-only configuration starts without creating authorization",async t=>{
  const f=await fixture(t,{withGrant:false});assert.equal((await f.req("/health")).status,200);assert.equal(f.runtime.oauth.grantFor("owner"),undefined);assert.equal(await f.runtime.oauth.authorize("owner-consumer"),false);assert.equal(f.rows().length,1);await f.preserved();
});

test("expired exception is auth-only; network, static-bearer and later OAuth validation retain their guards",()=>{
  const input=inputAt(join(tmpdir(),"synthetic-unread-expired-config"));assert.equal(parseConfig(input,false,true).bindings[0].authorizedUntil,EXPIRED);
  assert.throws(()=>parseConfig(input,true,true),/expired_or_unsupported_consumer_authorization/);
  const legacy={...input,oauth:undefined,bindings:[{...input.bindings[0],bearerFile:join(tmpdir(),"synthetic-unread-bearer"),callbackApprovalFile:undefined,callbackUrl:"https://chatgpt.com/callback/owner"}]};assert.throws(()=>parseConfig(legacy,true,false),/expired_or_unsupported_consumer_authorization/);
  const future=structuredClone(input);future.bindings[0].authorizedUntil=new Date(Date.now()+3600000).toISOString();assert.equal(parseConfig(future,true,true).enabled,true);
  const continuous=structuredClone(input);continuous.bindings[0].authorizedUntil=null;assert.equal(parseConfig(continuous,false,true).bindings[0].authorizedUntil,null);assert.equal(parseConfig(continuous,true,true).authEnabled,true);
  const unsafe=structuredClone(input);unsafe.oauth.redirectUris=["https://evil.example/callback"];assert.throws(()=>parseConfig(unsafe,false,true),/unsafe_oauth_redirect/);
  const foreign=structuredClone(input);foreign.bindings[0].senderId="555555555555555555";assert.throws(()=>parseConfig(foreign,false,true),/owner_binding_mismatch/);
});
