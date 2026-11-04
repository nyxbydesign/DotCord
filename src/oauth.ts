import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import Provider, { errors } from "oidc-provider";
import { createLocalJWKSet, jwtVerify, type JWK } from "jose";
import { AuthStore, authHash } from "./auth-store.js";
import { callbackHosts, oauthScopes, type Config, type SenderBinding, type OAuthScope } from "./config.js";
import { callbackUrl, createNetwork, equal } from "./networking.js";
import { isWithin, readPrivateFile } from "./storage.js";
import type { Network } from "./runtime.js";

const DAY=86400000;
export type Authorization = { id:string; version:number; bindingId:string; subject:string; clientId:string; scopes:OAuthScope[]; started:number; until:number; revoked:boolean; providerGrantId?:string };
export type Authenticated = SenderBinding & { authority:string; grantId:string; grantVersion:number; authorizedUntil:string };
export type AuthTransport=Pick<Network,"request"|"post"|"close">;
export class OAuthError extends Error {constructor(readonly status:number,readonly code:string,readonly scope?:string){super(code);}}
export const issuerFor=(config:Config)=>new URL("oauth",config.publicOrigin!).href;
export const resourceFor=(config:Config)=>new URL("mcp",config.publicOrigin!).href;
export const resourceMetadata=(config:Config)=>({resource:resourceFor(config),authorization_servers:[issuerFor(config)],scopes_supported:[...oauthScopes],bearer_methods_supported:["header"]});
export const oauthChallenge=(config:Config,error?:string,scope?:string)=>`Bearer resource_metadata="${new URL(".well-known/oauth-protected-resource/mcp",config.publicOrigin!).href}"${error?`, error="${error}"`:""}${scope?`, scope="${scope}"`:""}`;
export function requiredScopes(method:string,name?:string):OAuthScope[] {
  if(method==="events/subscribe" || method==="events/unsubscribe")return ["discord:events:subscribe"];
  if(method!=="tools/call")return ["discord:status"];
  if(name==="discord_conversation_read")return ["discord:context:read"];
  if(name==="discord_attachment_read")return ["discord:context:read","discord:attachments:read"];
  if(name==="discord_reply_to_message" || name==="discord_reply_batch")return ["discord:reply"];
  return ["discord:status"];
}
function textSecret(path:string) {const b=readPrivateFile(path);try{return b.toString("utf8").trim();}finally{b.fill(0);}}
function keySecret(path:string) {const s=textSecret(path),b=Buffer.from(s,"base64");if(b.length!==32 || b.toString("base64")!==s)throw new Error("invalid_oauth_key");return b;}
function html(value:string) {return value.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]!));}
function answer(res:ServerResponse,status:number,body:string,type="text/html",referrerPolicy:"no-referrer"|"same-origin"="no-referrer",formRedirect?:string) {res.writeHead(status,{"content-type":type+"; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff","referrer-policy":referrerPolicy,"content-security-policy":`default-src 'none'; form-action 'self'${formRedirect?` ${formRedirect}`:""}; frame-ancestors 'none'; base-uri 'none'`});res.end(body);}
async function form(req:IncomingMessage) {
  if(req.headers["content-type"]?.split(";",1)[0]!=="application/x-www-form-urlencoded" || req.headers["content-encoding"])throw new OAuthError(400,"invalid_request");
  let length=0;const chunks:Buffer[]=[];
  for await(const b of req){const chunk=Buffer.from(b);length+=chunk.length;if(length>16384)throw new OAuthError(400,"invalid_request");chunks.push(chunk);}
  const p=new URLSearchParams(Buffer.concat(chunks).toString("utf8"));for(const key of p.keys())if(p.getAll(key).length!==1)throw new OAuthError(400,"invalid_request");return p;
}
function cookies(req:IncomingMessage) {return new Map((req.headers.cookie??"").split(";").map(x=>{const at=x.indexOf("=");return [x.slice(0,at).trim(),x.slice(at+1)];}));}

export async function createOAuth(config:Config,log:(code:string)=>void=()=>{},injected?:AuthTransport) {
  if(!config.authEnabled || !config.oauth)throw new Error("oauth_not_enabled");
  const options=config.oauth,issuer=issuerFor(config),resource=resourceFor(config),origin=new URL(config.publicOrigin!).origin;
  const packageDirectory=resolve(dirname(fileURLToPath(import.meta.url)),"..");
  for(const path of [options.encryptionKeyFile,options.cookieKeyFile,options.signingKeyFile,options.discordClientSecretFile,...config.bindings.flatMap(b=>b.callbackApprovalFile?[b.callbackApprovalFile]:[])]) {
    if(isWithin(path,packageDirectory) || isWithin(path,options.stateDirectory) || config.stateDirectory && isWithin(path,config.stateDirectory))throw new Error("credentials_must_remain_external");
  }
  const key=keySecret(options.encryptionKeyFile),cookie=keySecret(options.cookieKeyFile);
  if(timingSafeEqual(key,cookie))throw new Error("credential_roles_must_be_separate");
  const rawKeys:unknown=JSON.parse(textSecret(options.signingKeyFile));
  const keys=(rawKeys && typeof rawKeys==="object" && "keys" in rawKeys?(rawKeys as {keys:unknown}).keys:[rawKeys]) as JWK[];
  if(!Array.isArray(keys) || !keys.length || keys.length>4 || keys.some(k=>!k || k.kty!=="EC" || k.crv!=="P-256" || typeof k.kid!=="string" || !/^[A-Za-z0-9_-]{1,80}$/.test(k.kid) || k.alg && k.alg!=="ES256")
    || typeof keys[0]?.d!=="string" || new Set(keys.map(k=>k.kid)).size!==keys.length)throw new Error("invalid_issuer_signing_key");
  const publicKeys=keys.map(({d,...publicKey})=>publicKey),verifier=createLocalJWKSet({keys:publicKeys});
  const loginSecret=textSecret(options.discordClientSecretFile);if(!/^[A-Za-z0-9._~-]{16,4096}$/.test(loginSecret))throw new Error("invalid_login_client_secret");
  const store=new AuthStore(options.stateDirectory,key,JSON.stringify(["oauth-v1",options.installationId,issuer,config.applicationId,config.botUserId,config.ownerUserId,config.ownerChannelId]));
  const network=injected??createNetwork("",callbackHosts,config.sourceAddress!);
  let stopped=false;
  const subjectFor=(b:SenderBinding)=>authHash(JSON.stringify([issuer,b.senderId]));
  const bindingFor=(subject:string)=>config.bindings.find(b=>subjectFor(b)===subject);
  const grantFor=(bindingId:string)=>store.get("authorization",bindingId,true)?.value as Authorization|undefined;
  const active=(g:Authorization|undefined)=>!stopped && Boolean(g && !g.revoked && g.until>Date.now() && config.bindings.some(b=>b.id===g.bindingId && b.grantVersion===g.version && Date.parse(b.authorizedUntil)>=g.until));
  const byProvider=(providerId:string)=>{const link=store.get("provider-link",providerId,true);return link?grantFor(String(link.value.bindingId)):undefined;};
  const revoke=(bindingId:string)=>{const g=grantFor(bindingId);if(g&&!g.revoked){store.set("authorization",bindingId,{...g,revoked:true},Number.MAX_SAFE_INTEGER);store.audit("grant_revoked",g.id);}};
  const revokeProvider=(providerId:string)=>{const g=byProvider(providerId);if(g)revoke(g.bindingId);store.revokeProviderGrant(providerId);};
  const assertGrant=(providerId:string,subject?:string)=>{const g=byProvider(providerId);if(!active(g) || subject && g!.subject!==subject)throw new errors.InvalidGrant("authorization is not active");return g!;};
  const ensureGrant=(binding:SenderBinding):Authorization=>store.atomic(()=>{
    const old=grantFor(binding.id);
    if(old?.version===binding.grantVersion){if(!active(old))throw new errors.AccessDenied("authorization expired or revoked");return old;}
    if(old && binding.grantVersion<=old.version)throw new errors.AccessDenied("authorization generation denied");
    const now=Date.now(),until=Math.min(now+DAY,Date.parse(binding.authorizedUntil));if(until<=now)throw new errors.AccessDenied("authorization expired");
    const g:Authorization={id:randomBytes(24).toString("base64url"),version:binding.grantVersion,bindingId:binding.id,subject:subjectFor(binding),clientId:options.clientId,scopes:[...binding.scopes],started:now,until,revoked:false};
    store.set("authorization",binding.id,g,Number.MAX_SAFE_INTEGER);store.audit("grant_consented",g.id);return g;
  });
  class Adapter {
    constructor(private readonly model:string) {}
    async upsert(id:string,payload:Record<string,unknown>,expiresIn:number) {
      if(payload.grantId && this.model!=="Grant")assertGrant(String(payload.grantId),typeof payload.accountId==="string"?payload.accountId:undefined);
      const cutoff=payload.grantId?byProvider(String(payload.grantId))?.until:undefined;
      store.set(this.model,id,payload,Math.min(Date.now()+expiresIn*1000,cutoff??Infinity));
    }
    async find(id:string) {const row=store.get(this.model,id);if(!row)return undefined;if(row.value.grantId)assertGrant(String(row.value.grantId));return row.value;}
    async findByUid(uid:string) {return store.find(this.model,"uid_ref",uid);}
    async findByUserCode(code:string) {return store.find(this.model,"user_ref",code);}
    async destroy(id:string) {if(this.model==="Grant")revokeProvider(id);else store.delete(this.model,id);}
    async consume(id:string) {if(!store.consume(this.model,id)){const r=store.get(this.model,id,true);if(typeof r?.value.grantId==="string")revokeProvider(r.value.grantId);throw new errors.InvalidGrant("credential already used");}}
    async revokeByGrantId(id:string) {revokeProvider(id);}
  }
  const tokenTTL=(_ctx:unknown,token:{grantId?:string;accountId?:string})=>{
    const g=token.grantId?byProvider(token.grantId):token.accountId?grantFor(bindingFor(token.accountId)?.id??""):undefined;
    return Math.max(0,Math.min(300,Math.floor(((g?.until??Date.now())-Date.now())/1000)));
  };
  let provider:any;
  try {
    provider=new Provider(issuer,{
      adapter:Adapter,jwks:{keys},cookies:{keys:[cookie.toString("base64url")],short:{secure:true,httpOnly:true,sameSite:"lax"},long:{secure:true,httpOnly:true,sameSite:"lax"}},
      clients:[{client_id:options.clientId,redirect_uris:options.redirectUris,response_types:["code"],grant_types:["authorization_code","refresh_token"],token_endpoint_auth_method:"none",id_token_signed_response_alg:"ES256"}],
      scopes:["openid","offline_access",...oauthScopes],claims:{openid:["sub"]},responseTypes:["code"],subjectTypes:["public"],clockTolerance:0,
      pkce:{required:()=>true},rotateRefreshToken:()=>true,revokeGrantPolicy:()=>true,
      clientDefaults:{id_token_signed_response_alg:"ES256"},
      features:{devInteractions:{enabled:false},registration:{enabled:false},clientCredentials:{enabled:false},clientIdMetadataDocument:{enabled:false},revocation:{enabled:true},
        resourceIndicators:{enabled:true,defaultResource:()=>resource,useGrantedResource:()=>true,getResourceServerInfo:(_ctx:unknown,r:string)=>{
          if(r!==resource)throw new errors.InvalidTarget();return {scope:oauthScopes.join(" "),audience:resource,accessTokenFormat:"jwt",accessTokenTTL:300,jwt:{sign:{alg:"ES256",kid:keys[0]!.kid}}};
        }}},
      routes:{authorization:"/authorize",token:"/token",jwks:"/jwks",revocation:"/revoke",userinfo:"/userinfo"},
      interactions:{url:(_ctx:unknown,interaction:{uid:string})=>`${issuer}/interaction/${interaction.uid}`},
      findAccount:async(_ctx:unknown,id:string)=>bindingFor(id)?{accountId:id,claims:async()=>({sub:id})}:undefined,
      loadExistingGrant:async(ctx:any)=>{const id=ctx.oidc.result?.consent?.grantId??ctx.oidc.session.grantIdFor(options.clientId);if(!id)return undefined;assertGrant(id,ctx.oidc.session.accountId);return provider.Grant.find(id);},
      ttl:{AuthorizationCode:60,Interaction:300,Session:900,IdToken:300,AccessToken:tokenTTL,
        Grant:(_ctx:unknown,grant:any)=>Math.max(1,Math.floor(((grantFor(bindingFor(grant.accountId)?.id??"")?.until??Date.now())-Date.now())/1000)),
        RefreshToken:(_ctx:unknown,token:any)=>Math.max(0,Math.floor((assertGrant(token.grantId).until-Date.now())/1000))},
      formats:{customizers:{jwt:async(ctx:any,token:any,jwt:any)=>{
        const g=assertGrant(token.grantId,token.accountId),r=ctx?.oidc?.params?.resource;
        if(r!==resource && !(Array.isArray(r)&&r.length===1&&r[0]===resource))throw new errors.InvalidTarget();
        if(token.clientId!==options.clientId)throw new errors.InvalidGrant();
        jwt.payload.grant_id=g.id;jwt.payload.grant_version=g.version;jwt.payload.nbf=jwt.payload.iat;
        jwt.payload.exp=Math.min(jwt.payload.exp,Math.floor(g.until/1000));
      }}},
      renderError:async(ctx:any)=>{log("oauth_request_denied");ctx.type="html";ctx.body="<!doctype html><title>Authorization failed</title><p>Authorization failed. Return to the connection and try again.</p>";}
    });
    provider.proxy=true;
    provider.on("server_error",()=>log("oauth_server_error"));provider.on("grant.error",()=>log("oauth_grant_denied"));
    provider.use(async(ctx:any,next:()=>Promise<void>)=>{
      // The native HTTP mount strips this prefix before Koa routing; retain it for resume URLs and cookie paths.
      ctx.mountPath="/oauth";
      if(ctx.path==="/authorize") {
        const u=new URL(ctx.req.url,issuer);
        if(u.searchParams.getAll("resource").length!==1 || u.searchParams.get("resource")!==resource)throw new errors.InvalidTarget();
        if(u.searchParams.get("code_challenge_method")!=="S256" || !/^[A-Za-z0-9_-]{43}$/.test(u.searchParams.get("code_challenge")??""))throw new errors.InvalidRequest("S256 PKCE required");
      }
      await next();
    });
  } catch(e){store.close();cookie.fill(0);await network.close();throw e;}
  const callback=provider.callback();
  const signed=(value:string)=>value+"."+createHmac("sha256",cookie).update(value).digest("base64url");
  const cookieMatch=(req:IncomingMessage,name:string,value:string)=>equal(cookies(req).get(name)??"",signed(value));
  const setCookie=(res:ServerResponse,name:string,value:string,maxAge=300)=>res.setHeader("set-cookie",`${name}=${signed(value)}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`);
  const details=async(req:IncomingMessage,res:ServerResponse,uid:string)=>{
    const d=await provider.interactionDetails(req,res);if(d.uid!==uid || d.params.client_id!==options.clientId || d.params.resource!==resource)throw new OAuthError(400,"invalid_interaction");return d;
  };
  const handle=async(req:IncomingMessage,res:ServerResponse):Promise<boolean>=>{
    const url=new URL(req.url??"/",origin);
    if(url.pathname==="/.well-known/oauth-protected-resource/mcp") {answer(res,200,JSON.stringify(resourceMetadata(config)),"application/json");return true;}
    if(url.pathname==="/.well-known/oauth-authorization-server/oauth") {res.writeHead(302,{location:issuer+"/.well-known/openid-configuration","cache-control":"no-store"});res.end();return true;}
    if(!url.pathname.startsWith("/oauth/"))return false;
    if(stopped){answer(res,503,"Authentication unavailable");return true;}
    // Trust the configured issuer, never caller-supplied forwarding headers or Host values.
    req.headers["x-forwarded-proto"]="https";req.headers["x-forwarded-host"]=new URL(origin).host;req.headers.host=new URL(origin).host;
    delete req.headers.forwarded;delete req.headers["x-forwarded-port"];delete req.headers["x-forwarded-prefix"];
    try {
      const finish=/^\/oauth\/interaction\/([A-Za-z0-9_-]{1,200})\/login$/.exec(url.pathname);
      if(finish && req.method==="GET") {
        const receipt=(cookies(req).get("__Host-dotcord-login-finish")??"").split(".")[0]??"",pending=store.get("login-finish",receipt);
        const d=await details(req,res,finish[1]!);
        if(!pending || pending.value.uid!==d.uid || d.prompt.name!=="login" || !cookieMatch(req,"__Host-dotcord-login-finish",receipt) || !store.consume("login-finish",receipt))throw new OAuthError(400,"invalid_login_return");
        setCookie(res,"__Host-dotcord-login-finish","",0);
        await provider.interactionFinished(req,res,{login:{accountId:String(pending.value.subject),remember:false}},{mergeWithLastSubmission:false});store.audit("login_verified");return true;
      }
      const interaction=/^\/oauth\/interaction\/([A-Za-z0-9_-]{1,200})$/.exec(url.pathname);
      if(interaction) {
        const d=await details(req,res,interaction[1]!);
        if(req.method==="GET" && d.prompt.name==="login") {
          const state=randomBytes(32).toString("base64url"),verifier=randomBytes(32).toString("base64url");
          store.set("login",state,{uid:d.uid,verifier},Date.now()+300000,null);setCookie(res,"__Host-dotcord-login",state);
          const destination=new URL("https://discord.com/api/oauth2/authorize");
          for(const [k,v]of Object.entries({client_id:options.discordClientId,response_type:"code",redirect_uri:issuer+"/login/discord/callback",scope:"identify",state,code_challenge:Buffer.from(authHash(verifier),"hex").toString("base64url"),code_challenge_method:"S256",prompt:"consent"}))destination.searchParams.set(k,v);
          res.writeHead(303,{location:destination.href,"cache-control":"no-store","referrer-policy":"no-referrer"});res.end();return true;
        }
        if(req.method==="GET" && d.prompt.name==="consent") {
          const b=bindingFor(d.session?.accountId);if(!b)throw new OAuthError(403,"identity_denied");
          const redirect=options.redirectUris.find(uri=>uri===d.params.redirect_uri);if(!redirect)throw new OAuthError(400,"invalid_interaction");
          const csrf=randomBytes(32).toString("base64url");store.set("consent",d.uid,{csrf,subject:d.session.accountId},Date.now()+300000);setCookie(res,"__Host-dotcord-consent",csrf);
          // Preserve the browser's same-origin form Origin without sharing this interaction URL across origins.
          // CSP ignores source paths after redirects; issuer registration remains the exact redirect boundary.
          answer(res,200,`<!doctype html><title>Authorize DotCord</title><h1>Authorize DotCord</h1><p>Allow this connection to receive and reply to your owner Discord DM for at most 24 hours, ending no later than ${html(b.authorizedUntil)}.</p><p>Permissions: ${html(b.scopes.join(", "))}</p><form method="post"><input type="hidden" name="csrf" value="${csrf}"><button name="action" value="approve">Authorize</button><button name="action" value="deny">Cancel</button></form>`,"text/html","same-origin",redirect);return true;
        }
        if(req.method==="POST" && d.prompt.name==="consent") {
          if(req.headers.origin!==origin)throw new OAuthError(403,"origin_denied");
          const p=await form(req),pending=store.get("consent",d.uid);
          if(!pending || pending.value.subject!==d.session?.accountId || !equal(p.get("csrf")??"",String(pending.value.csrf)) || !cookieMatch(req,"__Host-dotcord-consent",String(pending.value.csrf)) || !store.consume("consent",d.uid))throw new OAuthError(403,"invalid_consent");
          if(p.get("action")!=="approve"){await provider.interactionFinished(req,res,{error:"access_denied",error_description:"Authorization cancelled"},{mergeWithLastSubmission:false});return true;}
          const b=bindingFor(d.session.accountId);if(!b)throw new OAuthError(403,"identity_denied");const g=ensureGrant(b);
          let grant=g.providerGrantId?await provider.Grant.find(g.providerGrantId):undefined;
          if(!grant)grant=new provider.Grant({accountId:g.subject,clientId:options.clientId});
          // Advertised scopes also participate in the provider's OP consent policy; record the same approved set in both views.
          grant.addOIDCScope(["openid","offline_access",...g.scopes].join(" "));grant.addResourceScope(resource,g.scopes.join(" "));
          const providerGrantId=await grant.save();store.atomic(()=>{store.set("authorization",b.id,{...g,providerGrantId},Number.MAX_SAFE_INTEGER);store.set("provider-link",providerGrantId,{bindingId:b.id},Number.MAX_SAFE_INTEGER);});
          await provider.interactionFinished(req,res,{consent:{grantId:providerGrantId}},{mergeWithLastSubmission:true});return true;
        }
        throw new OAuthError(400,"invalid_interaction");
      }
      if(url.pathname==="/oauth/login/discord/callback") {
        const state=url.searchParams.get("state")??"",code=url.searchParams.get("code")??"",pending=store.get("login",state);
        if(req.method!=="GET" || url.searchParams.getAll("state").length!==1 || url.searchParams.getAll("code").length!==1 || url.searchParams.get("iss")!=="https://discord.com"
          || !pending || !/^[A-Za-z0-9_-]{1,4096}$/.test(code) || !cookieMatch(req,"__Host-dotcord-login",state) || !store.consume("login",state))throw new OAuthError(400,"invalid_login_return");
        const body=new URLSearchParams({grant_type:"authorization_code",code,redirect_uri:issuer+"/login/discord/callback",code_verifier:String(pending.value.verifier)}).toString();
        const result=await network.request("https://discord.com/api/oauth2/token","POST",body,{"content-type":"application/x-www-form-urlencoded",authorization:"Basic "+Buffer.from(options.discordClientId+":"+loginSecret).toString("base64")},16384);
        if(result.status!==200)throw new OAuthError(400,"identity_exchange_failed");const token=JSON.parse(result.bodyText);
        if(token.token_type?.toLowerCase()!=="bearer" || typeof token.access_token!=="string" || token.access_token.length>4096 || token.scope!=="identify")throw new OAuthError(400,"identity_exchange_failed");
        const identity=await network.request("https://discord.com/api/v10/users/@me","GET",undefined,{authorization:"Bearer "+token.access_token},16384);
        if(identity.status!==200)throw new OAuthError(400,"identity_exchange_failed");const user=JSON.parse(identity.bodyText),b=config.bindings.find(x=>x.senderId===user.id);
        if(!b || user.bot===true || b.senderId!==config.ownerUserId || Date.parse(b.authorizedUntil)<=Date.now())throw new OAuthError(403,"identity_denied");
        const receipt=randomBytes(32).toString("base64url");store.set("login-finish",receipt,{uid:pending.value.uid,subject:subjectFor(b)},Date.now()+60000,null);setCookie(res,"__Host-dotcord-login-finish",receipt,60);
        res.writeHead(303,{location:issuer+"/interaction/"+String(pending.value.uid)+"/login","cache-control":"no-store","referrer-policy":"no-referrer"});res.end();return true;
      }
      const original=req.url;req.url=(req.url??"").slice("/oauth".length)||"/";
      await new Promise<void>((resolve,reject)=>{res.once("finish",resolve);res.once("close",resolve);try{callback(req,res);}catch(e){reject(e);}});req.url=original;return true;
    } catch(e){log("oauth_request_denied");if(!res.headersSent)answer(res,e instanceof OAuthError?e.status:400,"<!doctype html><title>Authorization failed</title><p>Authorization failed. Return to the connection and try again.</p>");else if(!res.writableEnded)res.destroy();return true;}
  };
  const authenticate=async(header:string|undefined):Promise<Authenticated|undefined>=>{
    if(stopped || !header?.startsWith("Bearer ") || header.length>8192)return undefined;
    try {
      const verified=await jwtVerify(header.slice(7),verifier,{issuer,audience:resource,algorithms:["ES256"],typ:"at+jwt",clockTolerance:0,maxTokenAge:"5m"});
      const p=verified.payload;if(verified.protectedHeader.jku || verified.protectedHeader.x5u || p.client_id!==options.clientId || typeof p.sub!=="string" || typeof p.grant_id!=="string" || typeof p.grant_version!=="number" || typeof p.scope!=="string" || typeof p.iat!=="number" || typeof p.exp!=="number" || p.exp-p.iat>300 || typeof p.nbf!=="number")return undefined;
      const b=bindingFor(p.sub),g=b?grantFor(b.id):undefined;if(!b || !active(g) || g!.id!==p.grant_id || g!.version!==p.grant_version || g!.clientId!==p.client_id)return undefined;
      const scopeNames:ReadonlySet<string>=new Set(oauthScopes),isScope=(value:string):value is OAuthScope=>scopeNames.has(value);
      const scopes=p.scope.split(" ");if(!scopes.every(isScope))return undefined;if(scopes.some(s=>!g!.scopes.includes(s)))return undefined;
      return {...b,scopes,authority:g!.id+":"+g!.version,grantId:g!.id,grantVersion:g!.version,authorizedUntil:new Date(g!.until).toISOString()};
    }catch{return undefined;}
  };
  const authorize=async(principal:string,authority?:string)=>{try{const b=config.bindings.find(x=>x.principal===principal),g=b?grantFor(b.id):undefined;return active(g)&&(!authority || authority===g!.id+":"+g!.version);}catch{return false;}};
  const approvedCallback=(b:SenderBinding,g:Authorization)=>{
    if(b.callbackUrl)return b.callbackUrl;
    if(!b.callbackApprovalFile)return undefined;
    let value:unknown;
    try {value=JSON.parse(textSecret(b.callbackApprovalFile));}catch(error){if((error as NodeJS.ErrnoException).code==="ENOENT")return undefined;throw error;}
    if(!value || typeof value!=="object")return undefined;const approval=value as Record<string,unknown>;
    if(approval.grantId!==g.id || approval.grantVersion!==g.version || typeof approval.callbackUrl!=="string")return undefined;
    return callbackUrl(approval.callbackUrl,callbackHosts).toString();
  };
  const enroll=(b:SenderBinding,raw:string)=>{
    const g=grantFor(b.id);if(!active(g))throw new OAuthError(403,"grant_inactive");const url=callbackUrl(raw,callbackHosts).toString();
    const approved=approvedCallback(b,g!);
    if(!approved || approved!==url){store.set("callback-pending",b.id,{callbackUrl:url,grantId:g!.id,grantVersion:g!.version},g!.until);throw new OAuthError(403,"callback_approval_required");}
    const old=store.get("callback-enrollment",b.id,true);
    if(old && old.value.callbackUrl!==url)throw new OAuthError(403,"callback_migration_required");
    store.set("callback-enrollment",b.id,{callbackUrl:url,grantId:g!.id,grantVersion:g!.version},Number.MAX_SAFE_INTEGER);return {url,authority:g!.id+":"+g!.version};
  };
  const maintenance=setInterval(()=>{try{store.prune();}catch{stopped=true;log("auth_storage_failed");}},60000).unref();
  return {issuer,resource,provider,store,handle,authenticate,authorize,enroll,grantFor,revoke,network,
    stop:async()=>{if(stopped && !maintenance)return;stopped=true;clearInterval(maintenance);await network.close();store.close();cookie.fill(0);}};
}
export type OAuthRuntime=Awaited<ReturnType<typeof createOAuth>>;
