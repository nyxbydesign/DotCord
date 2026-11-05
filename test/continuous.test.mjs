import assert from "node:assert/strict";
import { test } from "node:test";
import { createCipheriv, randomBytes } from "node:crypto";
import { mkdtemp, chmod, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { AuthStore, authHash } from "../dist/auth-store.js";
import { EncryptedStore } from "../dist/storage.js";
import { DiscordEventsBridge, DAY } from "../dist/bridge.js";

test("legacy auth migration preserves every ciphertext and expiry; null records persist and authenticate expiry",async t=>{
  const directory=await mkdtemp(join(tmpdir(),"dotcord-auth-migration-")),file=join(directory,"auth.sqlite"),key=Buffer.alloc(32,6),installation="synthetic-migration";let clock=Date.now(),store;
  t.after(async()=>{store?.close();await rm(directory,{recursive:true,force:true});});
  const legacy=new DatabaseSync(file);legacy.exec("CREATE TABLE auth_v1 (ns TEXT NOT NULL,id TEXT NOT NULL,etag TEXT NOT NULL,expires INTEGER NOT NULL,body BLOB NOT NULL,grant_ref TEXT,uid_ref TEXT,user_ref TEXT,PRIMARY KEY(ns,id)); CREATE INDEX auth_grant ON auth_v1(grant_ref); CREATE INDEX auth_uid ON auth_v1(ns,uid_ref);");
  const seal=(ns,id,value,expires)=>{const iv=randomBytes(12),cipher=createCipheriv("aes-256-gcm",key,iv);cipher.setAAD(Buffer.from(JSON.stringify(["auth-v1",installation,ns,authHash(id)])));const body=Buffer.concat([cipher.update(JSON.stringify({value,expires})),cipher.final()]);return Buffer.concat([iv,cipher.getAuthTag(),body]);};
  for(const[ns,id,value,expires]of[["installation","primary",{identity:installation},Number.MAX_SAFE_INTEGER],["credential","finite",{fixture:true},clock+1000]])legacy.prepare("INSERT INTO auth_v1 VALUES (?,?,?,?,?,?,?,?)").run(ns,authHash(id),"legacy-etag",expires,seal(ns,id,value,expires),null,null,null);
  const before=legacy.prepare("SELECT * FROM auth_v1 ORDER BY ns,id").all();legacy.close();await chmod(file,0o600);
  store=new AuthStore(directory,Buffer.from(key),installation,()=>clock);assert.equal(store.get("credential","finite").value.fixture,true);
  const inspection=new DatabaseSync(file);assert.equal(inspection.prepare("PRAGMA table_info(auth_v1)").all().find(c=>c.name==="expires").notnull,0);assert.deepEqual(inspection.prepare("SELECT * FROM auth_v1 ORDER BY ns,id").all(),before);inspection.close();
  store.set("durable","one",{uid:"synthetic-uid",fixture:true},null,null);clock+=DAY*50;store.prune();assert.equal(store.get("credential","finite"),undefined);assert.equal(store.get("durable","one").expires,null);assert.equal(store.find("durable","uid_ref","synthetic-uid").fixture,true);
  const tamper=new DatabaseSync(file);tamper.prepare("UPDATE auth_v1 SET expires=? WHERE ns='durable'").run(clock+1000);tamper.close();assert.throws(()=>store.get("durable","one"),/integrity/);
});

test("unknown auth column contracts refuse migration without replacing the table",async t=>{
  const directory=await mkdtemp(join(tmpdir(),"dotcord-auth-schema-")),file=join(directory,"auth.sqlite");t.after(()=>rm(directory,{recursive:true,force:true}));
  const db=new DatabaseSync(file);db.exec("CREATE TABLE auth_v1 (ns TEXT NOT NULL,id TEXT NOT NULL,etag TEXT NOT NULL,expires TEXT NOT NULL,body BLOB NOT NULL,grant_ref TEXT,uid_ref TEXT,user_ref TEXT,PRIMARY KEY(ns,id));");db.close();await chmod(file,0o600);
  assert.throws(()=>new AuthStore(directory,Buffer.alloc(32,6),"synthetic"),/unknown_auth_storage_schema/);
  const unchanged=new DatabaseSync(file);assert.equal(unchanged.prepare("PRAGMA table_info(auth_v1)").all().find(c=>c.name==="expires").type,"TEXT");assert.equal(unchanged.prepare("SELECT count(*) n FROM sqlite_master WHERE name='auth_nullable_migration'").get().n,0);unchanged.close();
});

test("continuous subscriptions serialize null truthfully across restart; default leases and message retention stay finite",async t=>{
  const directory=await mkdtemp(join(tmpdir(),"dotcord-continuous-bridge-"));let clock=Date.now(),revoked=false,store,auth,bridge;const events=[];
  const config={enabled:true,audience:"owner-dm",botUserId:"222222222222222222",ownerUserId:"111111111111111111",senderUserId:"111111111111111111",ownerChannelId:"333333333333333333",callbackHosts:["chatgpt.com"],callbackUrl:"https://chatgpt.com/callback/owner"};
  const secret="whsec_"+Buffer.alloc(32,7).toString("base64"),principal="owner-client",authority="synthetic-grant:1";
  const params={name:"discord.message.created",arguments:{audience:"owner-dm"},delivery:{mode:"webhook",url:config.callbackUrl,secret}};
  const start=()=>{store=new EncryptedStore(join(directory,"live"),Buffer.alloc(32,2),"synthetic-continuous");auth=new AuthStore(join(directory,"auth"),Buffer.alloc(32,3),"synthetic-control",()=>clock);bridge=new DiscordEventsBridge(config,store.records("owner"),async(url,body)=>{const payload=JSON.parse(body);if(payload.type==="verification")return{status:200,body:JSON.stringify({challenge:payload.challenge})};events.push(payload);return{status:200,body:""};},async()=>"777777777777777777",async(p,a)=>!revoked&&p===principal&&(!a||a===authority),()=>{},()=>clock,undefined,undefined,auth.records("owner"));};
  const stop=async()=>{bridge.stop();await bridge.drain();store.close();auth.close();};start();t.after(async()=>{await stop();await rm(directory,{recursive:true,force:true});});
  const leased=await bridge.subscribe(principal,params,null,authority);assert.equal(leased.refreshBefore,new Date(clock+DAY).toISOString());
  const permanent=await bridge.subscribe(principal,{...params,ttlMs:null},null,authority);assert.equal(permanent.refreshBefore,null);assert.equal(auth.get("control:owner:subscription","dot").expires,null);
  const incoming=id=>({id,channel_id:config.ownerChannelId,author:{id:config.ownerUserId},content:"synthetic owner message",timestamp:new Date(clock).toISOString(),type:0});
  const first="444444444444444444";await bridge.receive(incoming(first));assert.equal(events.length,1);const oldAnchor={message_id:first,conversation_id:events[0].data.conversation_id};
  await stop();clock+=DAY+1;start();auth.prune();store.prune(clock);assert.equal(auth.get("control:owner:subscription","dot").value.expires,null);
  await assert.rejects(()=>bridge.conversation(principal,oldAnchor),/unknown_or_expired_message/);await bridge.receive(incoming("444444444444444445"));assert.equal(events.length,2);
  revoked=true;await assert.rejects(()=>bridge.receive(incoming("444444444444444446")),/forbidden/);await bridge.pump();assert.equal(auth.get("control:owner:subscription","dot").value.active,false);
});
