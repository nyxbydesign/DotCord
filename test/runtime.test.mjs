import assert from "node:assert/strict";
import { test } from "node:test";
import { request as httpRequest } from "node:http";
import { CloseEvent } from "undici";
import { mkdtemp, mkdir, writeFile, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as pause } from "node:timers/promises";
import { parseConfig } from "../dist/config.js";
import { createRuntime } from "../dist/runtime.js";
import { startHttpServer } from "../dist/http.js";
import { EncryptedStore } from "../dist/storage.js";

const OWNER="111111111111111111", OTHER="555555555555555555", BOT="222222222222222222", CHANNEL="333333333333333333", APP="888888888888888888";
const TOKEN_OWNER="synthetic_owner_bearer_01234567890123456789", TOKEN_OTHER="synthetic_other_bearer_01234567890123456789";
const SECRET="whsec_"+Buffer.alloc(32,7).toString("base64");
const meta={"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{name:"test",version:"1"},"io.modelcontextprotocol/clientCapabilities":{}};
class Socket extends EventTarget {
  sent=[]; closed=false;
  send(text){this.sent.push(JSON.parse(text));}
  close(code=1000){if(this.closed)return;this.closed=true;this.dispatchEvent(new CloseEvent("close",{code}));}
  packet(value){this.dispatchEvent(new MessageEvent("message",{data:JSON.stringify(value)}));}
  ready(){this.packet({op:10,d:{heartbeat_interval:10000}});this.packet({op:0,t:"READY",d:{user:{id:BOT,bot:true},application:{id:APP}}});}
  message(id,author=OWNER,extra={}){this.packet({op:0,t:"MESSAGE_CREATE",d:{id,channel_id:CHANNEL,author:{id:author},content:"synthetic live text",timestamp:new Date(Date.now()+1).toISOString(),type:0,...extra}});}
}
async function waitFor(predicate){const end=Date.now()+3000;while(!predicate()){if(Date.now()>end)throw new Error("condition_timeout");await pause(5);}}
async function files(){
  const directory=await mkdtemp(join(tmpdir(),"dotcord-test-")), secrets=join(directory,"external");await mkdir(secrets,{mode:0o700});
  const input={port:9294,stateDirectory:join(directory,"state"),botUserId:BOT,applicationId:APP,ownerUserId:OWNER,ownerChannelId:CHANNEL,
    sourceAddress:"127.0.0.1",botTokenFile:join(secrets,"bot"),encryptionKeyFile:join(secrets,"key"),
    bindings:[{id:"owner",senderId:OWNER,principal:"owner-client",bearerFile:join(secrets,"owner"),authorizedUntil:new Date(Date.now()+3600000).toISOString(),callbackUrl:"https://chatgpt.com/callback/owner",audience:"owner-dm"},
      {id:"other",senderId:OTHER,principal:"other-client",bearerFile:join(secrets,"other"),authorizedUntil:new Date(Date.now()+3600000).toISOString(),callbackUrl:"https://connectors.api.openai.com/callback/other",audience:"directed"}]};
  for(const [path,value] of [[input.botTokenFile,"synthetic_bot_token_01234567890123456789"],[input.encryptionKeyFile,Buffer.alloc(32,9).toString("base64")],[input.bindings[0].bearerFile,TOKEN_OWNER],[input.bindings[1].bearerFile,TOKEN_OTHER]])await writeFile(path,value,{mode:0o600});
  return {directory,input};
}
async function harness(t,{send,post,readAttachment,ownerAudience="owner-dm"}={}){
  const {directory,input}=await files(),socket=new Socket(),events=[],writes=[];input.bindings[0].audience=ownerAudience;
  const adapter={
    post:async(url,body,headers)=>{const payload=JSON.parse(body);if(payload.type==="verification")return{status:200,body:JSON.stringify({challenge:payload.challenge})};events.push({url,payload,headers});return post?post(url,body,headers):{status:200,body:""};},
    send:async(...args)=>{writes.push(args);return send?send(...args):String(777777777777777777n+BigInt(writes.length));},
    discord:async path=>path==="/users/@me"?{id:BOT,bot:true}:path==="/oauth2/applications/@me"?{id:APP}:path==="/gateway/bot"?{url:"wss://gateway.discord.gg",session_start_limit:{remaining:8}}:{id:CHANNEL,type:1,recipients:[{id:OWNER}]},
    request:async()=>{throw new Error("unexpected_request");},readAttachment:readAttachment??(async()=>({data:"synthetic-image",mimeType:"image/png",width:1,height:1})),socket:()=>socket,close:async()=>{}
  };
  let runtime=await createRuntime(parseConfig(input,true),()=>adapter),http=await startHttpServer(runtime,0);socket.ready();
  const hosts=[];http.server.prependListener("request",request=>hosts.push(request.headers.host));
  t.after(async()=>{await runtime.stop();await http.stop();});
  const endpoint=()=>`http://127.0.0.1:${http.server.address().port}/mcp`;
  const rpc=async(token,method,params={},extras={})=>{
    const headers={"content-type":"application/json",authorization:`Bearer ${token}`,"mcp-protocol-version":"2026-07-28","mcp-method":method,...(method==="tools/call"?{"mcp-name":params.name}:{}),...extras};
    const body=JSON.stringify({jsonrpc:"2.0",id:1,method,params:{...params,_meta:meta}});
    return await new Promise((resolve,reject)=>{
      const request=httpRequest(endpoint(),{method:"POST",headers},response=>{
        const chunks=[];response.on("data",chunk=>chunks.push(chunk));response.on("error",reject);
        response.on("end",()=>resolve({status:response.statusCode,body:JSON.parse(Buffer.concat(chunks).toString("utf8"))}));
      });request.on("error",reject);request.end(body);
    });
  };
  const subscribe=async()=>{for(const[index,token]of[TOKEN_OWNER,TOKEN_OTHER].entries()){const binding=input.bindings[index],result=await rpc(token,"events/subscribe",{name:"discord.message.created",arguments:{audience:binding.audience},delivery:{mode:"webhook",url:binding.callbackUrl,secret:SECRET},ttlMs:3600000});assert.equal(result.body.error,undefined);}};
  const anchor=id=>({message_id:id,conversation_id:events.find(event=>event.payload.data.message_id===id).payload.data.conversation_id});
  return{directory,input,socket,events,writes,hosts,rpc,subscribe,anchor,get runtime(){return runtime;},restart:async()=>{await runtime.stop();await http.stop();socket.closed=false;runtime=await createRuntime(parseConfig(input,true),()=>adapter);http=await startHttpServer(runtime,0);socket.ready();}};
}

test("disabled process binds loopback, reads no credential/state paths and performs no network intake",async t=>{
  let networkCalls=0;
  const config=parseConfig({botTokenFile:join(tmpdir(),"missing-token"),encryptionKeyFile:join(tmpdir(),"missing-key")});
  const runtime=await createRuntime(config,()=>{networkCalls++;throw new Error("must_not_connect");}),http=await startHttpServer(runtime,0);
  t.after(async()=>{await runtime.stop();await http.stop();});
  assert.equal(http.server.address().address,"127.0.0.1");
  const base=`http://127.0.0.1:${http.server.address().port}`;
  assert.deepEqual(await(await fetch(base+"/health")).json(),{enabled:false,ready:true});
  assert.equal((await fetch(base+"/mcp",{method:"POST"})).status,503);assert.equal(networkCalls,0);
});

test("real HTTP/MCP runtime routes immutable senders to separate stores/callbacks and refuses foreign references",async t=>{
  const f=await harness(t);await f.subscribe();
  f.socket.message("444444444444444444");f.socket.message("444444444444444445",OTHER);f.socket.message("444444444444444446","888888888888888888");
  await waitFor(()=>f.events.length===2);
  assert.deepEqual(f.events.map(item=>[item.url,item.payload.data.author_role]),[[f.input.bindings[0].callbackUrl,"owner"],[f.input.bindings[1].callbackUrl,"other"]]);
  const owner=f.anchor("444444444444444444"),other=f.anchor("444444444444444445");assert.notEqual(owner.conversation_id,other.conversation_id);
  for(const name of["discord_conversation_read","discord_reply_to_message","discord_attachment_read","discord_reply_batch"]){
    const args={...owner,...(name==="discord_reply_to_message"?{text:"cross-sender"}:name==="discord_reply_batch"?{texts:["cross-sender"]}:name==="discord_attachment_read"?{attachment_id:"666666666666666666"}:{})};
    const result=await f.rpc(TOKEN_OTHER,"tools/call",{name,arguments:args});assert.equal(result.body.error.message,"unknown_or_expired_message");
  }
  assert.equal((await f.rpc("forged_unauthorized_bearer_01234567890123456789","tools/list")).status,401);
  assert.equal((await f.rpc(TOKEN_OWNER,"tools/list",{}, {"mcp-method":"events/subscribe"})).status,400);
  assert.equal((await f.rpc(TOKEN_OWNER,"tools/list",{}, {origin:"https://evil.example"})).status,403);
  assert.equal((await f.rpc(TOKEN_OWNER,"tools/list",{}, {host:"evil.example"})).status,403);assert.equal(f.hosts.at(-1),"evil.example");
  const listed=await f.rpc(TOKEN_OTHER,"tools/list");assert.deepEqual(listed.body.result.tools.map(tool=>tool.name).sort(),["discord_attachment_read","discord_connection_status","discord_conversation_read","discord_reply_batch","discord_reply_to_message"]);
  const context=await f.rpc(TOKEN_OTHER,"tools/call",{name:"discord_conversation_read",arguments:other});assert.equal(JSON.parse(context.body.result.content[0].text).turns.length,1);
  const denied=await f.rpc(TOKEN_OTHER,"events/subscribe",{name:"discord.message.created",arguments:{audience:"directed"},delivery:{mode:"webhook",url:f.input.bindings[0].callbackUrl,secret:SECRET}});assert.equal(denied.body.error.message,"unsafe_callback");
  await writeFile(f.input.bindings[1].bearerFile,"synthetic_rotated_bearer_01234567890123456789");assert.equal((await f.rpc(TOKEN_OTHER,"tools/list")).status,401);
  assert.equal(f.writes.length,0);
});

test("ordered batches remain contiguous across concurrent anchors and confirmed duplicates never send again",async t=>{
  let release;const blocked=new Promise(resolve=>{release=resolve;});let count=0;
  const f=await harness(t,{send:async()=>{if(++count===1)await blocked;return String(777777777777777777n+BigInt(count));}});await f.subscribe();
  f.socket.message("444444444444444444");f.socket.message("444444444444444445");await waitFor(()=>f.events.length===2);
  const first=f.rpc(TOKEN_OWNER,"tools/call",{name:"discord_reply_batch",arguments:{...f.anchor("444444444444444444"),texts:["a1","a2"]}});await waitFor(()=>f.writes.length===1);
  const second=f.rpc(TOKEN_OWNER,"tools/call",{name:"discord_reply_batch",arguments:{...f.anchor("444444444444444445"),texts:["b1","b2"]}});await pause(20);assert.equal(f.writes.length,1);release();
  for(const result of await Promise.all([first,second]))assert.equal(result.body.error,undefined);
  assert.deepEqual(f.writes.map(args=>args[2]),["a1","a2","b1","b2"]);assert.equal(new Set(f.writes.map(args=>args[3])).size,4);
  const again=await f.rpc(TOKEN_OWNER,"tools/call",{name:"discord_reply_batch",arguments:{...f.anchor("444444444444444444"),texts:["a1","a2"]}});assert.equal(JSON.parse(again.body.result.content[0].text).duplicate,true);assert.equal(f.writes.length,4);
});

test("partial batch uncertainty blocks later batches in that conversation across encrypted restart",async t=>{
  let sent=0;const f=await harness(t,{ownerAudience:"directed",send:async()=>{if(++sent===2)throw new Error("synthetic_timeout");return String(777777777777777777n+BigInt(sent));}});await f.subscribe();
  f.socket.message("444444444444444444");f.socket.message("444444444444444445");f.socket.message("444444444444444446",OWNER,{guild_id:"999999999999999999",mentions:[{id:BOT}]});
  await waitFor(()=>f.events.length===3);
  const args={...f.anchor("444444444444444444"),texts:["secret_synthetic_first","second"]},later={...f.anchor("444444444444444445"),texts:["later"]};
  assert.equal((await f.rpc(TOKEN_OWNER,"tools/call",{name:"discord_reply_batch",arguments:args})).body.error.message,"reply_outcome_uncertain_no_resend");
  assert.equal((await f.rpc(TOKEN_OWNER,"tools/call",{name:"discord_reply_batch",arguments:later})).body.error.message,"conversation_send_uncertain_no_resend");assert.equal(sent,2);
  const ownerBridge=f.runtime.bridges.get("owner"),barrier=await ownerBridge.records.get("send-lane",args.conversation_id);assert.deepEqual(barrier.value.message_ids,["777777777777777778"]);
  // Another conversation under the same authenticated sender remains usable.
  assert.equal((await f.rpc(TOKEN_OWNER,"tools/call",{name:"discord_reply_batch",arguments:{...f.anchor("444444444444444446"),texts:["independent conversation"]}})).body.error,undefined);assert.equal(sent,3);
  await f.restart();
  assert.equal((await f.rpc(TOKEN_OWNER,"tools/call",{name:"discord_reply_batch",arguments:args})).body.error.message,"reply_outcome_uncertain_no_resend");
  assert.equal((await f.rpc(TOKEN_OWNER,"tools/call",{name:"discord_reply_batch",arguments:later})).body.error.message,"conversation_send_uncertain_no_resend");assert.equal(sent,3);
  const database=await readFile(join(f.input.stateDirectory,"dotcord.sqlite"));assert.equal(database.includes(Buffer.from("secret_synthetic_first")),false);assert.equal(database.includes(Buffer.from("synthetic live text")),false);
});

test("final confirmation persistence failure keeps the durable conversation barrier closed",async t=>{
  const f=await harness(t);await f.subscribe();f.socket.message("444444444444444444");f.socket.message("444444444444444445");await waitFor(()=>f.events.length===2);
  const bridge=f.runtime.bridges.get("owner"),put=bridge.records.put.bind(bridge.records);
  bridge.records.put=async(type,key,value,...rest)=>{if(type==="message"&&value.reply?.status==="sent")throw new Error("synthetic_final_confirmation_failure");return put(type,key,value,...rest);};
  const first={...f.anchor("444444444444444444"),texts:["confirmed by provider"]},later={...f.anchor("444444444444444445"),texts:["must wait"]};
  assert.equal((await f.rpc(TOKEN_OWNER,"tools/call",{name:"discord_reply_batch",arguments:first})).body.error.message,"reply_outcome_uncertain_no_resend");assert.equal(f.writes.length,1);
  assert.equal((await f.rpc(TOKEN_OWNER,"tools/call",{name:"discord_reply_batch",arguments:later})).body.error.message,"forbidden");assert.equal(f.writes.length,1);
  await f.restart();
  assert.equal((await f.rpc(TOKEN_OWNER,"tools/call",{name:"discord_reply_batch",arguments:later})).body.error.message,"conversation_send_uncertain_no_resend");assert.equal(f.writes.length,1);
  const retained=await f.runtime.bridges.get("owner").records.get("send-lane",first.conversation_id);assert.deepEqual(retained.value.message_ids,["777777777777777778"]);assert.equal(retained.value.status,"pending");
});

test("duplicate bearer values and callback reuse fail before provider access",async()=>{
  const{input}=await files();let connected=false;await writeFile(input.bindings[1].bearerFile,TOKEN_OWNER);
  await assert.rejects(()=>createRuntime(parseConfig(input,true),()=>{connected=true;throw new Error();}),/sender_bearers_must_be_separate/);assert.equal(connected,false);
  input.bindings[1].callbackUrl=input.bindings[0].callbackUrl;assert.throws(()=>parseConfig(input,true),/sender_bindings_must_be_separate/);
});

test("durable storage enforces CAS, GCM authentication, expiry and a single local consumer",async()=>{
  const directory=await mkdtemp(join(tmpdir(),"dotcord-store-")),key=Buffer.alloc(32,12);const store=new EncryptedStore(directory,key,"scope");
  const records=store.records("sender-a"),written=await records.put("message","444444444444444444",{delivery:{status:"queued",next:0},text:"private_synthetic_text"},null,Date.now()-1);
  assert.throws(()=>new EncryptedStore(directory,Buffer.alloc(32,12),"scope"),/EEXIST/);
  await assert.rejects(()=>records.put("message","444444444444444444",{},null),/storage_conflict/);
  assert.equal((await records.get("message","444444444444444444")).etag,written.etag);assert.equal(await store.records("sender-b").get("message","444444444444444444"),undefined);
  store.prune();assert.equal(await records.get("message","444444444444444444"),undefined);store.close();
  assert.equal((await readdir(directory)).includes("consumer.lock"),false);
  assert.throws(()=>new EncryptedStore(directory,Buffer.alloc(32,13),"scope"));
  const recovered=new EncryptedStore(directory,Buffer.alloc(32,12),"scope");recovered.close();
});
