import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCanvas } from "@napi-rs/canvas";
import { DiscordEventsBridge, DAY } from "../dist/bridge.js";
import { EncryptedStore } from "../dist/storage.js";
import { attachmentUrl, createAttachmentReader, imageAttachments, MAX_IMAGE_BYTES, validateImage } from "../dist/attachments.js";
import { callbackUrl, createNetwork, pinnedAddress, publicIPv4, signature } from "../dist/networking.js";
import { gatewayUrl } from "../dist/gateway.js";
const OWNER="111111111111111111",BOT="222222222222222222",CHANNEL="333333333333333333",ATTACHMENT="666666666666666666",MESSAGE="444444444444444444";
const SECRET="whsec_"+Buffer.alloc(32,7).toString("base64");
const config={enabled:true,audience:"owner-dm",botUserId:BOT,ownerUserId:OWNER,senderUserId:OWNER,ownerChannelId:CHANNEL,callbackHosts:["chatgpt.com"],callbackUrl:"https://chatgpt.com/callback/owner"};
const canvas=createCanvas(2,2);canvas.getContext("2d").fillRect(0,0,2,2);const png=canvas.toBuffer("image/png"),jpeg=canvas.toBuffer("image/jpeg");
function raw(bytes=png){return{id:ATTACHMENT,filename:bytes===jpeg?"fixture.jpg":"fixture.png",content_type:bytes===jpeg?"image/jpeg":"image/png",size:bytes.length,width:2,height:2};}
function binding(bytes=png){return{messageId:MESSAGE,channelId:CHANNEL,guildId:null,authorId:OWNER,attachment:imageAttachments([raw(bytes)])[0]};}
function signed(target=binding()){return`https://cdn.discordapp.com/attachments/${CHANNEL}/${ATTACHMENT}/${target.attachment.filename}?ex=${Math.floor(Date.now()/1000+3600).toString(16)}&is=${Math.floor(Date.now()/1000-60).toString(16)}&hm=${"a".repeat(64)}`;}
async function core(t,poster){
  const directory=await mkdtemp(join(tmpdir(),"dotcord-boundary-")),store=new EncryptedStore(directory,Buffer.alloc(32,2),"synthetic-core");
  let time=Date.now();const events=[];
  const post=async(url,body,headers)=>{const payload=JSON.parse(body);if(payload.type==="verification")return{status:200,body:JSON.stringify({challenge:payload.challenge})};events.push({body,headers,payload});return poster?poster(events.length):{status:200,body:""};};
  const bridge=new DiscordEventsBridge(config,store.records("owner"),post,async()=>"777777777777777777",async p=>p==="owner-client",()=>{},()=>time);
  t.after(async()=>{bridge.stop();await bridge.drain();store.close();});
  const subscribe=()=>bridge.subscribe("owner-client",{name:"discord.message.created",arguments:{audience:"owner-dm"},delivery:{mode:"webhook",url:config.callbackUrl,secret:SECRET}},time+DAY*3);
  const incoming=id=>({id,channel_id:CHANNEL,author:{id:OWNER},content:"synthetic live context",timestamp:new Date(time).toISOString(),type:0});
  const anchor=id=>({message_id:id,conversation_id:events.find(event=>event.payload.data.message_id===id).payload.data.conversation_id});
  return{bridge,events,subscribe,incoming,anchor,advance:ms=>{time+=ms;}};
}

test("signed callbacks preserve exact retry body and event ID while backoff holds later conversation events",async t=>{
  const f=await core(t,count=>({status:count===1?503:200,body:""}));await f.subscribe();
  await f.bridge.receive(f.incoming(MESSAGE));await f.bridge.receive(f.incoming("444444444444444445"));assert.equal(f.events.length,1);
  f.advance(2000);await f.bridge.pump();await f.bridge.pump();
  assert.deepEqual(f.events.map(item=>item.payload.data.message_id),[MESSAGE,MESSAGE,"444444444444444445"]);assert.equal(f.events[0].body,f.events[1].body);
  for(const event of f.events)assert.equal(event.headers["webhook-signature"],signature(SECRET,event.headers["webhook-id"],event.headers["webhook-timestamp"],event.body));
  await f.bridge.receive(f.incoming(MESSAGE));assert.equal(f.events.length,3);
});

test("context keeps at most40 scoped turns and expires after24 hours",async t=>{
  const f=await core(t);await f.subscribe();
  for(let i=0;i<45;i++){if(i)f.advance(60001);await f.bridge.receive(f.incoming(String(BigInt(MESSAGE)+BigInt(i))));}
  const latest=String(BigInt(MESSAGE)+44n),context=await f.bridge.conversation("owner-client",f.anchor(latest));assert.equal(context.turns.length,40);assert.equal(context.turns[0].message_id,String(BigInt(MESSAGE)+5n));
  f.advance(DAY+1);await assert.rejects(()=>f.bridge.conversation("owner-client",f.anchor(latest)),/unknown_or_expired_message/);
  await f.subscribe();const next=String(BigInt(MESSAGE)+45n);await f.bridge.receive(f.incoming(next));assert.equal((await f.bridge.conversation("owner-client",f.anchor(next))).turns.length,1);
});

test("attachment adapter rechecks exact provider binding, strips token on CDN, and decodes real PNG/JPEG",async()=>{
  for(const bytes of[png,jpeg]){
    const target=binding(bytes),url=signed(target),calls=[];
    const request=async(requestUrl,method,body,headers,maxBytes,timeout,signal)=>{
      calls.push({requestUrl,method,body,headers,maxBytes,timeout,signal});
      return requestUrl===url?{url,status:200,headers:{"content-type":target.attachment.mime_type,"content-length":String(bytes.length)},bodyText:"",bodyBase64:bytes.toString("base64"),truncated:false}
        :{url:requestUrl,status:200,headers:{},bodyText:JSON.stringify({id:MESSAGE,channel_id:CHANNEL,author:{id:OWNER},attachments:[{...raw(bytes),url}]}),truncated:false};
    };
    const image=await createAttachmentReader(request,"synthetic-token")(target,AbortSignal.timeout(5000));assert.deepEqual(image,{data:bytes.toString("base64"),mimeType:target.attachment.mime_type,width:2,height:2});
    assert.deepEqual(calls[0].headers,{Authorization:"Bot synthetic-token"});assert.deepEqual(calls[1].headers,{});assert.equal(calls[1].maxBytes,MAX_IMAGE_BYTES);assert.equal(calls[0].requestUrl,`https://discord.com/api/v10/channels/${CHANNEL}/messages/${MESSAGE}`);
  }
  const target=binding();let calls=0;const reader=createAttachmentReader(async url=>{calls++;return{url,status:200,bodyText:JSON.stringify({id:MESSAGE,channel_id:CHANNEL,author:{id:"555555555555555555"},attachments:[]})};},"synthetic-token");
  await assert.rejects(()=>reader(target,AbortSignal.timeout(5000)),/attachment_unavailable/);assert.equal(calls,1);
});

test("image descriptors and native decoder refuse corrupt, oversized, animated and wrong-origin images",async()=>{
  const target=binding(),url=signed();
  for(const altered of[url.replace("cdn.discordapp.com","evil.example"),url.replace(CHANNEL,"333333333333333334"),url.replace("fixture.png","other.png"),url.replace("https:","http:"),url.replace("https://","https://user:password@"),url+"&ex=ffffffff",url.replace(/ex=[^&]+/,"ex=000000"),url+"#fragment"])assert.throws(()=>attachmentUrl(altered,target));
  assert.equal(imageAttachments([{...raw(),size:MAX_IMAGE_BYTES+1},{...raw(),content_type:"image/svg+xml"}]).length,0);
  const corrupt=Buffer.from(png);corrupt[corrupt.length-1]^=1;
  for(const[bytes,mime]of[[Buffer.from("invalid image"),"image/png"],[corrupt,"image/png"],[jpeg,"image/png"],[Buffer.alloc(MAX_IMAGE_BYTES+1),"image/png"]])await assert.rejects(()=>validateImage(bytes,mime,AbortSignal.timeout(5000)));
  const bomb=Buffer.from(png);bomb.writeUInt32BE(100000,16);bomb.writeUInt32BE(100000,20);await assert.rejects(()=>validateImage(bomb,"image/png",AbortSignal.timeout(5000)),/attachment_image_limits/);
  const payload=Buffer.alloc(8);payload.writeUInt32BE(2);const type=Buffer.from("acTL"),size=Buffer.alloc(4),checksum=Buffer.alloc(4);size.writeUInt32BE(8);
  let crc=0xffffffff;for(const byte of Buffer.concat([type,payload])){crc^=byte;for(let bit=0;bit<8;bit++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}checksum.writeUInt32BE((crc^0xffffffff)>>>0);
  const animated=Buffer.concat([png.subarray(0,33),size,type,payload,checksum,png.subarray(33)]);await assert.rejects(()=>validateImage(animated,"image/png",AbortSignal.timeout(5000)),/attachment_image_limits/);
  await assert.rejects(()=>validateImage(png,"image/png",AbortSignal.abort()),/attachment_timeout/);
});

test("callback, Gateway and public-DNS boundaries reject unsafe destinations without provider traffic",async()=>{
  for(const raw of["http://chatgpt.com/callback","https://chatgpt.com.evil.example/callback","https://u:p@chatgpt.com/callback","https://chatgpt.com:444/callback","https://chatgpt.com/callback#x"])assert.throws(()=>callbackUrl(raw,["chatgpt.com"]));
  for(const raw of["ws://gateway.discord.gg","wss://evil.example","wss://gateway.discord.gg:444"])assert.throws(()=>gatewayUrl(raw));
  for(const ip of["0.0.0.0","10.1.2.3","127.0.0.1","169.254.169.254","172.16.0.1","192.168.0.1","100.64.0.1","198.18.0.1","192.0.2.1","203.0.113.1","224.0.0.1","8.8.8.999","8.008.8.8","::1"])assert.equal(publicIPv4(ip),false,ip);
  assert.equal(publicIPv4("8.8.8.8"),true);
  await assert.rejects(()=>pinnedAddress("chatgpt.com",async()=>[{address:"8.8.8.8"},{address:"127.0.0.1"}]),/public_destination_required/);
  await assert.rejects(()=>pinnedAddress("evil.example",async()=>{throw new Error("must_not_resolve");}),/destination_denied/);
  const network=createNetwork("synthetic-token",["chatgpt.com"],"127.0.0.1");
  try{await assert.rejects(()=>network.post("https://evil.example/callback","{}",{}),/unsafe_callback/);await assert.rejects(()=>network.discord("/channels/333333333333333333/messages?limit=100"),/discord_path_denied/);}finally{await network.close();}
});
