import { createRequire } from "node:module";
import { Worker } from "node:worker_threads";
import { z } from "zod";
import type { NetworkRequest, NetworkResult } from "./networking.js";
import { snowflake } from "./config.js";

export const MAX_IMAGE_BYTES = 2 * 1024 * 1024;
export const MAX_IMAGE_PIXELS = 10_000_000;
export const MAX_MESSAGE_IMAGES = 4;
export const IMAGE_READ_TIMEOUT_MS = 15_000;
const mime = z.enum(["image/png", "image/jpeg"]);
const descriptorSchema = z.object({
  id: snowflake, filename: z.string().min(1).max(256).refine(value => !/[\x00-\x1f\x7f/\\]/.test(value) && ![".", ".."].includes(value)),
  content_type: mime, size: z.number().int().positive().max(MAX_IMAGE_BYTES),
  width: z.number().int().positive().max(MAX_IMAGE_PIXELS).nullish(),
  height: z.number().int().positive().max(MAX_IMAGE_PIXELS).nullish()
});
export type ImageAttachment = { id: string; filename: string; mime_type: "image/png" | "image/jpeg"; size: number; width?: number; height?: number };
export type AttachmentBinding = { messageId: string; channelId: string; guildId: string | null; authorId: string; attachment: ImageAttachment };
export type AttachmentImage = { data: string; mimeType: ImageAttachment["mime_type"]; width: number; height: number };
export type AttachmentReader = (binding: AttachmentBinding, signal: AbortSignal) => Promise<AttachmentImage>;
export class AttachmentError extends Error {}

export function imageAttachments(raw: unknown[]): ImageAttachment[] {
  const result: ImageAttachment[] = [];
  for (const item of raw) {
    const parsed = descriptorSchema.safeParse(item);
    if (!parsed.success) continue;
    const a = parsed.data;
    if (a.width && a.height && a.width * a.height > MAX_IMAGE_PIXELS) continue;
    if (result.some(value => value.id === a.id)) continue;
    result.push({ id: a.id, filename: a.filename, mime_type: a.content_type, size: a.size,
      ...(a.width ? { width: a.width } : {}), ...(a.height ? { height: a.height } : {}) });
    if (result.length === MAX_MESSAGE_IMAGES) break;
  }
  return result;
}

export function attachmentUrl(raw: unknown, binding: AttachmentBinding, now = Date.now()): string {
  if (typeof raw !== "string" || raw.length > 4096) throw new AttachmentError("attachment_url_denied");
  let url: URL;
  try { url = new URL(raw); } catch { throw new AttachmentError("attachment_url_denied"); }
  const prefix = `/attachments/${binding.channelId}/${binding.attachment.id}/`;
  let filename: string;
  try { filename = decodeURIComponent(url.pathname.slice(prefix.length)); } catch { throw new AttachmentError("attachment_url_denied"); }
  if (url.protocol !== "https:" || url.hostname !== "cdn.discordapp.com" || url.username || url.password || url.port || url.hash
    || !url.pathname.startsWith(prefix) || filename !== binding.attachment.filename || /[/\\]/.test(filename)
    || [...url.searchParams.keys()].length !== 3 || !["ex", "is", "hm"].every(key => url.searchParams.getAll(key).length === 1)
    || !/^[a-f0-9]{6,16}$/i.test(url.searchParams.get("ex") ?? "") || !/^[a-f0-9]{6,16}$/i.test(url.searchParams.get("is") ?? "")
    || !/^[a-f0-9]{64}$/i.test(url.searchParams.get("hm") ?? "")) throw new AttachmentError("attachment_url_denied");
  const expires = Number.parseInt(url.searchParams.get("ex")!, 16) * 1000;
  const issued = Number.parseInt(url.searchParams.get("is")!, 16) * 1000;
  if (!Number.isSafeInteger(expires) || !Number.isSafeInteger(issued) || expires <= now || issued > now + 60_000 || issued >= expires) {
    throw new AttachmentError("attachment_url_expired");
  }
  return url.toString();
}

// This fixed worker accepts bytes only. Header bounds precede native decoding;
// neither filenames nor caller-controlled code/URLs reach the decoder.
const decodeWorker = String.raw`
const {parentPort,workerData}=require('node:worker_threads');
const fail=reason=>{throw new Error(reason)};
const bounds=(width,height)=>{if(!Number.isSafeInteger(width)||!Number.isSafeInteger(height)||width<1||height<1||width*height>workerData.maxPixels)fail('attachment_image_limits');return {width,height}};
const bytes=Buffer.from(workerData.bytes);
function dimensions(){
 if(workerData.mime==='image/png'){
  if(bytes.length<45||bytes.subarray(0,8).toString('hex')!=='89504e470d0a1a0a')fail('attachment_invalid_image');
  let offset=8,frame,idat=false,ended=false;
  while(offset+12<=bytes.length){
   const size=bytes.readUInt32BE(offset),end=offset+12+size;
   if(end>bytes.length)fail('attachment_invalid_image');
   const type=bytes.toString('ascii',offset+4,offset+8);
   if(!frame&&type!=='IHDR')fail('attachment_invalid_image');
   if(['acTL','fcTL','fdAT'].includes(type))fail('attachment_image_limits');
   if(type==='IHDR'){
    if(frame||size!==13)fail('attachment_invalid_image');
    frame=bounds(bytes.readUInt32BE(offset+8),bytes.readUInt32BE(offset+12));
   }
   let crc=0xffffffff;
   for(let i=offset+4;i<end-4;i++){crc^=bytes[i];for(let bit=0;bit<8;bit++)crc=(crc>>>1)^((crc&1)?0xedb88320:0)}
   if(((crc^0xffffffff)>>>0)!==bytes.readUInt32BE(end-4))fail('attachment_invalid_image');
   if(type==='IDAT')idat=true;
   offset=end;
   if(type==='IEND'){if(size!==0||offset!==bytes.length)fail('attachment_invalid_image');ended=true;break}
  }
  if(!frame||!idat||!ended)fail('attachment_invalid_image');return frame;
 }
 if(bytes.length<12||bytes.readUInt16BE(0)!==0xffd8||bytes.readUInt16BE(bytes.length-2)!==0xffd9)fail('attachment_invalid_image');
 let offset=2,frame,scan=false,sawScan=false;
 while(offset<bytes.length){
  if(scan){while(offset<bytes.length&&bytes[offset]!==0xff)offset++;if(offset>=bytes.length)fail('attachment_invalid_image')}
  if(bytes[offset++]!==0xff)fail('attachment_invalid_image');
  while(bytes[offset]===0xff)offset++;
  const marker=bytes[offset++];
  if(marker===0x00){if(!scan)fail('attachment_invalid_image');continue}
  if(marker===0xd9){if(!frame||!sawScan||offset!==bytes.length)fail('attachment_invalid_image');return frame}
  if(marker===0xd8)fail('attachment_image_limits');
  if(marker===0x01||(marker>=0xd0&&marker<=0xd7))continue;
  if(offset+2>bytes.length)fail('attachment_invalid_image');
  const size=bytes.readUInt16BE(offset);
  if(size<2||offset+size>bytes.length)fail('attachment_invalid_image');
  if(marker===0xe2&&bytes.toString('ascii',offset+2,offset+6)==='MPF\x00')fail('attachment_image_limits');
  if([0xc0,0xc1,0xc2].includes(marker)){
   if(frame||size<8||bytes[offset+2]!==8)fail('attachment_invalid_image');
   frame=bounds(bytes.readUInt16BE(offset+5),bytes.readUInt16BE(offset+3));
  }
  if(marker===0xda){if(!frame)fail('attachment_invalid_image');scan=true;sawScan=true}else scan=false;
  offset+=size;
 }
 fail('attachment_invalid_image');
}
(async()=>{
 try{
  const expected=dimensions();
  const {loadImage}=require(workerData.decoder);
  const image=await loadImage(bytes);
  if(!image.complete||image.naturalWidth!==expected.width||image.naturalHeight!==expected.height)fail('attachment_invalid_image');
  parentPort.postMessage({ok:true,...expected});
 }catch(error){parentPort.postMessage({ok:false,reason:['attachment_image_limits','attachment_invalid_image'].includes(error.message)?error.message:'attachment_invalid_image'})}
})();
`;

export async function validateImage(bytes: Buffer, mimeType: ImageAttachment["mime_type"], signal: AbortSignal): Promise<{ width: number; height: number }> {
  if (!bytes.length || bytes.length > MAX_IMAGE_BYTES || !mime.safeParse(mimeType).success) throw new AttachmentError("attachment_image_limits");
  if (signal.aborted) throw new AttachmentError("attachment_timeout");
  const decoder = createRequire(import.meta.url).resolve("@napi-rs/canvas");
  const worker = new Worker(decodeWorker, { eval: true, execArgv: [], env: {}, stdout: true, stderr: true, workerData: { bytes, mime: mimeType, maxPixels: MAX_IMAGE_PIXELS, decoder },
    resourceLimits: { maxOldGenerationSizeMb: 64, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 } });
  worker.stdout?.resume(); worker.stderr?.resume();
  return await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: AttachmentError, result?: { width: number; height: number }) => {
      if (settled) return; settled = true;
      clearTimeout(timer); signal.removeEventListener("abort", abort);
      void worker.terminate().then(() => error ? reject(error) : resolve(result!), () => reject(new AttachmentError("attachment_invalid_image")));
    };
    const abort = () => finish(new AttachmentError("attachment_timeout"));
    const timer = setTimeout(abort, 5000);
    signal.addEventListener("abort", abort, { once: true });
    worker.once("message", (result) => {
      if (!result?.ok) return finish(new AttachmentError(result?.reason === "attachment_image_limits" ? result.reason : "attachment_invalid_image"));
      if (!Number.isSafeInteger(result.width) || !Number.isSafeInteger(result.height) || result.width < 1 || result.height < 1
        || result.width * result.height > MAX_IMAGE_PIXELS) return finish(new AttachmentError("attachment_image_limits"));
      finish(undefined, { width: result.width, height: result.height });
    });
    worker.once("error", () => finish(new AttachmentError("attachment_invalid_image")));
    worker.once("exit", () => finish(new AttachmentError("attachment_invalid_image")));
    if (signal.aborted) abort();
  });
}

export function createAttachmentReader(network: NetworkRequest, token: string): AttachmentReader {
  return async (binding, signal) => {
    const deadline = Date.now() + IMAGE_READ_TIMEOUT_MS;
    const request = async (url: string, binary: boolean): Promise<NetworkResult> => {
      if (signal.aborted || Date.now() >= deadline) throw new AttachmentError("attachment_timeout");
      return await network(url, "GET", undefined, binary ? {} : { Authorization: `Bot ${token}` },
        binary ? MAX_IMAGE_BYTES : 65_536, Math.max(1, deadline - Date.now()), signal);
    };
    try {
      const messageUrl = `https://discord.com/api/v10/channels/${snowflake.parse(binding.channelId)}/messages/${snowflake.parse(binding.messageId)}`;
      const metadata = await request(messageUrl, false);
      if (metadata.status !== 200 || metadata.truncated || metadata.url !== messageUrl) throw new AttachmentError("attachment_unavailable");
      const message = JSON.parse(metadata.bodyText);
      if (message.id !== binding.messageId || message.channel_id !== binding.channelId || (message.guild_id ?? null) !== binding.guildId
        || message.author?.id !== binding.authorId || message.author.bot || !Array.isArray(message.attachments)) throw new AttachmentError("attachment_unavailable");
      const matching = message.attachments.filter((item: { id?: unknown }) => item?.id === binding.attachment.id);
      if (matching.length !== 1 || JSON.stringify(imageAttachments(matching)[0]) !== JSON.stringify(binding.attachment)) throw new AttachmentError("attachment_unavailable");
      const url = attachmentUrl(matching[0].url, binding);
      const response = await request(url, true);
      const type = response.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
      const declaredLength = response.headers["content-length"];
      if (response.status !== 200 || response.url !== url || response.truncated || type !== binding.attachment.mime_type
        || typeof response.bodyBase64 !== "string" || response.bodyBase64.length > 4 * Math.ceil(MAX_IMAGE_BYTES / 3)
        || (declaredLength !== undefined && (!/^\d+$/.test(declaredLength) || Number(declaredLength) !== binding.attachment.size))) {
        throw new AttachmentError("attachment_unavailable");
      }
      const bytes = Buffer.from(response.bodyBase64, "base64");
      if (bytes.toString("base64") !== response.bodyBase64 || bytes.length !== binding.attachment.size) throw new AttachmentError("attachment_unavailable");
      const dimensions = await validateImage(bytes, binding.attachment.mime_type, signal);
      if ((binding.attachment.width !== undefined && binding.attachment.width !== dimensions.width)
        || (binding.attachment.height !== undefined && binding.attachment.height !== dimensions.height)) throw new AttachmentError("attachment_unavailable");
      if (signal.aborted) throw new AttachmentError("attachment_timeout");
      return { data: response.bodyBase64, mimeType: binding.attachment.mime_type, ...dimensions };
    } catch (error) {
      if (error instanceof AttachmentError) throw error;
      throw new AttachmentError(signal.aborted ? "attachment_timeout" : "attachment_unavailable");
    }
  };
}
