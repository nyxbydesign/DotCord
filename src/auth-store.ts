import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { closeSync, existsSync, lstatSync, mkdirSync, openSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { BridgeRecords } from "./storage.js";

export const authHash = (value: string) => createHash("sha256").update(value).digest("hex");
type Stored = { value: Record<string, unknown>; etag: string; expires: number };
/** A single owned process uses synchronous SQLite transactions for consume and grant changes. */
export class AuthStore {
  private readonly db!: DatabaseSync;
  private readonly lock: string;
  private closed = false;
  private inTransaction = false;
  constructor(readonly directory: string, private readonly key: Buffer, private readonly installation: string, private readonly now = Date.now) {
    if (key.length !== 32) throw new Error("invalid_auth_storage_key");
    mkdirSync(directory,{recursive:true,mode:0o700});
    const stat=lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(directory)!==resolve(directory)
      || process.platform!=="win32" && ((stat.mode&0o077)!==0 || stat.uid!==process.getuid?.())) throw new Error("auth_state_directory_denied");
    this.lock=join(directory,"auth.lock");
    const fd=openSync(this.lock,"wx",0o600);writeFileSync(fd,String(process.pid));closeSync(fd);
    try {
      const file=join(directory,"auth.sqlite");
      if (existsSync(file)) {
        const s=lstatSync(file);
        if (!s.isFile() || s.isSymbolicLink() || process.platform!=="win32" && ((s.mode&0o077)!==0 || s.uid!==process.getuid?.())) throw new Error("auth_state_file_denied");
      } else closeSync(openSync(file,"wx",0o600));
      this.db=new DatabaseSync(file);
      this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; CREATE TABLE IF NOT EXISTS auth_v1 (ns TEXT NOT NULL,id TEXT NOT NULL,etag TEXT NOT NULL,expires INTEGER NOT NULL,body BLOB NOT NULL,grant_ref TEXT,uid_ref TEXT,user_ref TEXT,PRIMARY KEY(ns,id)); CREATE INDEX IF NOT EXISTS auth_grant ON auth_v1(grant_ref); CREATE INDEX IF NOT EXISTS auth_uid ON auth_v1(ns,uid_ref);");
      const old=this.get("installation","primary",true);
      if (old && old.value.identity!==installation) throw new Error("auth_installation_changed");
      if (!old) this.set("installation","primary",{identity:installation},Number.MAX_SAFE_INTEGER);
    } catch(error) { this.db!?.close();unlinkSync(this.lock);throw error; }
  }
  private seal(ns:string,id:string,value:unknown,expires:number) {
    const iv=randomBytes(12),c=createCipheriv("aes-256-gcm",this.key,iv);c.setAAD(Buffer.from(JSON.stringify(["auth-v1",this.installation,ns,id])));
    const bytes=Buffer.concat([c.update(JSON.stringify({value,expires})),c.final()]);return Buffer.concat([iv,c.getAuthTag(),bytes]);
  }
  private decode(ns:string,id:string,row:Record<string,unknown>):Stored {
    const b=Buffer.from(row.body as Uint8Array),d=createDecipheriv("aes-256-gcm",this.key,b.subarray(0,12));d.setAAD(Buffer.from(JSON.stringify(["auth-v1",this.installation,ns,id])));d.setAuthTag(b.subarray(12,28));
    const decoded=JSON.parse(Buffer.concat([d.update(b.subarray(28)),d.final()]).toString("utf8"));
    if(decoded.expires!==Number(row.expires))throw new Error("auth_expiry_integrity_failed");
    return {value:decoded.value,etag:String(row.etag),expires:decoded.expires};
  }
  get(ns:string,id:string,includeExpired=false):Stored|undefined {
    const hashed=authHash(id),row=this.db.prepare("SELECT * FROM auth_v1 WHERE ns=? AND id=?").get(ns,hashed);
    if (!row || !includeExpired && Number(row.expires)<=this.now()) return undefined;return this.decode(ns,hashed,row);
  }
  set(ns:string,id:string,value:Record<string,unknown>,expires:number,expected?:string|null):string {
    if (Buffer.byteLength(JSON.stringify(value))>262144 || !Number.isFinite(expires)) throw new Error("auth_record_rejected");
    const existing=this.get(ns,id,true);
    if(!existing && !this.inTransaction)return this.atomic(()=>this.set(ns,id,value,expires,expected));
    if(!existing && Number(this.db.prepare("SELECT count(*) n FROM auth_v1").get()!.n)>=10000)throw new Error("auth_capacity_reached");
    const hashed=authHash(id),etag=randomUUID(),body=this.seal(ns,hashed,value,expires);
    const refs=[typeof value.grantId==="string"?authHash(value.grantId):null,typeof value.uid==="string"?authHash(value.uid):null,typeof value.userCode==="string"?authHash(value.userCode):null];
    if (expected===undefined) {
      this.db.prepare("INSERT INTO auth_v1 VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(ns,id) DO UPDATE SET etag=excluded.etag,expires=excluded.expires,body=excluded.body,grant_ref=excluded.grant_ref,uid_ref=excluded.uid_ref,user_ref=excluded.user_ref").run(ns,hashed,etag,expires,body,...refs);
    } else {
      if(expected===null && existing && existing.expires<=this.now())this.delete(ns,id);
      const result=expected===null
        ? this.db.prepare("INSERT OR IGNORE INTO auth_v1 VALUES (?,?,?,?,?,?,?,?)").run(ns,hashed,etag,expires,body,...refs)
        : this.db.prepare("UPDATE auth_v1 SET etag=?,expires=?,body=?,grant_ref=?,uid_ref=?,user_ref=? WHERE ns=? AND id=? AND etag=?").run(etag,expires,body,...refs,ns,hashed,expected);
      if (Number(result.changes)!==1) throw new Error("storage_conflict");
    }
    return etag;
  }
  delete(ns:string,id:string) {this.db.prepare("DELETE FROM auth_v1 WHERE ns=? AND id=?").run(ns,authHash(id));}
  atomic<T>(work:()=>T):T {if(this.inTransaction)return work();this.db.exec("BEGIN IMMEDIATE");this.inTransaction=true;try {const r=work();this.db.exec("COMMIT");return r;}catch(e){this.db.exec("ROLLBACK");throw e;}finally{this.inTransaction=false;}}
  consume(ns:string,id:string):boolean {return this.atomic(()=>{const old=this.get(ns,id);if (!old || old.value.consumed) return false;this.set(ns,id,{...old.value,consumed:Math.floor(this.now()/1000)},old.expires,old.etag);return true;});}
  find(ns:string,field:"uid_ref"|"user_ref",value:string) {const row=this.db.prepare(`SELECT * FROM auth_v1 WHERE ns=? AND ${field}=? AND expires>? LIMIT 1`).get(ns,authHash(value),this.now());return row?this.decode(ns,String(row.id),row).value:undefined;}
  revokeProviderGrant(id:string) {this.db.prepare("DELETE FROM auth_v1 WHERE grant_ref=? OR (ns='Grant' AND id=?)").run(authHash(id),authHash(id));}
  records(namespace:string):BridgeRecords {
    const ns=`control:${namespace}`;
    return {
      get:async<T>(type:string,id:string)=>{const r=this.get(ns+":"+type,id);return r?{value:r.value as T,etag:r.etag}:undefined;},
      put:async<T>(type:string,id:string,value:T,etag:string|null,expires=Number.MAX_SAFE_INTEGER)=>({value:structuredClone(value),etag:this.set(ns+":"+type,id,value as Record<string,unknown>,
        type==="subscription"&&typeof(value as {expires?:unknown}).expires==="number"?(value as {expires:number}).expires:expires,etag)}),
      list:async()=>[],delete:async(type,id)=>this.delete(ns+":"+type,id)
    };
  }
  audit(code:string,grantId?:string) {if (!/^[a-z_]{1,64}$/.test(code)) return;this.set("audit",randomUUID(),{at:this.now(),code,...(grantId?{grant:authHash(grantId)}:{})},this.now()+7*86400000);}
  prune() {this.db.prepare("DELETE FROM auth_v1 WHERE expires<=?").run(this.now());}
  close() {if(this.closed)return;this.closed=true;this.db.close();this.key.fill(0);unlinkSync(this.lock);}
}
