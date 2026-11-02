import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

export type Versioned<T> = { value: T; etag: string };
export type BridgeRecordSummary = { key: string; expires?: number; queued?: boolean; next?: number };
export type BridgeRecords = {
  get<T>(type: string, key: string): Promise<Versioned<T> | undefined>;
  put<T>(type: string, key: string, value: T, etag: string | null, expires?: number): Promise<Versioned<T>>;
  list(type: string, limit: number): Promise<BridgeRecordSummary[]>;
  delete(type: string, key: string): Promise<void>;
};
type Row = { body: Uint8Array; etag: string; expires: number | null; record_key: string };
export function readPrivateFile(path: string): Buffer {
  const resolved = resolve(path);
  if (realpathSync(resolved) !== resolved) throw new Error("credential_symlink_denied");
  const fd = openSync(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > 16384) throw new Error("invalid_credential_reference");
    if (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.())) throw new Error("credential_file_must_be_private_and_owned");
    return readFileSync(fd);
  } finally { closeSync(fd); }
}
export function isWithin(path: string, parent: string): boolean {
  const delta = relative(resolve(parent), resolve(path));
  return !delta.startsWith("..") && !delta.includes(":") && delta !== "";
}
/** One process owns one new state directory. No archive or Pandemonium import path exists. */
export class EncryptedStore {
  private readonly db!: DatabaseSync;
  private readonly lock: string;
  private closed = false;
  constructor(readonly directory: string, private readonly key: Buffer, scope: string) {
    if (key.length !== 32) throw new Error("invalid_storage_key");
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(directory) !== resolve(directory)) throw new Error("state_directory_denied");
    if (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.())) throw new Error("state_directory_must_be_private_and_owned");
    this.lock = join(directory, "consumer.lock");
    const fd = openSync(this.lock, "wx", 0o600);
    writeFileSync(fd, String(process.pid)); closeSync(fd);
    try {
      const database = join(directory, "dotcord.sqlite");
      if (existsSync(database)) {
        const file = lstatSync(database);
        if (!file.isFile() || file.isSymbolicLink() || process.platform !== "win32" && ((file.mode & 0o077) !== 0 || file.uid !== process.getuid?.())) throw new Error("state_file_denied");
      } else closeSync(openSync(database,"wx",0o600));
      this.db = new DatabaseSync(database);
      this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;");
      this.db.exec("CREATE TABLE IF NOT EXISTS dotcord_v1 (scope TEXT NOT NULL, record_type TEXT NOT NULL, record_key TEXT NOT NULL, etag TEXT NOT NULL, expires INTEGER, body BLOB NOT NULL, PRIMARY KEY(scope,record_type,record_key))");
      const expected = createHash("sha256").update(scope).digest("hex");
      const installed = this.db.prepare("SELECT scope,body FROM dotcord_v1 WHERE record_type='installation'").get();
      if (installed && installed.scope !== expected) throw new Error("installation_scope_changed");
      if (!installed) this.db.prepare("INSERT INTO dotcord_v1 VALUES (?, 'installation', 'primary', ?, NULL, ?)").run(expected, randomUUID(), this.seal(expected, "installation", "primary", { version: 1 }));
      else this.open(expected, "installation", "primary", installed.body as Uint8Array);
    } catch (error) { this.db?.close(); unlinkSync(this.lock); throw error; }
  }
  private seal(scope: string, type: string, key: string, value: unknown): Buffer {
    const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(JSON.stringify(["dotcord-v1", scope, type, key])));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
  }
  private open<T>(scope: string, type: string, key: string, body: Uint8Array): T {
    const bytes = Buffer.from(body), decipher = createDecipheriv("aes-256-gcm", this.key, bytes.subarray(0,12));
    decipher.setAAD(Buffer.from(JSON.stringify(["dotcord-v1", scope, type, key]))); decipher.setAuthTag(bytes.subarray(12,28));
    return JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString("utf8")) as T;
  }
  records(scope: string): BridgeRecords {
    const query = (type: string, key: string) => this.db.prepare("SELECT body,etag,expires,record_key FROM dotcord_v1 WHERE scope=? AND record_type=? AND record_key=?").get(scope,type,key) as Row | undefined;
    return {
      get: async <T>(type: string, key: string) => {
        const row = query(type,key); return row ? { value: this.open<T>(scope,type,key,row.body), etag: row.etag } : undefined;
      },
      put: async <T>(type: string, key: string, value: T, etag: string | null, expires?: number) => {
        if (Buffer.byteLength(JSON.stringify(value)) > 262144) throw new Error("record_too_large");
        const next = randomUUID(), bytes = this.seal(scope,type,key,value);
        const result = etag === null
          ? this.db.prepare("INSERT OR IGNORE INTO dotcord_v1 VALUES (?,?,?,?,?,?)").run(scope,type,key,next,expires ?? null,bytes)
          : this.db.prepare("UPDATE dotcord_v1 SET etag=?,expires=?,body=? WHERE scope=? AND record_type=? AND record_key=? AND etag=?").run(next,expires ?? null,bytes,scope,type,key,etag);
        if (Number(result.changes) !== 1) throw new Error("storage_conflict");
        return { value: structuredClone(value), etag: next };
      },
      list: async (type, limit) => {
        const rows = this.db.prepare("SELECT body,etag,expires,record_key FROM dotcord_v1 WHERE scope=? AND record_type=? ORDER BY length(record_key),record_key LIMIT ?").all(scope,type,Math.min(1000,limit)) as Row[];
        return rows.map(row => {
          const value = type === "message" ? this.open<{delivery: {status: string; next: number}}>(scope,type,row.record_key,row.body) : undefined;
          return { key: row.record_key, expires: row.expires ?? undefined, queued: value?.delivery.status === "queued", next: value?.delivery.next };
        });
      },
      delete: async (type,key) => { this.db.prepare("DELETE FROM dotcord_v1 WHERE scope=? AND record_type=? AND record_key=?").run(scope,type,key); }
    };
  }
  prune(now = Date.now()) { this.db.prepare("DELETE FROM dotcord_v1 WHERE expires IS NOT NULL AND expires<=?").run(now); }
  close() { if (this.closed) return; this.closed = true; this.db.close(); unlinkSync(this.lock); this.key.fill(0); }
}
