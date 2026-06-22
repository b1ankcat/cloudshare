/**
 * Cloudflare Worker bindings injected by the runtime.
 * Configure in wrangler.toml: [[r2_buckets]] binding="FILES_BUCKET",
 * [[kv_namespaces]] binding="cloudshare_shares".
 */
export interface Env {
  FILES_BUCKET: R2Bucket;
  cloudshare_shares: KVNamespace;
  /** Plain text secret compared in constant time against the login form. */
  ADMIN_PASSWORD: string;
  /**
   * CORS allow-origin. Empty string = same-origin only (no CORS headers).
   * Set via `wrangler secret put ALLOWED_ORIGIN` or [vars] in wrangler.toml.
   */
  ALLOWED_ORIGIN?: string;
}

/** Persisted share metadata. passwordHash is pbkdf2$<iter>$<saltB64u>$<hashB64u>. */
export interface ShareData {
  token: string;
  type: "file" | "folder";
  path: string;
  name: string;
  createdAt: string;
  expiresAt: string | null;
  passwordHash: string | null;
}

/** Share data safe to send to the client (no passwordHash). */
export interface PublicShareData extends Omit<ShareData, "passwordHash"> {
  hasPassword: boolean;
}

/** KV record holding dedup ref count + size + content type for a sha256. */
export interface RefCountEntry {
  refCount: number;
  size: number;
  contentType: string;
}

/** Single file entry returned by GET /api/files*. */
export interface FileEntry {
  name: string;
  size: number;
  uploaded: Date;
  key: string;
  folder: string;
  refCount?: number;
}

/** Single folder entry returned by GET /api/files*. */
export interface FolderEntry {
  name: string;
  type: "folder";
}

/** Response of GET /api/files and GET /api/files/:folder. */
export interface ListFilesResponse {
  folder: string;
  files: FileEntry[];
  folders: FolderEntry[];
}

/** Hex sha256 — 64 lowercase hex chars. */
export type Sha256 = string;
