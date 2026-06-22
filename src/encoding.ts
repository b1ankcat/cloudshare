/**
 * Encoding + HTML/JS escape helpers.
 *
 * `jsAttrString` is the ONLY safe way to embed a string into an HTML attribute
 * that contains a JS literal, e.g.  onclick="handler(${jsAttrString(name)})".
 * The previous escapeJsArg left " unescaped, allowing attribute breakout (XSS).
 *
 * Server-side `validateName` rejects characters that could become XSS payloads
 * even if the front-end escape is bypassed.
 */

// Characters forbidden in file and folder names. Rejected at the API
// boundary so XSS payloads (< > " '), path separators (/ \), and platform
// reserved characters (< > : " | ? *) can never reach the storage layer.
const FORBIDDEN_NAME_CHARS = /[<>:'"|?*\\\/]|[\x00-\x1f\x7f]/;

/** Decode percent-encoded string. Throws URIError on invalid input. */
export function safeDecode(value: string): string {
  return decodeURIComponent(value);
}

/** URL-encode a single path segment so `/`, `?`, `#` etc. become `%XX`. */
export function encodePathSegment(value: string): string {
  return encodeURIComponent(safeDecode(value));
}

/**
 * Normalize a folder path. Strips leading/trailing slashes, splits on `/`,
 * encodes each segment, joins with `/`. Empty input returns "".
 */
export function normalizeFolderPath(folder: string): string {
  const decoded = safeDecode(folder || "").replace(/^\/+|\/+$/g, "");
  if (!decoded) return "";
  return decoded
    .split("/")
    .filter(Boolean)
    .map(encodePathSegment)
    .join("/");
}

/** Inverse of normalizeFolderPath: decode each segment, join with `/`. */
export function decodeFolderPath(folder: string): string {
  return normalizeFolderPath(folder)
    .split("/")
    .filter(Boolean)
    .map(safeDecode)
    .join("/");
}

/**
 * Build an R2 key for a file. Each segment is URL-encoded so `/` inside a
 * filename becomes `%2F` (still R2-safe; not a path separator).
 */
export function buildR2Key(folder: string, filename: string): string {
  const cleanFolder = normalizeFolderPath(folder);
  const cleanFilename = encodePathSegment(filename);
  return cleanFolder ? `${cleanFolder}/${cleanFilename}` : cleanFilename;
}

/**
 * Normalize a full object key (may contain slashes). Splits, encodes the
 * filename, rejoins. Returns "" if no filename.
 */
export function normalizeObjectKey(path: string): string {
  const decoded = safeDecode(path || "").replace(/^\/+|\/+$/g, "");
  if (!decoded) return "";
  const parts = decoded.split("/").filter(Boolean);
  const filename = parts.pop();
  if (!filename) return "";
  return buildR2Key(parts.join("/"), filename);
}

/** true iff value is a 64-char lowercase hex string. */
export function isValidSha256(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

/**
 * Validate a file or folder name. Throws if the name is empty after trim,
 * equals "." or "..", contains forbidden characters, or contains control chars.
 */
export function validateName(name: string, kind: "file" | "folder" = "file"): void {
  const trimmed = (name || "").trim();
  if (!trimmed) {
    throw new ValidationError(`${kind === "file" ? "文件名" : "文件夹名"}不能为空`);
  }
  if (trimmed === "." || trimmed === "..") {
    throw new ValidationError(`${kind === "file" ? "文件名" : "文件夹名"}不能为 . 或 ..`);
  }
  if (FORBIDDEN_NAME_CHARS.test(trimmed)) {
    throw new ValidationError(
      `${kind === "file" ? "文件名" : "文件夹名"}包含非法字符 (< > : " | ? * \\ / 或控制字符)`,
    );
  }
}

/** Internal storage prefix for content-addressed blobs. */
export const BLOB_PREFIX = "__blob__/";

/** true iff the R2 key is internal (blob store, .folder marker, reserved). */
export function isInternalR2Key(key: string): boolean {
  return (
    key.startsWith(BLOB_PREFIX) ||
    key === "__blob__" ||
    key === ".folder" ||
    key.endsWith("/.folder")
  );
}

/**
 * Escape a string for safe insertion into HTML text content.
 * Uses textContent semantics: <, >, &, " all become entities.
 */
export function escapeHtml(value: string): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Escape a string for safe insertion into an HTML attribute that contains a
 * JS string literal, e.g.  onclick="fn(${jsAttrString(s)})".
 *
 * Combines JSON.stringify (gives a valid JS literal with proper " / \ escapes)
 * with HTML entity escaping so the resulting literal is also safe inside
 * an HTML attribute value. Without the HTML entity step, the inner " would
 * close the attribute and the " would let the attacker inject markup.
 */
export function jsAttrString(value: string): string {
  return JSON.stringify(String(value ?? ""))
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Thrown by validateName. Callers translate to 400 responses. */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}
