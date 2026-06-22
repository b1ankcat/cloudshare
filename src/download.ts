/**
 * R2 file download: content-type sniffing, Range parsing, streaming.
 */

import { errorResponse } from "./responses";
import { getRefCount } from "./storage";
import { BLOB_PREFIX } from "./encoding";
import type { Env } from "./types";

const MIME_TYPES: Record<string, string> = {
  txt: "text/plain",
  html: "text/html",
  htm: "text/html",
  css: "text/css",
  js: "text/javascript",
  mjs: "text/javascript",
  json: "application/json",
  xml: "application/xml",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  svg: "image/svg+xml",
  ico: "image/x-icon",
  pdf: "application/pdf",
  doc: "application/msword",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xls: "application/vnd.ms-excel",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ppt: "application/vnd.ms-powerpoint",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  zip: "application/zip",
  rar: "application/x-rar-compressed",
  "7z": "application/x-7z-compressed",
  gz: "application/gzip",
  tar: "application/x-tar",
  mp3: "audio/mpeg",
  wav: "audio/wav",
  ogg: "audio/ogg",
  flac: "audio/flac",
  mp4: "video/mp4",
  webm: "video/webm",
  avi: "video/x-msvideo",
  mov: "video/quicktime",
  mkv: "video/x-matroska",
};

const PUBLIC_CACHE_HEADERS: Record<string, string> = {
  "Cache-Control": "public, max-age=86400, s-maxage=86400",
  "CDN-Cache-Control": "public, max-age=86400",
};

export function getMimeType(filename: string): string {
  const dot = filename.lastIndexOf(".");
  if (dot === -1) return "application/octet-stream";
  const ext = filename.slice(dot + 1).toLowerCase();
  return MIME_TYPES[ext] || "application/octet-stream";
}

/**
 * Parse an HTTP Range header. Returns:
 *   null            - no Range header
 *   {offset, end, length}  - valid range
 *   "invalid"       - syntactically wrong or out-of-bounds
 */
export function parseRangeHeader(
  rangeHeader: string | null,
  size: number,
):
  | { offset: number; end: number; length: number }
  | "invalid"
  | null {
  if (!rangeHeader) return null;
  const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
  if (!match) return "invalid";
  const startStr = match[1] as string;
  const endStr = match[2] as string;
  let start: number;
  let end: number;
  if (startStr === "") {
    const suffixLength = Number(endStr);
    if (!Number.isFinite(suffixLength) || suffixLength <= 0) return "invalid";
    start = Math.max(size - suffixLength, 0);
    end = size - 1;
  } else {
    start = Number(startStr);
    end = endStr === "" ? size - 1 : Number(endStr);
  }
  if (
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    start < 0 ||
    end < start ||
    start >= size
  ) {
    return "invalid";
  }
  end = Math.min(end, size - 1);
  return { offset: start, end, length: end - start + 1 };
}

/**
 * Resolve a visible key to the actual blob to stream. Returns the R2 object
 * + the key to read it from, or null if the visible pointer is missing.
 */
export async function resolveDownloadObject(
  env: Env,
  key: string,
): Promise<{ object: R2Object; downloadKey: string } | null> {
  const obj = await env.FILES_BUCKET.head(key);
  if (!obj) return null;
  const sha256 = obj.customMetadata?.sha256;
  if (!sha256) return { object: obj, downloadKey: key };
  const blob = await env.FILES_BUCKET.head(BLOB_PREFIX + sha256);
  if (!blob) {
    // Blob missing for a dedup pointer — surface as not-found rather than
    // returning a half-broken download. The KV invariant is broken; this
    // is a server error condition, but we still want a clean 404 here.
    const ref = await getRefCount(env, sha256);
    if (!ref) return null;
    return null;
  }
  return { object: blob, downloadKey: BLOB_PREFIX + sha256 };
}

/** Build a 200/206 download response for an R2 object. */
export async function r2DownloadResponse(
  request: Request,
  env: Env,
  key: string,
  filename: string,
): Promise<Response> {
  const resolved = await resolveDownloadObject(env, key);
  if (!resolved) return errorResponse(env, "文件不存在或已被删除", 404);
  const { object, downloadKey } = resolved;

  const range = parseRangeHeader(request.headers.get("Range"), object.size);
  if (range === "invalid") {
    return new Response(null, {
      status: 416,
      headers: {
        "Content-Range": `bytes */${object.size}`,
      },
    });
  }

  const body = await env.FILES_BUCKET.get(
    downloadKey,
    range ? { range: { offset: range.offset, length: range.length } } : undefined,
  );
  if (!body) return errorResponse(env, "文件不存在或已被删除", 404);

  const headers = new Headers();
  headers.set(
    "Content-Type",
    object.httpMetadata?.contentType || getMimeType(filename),
  );
  headers.set(
    "Content-Disposition",
    `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`,
  );
  headers.set("Accept-Ranges", "bytes");
  for (const [k, v] of Object.entries(PUBLIC_CACHE_HEADERS)) headers.set(k, v);
  if (object.httpEtag) headers.set("ETag", object.httpEtag);
  object.writeHttpMetadata(headers);
  headers.set("Content-Length", String(range ? range.length : object.size));
  if (range) {
    headers.set("Content-Range", `bytes ${range.offset}-${range.end}/${object.size}`);
  }

  return new Response(body.body, {
    status: range ? 206 : 200,
    headers,
  });
}
