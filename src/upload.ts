/**
 * Upload handlers: single-shot upload, dedup pointer creation,
 * chunked multipart init/part/complete/abort.
 *
 * Large files (>40 MiB by default) use R2 multipart uploads. The browser
 * hashes the file in a streaming SHA-256 first, asks the server whether
 * the content is already known (dedup), then either creates a pointer or
 * streams the chunks. The server enforces that the chunks' final
 * `key` matches `BLOB_PREFIX + sha256`.
 */

import { errorResponse, jsonResponse } from "./responses";
import {
  getRefCount,
  incrementRefCount,
  putDedupPointer,
} from "./storage";
import { buildR2Key, isValidSha256, BLOB_PREFIX } from "./encoding";
import {
  BadRequestError,
  toNonNegativeInt,
  validateName,
} from "./validation";
import { getMimeType } from "./download";
import type { Env, Sha256 } from "./types";

const MAX_CHUNK_PARTS = 10_000;

/** Get all File entries for a field from FormData. The Workers FormData
 * type declares getAll() as string[], but at runtime values may be File.
 * The `unknown` intermediate type forces the caller to narrow. */
function getFormFiles(form: FormData, name: string): File[] {
  const out: File[] = [];
  for (const v of form.getAll(name) as unknown[]) {
    if (typeof v === "object" && v !== null && "name" in v && "size" in v) {
      out.push(v as File);
    }
  }
  return out;
}

export async function handleUpload(request: Request, env: Env): Promise<Response> {
  const form = await request.formData();
  const folder = String(form.get("folder") || "");
  const files = getFormFiles(form, "files");
  if (files.length === 0) return errorResponse(env, "没有选择文件", 400);
  if (files.length !== 1) return errorResponse(env, "每次上传只能包含一个文件", 400);

  const file = files[0]!;
  validateName(file.name, "file");
  const sha256Raw = form.get("sha256");
  if (typeof sha256Raw !== "string" || !isValidSha256(sha256Raw)) {
    throw new BadRequestError("缺少或无效的 sha256");
  }
  const sha256 = sha256Raw as Sha256;
  const contentType = file.type || getMimeType(file.name);
  const key = buildR2Key(folder, file.name);

  const existing = await getRefCount(env, sha256);
  if (existing) {
    const created = await putDedupPointer(env, key, sha256, file.size, contentType);
    return jsonResponse(env, {
      success: true,
      files: [
        {
          name: file.name,
          folder,
          size: file.size,
          key,
          dedup: true,
          refCount: existing.refCount + (created ? 1 : 0),
        },
      ],
    });
  }

  await env.FILES_BUCKET.put(BLOB_PREFIX + sha256, file.stream(), {
    httpMetadata: { contentType },
  });
  await incrementRefCount(env, sha256, file.size, contentType);
  await env.FILES_BUCKET.put(key, new Uint8Array(0), {
    customMetadata: { sha256 },
    httpMetadata: { contentType },
  });
  return jsonResponse(env, {
    success: true,
    files: [{ name: file.name, folder, size: file.size, key, refCount: 1 }],
  });
}

export async function handleDedupUpload(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = (await request.json()) as {
    folder?: string;
    filename?: string;
    sha256?: string;
    size?: number;
    contentType?: string;
  };
  const filename = body.filename;
  if (!filename) throw new BadRequestError("缺少 filename");
  validateName(filename, "file");
  if (!isValidSha256(body.sha256)) throw new BadRequestError("缺少或无效的 sha256");
  const sha256 = body.sha256 as Sha256;
  const existing = await getRefCount(env, sha256);
  if (!existing) {
    return jsonResponse(env, { success: true, exists: false });
  }
  const folder = body.folder || "";
  const key = buildR2Key(folder, filename);
  const contentType = body.contentType || existing.contentType || getMimeType(filename);
  const size = toNonNegativeInt(body.size ?? existing.size, "size");
  const created = await putDedupPointer(env, key, sha256, size, contentType);
  return jsonResponse(env, {
    success: true,
    exists: true,
    dedup: true,
    file: {
      name: filename,
      folder,
      size: size || existing.size,
      key,
      dedup: true,
      refCount: existing.refCount + (created ? 1 : 0),
    },
  });
}

export async function handleChunkedInit(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = (await request.json()) as {
    folder?: string;
    filename?: string;
    contentType?: string;
    sha256?: string;
  };
  if (!body.filename) throw new BadRequestError("缺少 filename");
  validateName(body.filename, "file");
  if (!isValidSha256(body.sha256)) throw new BadRequestError("缺少或无效的 sha256");
  const sha256 = body.sha256 as Sha256;
  const folder = body.folder || "";
  const key = buildR2Key(folder, body.filename);
  const blobKey = BLOB_PREFIX + sha256;

  const existing = await getRefCount(env, sha256);
  if (existing) {
    return jsonResponse(env, { exists: true, key: blobKey, targetKey: key });
  }
  const options = {
    httpMetadata: {
      contentType: body.contentType || getMimeType(body.filename),
    },
  };
  const upload = await env.FILES_BUCKET.createMultipartUpload(blobKey, options);
  return jsonResponse(env, { uploadId: upload.uploadId, key: blobKey, targetKey: key });
}

export async function handleChunkedPart(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const uploadId = url.searchParams.get("uploadId");
  const key = url.searchParams.get("key");
  const partNumberRaw = url.searchParams.get("partNumber");
  if (!uploadId || !key || !partNumberRaw || !request.body) {
    throw new BadRequestError(
      "缺少必要参数 (uploadId, key, partNumber, chunk)",
    );
  }
  const partNumber = Number(partNumberRaw);
  if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > MAX_CHUNK_PARTS) {
    throw new BadRequestError("无效的分片序号");
  }
  if (!key.startsWith(BLOB_PREFIX)) {
    throw new BadRequestError("分片 key 必须指向 blob 存储");
  }
  const upload = env.FILES_BUCKET.resumeMultipartUpload(key, uploadId);
  const uploaded = await upload.uploadPart(partNumber, request.body);
  return jsonResponse(env, { partNumber, etag: uploaded.etag });
}

export async function handleChunkedComplete(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = (await request.json()) as {
    uploadId?: string;
    key?: string;
    targetKey?: string;
    parts?: { partNumber: number; etag: string }[];
    sha256?: string;
    size?: number;
    contentType?: string;
  };
  if (
    !body.uploadId ||
    !body.key ||
    !Array.isArray(body.parts) ||
    body.parts.length === 0
  ) {
    throw new BadRequestError("缺少必要参数 (uploadId, key, parts)");
  }
  if (!isValidSha256(body.sha256) || !body.targetKey) {
    throw new BadRequestError("分片上传参数无效");
  }
  if (body.key !== BLOB_PREFIX + body.sha256.toLowerCase()) {
    throw new BadRequestError("分片 key 与 sha256 不匹配");
  }
  const normalized = body.parts
    .map((p) => ({ partNumber: Number(p.partNumber), etag: String(p.etag) }))
    .filter((p) => Number.isInteger(p.partNumber) && p.partNumber > 0 && p.etag)
    .sort((a, b) => a.partNumber - b.partNumber);
  if (normalized.length !== body.parts.length) {
    throw new BadRequestError("分片列表无效");
  }
  const upload = env.FILES_BUCKET.resumeMultipartUpload(body.key, body.uploadId);
  await upload.complete(normalized);
  const contentType = body.contentType || getMimeType(body.targetKey);
  const size = toNonNegativeInt(body.size ?? 0, "size");
  await putDedupPointer(env, body.targetKey, body.sha256 as Sha256, size, contentType);
  return jsonResponse(env, { success: true, key: body.targetKey });
}

export async function handleChunkedAbort(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = (await request.json()) as { uploadId?: string; key?: string };
  if (!body.uploadId || !body.key) throw new BadRequestError("缺少必要参数");
  if (!body.key.startsWith(BLOB_PREFIX)) {
    throw new BadRequestError("分片 key 必须指向 blob 存储");
  }
  const upload = env.FILES_BUCKET.resumeMultipartUpload(body.key, body.uploadId);
  await upload.abort();
  return jsonResponse(env, { success: true });
}
