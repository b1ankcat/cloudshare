/**
 * R2 storage layer: content-addressed dedup + ref count lifecycle.
 *
 * Storage model:
 *   __blob__/<sha256>           the actual bytes (one per unique content)
 *   <folder>/<filename>         a 0-byte pointer object whose
 *                               customMetadata.sha256 names the blob
 *   fhash:<sha256>  (in KV)     refCount + size + contentType
 *
 * Invariants:
 *   - For every visible pointer P with sha256 S, KV[fhash:S].refCount >= 1
 *     and R2[__blob__/S] exists.
 *   - When refCount drops to 0, the blob is deleted.
 *   - The current refCount in KV is the source of truth; R2 is only
 *     scanned when deleting a blob to confirm no pointer still references
 *     it (this is a safety check, not a fallback — see countObjectRefs).
 */

import { BLOB_PREFIX } from "./encoding";
import type { Env, RefCountEntry, Sha256 } from "./types";

const REFCOUNT_KEY_PREFIX = "fhash:";
const R2_LIST_PAGE_SIZE = 1000;

/** Read a refCount entry + blob existence. Returns null if blob doesn't exist. */
export async function getRefCount(
  env: Env,
  hash: Sha256,
): Promise<RefCountEntry | null> {
  const entry = await env.cloudshare_shares.get<RefCountEntry>(
    `${REFCOUNT_KEY_PREFIX}${hash}`,
    "json",
  );
  const blob = await env.FILES_BUCKET.head(BLOB_PREFIX + hash);
  if (!blob) return null;
  return {
    refCount: Number(entry?.refCount) || 0,
    size: Number(entry?.size) || blob.size,
    contentType:
      entry?.contentType || blob.httpMetadata?.contentType || "application/octet-stream",
  };
}

/**
 * Scan R2 for all pointer objects that reference `hash`. Used only as a
 * safety check when refCount is about to hit 0, to make sure we don't
 * delete a blob while a pointer still exists (e.g. KV record lost but
 * pointer object still there).
 */
export async function countObjectRefs(
  env: Env,
  hash: Sha256,
  excludeKey = "",
): Promise<number> {
  let count = 0;
  let cursor: string | undefined;
  do {
    const listed = await env.FILES_BUCKET.list({ cursor });
    const candidates = listed.objects.filter(
      (o) =>
        o.key !== excludeKey &&
        !o.key.startsWith(BLOB_PREFIX) &&
        o.key !== ".folder" &&
        !o.key.endsWith("/.folder") &&
        o.size === 0,
    );
    for (const obj of candidates) {
      const head = await env.FILES_BUCKET.head(obj.key);
      if (head?.customMetadata?.sha256 === hash) count++;
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);
  return count;
}

/** Atomically increment the ref count. Returns the new count. */
export async function incrementRefCount(
  env: Env,
  hash: Sha256,
  size: number,
  contentType: string,
): Promise<number> {
  const key = `${REFCOUNT_KEY_PREFIX}${hash}`;
  const existing = await env.cloudshare_shares.get<RefCountEntry>(key, "json");
  const next = (Number(existing?.refCount) || 0) + 1;
  const merged: RefCountEntry = {
    refCount: next,
    size: Number(size) || Number(existing?.size) || 0,
    contentType: contentType || existing?.contentType || "application/octet-stream",
  };
  await env.cloudshare_shares.put(key, JSON.stringify(merged));
  return next;
}

/**
 * Decrement the ref count. If it would drop to 0, first scan R2 to confirm
 * no pointer still references `hash`; only then delete the blob.
 * Returns the new count.
 */
export async function decrementRefCount(
  env: Env,
  hash: Sha256,
  excludeKey: string,
  contentType: string,
): Promise<number> {
  const key = `${REFCOUNT_KEY_PREFIX}${hash}`;
  const existing = await env.cloudshare_shares.get<RefCountEntry>(key, "json");
  if (!existing) {
    throw new Error(`Missing refCount record for hash: ${hash}`);
  }
  const next = Number(existing.refCount) - 1;
  if (next > 0) {
    await env.cloudshare_shares.put(key, JSON.stringify({ ...existing, refCount: next }));
    return next;
  }
  // Would hit 0 — verify with a full R2 scan before deleting the blob.
  const actualRefs = await countObjectRefs(env, hash, excludeKey);
  if (actualRefs > 0) {
    await env.cloudshare_shares.put(
      key,
      JSON.stringify({
        ...existing,
        refCount: actualRefs,
        contentType: existing.contentType || contentType,
      }),
    );
    return actualRefs;
  }
  await env.cloudshare_shares.delete(key);
  await env.FILES_BUCKET.delete(BLOB_PREFIX + hash);
  return 0;
}

/**
 * Release a pointer's ref on its blob. If the ref drops to 0, the blob is
 * deleted by `decrementRefCount`. Returns the sha256 that was released, or
 * null if the key was not a dedup pointer.
 */
export async function releaseObjectRef(env: Env, key: string): Promise<Sha256 | null> {
  const obj = await env.FILES_BUCKET.head(key);
  if (!obj) return null;
  const sha256 = obj.customMetadata?.sha256 as Sha256 | undefined;
  if (!sha256) return null;
  const remaining = await decrementRefCount(
    env,
    sha256,
    key,
    obj.httpMetadata?.contentType || "application/octet-stream",
  );
  if (remaining === 0) {
    await env.FILES_BUCKET.delete(BLOB_PREFIX + sha256);
  }
  return sha256;
}

/**
 * Make `key` a dedup pointer to (sha256, size, contentType). If the key
 * already points to a different sha256, the old ref is released first.
 * Returns true if the pointer was created or updated; false if it already
 * pointed to the same sha256 (no-op).
 */
export async function putDedupPointer(
  env: Env,
  key: string,
  sha256: Sha256,
  size: number,
  contentType: string,
): Promise<boolean> {
  const existing = await env.FILES_BUCKET.head(key);
  const existingSha = existing?.customMetadata?.sha256 as Sha256 | undefined;
  if (existingSha === sha256) return false;
  if (existingSha) {
    await releaseObjectRef(env, key);
  }
  await env.FILES_BUCKET.put(key, new Uint8Array(0), {
    customMetadata: { sha256 },
    httpMetadata: { contentType },
  });
  await incrementRefCount(env, sha256, size, contentType);
  return true;
}

/**
 * Resolve a visible file key to {name, size, key}. Throws if the pointer
 * has a sha256 but no corresponding blob (invariant violation).
 */
export async function getVisibleFileInfo(
  env: Env,
  key: string,
  name: string,
): Promise<{ name: string; size: number; key: string } | null> {
  const obj = await env.FILES_BUCKET.head(key);
  if (!obj) return null;
  const sha256 = obj.customMetadata?.sha256 as Sha256 | undefined;
  if (!sha256) {
    return { name, size: obj.size, key };
  }
  const ref = await getRefCount(env, sha256);
  if (!ref) {
    throw new Error(`Dedup blob missing for file: ${key}`);
  }
  return { name, size: ref.size, key };
}

/** Page through every object in R2 (no prefix filter). */
export async function listAllR2(
  env: Env,
  options: R2ListOptions = {},
): Promise<{ objects: R2Object[]; delimitedPrefixes: string[] }> {
  const objects: R2Object[] = [];
  const prefixes: string[] = [];
  let cursor: string | undefined;
  do {
    const listed = await env.FILES_BUCKET.list({ ...options, cursor });
    objects.push(...listed.objects);
    if (listed.delimitedPrefixes) prefixes.push(...listed.delimitedPrefixes);
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);
  return { objects, delimitedPrefixes: prefixes };
}

/** Page through every KV key with a given prefix. */
export async function listAllKVKeys(
  env: Env,
  prefix: string,
): Promise<{ name: string }[]> {
  const out: { name: string }[] = [];
  let cursor: string | undefined;
  do {
    const listed = await env.cloudshare_shares.list({ prefix, cursor });
    out.push(...listed.keys);
    if (listed.list_complete) break;
    cursor = listed.cursor;
  } while (cursor);
  return out;
}

export const STORAGE_R2_LIST_PAGE_SIZE = R2_LIST_PAGE_SIZE;
