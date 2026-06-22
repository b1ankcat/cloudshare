/**
 * Share metadata CRUD: create, fetch, update, delete, password verify.
 *
 * Share records are stored in KV as `share:<uuid>`. Passwords are PBKDF2
 * hashed with 100k iterations. The expiresAt is an ISO 8601 string or null.
 */

import {
  hashPassword,
  verifyPasswordAsync,
} from "./crypto";
import {
  getVisibleFileInfo,
  listAllKVKeys,
  listAllR2,
} from "./storage";
import { errorResponse, jsonResponse, notFoundResponse } from "./responses";
import { isInternalR2Key, normalizeFolderPath, normalizeObjectKey } from "./encoding";
import { BadRequestError, toNonNegativeInt } from "./validation";
import type { Env, PublicShareData, ShareData, Sha256 } from "./types";

const SHARE_KEY_PREFIX = "share:";
const SHARE_LIST_PREFIX = "share:";

export function shareKey(token: string): string {
  return SHARE_KEY_PREFIX + token;
}

export function isShareExpired(share: ShareData): boolean {
  if (!share.expiresAt) return false;
  return new Date(share.expiresAt).getTime() < Date.now();
}

export function publicShareData(share: ShareData): PublicShareData {
  const { passwordHash, ...safe } = share;
  return { ...safe, hasPassword: passwordHash !== null };
}

/**
 * Check whether a request can access a password-protected share. The pw
 * is taken from the `?pw=` query param (used by the "share-with-password
 * link" feature) or the `x-share-password` header.
 */
export async function isSharePasswordAllowed(
  request: Request,
  share: ShareData,
): Promise<boolean> {
  if (!share.passwordHash) return true;
  const url = new URL(request.url);
  const fromQuery = url.searchParams.get("pw");
  const fromHeader = request.headers.get("x-share-password");
  const password = fromQuery || fromHeader || "";
  if (!password) return false;
  return await verifyPasswordAsync(password, share.passwordHash);
}

export async function getShare(env: Env, token: string): Promise<ShareData | null> {
  const data = await env.cloudshare_shares.get<ShareData>(shareKey(token), "json");
  return data || null;
}

export async function createShare(
  env: Env,
  args: {
    type: "file" | "folder";
    path: string;
    name: string;
    password: string | null;
    expiresIn: number | null;
  },
): Promise<ShareData> {
  const token = crypto.randomUUID();
  const now = new Date();
  const data: ShareData = {
    token,
    type: args.type,
    path: args.path,
    name: args.name,
    createdAt: now.toISOString(),
    expiresAt:
      args.expiresIn !== null
        ? new Date(now.getTime() + args.expiresIn * 1000).toISOString()
        : null,
    passwordHash: args.password ? await hashPassword(args.password) : null,
  };
  await env.cloudshare_shares.put(shareKey(token), JSON.stringify(data));
  return data;
}

export async function deleteShare(env: Env, token: string): Promise<void> {
  await env.cloudshare_shares.delete(shareKey(token));
}

export async function updateShare(
  env: Env,
  token: string,
  action: "extend" | "password" | "cancel",
  payload: { expiresIn?: number | null; password?: string | null },
): Promise<ShareData | null> {
  const existing = await getShare(env, token);
  if (!existing) return null;
  switch (action) {
    case "extend": {
      const now = new Date();
      existing.expiresAt =
        payload.expiresIn !== undefined && payload.expiresIn !== null
          ? new Date(now.getTime() + payload.expiresIn * 1000).toISOString()
          : null;
      break;
    }
    case "password": {
      existing.passwordHash = payload.password
        ? await hashPassword(payload.password)
        : null;
      break;
    }
    case "cancel":
      await deleteShare(env, token);
      return null;
  }
  await env.cloudshare_shares.put(shareKey(token), JSON.stringify(existing));
  return existing;
}

/**
 * Fetch the share with its visible files. Public function used by both the
 * public GET /api/share/:token endpoint and the admin GET.
 */
export async function getShareWithFiles(
  request: Request,
  env: Env,
  share: ShareData,
): Promise<{
  share: PublicShareData;
  files: { name: string; size: number; key: string }[];
  passwordRequired: boolean;
  expired: boolean;
}> {
  const expired = isShareExpired(share);
  const passwordAllowed = await isSharePasswordAllowed(request, share);
  const files: { name: string; size: number; key: string }[] = [];

  if (!expired && passwordAllowed) {
    if (share.type === "folder") {
      const folderPath = normalizeFolderPath(share.path);
      const prefix = folderPath ? `${folderPath}/` : "";
      const listed = await listAllR2(env, { prefix });
      const visible: { key: string; name: string }[] = [];
      for (const obj of listed.objects) {
        if (isInternalR2Key(obj.key)) continue;
        const fileName = obj.key.slice(prefix.length);
        if (!fileName) continue;
        visible.push({ key: obj.key, name: decodeURIComponent(fileName) });
      }
      for (const v of visible) {
        const info = await getVisibleFileInfo(env, v.key, v.name);
        if (info) files.push({ name: info.name, size: info.size, key: info.key });
      }
    } else {
      const obj = await getVisibleFileInfo(
        env,
        normalizeObjectKey(share.path),
        share.name,
      );
      if (obj) files.push({ name: obj.name, size: obj.size, key: obj.key });
    }
  }

  const safe = publicShareData(share);
  const passwordRequired = !!share.passwordHash && !passwordAllowed;
  if (passwordRequired) safe.path = "";
  return { share: safe, files, passwordRequired, expired };
}

/** List all share tokens (admin only — caller is responsible for auth). */
export async function listAllShares(env: Env): Promise<PublicShareData[]> {
  const keys = await listAllKVKeys(env, SHARE_LIST_PREFIX);
  const out: PublicShareData[] = [];
  for (const k of keys) {
    const data = await env.cloudshare_shares.get<ShareData>(k.name, "json");
    if (data) out.push(publicShareData(data));
  }
  return out;
}

/**
 * Delete every share that points to `key` (file delete) or whose path
 * starts with `folder/` (folder delete). Admin auth is the caller's job.
 */
export async function deleteSharesPointingAt(
  env: Env,
  predicate: (share: ShareData) => boolean,
): Promise<void> {
  const keys = await listAllKVKeys(env, SHARE_LIST_PREFIX);
  for (const k of keys) {
    const data = await env.cloudshare_shares.get<ShareData>(k.name, "json");
    if (data && predicate(data)) {
      await env.cloudshare_shares.delete(k.name);
    }
  }
}
