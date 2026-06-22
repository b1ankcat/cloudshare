/**
 * File system-style operations on top of R2:
 *   - list files / folders in a prefix
 *   - delete a file (releases dedup ref, cancels its shares)
 *   - create / delete a folder
 *
 * Folders are tracked with a 0-byte `.folder` marker object inside the
 * folder's prefix. Subfolders are inferred from delimitedPrefixes plus
 * nested `.folder` markers in the listing.
 */

import { errorResponse, jsonResponse } from "./responses";
import {
  getRefCount,
  getVisibleFileInfo,
  listAllR2,
  releaseObjectRef,
} from "./storage";
import {
  buildR2Key,
  decodeFolderPath,
  isInternalR2Key,
  normalizeFolderPath,
  validateName,
} from "./encoding";
import { deleteSharesPointingAt } from "./share";
import { BadRequestError } from "./validation";
import type { Env, FileEntry, FolderEntry, ListFilesResponse } from "./types";

const FOLDER_MARKER = ".folder";

export async function handleCreateFolder(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = (await request.json()) as { name?: string; currentFolder?: string };
  if (!body.name) throw new BadRequestError("缺少 name");
  validateName(body.name, "folder");
  const currentFolder = normalizeFolderPath(body.currentFolder || "");
  const fullPath = currentFolder ? `${currentFolder}/${body.name}` : body.name;
  const key = buildR2Key(fullPath, FOLDER_MARKER);
  await env.FILES_BUCKET.put(key, new Uint8Array(0));
  return jsonResponse(env, {
    success: true,
    folder: decodeFolderPath(fullPath),
  });
}

export async function handleListFiles(
  env: Env,
  folderParam: string | null,
): Promise<Response> {
  const folder = normalizeFolderPath(folderParam || "");
  const prefix = folder ? `${folder}/` : "";
  const cleanCurrentFolder = decodeFolderPath(folder);

  const listed = await listAllR2(env, { prefix, delimiter: "/" });
  const files: FileEntry[] = [];
  const folders: FolderEntry[] = [];
  const folderSet = new Set<string>();

  for (const obj of listed.objects) {
    if (isInternalR2Key(obj.key)) continue;
    const fileName = obj.key.slice(prefix.length);
    if (fileName === FOLDER_MARKER || !fileName) continue;
    if (fileName.includes("/")) {
      if (fileName.endsWith(`/${FOLDER_MARKER}`)) {
        const top = fileName.split("/")[0] as string;
        if (top && !folderSet.has(top)) {
          folders.push({ name: decodeURIComponent(top), type: "folder" });
          folderSet.add(top);
        }
      }
      continue;
    }
    files.push({
      name: decodeURIComponent(fileName),
      size: obj.size,
      uploaded: obj.uploaded,
      key: obj.key,
      folder: cleanCurrentFolder,
    });
  }

  for (const p of listed.delimitedPrefixes) {
    if (isInternalR2Key(p)) continue;
    const folderName = p.slice(prefix.length, -1);
    if (folderName && !folderSet.has(folderName)) {
      folders.push({ name: decodeURIComponent(folderName), type: "folder" });
      folderSet.add(folderName);
    }
  }

  // Resolve dedup pointer files (size=0) to their real size + refCount.
  for (const f of files) {
    if (f.size === 0) {
      const info = await getVisibleFileInfo(env, f.key, f.name);
      if (!info) {
        throw new Error(`Dedup blob missing for file: ${f.key}`);
      }
      const sha = (await env.FILES_BUCKET.head(f.key))?.customMetadata?.sha256;
      f.size = info.size;
      if (sha) {
        const ref = await getRefCount(env, sha);
        f.refCount = ref?.refCount;
      }
    }
  }

  const response: ListFilesResponse = {
    folder: cleanCurrentFolder,
    files,
    folders,
  };
  return jsonResponse(env, response);
}

export async function handleDeleteFile(
  env: Env,
  folder: string,
  filename: string,
): Promise<Response> {
  validateName(filename, "file");
  const key = buildR2Key(folder, filename);
  await deleteSharesPointingAt(env, (s) => s.type === "file" && s.path === key);
  await releaseObjectRef(env, key);
  await env.FILES_BUCKET.delete(key);
  return jsonResponse(env, { success: true });
}

export async function handleDeleteFolder(
  env: Env,
  folder: string,
): Promise<Response> {
  const cleanFolder = normalizeFolderPath(folder);
  if (!cleanFolder) throw new BadRequestError("不能删除根目录");
  const prefix = `${cleanFolder}/`;
  const keysToDelete: string[] = [];
  let cursor: string | undefined;
  do {
    const listed = await env.FILES_BUCKET.list({ prefix, cursor });
    for (const obj of listed.objects) keysToDelete.push(obj.key);
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);

  for (const key of keysToDelete) {
    await releaseObjectRef(env, key);
  }
  for (let i = 0; i < keysToDelete.length; i += 1000) {
    const batch = keysToDelete.slice(i, i + 1000);
    await env.FILES_BUCKET.delete(batch);
  }

  await deleteSharesPointingAt(
    env,
    (s) =>
      s.path === cleanFolder ||
      normalizeFolderPath(s.path).startsWith(`${cleanFolder}/`),
  );

  return jsonResponse(env, { success: true, deleted: keysToDelete.length });
}
