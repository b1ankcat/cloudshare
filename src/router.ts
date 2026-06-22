/**
 * Top-level fetch router. Each branch is a small dispatcher; complex logic
 * lives in dedicated modules (auth, files, share, upload, download).
 *
 * Error handling: handlers throw BadRequestError / ValidationError for
 * client errors (translated to 4xx by the wrapper below) and any other
 * error becomes a 500. The error message returned to the client is the
 * thrown error's message — handlers are responsible for not leaking
 * internal detail in their messages.
 */

import {
  ADMIN_SESSION_COOKIE,
  buildAdminCookie,
  createAdminSession,
  getAdminSessionSecret,
  isAdminRoute,
  parseCookies,
  requireAdmin,
  safeNextPath,
  verifyAdmin,
  verifyAdminCredential,
  clearLoginFailures,
  getLoginFailures,
  recordLoginFailure,
  LOGIN_RATE_LIMIT_MAX_FAILURES,
  LOGIN_RATE_LIMIT_WINDOW,
} from "./auth";
import {
  errorResponse,
  htmlResponse,
  jsonResponse,
  notFoundResponse,
  preflightResponse,
  publicHtmlResponse,
  redirectResponse,
} from "./responses";
import { handleCreateFolder, handleDeleteFile, handleDeleteFolder, handleListFiles } from "./files";
import {
  createShare,
  deleteShare,
  getShare,
  getShareWithFiles,
  isShareExpired,
  isSharePasswordAllowed,
  listAllShares,
  publicShareData,
  updateShare,
} from "./share";
import { r2DownloadResponse } from "./download";
import { verifyPasswordAsync } from "./crypto";
import {
  handleChunkedAbort,
  handleChunkedComplete,
  handleChunkedInit,
  handleChunkedPart,
  handleDedupUpload,
  handleUpload,
} from "./upload";
import { isValidUuid } from "./validation";
import { normalizeFolderPath, normalizeObjectKey } from "./encoding";
import { BadRequestError, ValidationError } from "./validation";
import { loginPageHTML } from "./pages/login";
import { managePageHTML } from "./pages/manage";
import { mainPageHTML } from "./pages/main";
import { notFoundHTML } from "./pages/not-found";
import { sharePageHTML } from "./pages/share";
import type { Env, Sha256 } from "./types";

const SHARE_KEY_PREFIX = "share:";

async function handleLogin(request: Request, env: Env): Promise<Response> {
  if (!getAdminSessionSecret(env)) {
    return htmlResponse(env, loginPageHTML(env, "/", "ADMIN_PASSWORD 未配置"), 500);
  }
  const failures = await getLoginFailures(request, env);
  if (failures.count >= LOGIN_RATE_LIMIT_MAX_FAILURES) {
    return htmlResponse(
      env,
      loginPageHTML(env, "/", "登录失败次数过多，请 10 分钟后再试"),
      429,
    );
  }
  const contentType = request.headers.get("Content-Type") || "";
  let credential = "";
  let next = "/";
  if (contentType.includes("application/json")) {
    const body = (await request.json()) as { password?: string; credential?: string; next?: string };
    credential = String(body.password || body.credential || "");
    next = String(body.next || "/");
  } else {
    const form = await request.formData();
    credential = String(form.get("credential") || form.get("password") || "");
    next = String(form.get("next") || "/");
  }
  const safeNext = safeNextPath(next);
  if (!verifyAdminCredential(credential, env)) {
    await recordLoginFailure(request, env);
    return htmlResponse(env, loginPageHTML(env, safeNext, "凭据错误，请重试"), 401);
  }
  await clearLoginFailures(request, env);
  const session = await createAdminSession(env);
  if (!session) {
    return htmlResponse(env, loginPageHTML(env, "/", "ADMIN_PASSWORD 未配置"), 500);
  }
  return redirectResponse(env, safeNext, 303, {
    "Set-Cookie": buildAdminCookie(request, session),
  });
}

function handleLogout(request: Request, env: Env): Response {
  return redirectResponse(env, "/login", 303, {
    "Set-Cookie": buildAdminCookie(request, "", 0),
  });
}

async function serveLoginPage(request: Request, env: Env): Promise<Response> {
  if (!getAdminSessionSecret(env)) {
    return htmlResponse(env, loginPageHTML(env, "/", "ADMIN_PASSWORD 未配置"), 500);
  }
  if (await verifyAdmin(request, env)) {
    return redirectResponse(env, "/");
  }
  const url = new URL(request.url);
  const next = safeNextPath(url.searchParams.get("next") || "/");
  const error = url.searchParams.get("error") ? "凭据错误，请重试" : "";
  return htmlResponse(env, loginPageHTML(env, next, error));
}

async function serveSharePage(env: Env, token: string): Promise<Response> {
  if (!isValidUuid(token)) {
    return htmlResponse(env, notFoundHTML("无效的分享链接"), 404);
  }
  const share = await getShare(env, token);
  if (!share) {
    return htmlResponse(env, notFoundHTML(), 404);
  }
  return publicHtmlResponse(env, sharePageHTML(token));
}

async function handleShareGet(
  request: Request,
  env: Env,
  token: string,
): Promise<Response> {
  if (!isValidUuid(token)) return notFoundResponse(env, "无效的分享");
  const share = await getShare(env, token);
  if (!share) return notFoundResponse(env, "分享不存在或已过期");
  const payload = await getShareWithFiles(request, env, share);
  return jsonResponse(env, { ...payload.share, passwordRequired: payload.passwordRequired, expired: payload.expired, files: payload.files });
}

async function handleShareCreate(request: Request, env: Env): Promise<Response> {
  const body = (await request.json()) as {
    type?: string;
    path?: string;
    name?: string;
    password?: string;
    expiresIn?: number | string;
  };
  if (!body.type || !body.path || !body.name) {
    throw new BadRequestError("缺少必要参数 (type, path, name)");
  }
  if (body.type !== "file" && body.type !== "folder") {
    throw new BadRequestError("type 必须是 file 或 folder");
  }
  const expiresIn =
    body.expiresIn === undefined || body.expiresIn === null
      ? null
      : Number(body.expiresIn);
  if (expiresIn !== null && (!Number.isFinite(expiresIn) || expiresIn < 0)) {
    throw new BadRequestError("expiresIn 必须是正数或 null");
  }
  const data = await createShare(env, {
    type: body.type,
    path: body.path,
    name: body.name,
    password: body.password ? String(body.password) : null,
    expiresIn,
  });
  return jsonResponse(env, {
    success: true,
    share: publicShareData(data),
    url: `${new URL(request.url).origin}/s/${data.token}`,
  });
}

async function handleShareUpdate(
  request: Request,
  env: Env,
  token: string,
): Promise<Response> {
  if (!isValidUuid(token)) return notFoundResponse(env, "无效的分享");
  const body = (await request.json()) as {
    action?: string;
    expiresIn?: number | string | null;
    password?: string | null;
  };
  if (body.action !== "extend" && body.action !== "password" && body.action !== "cancel") {
    throw new BadRequestError("无效的 action");
  }
  const payload: { expiresIn?: number | null; password?: string | null } = {};
  if (body.action === "extend") {
    payload.expiresIn = body.expiresIn === undefined || body.expiresIn === null
      ? null
      : Number(body.expiresIn);
    if (payload.expiresIn !== null && (!Number.isFinite(payload.expiresIn) || payload.expiresIn < 0)) {
      throw new BadRequestError("expiresIn 必须是正数或 null");
    }
  } else if (body.action === "password") {
    payload.password = body.password ? String(body.password) : null;
  }
  const updated = await updateShare(env, token, body.action, payload);
  if (body.action === "cancel" || !updated) {
    return jsonResponse(env, { success: true });
  }
  return jsonResponse(env, { success: true, share: publicShareData(updated) });
}

async function handleShareVerify(
  request: Request,
  env: Env,
  token: string,
): Promise<Response> {
  if (!isValidUuid(token)) return notFoundResponse(env, "无效的分享");
  const share = await getShare(env, token);
  if (!share) return notFoundResponse(env, "分享不存在或已过期");
  if (isShareExpired(share)) {
    return jsonResponse(env, { valid: false, expired: true });
  }
  if (!share.passwordHash) {
    return jsonResponse(env, { valid: true, needPassword: false });
  }
  const body = (await request.json()) as { password?: string };
  if (!body.password) {
    return jsonResponse(env, { valid: false, needPassword: true });
  }
  const valid = await verifyPasswordAsync(String(body.password), share.passwordHash);
  return jsonResponse(env, { valid, needPassword: true });
}

async function handleShareDelete(
  env: Env,
  token: string,
): Promise<Response> {
  if (!isValidUuid(token)) return notFoundResponse(env, "无效的分享");
  await deleteShare(env, token);
  return jsonResponse(env, { success: true });
}

async function handleShareList(env: Env): Promise<Response> {
  const shares = await listAllShares(env);
  return jsonResponse(env, { shares });
}

async function handleDownload(
  request: Request,
  env: Env,
  token: string,
  filename: string | null,
): Promise<Response> {
  if (!isValidUuid(token)) return notFoundResponse(env, "无效的下载链接");
  const share = await getShare(env, token);
  if (!share) return notFoundResponse(env, "分享不存在或已过期");
  if (isShareExpired(share)) return errorResponse(env, "分享已过期", 410);
  if (!(await isSharePasswordAllowed(request, share))) {
    return errorResponse(env, "需要分享密码", 403);
  }
  let objectKey: string;
  let downloadName: string;
  if (share.type === "file") {
    objectKey = normalizeObjectKey(share.path);
    downloadName = share.name;
  } else {
    if (!filename) return errorResponse(env, "请指定要下载的文件名", 400);
    const folderPath = normalizeFolderPath(share.path);
    const prefix = folderPath ? `${folderPath}/` : "";
    objectKey = prefix + normalizeFolderPath(filename);
    downloadName = filename;
  }
  return await r2DownloadResponse(request, env, objectKey, downloadName);
}

async function handleAdminDownload(
  request: Request,
  env: Env,
  folder: string,
  filename: string,
): Promise<Response> {
  const key = `${folder ? folder + "/" : ""}${filename}`;
  return await r2DownloadResponse(request, env, key, filename);
}

/** Translate thrown errors into 4xx / 500 responses. */
function wrapHandler<T extends unknown[]>(
  handler: (...args: T) => Promise<Response>,
): (...args: T) => Promise<Response> {
  return async (...args: T): Promise<Response> => {
    const env = args[1] as Env;
    try {
      return await handler(...args);
    } catch (e) {
      if (e instanceof BadRequestError || e instanceof ValidationError) {
        return errorResponse(env, e.message, 400);
      }
      console.error("handler error:", e);
      return errorResponse(env, "服务器内部错误", 500);
    }
  };
}

const H = wrapHandler;

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const pathname = url.pathname;

  if (request.method === "OPTIONS") {
    return preflightResponse(env);
  }

  try {
    if (request.method === "GET" && pathname === "/login") {
      return await serveLoginPage(request, env);
    }
    if (request.method === "POST" && pathname === "/api/login") {
      return await H(handleLogin)(request, env);
    }
    if ((request.method === "POST" || request.method === "GET") && pathname === "/api/logout") {
      return handleLogout(request, env);
    }

    if (isAdminRoute(request.method, pathname)) {
      const err = await requireAdmin(request, env);
      if (err) return err;
    }

    if (request.method === "GET" && pathname === "/") {
      return htmlResponse(env, mainPageHTML());
    }
    if (request.method === "GET" && pathname === "/manage") {
      return htmlResponse(env, managePageHTML());
    }

    if (request.method === "GET" && pathname.startsWith("/s/")) {
      const token = pathname.slice(3).split("/")[0] || "";
      return await serveSharePage(env, token);
    }

    if (request.method === "GET" && pathname.startsWith("/dl/")) {
      const parts = pathname.slice(4).split("/").filter(Boolean);
      const token = parts[0] || "";
      const filename = parts.length > 1 ? decodeURIComponent(parts.slice(1).join("/")) : null;
      return await handleDownload(request, env, token, filename);
    }

    // ── API routes ──

    if (request.method === "POST" && pathname === "/api/upload") {
      return await H(handleUpload)(request, env);
    }
    if (request.method === "POST" && pathname === "/api/upload/dedup") {
      return await H(handleDedupUpload)(request, env);
    }
    if (request.method === "POST" && pathname === "/api/upload/init") {
      return await H(handleChunkedInit)(request, env);
    }
    if (request.method === "POST" && pathname === "/api/upload/part") {
      return await H(handleChunkedPart)(request, env);
    }
    if (request.method === "POST" && pathname === "/api/upload/complete") {
      return await H(handleChunkedComplete)(request, env);
    }
    if (request.method === "DELETE" && pathname === "/api/upload/abort") {
      return await H(handleChunkedAbort)(request, env);
    }

    if (request.method === "POST" && pathname === "/api/folders") {
      return await H(handleCreateFolder)(request, env);
    }

    if (request.method === "POST" && pathname === "/api/share") {
      return await H(handleShareCreate)(request, env);
    }
    if (request.method === "GET" && pathname === "/api/shares") {
      return await H(handleShareList)(env);
    }
    if (request.method === "POST" && pathname.startsWith("/api/share/") && pathname.endsWith("/verify")) {
      const token = pathname.slice("/api/share/".length, -"/verify".length);
      return await H(handleShareVerify)(request, env, token);
    }
    if (request.method === "PUT" && pathname.startsWith("/api/share/")) {
      const token = pathname.slice("/api/share/".length);
      return await H(handleShareUpdate)(request, env, token);
    }
    if (request.method === "GET" && pathname.startsWith("/api/share/")) {
      const token = pathname.slice("/api/share/".length);
      return await H(handleShareGet)(request, env, token);
    }
    if (request.method === "DELETE" && pathname.startsWith("/api/share/")) {
      const token = pathname.slice("/api/share/".length);
      return await H(handleShareDelete)(env, token);
    }

    if (request.method === "GET" && pathname.startsWith("/api/admin-download/")) {
      const rest = pathname.slice("/api/admin-download/".length);
      const parts = rest.split("/").filter(Boolean);
      if (parts.length === 0) return errorResponse(env, "路径无效", 400);
      const filename = parts[parts.length - 1] as string;
      const folder = parts.slice(0, -1).join("/");
      return await H(handleAdminDownload)(request, env, folder, filename);
    }

    if (request.method === "GET" && pathname === "/api/files") {
      return await H(handleListFiles)(env, null);
    }
    if (request.method === "GET" && pathname.startsWith("/api/files/")) {
      const folder = pathname.slice("/api/files/".length);
      if (!folder) return errorResponse(env, "路径无效", 400);
      return await H(handleListFiles)(env, folder);
    }
    if (request.method === "DELETE" && pathname.startsWith("/api/files/")) {
      const parts = pathname.slice("/api/files/".length).split("/").filter(Boolean);
      if (parts.length < 1) return errorResponse(env, "路径无效", 400);
      const filename = parts[parts.length - 1] as string;
      const folder = parts.slice(0, -1).join("/");
      return await H(handleDeleteFile)(env, folder, filename);
    }
    if (request.method === "DELETE" && pathname.startsWith("/api/folders/")) {
      const folder = pathname.slice("/api/folders/".length);
      if (!folder) return errorResponse(env, "路径无效", 400);
      return await H(handleDeleteFolder)(env, folder);
    }

    // Static HTML catch-all
    if (request.method === "GET" && !pathname.startsWith("/api/")) {
      return htmlResponse(env, notFoundHTML("页面不存在"), 404);
    }
    return errorResponse(env, "Not found", 404);
  } catch (e) {
    if (e instanceof BadRequestError || e instanceof ValidationError) {
      return errorResponse(env, e.message, 400);
    }
    console.error("router error:", e);
    return errorResponse(env, "服务器内部错误", 500);
  }
}
