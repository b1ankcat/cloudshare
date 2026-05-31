// ─── 通用常量 ────────────────────────────────────────────────────────────────
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};
const CACHE_HEADERS = {
  'Cache-Control': 'public, max-age=86400, s-maxage=86400',
  'CDN-Cache-Control': 'public, max-age=86400',
};
const ADMIN_SESSION_COOKIE = 'cloudshare_admin';
const ADMIN_SESSION_MAX_AGE = 7 * 24 * 60 * 60;
const PBKDF2_MIN_ITERATIONS = 90000;
const PBKDF2_ITERATIONS = 100000;
const LOGIN_RATE_LIMIT_WINDOW = 10 * 60;
const LOGIN_RATE_LIMIT_MAX_FAILURES = 5;

// ─── MIME 类型映射 ──────────────────────────────────────────────────────────
const MIME_TYPES = {
  txt: 'text/plain', html: 'text/html', css: 'text/css', js: 'text/javascript',
  json: 'application/json', xml: 'application/xml',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
  webp: 'image/webp', svg: 'image/svg+xml', ico: 'image/x-icon',
  pdf: 'application/pdf', doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  zip: 'application/zip', rar: 'application/x-rar-compressed', '7z': 'application/x-7z-compressed',
  mp3: 'audio/mpeg', wav: 'audio/wav', mp4: 'video/mp4', avi: 'video/x-msvideo',
};

function getMimeType(filename) {
  const ext = filename.split('.').pop()?.toLowerCase();
  return MIME_TYPES[ext] || 'application/octet-stream';
}

// 构建下载响应头 (R2 + CDN 缓存)
function setDownloadHeaders(headers, object, filename) {
  headers.set('Content-Type', object.httpMetadata?.contentType || getMimeType(filename));
  headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
  headers.set('Accept-Ranges', 'bytes');
  for (const [k, v] of Object.entries(CACHE_HEADERS)) headers.set(k, v);
  if (object.httpEtag) headers.set('ETag', object.httpEtag);
  object.writeHttpMetadata(headers);
}

function parseRangeHeader(rangeHeader, size) {
  if (!rangeHeader) return null;
  const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
  if (!match) return 'invalid';

  let start;
  let end;
  if (match[1] === '') {
    const suffixLength = Number(match[2]);
    if (!Number.isFinite(suffixLength) || suffixLength <= 0) return 'invalid';
    start = Math.max(size - suffixLength, 0);
    end = size - 1;
  } else {
    start = Number(match[1]);
    end = match[2] === '' ? size - 1 : Number(match[2]);
  }

  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || start >= size) {
    return 'invalid';
  }

  end = Math.min(end, size - 1);
  return { offset: start, end, length: end - start + 1 };
}

async function resolveDownloadObject(env, key) {
  let object = await env.FILES_BUCKET.head(key);
  if (!object) return null;

  let downloadKey = key;
  const sha256 = object.customMetadata?.sha256;
  if (sha256) {
    const blobKey = BLOB_PREFIX + sha256;
    const blob = await env.FILES_BUCKET.head(blobKey);
    if (!blob) return null;
    object = blob;
    downloadKey = blobKey;
  }

  return { object, downloadKey };
}

async function r2DownloadResponse(request, env, key, filename) {
  const resolved = await resolveDownloadObject(env, key);
  if (!resolved) return errorResponse('文件不存在或已被删除', 404);

  const { object, downloadKey } = resolved;
  const range = parseRangeHeader(request.headers.get('Range'), object.size);
  if (range === 'invalid') {
    return new Response(null, {
      status: 416,
      headers: { 'Content-Range': `bytes */${object.size}`, ...CORS_HEADERS },
    });
  }

  const bodyObject = await env.FILES_BUCKET.get(
    downloadKey,
    range ? { range: { offset: range.offset, length: range.length } } : undefined,
  );
  if (!bodyObject) return errorResponse('文件不存在或已被删除', 404);

  const headers = new Headers();
  setDownloadHeaders(headers, object, filename);
  headers.set('Content-Length', String(range ? range.length : object.size));
  if (range) headers.set('Content-Range', `bytes ${range.offset}-${range.end}/${object.size}`);

  return new Response(bodyObject.body, { status: range ? 206 : 200, headers });
}

// ─── 密码哈希 ────────────────────────────────────────────────────────────────
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derivePbkdf2Hash(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${base64Url(salt)}$${base64Url(hash)}`;
}

async function verifyPasswordAsync(input, storedHash) {
  if (!storedHash?.startsWith('pbkdf2$')) return false;
  const [, iterRaw, saltRaw, hashRaw] = storedHash.split('$');
  const iterations = Number(iterRaw);
  if (!Number.isInteger(iterations) || iterations < PBKDF2_MIN_ITERATIONS || iterations > PBKDF2_ITERATIONS || !saltRaw || !hashRaw) return false;
  const salt = base64UrlDecode(saltRaw);
  const hash = await derivePbkdf2Hash(input, salt, iterations);
  return timingSafeEqual(base64Url(hash), hashRaw);
}

async function derivePbkdf2Hash(password, salt, iterations) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

function base64Url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function isSharePasswordAllowed(request, shareData) {
  if (!shareData.passwordHash) return true;
  const password = new URL(request.url).searchParams.get('pw') || request.headers.get('x-share-password') || '';
  return password ? await verifyPasswordAsync(password, shareData.passwordHash) : false;
}

function isShareExpired(shareData) {
  return shareData.expiresAt ? new Date(shareData.expiresAt) < new Date() : false;
}

function publicShareData(shareData) {
  const { passwordHash, ...safe } = shareData;
  return { ...safe, hasPassword: !!passwordHash };
}

// =============================================================================
// 工具函数
// =============================================================================

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS },
  });
}

function htmlResponse(html, status = 200, extraHeaders = {}) {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', ...extraHeaders },
  });
}

function redirectResponse(location, status = 302, extraHeaders = {}) {
  return new Response(null, {
    status,
    headers: { Location: location, ...extraHeaders },
  });
}

function parseCookies(request) {
  const cookies = {};
  const raw = request.headers.get('Cookie') || '';
  for (const part of raw.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name) cookies[name] = value;
  }
  return cookies;
}

function getAdminSessionSecret(env) {
  return env.ADMIN_PASSWORD || '';
}

function safeNextPath(value) {
  const next = String(value || '/');
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/login') || next.startsWith('/api/login')) {
    return '/';
  }
  return next;
}

function buildAdminCookie(request, value, maxAge = ADMIN_SESSION_MAX_AGE) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `${ADMIN_SESSION_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${secure}`;
}

function getClientIp(request) {
  return request.headers.get('CF-Connecting-IP')
    || (request.headers.get('X-Forwarded-For') || '').split(',')[0].trim()
    || 'unknown';
}

function loginRateLimitKey(request) {
  return `login_fail:${getClientIp(request)}`;
}

async function getLoginFailures(request, env) {
  return await env.cloudshare_shares.get(loginRateLimitKey(request), 'json') || { count: 0 };
}

async function recordLoginFailure(request, env) {
  const key = loginRateLimitKey(request);
  const current = await env.cloudshare_shares.get(key, 'json') || { count: 0 };
  await env.cloudshare_shares.put(key, JSON.stringify({ count: Number(current.count || 0) + 1 }), {
    expirationTtl: LOGIN_RATE_LIMIT_WINDOW,
  });
}

async function clearLoginFailures(request, env) {
  await env.cloudshare_shares.delete(loginRateLimitKey(request));
}

async function signAdminSession(secret, issuedAt) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(String(issuedAt)));
  return base64Url(new Uint8Array(signature));
}

async function createAdminSession(env) {
  const secret = getAdminSessionSecret(env);
  if (!secret) return null;
  const issuedAt = Date.now();
  const signature = await signAdminSession(secret, issuedAt);
  return `${issuedAt}.${signature}`;
}

async function verifyAdminSession(value, env) {
  const secret = getAdminSessionSecret(env);
  if (!secret || !value) return false;
  const [issuedAtRaw, signature] = String(value).split('.');
  const issuedAt = Number(issuedAtRaw);
  const now = Date.now();
  if (!Number.isFinite(issuedAt) || !signature) return false;
  if (issuedAt > now + 5 * 60 * 1000) return false;
  if (now - issuedAt > ADMIN_SESSION_MAX_AGE * 1000) return false;
  const expected = await signAdminSession(secret, issuedAt);
  return timingSafeEqual(signature, expected);
}

function verifyAdmin(request, env) {
  return verifyAdminSession(parseCookies(request)[ADMIN_SESSION_COOKIE], env);
}

function verifyAdminCredential(input, env) {
  const credential = String(input || '');
  const password = getAdminSessionSecret(env);
  return password ? timingSafeEqual(credential, password) : false;
}

async function requireAdmin(request, env) {
  if (await verifyAdmin(request, env)) return null;
  const url = new URL(request.url);
  const next = encodeURIComponent(url.pathname + url.search);
  if (!getAdminSessionSecret(env)) {
    return htmlResponse(loginPageHTML('/', 'ADMIN_PASSWORD 未配置'), 500);
  }
  return redirectResponse(`/login?next=${next}`);
}

function isAdminRoute(method, pathname) {
  if (pathname === '/login' || pathname === '/api/login' || pathname === '/api/logout') return false;
  if (method === 'GET' && (pathname.startsWith('/s/') || pathname.startsWith('/dl/'))) return false;
  if (method === 'GET' && pathname.startsWith('/api/share/')) return false;
  if (method === 'POST' && pathname.startsWith('/api/share/') && pathname.endsWith('/verify')) return false;
  return true;
}

function escapeHtmlText(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function loginPageHTML(next = '/', error = '') {
  const safeNext = escapeHtmlText(safeNextPath(next));
  const safeError = escapeHtmlText(error);
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 - CloudShare</title>
<style>
  :root { --ink:#17211b; --muted:#647067; --line:#d9e1d8; --paper:#fffdf6; --field:#f7f3e8; --accent:#2f6f4e; --accent2:#d97706; --danger:#b91c1c; }
  * { box-sizing:border-box; }
  body { min-height:100vh; margin:0; display:grid; place-items:center; font-family: ui-serif, Georgia, "Times New Roman", serif; color:var(--ink); background:radial-gradient(circle at 20% 15%, #f8e9bc 0 18%, transparent 19%), radial-gradient(circle at 80% 10%, #cfe8d8 0 16%, transparent 17%), linear-gradient(135deg,#eef5e9,#fbf3dc 55%,#efe2c2); }
  .login-card { width:min(420px, calc(100vw - 32px)); padding:34px; background:rgba(255,253,246,.9); border:1px solid rgba(47,111,78,.18); border-radius:28px; box-shadow:0 28px 80px rgba(45,55,72,.18); backdrop-filter:blur(16px); }
  .brand { display:flex; align-items:center; gap:12px; margin-bottom:28px; }
  .mark { width:48px; height:48px; border-radius:16px; display:grid; place-items:center; color:white; font-size:24px; background:linear-gradient(135deg,var(--accent),#8a9f45); box-shadow:0 12px 28px rgba(47,111,78,.28); }
  h1 { margin:0; font-size:28px; letter-spacing:-.03em; }
  p { margin:6px 0 0; color:var(--muted); font-size:14px; line-height:1.6; }
  label { display:block; margin:22px 0 8px; font-size:13px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; color:#365143; }
  input { width:100%; border:1px solid var(--line); border-radius:16px; padding:15px 16px; background:var(--field); color:var(--ink); font:inherit; outline:none; }
  input:focus { border-color:var(--accent); box-shadow:0 0 0 4px rgba(47,111,78,.12); background:white; }
  button { width:100%; margin-top:18px; border:0; border-radius:16px; padding:15px 16px; cursor:pointer; color:white; font:700 15px ui-sans-serif, system-ui, sans-serif; background:linear-gradient(135deg,var(--accent),#7f8f2d); box-shadow:0 14px 32px rgba(47,111,78,.24); }
  .error { margin:0 0 16px; padding:12px 14px; border-radius:14px; background:#fee2e2; color:var(--danger); font:600 13px ui-sans-serif, system-ui, sans-serif; }
  .hint { margin-top:16px; text-align:center; font:12px ui-sans-serif, system-ui, sans-serif; color:var(--muted); }
</style>
</head>
<body>
  <main class="login-card">
    <div class="brand">
      <div class="mark">☁</div>
      <div>
        <h1>CloudShare</h1>
        <p>输入管理员密码后继续访问。</p>
      </div>
    </div>
    ${safeError ? `<div class="error">${safeError}</div>` : ''}
    <form method="POST" action="/api/login">
      <input type="hidden" name="next" value="${safeNext}">
      <label for="credential">管理员凭据</label>
      <input id="credential" name="credential" type="password" autocomplete="current-password" autofocus required placeholder="ADMIN_PASSWORD">
      <button type="submit">进入管理后台</button>
    </form>
    <div class="hint">登录状态保存在 HttpOnly Cookie 中，有效期 7 天。</div>
  </main>
</body>
</html>`;
}

async function handleLogin(request, env) {
  if (!getAdminSessionSecret(env)) {
    return htmlResponse(loginPageHTML('/', 'ADMIN_PASSWORD 未配置'), 500);
  }

  const failures = await getLoginFailures(request, env);
  if (Number(failures.count || 0) >= LOGIN_RATE_LIMIT_MAX_FAILURES) {
    return htmlResponse(loginPageHTML('/', '登录失败次数过多，请 10 分钟后再试'), 429);
  }

  let credential = '';
  let next = '/';
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('application/json')) {
    const body = await request.json();
    credential = body.password || body.credential || '';
    next = body.next || '/';
  } else {
    const formData = await request.formData();
    credential = formData.get('credential') || formData.get('password') || '';
    next = formData.get('next') || '/';
  }

  const safeNext = safeNextPath(next);
  if (!verifyAdminCredential(credential, env)) {
    await recordLoginFailure(request, env);
    return htmlResponse(loginPageHTML(safeNext, '凭据错误，请重试'), 401);
  }

  await clearLoginFailures(request, env);
  const session = await createAdminSession(env);
  return redirectResponse(safeNext, 303, {
    'Set-Cookie': buildAdminCookie(request, session),
  });
}

function handleLogout(request) {
  return redirectResponse('/login', 303, {
    'Set-Cookie': buildAdminCookie(request, '', 0),
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

// 统一构建 R2 存储 Key 的方法，避免首尾斜杠及多重编码混乱
function safeDecode(value) {
  return decodeURIComponent(value);
}

function encodePathSegment(value) {
  return encodeURIComponent(safeDecode(String(value || '')));
}

function normalizeFolderPath(folder) {
  const decodedFolder = safeDecode(String(folder || '')).replace(/^\/+|\/+$/g, '');
  return decodedFolder
    ? decodedFolder.split('/').filter(Boolean).map(encodePathSegment).join('/')
    : '';
}

function decodeFolderPath(folder) {
  return normalizeFolderPath(folder).split('/').filter(Boolean).map(safeDecode).join('/');
}

function buildR2Key(folder, filename) {
  const cleanFolder = normalizeFolderPath(folder);
  const cleanFilename = encodePathSegment(filename);
  return cleanFolder ? `${cleanFolder}/${cleanFilename}` : cleanFilename;
}

function normalizeObjectKey(path) {
  const parts = safeDecode(String(path || '')).replace(/^\/+|\/+$/g, '').split('/').filter(Boolean);
  const filename = parts.pop();
  return filename ? buildR2Key(parts.join('/'), filename) : '';
}

// ─── 文件去重 & 引用计数 ──────────────────────────────────────────────────
const BLOB_PREFIX = '__blob__/';

function isInternalR2Key(key) {
  return key.startsWith(BLOB_PREFIX) || key.startsWith('_root_/') || key === '__blob__' || key === '_root_';
}

function isValidSha256(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value);
}

async function listAllR2(env, options) {
  const objects = [];
  const delimitedPrefixes = [];
  let cursor;
  do {
    const listed = await env.FILES_BUCKET.list({ ...options, cursor });
    objects.push(...listed.objects);
    if (listed.delimitedPrefixes) delimitedPrefixes.push(...listed.delimitedPrefixes);
    cursor = listed.cursor;
  } while (cursor);
  return { objects, delimitedPrefixes };
}

async function listAllSharesKV(env) {
  const keys = [];
  let cursor;
  do {
    const listed = await env.cloudshare_shares.list({ prefix: 'share:', cursor });
    keys.push(...listed.keys);
    cursor = listed.cursor;
  } while (cursor);
  return keys;
}

// 获取文件哈希的引用计数
async function getRefCount(env, hash) {
  const entry = await env.cloudshare_shares.get(`fhash:${hash}`, 'json');
  const blob = await env.FILES_BUCKET.head(BLOB_PREFIX + hash);
  if (!blob) {
    if (entry) throw new Error(`R2 blob missing for indexed hash: ${hash}`);
    return null;
  }

  return {
    refCount: Number(entry?.refCount) || 0,
    size: Number(entry?.size) || blob.size || 0,
    contentType: entry?.contentType || blob.httpMetadata?.contentType || 'application/octet-stream',
  };
}

// 正常路径优先使用 KV 中记录好的 refCount。
// 只有 refCount 归零、准备删除 blob 前，才扫描 R2 指针做最终确认；这是删除安全校验，不是兼容兜底。
async function countObjectRefs(env, hash, excludeKey = '') {
  let realCount = 0;
  let cursor;
  do {
    const listed = await env.FILES_BUCKET.list({ cursor });
    const candidates = listed.objects.filter(
      obj => obj.key !== excludeKey && !isInternalR2Key(obj.key) && obj.size === 0
    );
    if (candidates.length > 0) {
      const heads = await Promise.all(candidates.map(obj => env.FILES_BUCKET.head(obj.key)));
      for (const pointer of heads) {
        if (pointer?.customMetadata?.sha256 === hash) realCount++;
      }
    }
    cursor = listed.cursor;
  } while (cursor);
  return realCount;
}

async function incrementRefCount(env, hash, size = 0, contentType = 'application/octet-stream') {
  const key = `fhash:${hash}`;
  const existing = await env.cloudshare_shares.get(key, 'json');
  const refCount = Number(existing?.refCount || 0) + 1;
  await env.cloudshare_shares.put(key, JSON.stringify({
    refCount,
    size: Number(size) || Number(existing?.size) || 0,
    contentType: contentType || existing?.contentType || 'application/octet-stream',
  }));
  return refCount;
}

async function decrementRefCount(env, hash, excludeKey, contentType = 'application/octet-stream') {
  const key = `fhash:${hash}`;
  const existing = await env.cloudshare_shares.get(key, 'json');
  if (!existing) throw new Error(`Missing refCount record for hash: ${hash}`);

  const nextCount = Number(existing.refCount || 0) - 1;
  if (nextCount > 0) {
    await env.cloudshare_shares.put(key, JSON.stringify({ ...existing, refCount: nextCount }));
    return nextCount;
  }

  const actualRefs = await countObjectRefs(env, hash, excludeKey);
  if (actualRefs > 0) {
    await env.cloudshare_shares.put(key, JSON.stringify({ ...existing, refCount: actualRefs, contentType: existing.contentType || contentType }));
    return actualRefs;
  }

  await env.cloudshare_shares.delete(key);
  return 0;
}

async function releaseObjectRef(env, key) {
  const obj = await env.FILES_BUCKET.head(key);
  const sha256 = obj?.customMetadata?.sha256;
  if (!sha256) return null;
  const remainingRefs = await decrementRefCount(env, sha256, key, obj.httpMetadata?.contentType);
  if (remainingRefs <= 0) await env.FILES_BUCKET.delete(BLOB_PREFIX + sha256);
  return sha256;
}

async function putDedupPointer(env, key, sha256, size, contentType) {
  const old = await env.FILES_BUCKET.head(key);
  const oldSha = old?.customMetadata?.sha256;
  if (oldSha === sha256) {
    return false;
  }
  if (oldSha) await releaseObjectRef(env, key);
  await env.FILES_BUCKET.put(key, new Uint8Array(0), {
    customMetadata: { sha256 },
    httpMetadata: { contentType },
  });
  await incrementRefCount(env, sha256, size, contentType);
  return true;
}

async function getVisibleFileInfo(env, key, name) {
  const obj = await env.FILES_BUCKET.head(key);
  if (!obj) return null;

  const sha256 = obj.customMetadata?.sha256;
  if (!sha256) return { name, size: obj.size, key };

  const ref = await getRefCount(env, sha256);
  if (!ref) throw new Error(`Dedup blob missing for file: ${key}`);
  return { name, size: ref.size, key };
}

// 管理端直接下载 (无需分享令牌)
// GET /api/admin-download/:folder/:filename
async function handleAdminDownload(request, env, folder, filename) {
  try {
    const key = buildR2Key(folder, filename);
    return await r2DownloadResponse(request, env, key, filename);
  } catch (e) {
    return errorResponse('下载失败: ' + e.message, 500);
  }
}

// =============================================================================
// API 处理函数
// =============================================================================

// POST /api/upload - 上传文件
async function handleUpload(request, env) {
  try {
    const formData = await request.formData();
    const folder = formData.get('folder') || '';
    const files = formData.getAll('files').filter(file => file instanceof File);

    if (files.length === 0) {
      return errorResponse('没有选择文件');
    }
    if (files.length !== 1) {
      return errorResponse('每次上传只能包含一个文件', 400);
    }

    const results = [];
    for (const file of files) {
      const key = buildR2Key(folder, file.name);
      const sha256 = formData.get('sha256');
      const contentType = file.type || getMimeType(file.name);

      if (!isValidSha256(sha256)) {
        return errorResponse('缺少或无效的 sha256', 400);
      }
      const normalizedSha256 = sha256.toLowerCase();
      const existing = await getRefCount(env, normalizedSha256);
      if (existing) {
        const created = await putDedupPointer(env, key, normalizedSha256, file.size, contentType);
        results.push({ name: file.name, folder, size: file.size, key, dedup: true, refCount: existing.refCount + (created ? 1 : 0) });
        continue;
      }

      await env.FILES_BUCKET.put(BLOB_PREFIX + normalizedSha256, file.stream(), { httpMetadata: { contentType } });
      await putDedupPointer(env, key, normalizedSha256, file.size, contentType);
      results.push({ name: file.name, folder, size: file.size, key, refCount: 1 });
    }

    return jsonResponse({ success: true, files: results });
  } catch (e) {
    return errorResponse('上传失败: ' + e.message, 500);
  }
}

// ─── 分片上传 API ────────────────────────────────────────────────────────

// POST /api/upload/init - 初始化分片上传
async function handleDedupUpload(request, env) {
  try {
    const { folder = '', filename, sha256, size = 0, contentType } = await request.json();
    if (!filename || !isValidSha256(sha256)) return errorResponse('缺少必要参数 (filename, sha256)', 400);

    const normalizedSha256 = sha256.toLowerCase();
    const existing = await getRefCount(env, normalizedSha256);
    if (!existing) return jsonResponse({ success: true, exists: false });

    const key = buildR2Key(folder, filename);
    const finalContentType = contentType || existing.contentType || getMimeType(filename);
    const created = await putDedupPointer(env, key, normalizedSha256, Number(size) || existing.size || 0, finalContentType);

    return jsonResponse({
      success: true,
      exists: true,
      dedup: true,
      file: { name: filename, folder, size: Number(size) || existing.size || 0, key, dedup: true, refCount: existing.refCount + (created ? 1 : 0) },
    });
  } catch (e) {
    return errorResponse('去重上传失败: ' + e.message, 500);
  }
}

async function handleChunkedInit(request, env) {
  try {
    const { folder, filename, contentType, sha256 } = await request.json();
    if (!filename) return errorResponse('缺少文件名');
    if (!isValidSha256(sha256)) return errorResponse('缺少或无效的 sha256', 400);
    const targetKey = buildR2Key(folder, filename);
    const normalizedSha256 = sha256.toLowerCase();
    const key = BLOB_PREFIX + normalizedSha256;
    const existing = await getRefCount(env, normalizedSha256);
    if (existing) return jsonResponse({ exists: true, key, targetKey });
    const options = { httpMetadata: { contentType: contentType || getMimeType(filename) } };
    const upload = await env.FILES_BUCKET.createMultipartUpload(key, options);
    return jsonResponse({ uploadId: upload.uploadId, key, targetKey });
  } catch (e) {
    return errorResponse('初始化分片上传失败: ' + e.message, 500);
  }
}

// POST /api/upload/part - 上传分片
async function handleChunkedPart(request, env) {
  try {
    const url = new URL(request.url);
    const uploadId = url.searchParams.get('uploadId') || request.headers.get('x-upload-id');
    const key = url.searchParams.get('key') || request.headers.get('x-upload-key');
    const partNumber = parseInt(url.searchParams.get('partNumber') || request.headers.get('x-part-number'), 10);
    const partBody = request.body;

    if (!uploadId || !key || !partNumber || !partBody) {
      return errorResponse('缺少必要参数 (uploadId, key, partNumber, chunk)');
    }
    if (partNumber < 1 || partNumber > 10000) {
      return errorResponse('无效的分片序号', 400);
    }

    const upload = env.FILES_BUCKET.resumeMultipartUpload(key, uploadId);
    const uploadedPart = await upload.uploadPart(partNumber, partBody);
    
    return jsonResponse({ partNumber, etag: uploadedPart.etag });
  } catch (e) {
    return errorResponse('上传分片失败: ' + e.message, 500);
  }
}

// POST /api/upload/complete - 完成分片上传
async function handleChunkedComplete(request, env) {
  try {
    const { uploadId, key, targetKey, parts, sha256, size = 0, contentType } = await request.json();
    if (!uploadId || !key || !parts || !parts.length) {
      return errorResponse('缺少必要参数 (uploadId, key, parts)');
    }
    if (!targetKey || !isValidSha256(sha256) || key !== BLOB_PREFIX + sha256.toLowerCase()) {
      return errorResponse('分片上传参数无效', 400);
    }
    const normalizedParts = parts
      .map(p => ({ partNumber: Number(p.partNumber), etag: p.etag }))
      .filter(p => Number.isInteger(p.partNumber) && p.partNumber > 0 && p.etag)
      .sort((a, b) => a.partNumber - b.partNumber);
    if (normalizedParts.length !== parts.length) {
      return errorResponse('分片列表无效', 400);
    }
    const upload = env.FILES_BUCKET.resumeMultipartUpload(key, uploadId);
    await upload.complete(normalizedParts);
    const finalContentType = contentType || getMimeType(targetKey);
    try {
      await putDedupPointer(env, targetKey, sha256.toLowerCase(), Number(size) || 0, finalContentType);
    } catch (pointerError) {
      const refs = await countObjectRefs(env, sha256.toLowerCase());
      if (refs === 0) await env.FILES_BUCKET.delete(key);
      throw pointerError;
    }
    return jsonResponse({ success: true, key: targetKey });
  } catch (e) {
    return errorResponse('完成分片上传失败: ' + e.message, 500);
  }
}

// DELETE /api/upload/abort - 取消分片上传
async function handleChunkedAbort(request, env) {
  try {
    const { uploadId, key } = await request.json();
    if (!uploadId || !key) return errorResponse('缺少必要参数');
    const upload = env.FILES_BUCKET.resumeMultipartUpload(key, uploadId);
    await upload.abort();
    return jsonResponse({ success: true });
  } catch (e) {
    return errorResponse('取消上传失败: ' + e.message, 500);
  }
}

// POST /api/folders - 创建文件夹
async function handleCreateFolder(request, env) {
  try {
    const { name, currentFolder } = await request.json(); // 允许接收当前父级文件夹目录
    if (!name || !name.trim()) {
      return errorResponse('无效的文件夹名称');
    }
    
    const fullFolderPath = currentFolder ? `${currentFolder}/${name.trim()}` : name.trim();
    const key = buildR2Key(fullFolderPath, '.folder');
    await env.FILES_BUCKET.put(key, new Uint8Array([]));
    return jsonResponse({ success: true, folder: decodeFolderPath(fullFolderPath) });
  } catch (e) {
    return errorResponse('创建文件夹失败: ' + e.message, 500);
  }
}

// GET /api/files - 列出所有文件夹
// GET /api/files/:folder - 列出文件夹内文件
async function handleListFiles(request, env, params) {
  try {
    let folder = normalizeFolderPath(params?.folder || '');
    if (folder && !folder.endsWith('/')) folder += '/';
    const prefix = folder;
    const cleanCurrentFolder = decodeFolderPath(folder.replace(/\/$/, ''));

    const listed = await listAllR2(env, { prefix, delimiter: '/' });
    const files = [];
    const folders = [];
    const folderSet = new Set();

    // 1. 解析当前层级的文件
    for (const obj of listed.objects) {
      if (isInternalR2Key(obj.key)) continue;
      const fileName = obj.key.slice(prefix.length);
      if (fileName === '.folder' || !fileName) continue;
      if (fileName.includes('/')) {
        // 检测嵌套的 .folder 标记 → 提取下一层子文件夹
        if (fileName.endsWith('/.folder')) {
          const topSubFolder = fileName.split('/')[0];
          if (topSubFolder && !folderSet.has(topSubFolder)) {
            folders.push({ name: decodeURIComponent(topSubFolder), type: 'folder' });
            folderSet.add(topSubFolder);
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
        isDedup: obj.size === 0,
      });
    }

    // 2. 从 delimitedPrefixes 获取下一层子文件夹
    for (const p of listed.delimitedPrefixes || []) {
      if (isInternalR2Key(p)) continue;
      const folderName = p.slice(prefix.length, -1);
      if (folderName && !folderSet.has(folderName)) {
        folders.push({ name: decodeURIComponent(folderName), type: 'folder' });
        folderSet.add(folderName);
      }
    }

    // 3. 并行解析去重指针文件的真实大小和引用计数
    const dedupFiles = files.filter(f => f.isDedup);
    if (dedupFiles.length > 0) {
      const results = await Promise.all(dedupFiles.map(async (f) => {
        const obj = await env.FILES_BUCKET.head(f.key);
        const sha = obj?.customMetadata?.sha256;
        if (!sha) throw new Error(`Dedup pointer missing sha256 metadata: ${f.key}`);
        const ref = await getRefCount(env, sha);
        if (!ref) throw new Error(`Dedup blob missing for file: ${f.key}`);
        return { key: f.key, size: ref.size, refCount: ref.refCount };
      }));
      const refMap = new Map(results.map(r => [r.key, r]));
      for (const f of dedupFiles) {
        const ref = refMap.get(f.key);
        f.size = ref.size;
        f.refCount = ref.refCount;
        delete f.isDedup;
      }
    }

    return jsonResponse({ folder: cleanCurrentFolder, files, folders });
  } catch (e) {
    return errorResponse('获取文件列表失败: ' + e.message, 500);
  }
}

// DELETE /api/files/:folder/:file - 删除文件 (含去重引用计数)
async function handleDeleteFile(request, env, folder, fileName) {
  try {
    const key = buildR2Key(folder, fileName);

    // 检查是否有活跃分享，如果有则先取消
    const shareKeys = await listAllSharesKV(env);
    if (shareKeys.length > 0) {
      const results = await Promise.all(shareKeys.map(sk => env.cloudshare_shares.get(sk.name, 'json')));
      const deletePromises = [];
      for (let i = 0; i < results.length; i++) {
        const shareData = results[i];
        if (shareData && shareData.type === 'file' && shareData.path === key) {
          deletePromises.push(env.cloudshare_shares.delete(shareKeys[i].name));
        }
      }
      if (deletePromises.length > 0) await Promise.all(deletePromises);
    }

    await releaseObjectRef(env, key);
    await env.FILES_BUCKET.delete(key);
    return jsonResponse({ success: true });
  } catch (e) {
    return errorResponse('删除文件失败: ' + e.message, 500);
  }
}

// DELETE /api/folders/:folder - 删除文件夹（含所有文件）
async function handleDeleteFolder(request, env, folder) {
  try {
    folder = normalizeFolderPath(folder);
    const prefix = `${folder}/`;
    let cursor;
    const keysToDelete = [];

    do {
      const listed = await env.FILES_BUCKET.list({ prefix, cursor });
      for (const obj of listed.objects) {
        keysToDelete.push(obj.key);
      }
      cursor = listed.cursor;
    } while (cursor);

    // 先释放所有引用计数（有副作用，需顺序执行）
    for (const key of keysToDelete) {
      await releaseObjectRef(env, key);
    }
    // 批量删除 R2 对象（R2 支持每次最多 1000 个 key）
    for (let i = 0; i < keysToDelete.length; i += 1000) {
      const batch = keysToDelete.slice(i, i + 1000);
      await env.FILES_BUCKET.delete(batch);
    }

    // 同时清理相关的分享
    if (env.cloudshare_shares) {
      const shareKeys = await listAllSharesKV(env);
      const deletePromises = [];
      for (const shareKey of shareKeys) {
        const shareData = await env.cloudshare_shares.get(shareKey.name, 'json');
        const sharePath = shareData ? normalizeFolderPath(shareData.path) : '';
        if (shareData && (sharePath === folder || sharePath.startsWith(`${folder}/`))) {
          deletePromises.push(env.cloudshare_shares.delete(shareKey.name));
        }
      }
      if (deletePromises.length > 0) await Promise.all(deletePromises);
    }

    return jsonResponse({ success: true, deleted: keysToDelete.length });
  } catch (e) {
    return errorResponse('删除文件夹失败: ' + e.message, 500);
  }
}

// POST /api/share - 创建分享链接
async function handleCreateShare(request, env) {
  try {
    const { type, path, name, password, expiresIn } = await request.json();
    if (!type || !path || !name) {
      return errorResponse('缺少必要参数 (type, path, name)');
    }
    if (!['file', 'folder'].includes(type)) {
      return errorResponse('type 必须是 file 或 folder');
    }

    const token = crypto.randomUUID();
    const now = new Date();
    const shareData = {
      token,
      type,
      path,
      name,
      createdAt: now.toISOString(),
      expiresAt: expiresIn ? new Date(now.getTime() + expiresIn * 1000).toISOString() : null,
      passwordHash: password ? await hashPassword(password) : null,
    };

    await env.cloudshare_shares.put(`share:${token}`, JSON.stringify(shareData));

    // 返回时去除敏感字段
    return jsonResponse({
      success: true,
      share: publicShareData(shareData),
      url: `${new URL(request.url).origin}/s/${token}`,
    });
  } catch (e) {
    return errorResponse('创建分享失败: ' + e.message, 500);
  }
}

// GET /api/share/:token - 获取分享详情
async function handleGetShare(request, env, token) {
  try {
    const shareData = await env.cloudshare_shares.get(`share:${token}`, 'json');
    if (!shareData) {
      return errorResponse('分享不存在或已过期', 404);
    }

    // 检查过期
    const expired = isShareExpired(shareData);

    // 如果是文件夹分享，列出文件夹内的文件
    let files = [];
    const passwordAllowed = await isSharePasswordAllowed(request, shareData);
    if (!expired && passwordAllowed) {
      if (shareData.type === 'folder') {
        const folderPath = normalizeFolderPath(shareData.path);
        const prefix = folderPath ? `${folderPath}/` : '';
        const listed = await listAllR2(env, { prefix });
        const visibleObjects = [];
        for (const obj of listed.objects) {
          if (isInternalR2Key(obj.key)) continue;
          const fileName = obj.key.slice(prefix.length);
          if (fileName === '.folder' || fileName.endsWith('/.folder') || !fileName) continue;
          visibleObjects.push({ key: obj.key, name: decodeURIComponent(fileName) });
        }
        const results = await Promise.all(visibleObjects.map(o => getVisibleFileInfo(env, o.key, o.name)));
        files = results.filter(Boolean);
      } else {
        const obj = await getVisibleFileInfo(env, normalizeObjectKey(shareData.path), shareData.name);
        if (!obj) return errorResponse('分享文件不存在', 404);
        files.push({
          name: shareData.name,
          size: obj.size,
          key: shareData.path,
        });
      }
    }

    // 返回时去除敏感字段
    const safe = publicShareData(shareData);
    const passwordRequired = !!shareData.passwordHash && !passwordAllowed;
    if (passwordRequired) safe.path = '';
    return jsonResponse({
      ...safe,
      passwordRequired,
      expired,
      files,
    });
  } catch (e) {
    return errorResponse('获取分享失败: ' + e.message, 500);
  }
}

// DELETE /api/share/:token - 取消分享
async function handleDeleteShare(request, env, token) {
  try {
    await env.cloudshare_shares.delete(`share:${token}`);
    return jsonResponse({ success: true });
  } catch (e) {
    return errorResponse('取消分享失败: ' + e.message, 500);
  }
}

// PUT /api/share/:token - 更新分享设置 (续期 / 修改密码)
async function handleUpdateShare(request, env, token) {
  try {
    const shareData = await env.cloudshare_shares.get(`share:${token}`, 'json');
    if (!shareData) {
      return errorResponse('分享不存在', 404);
    }

    const { action, expiresIn, password } = await request.json();

    switch (action) {
      case 'extend': {
        // 续期: 从现在起延长 expiresIn 秒; expiresIn=null 表示永不过期
        const now = new Date();
        shareData.expiresAt = expiresIn ? new Date(now.getTime() + expiresIn * 1000).toISOString() : null;
        break;
      }
      case 'password': {
        // 修改密码: password=null 或 '' 表示移除密码
        shareData.passwordHash = password ? await hashPassword(password) : null;
        break;
      }
      case 'cancel': {
        // 取消分享
        await env.cloudshare_shares.delete(`share:${token}`);
        return jsonResponse({ success: true });
      }
      default:
        return errorResponse('无效的 action');
    }

    await env.cloudshare_shares.put(`share:${token}`, JSON.stringify(shareData));

    return jsonResponse({
      success: true,
      share: publicShareData(shareData),
    });
  } catch (e) {
    return errorResponse('更新分享失败: ' + e.message, 500);
  }
}

// POST /api/share/:token/verify - 验证分享密码
async function handleVerifyPassword(request, env, token) {
  try {
    const shareData = await env.cloudshare_shares.get(`share:${token}`, 'json');
    if (!shareData) {
      return errorResponse('分享不存在或已过期', 404);
    }

    // 检查过期
    if (isShareExpired(shareData)) {
      return jsonResponse({ valid: false, expired: true });
    }

    if (!shareData.passwordHash) {
      return jsonResponse({ valid: true, needPassword: false });
    }

    const { password } = await request.json();
    if (!password) {
      return jsonResponse({ valid: false, needPassword: true });
    }

    const valid = await verifyPasswordAsync(password, shareData.passwordHash);
    return jsonResponse({ valid, needPassword: true });
  } catch (e) {
    return errorResponse('验证失败: ' + e.message, 500);
  }
}

// GET /api/shares - 列出所有分享
async function handleListShares(request, env) {
  try {
    const shareKeys = await listAllSharesKV(env);
    const results = await Promise.all(shareKeys.map(key => env.cloudshare_shares.get(key.name, 'json')));
    const shares = results.filter(Boolean).map(publicShareData);
    return jsonResponse({ shares });
  } catch (e) {
    return errorResponse('获取分享列表失败: ' + e.message, 500);
  }
}

// GET /dl/:token - 下载分享的单个文件
// GET /dl/:token/:filename - 下载分享文件夹中的文件
async function handleDownload(request, env, token, filename) {
  try {
    const shareData = await env.cloudshare_shares.get(`share:${token}`, 'json');
    if (!shareData) {
      return errorResponse('分享不存在或已过期', 404);
    }

    // 检查过期
    if (isShareExpired(shareData)) {
      return errorResponse('分享已过期', 410);
    }
    if (!(await isSharePasswordAllowed(request, shareData))) {
      return errorResponse('需要分享密码', 403);
    }

    let objectKey;
    let downloadName;

    if (shareData.type === 'file') {
      objectKey = normalizeObjectKey(shareData.path);
      downloadName = shareData.name;
    } else {
      // 文件夹分享
      if (!filename) {
        return errorResponse('请指定要下载的文件名', 400);
      }
      const folderPath = normalizeFolderPath(shareData.path);
      const prefix = folderPath ? `${folderPath}/` : '';
      // filename 来自 URL pathname 已被自动解码，需重新编码以匹配 R2 key
      objectKey = prefix + normalizeFolderPath(filename);
      downloadName = filename;
    }

    return await r2DownloadResponse(request, env, objectKey, downloadName);
  } catch (e) {
    return errorResponse('下载失败: ' + e.message, 500);
  }
}

// =============================================================================
// HTML 模板 - 管理主页
// =============================================================================

function mainPageHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudShare - 文件分享管理</title>
<style>
  :root {
    --bg: #f0f2f5; --surface: #fff; --primary: #3b82f6; --primary-hover: #2563eb;
    --danger: #ef4444; --danger-hover: #dc2626; --success: #22c55e;
    --text: #1e293b; --text-secondary: #64748b; --border: #e2e8f0;
    --radius: 12px; --radius-sm: 8px; --shadow-lg: 0 10px 25px rgba(0,0,0,0.1);
    --transition: 0.2s ease;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); display:flex; flex-direction:column; height:100vh; overflow:hidden; }

  /* ── 顶栏 ── */
  .topbar { background:var(--surface); border-bottom:1px solid var(--border); padding:14px 32px; display:flex; align-items:center; justify-content:space-between; flex-shrink:0; }
  .breadcrumb { display:flex; align-items:center; gap:4px; font-size:15px; flex-wrap:wrap; }
  .breadcrumb a { color:var(--primary); text-decoration:none; padding:2px 6px; border-radius:4px; transition:background var(--transition); white-space:nowrap; }
  .breadcrumb a:hover { background:#eff6ff; }
  .breadcrumb .sep { color:var(--text-secondary); user-select:none; }
  .breadcrumb .current { font-weight:600; color:var(--text); padding:2px 6px; }
  .topbar-actions { display:flex; gap:8px; }

  /* ── 进度条 ── */
  .upload-progress { margin:0 32px; padding:12px 16px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); display:none; flex-shrink:0; }
  .upload-progress.show { display:block; }
  .progress-bar { height:6px; background:var(--border); border-radius:3px; overflow:hidden; margin-top:6px; }
  .progress-fill { height:100%; background:var(--primary); border-radius:3px; transition:width 0.3s ease; width:0%; }

  /* ── 文件网格 ── */
  .file-grid-wrap { flex:1; overflow-y:auto; padding:24px 32px; }
  .file-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(180px, 1fr)); gap:12px; align-content:start; }
  .file-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:16px; cursor:default; transition:all var(--transition); display:flex; flex-direction:column; gap:8px; position:relative; }
  .file-card:hover { box-shadow:var(--shadow-lg); border-color:#94a3b8; }
  .file-card .file-icon { font-size:36px; text-align:center; }
  .file-card .file-name { font-size:13px; font-weight:500; text-align:center; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .file-card .file-meta { font-size:11px; color:var(--text-secondary); text-align:center; }
  .file-card .card-actions { display:flex; gap:4px; justify-content:center; }

  /* ── + 卡片 ── */
  .add-card { background:var(--surface); border:2px dashed #cbd5e1; border-radius:var(--radius); padding:16px; cursor:pointer; transition:all var(--transition); display:flex; flex-direction:column; align-items:center; justify-content:center; gap:6px; min-height:160px; position:relative; }
  .add-card:hover { border-color:var(--primary); background:#f8faff; }
  .add-card .add-icon { font-size:40px; color:var(--primary); }
  .add-card .add-text { font-size:13px; color:var(--text-secondary); }
  .add-popup { display:none; position:absolute; top:100%; left:0; margin-top:4px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); box-shadow:var(--shadow-lg); z-index:50; min-width:180px; overflow:hidden; }
  .add-popup.show { display:block; }
  .add-popup-item { display:flex; align-items:center; gap:10px; padding:12px 16px; cursor:pointer; font-size:14px; transition:background var(--transition); border:none; background:none; width:100%; text-align:left; }
  .add-popup-item:hover { background:var(--bg); }
  .add-popup-item .popup-icon { font-size:20px; }

  /* ── 按钮 ── */
  .btn-icon { width:32px; height:32px; border:none; background:transparent; border-radius:6px; cursor:pointer; font-size:16px; display:inline-flex; align-items:center; justify-content:center; transition:background var(--transition); }
  .btn-icon:hover { background:var(--bg); }
  .btn-icon.danger:hover { background:#fef2f2; color:var(--danger); }
  .btn { padding:8px 16px; border:none; border-radius:var(--radius-sm); cursor:pointer; font-size:13px; font-weight:500; transition:all var(--transition); display:inline-flex; align-items:center; gap:6px; }
  .btn-primary { background:var(--primary); color:#fff; }
  .btn-primary:hover { background:var(--primary-hover); }
  .btn-danger { background:var(--danger); color:#fff; }
  .btn-danger:hover { background:var(--danger-hover); }
  .btn-outline { background:#fff; color:var(--text); border:1px solid var(--border); }
  .btn-outline:hover { background:var(--bg); }
  .btn-sm { padding:6px 10px; font-size:12px; }

  /* ── 模态框 ── */
  .modal-overlay { position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.5); display:flex; align-items:center; justify-content:center; z-index:100; animation:fadeIn 0.15s ease; }
  .modal { background:var(--surface); border-radius:var(--radius); padding:28px; width:480px; max-width:90vw; box-shadow:var(--shadow-lg); animation:slideUp 0.2s ease; }
  .modal h3 { font-size:18px; margin-bottom:12px; }
  .modal .share-url { width:100%; padding:10px 12px; border:1px solid var(--border); border-radius:var(--radius-sm); font-size:13px; background:var(--bg); margin:12px 0; font-family:monospace; }
  .modal .modal-actions { display:flex; gap:8px; margin-top:16px; justify-content:flex-end; }
  @keyframes fadeIn { from{opacity:0} to{opacity:1} }
  @keyframes slideUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }

  /* ── 通用弹窗 ── */
  .dialog-input { width:100%; padding:10px 14px; border:2px solid var(--border); border-radius:var(--radius-sm); font-size:14px; outline:none; margin:8px 0; }
  .dialog-input:focus { border-color:var(--primary); }
  .dialog-text { font-size:14px; line-height:1.5; }

  /* ── Toast ── */
  .toast-container { position:fixed; bottom:24px; right:24px; display:flex; flex-direction:column; gap:8px; z-index:200; }
  .toast { padding:12px 20px; background:#1e293b; color:#f1f5f9; border-radius:var(--radius-sm); font-size:13px; box-shadow:var(--shadow-lg); animation:slideUp 0.2s ease; }
  .toast.success { border-left:3px solid var(--success); }
  .toast.error { border-left:3px solid var(--danger); }

  /* ── 表单 ── */
  .form-group { margin-bottom:14px; }
  .form-label { display:block; font-size:13px; font-weight:500; margin-bottom:4px; }
  .form-hint { font-weight:400; color:var(--text-secondary); font-size:12px; }
  .form-input { width:100%; padding:8px 12px; border:1px solid var(--border); border-radius:6px; font-size:13px; font-family:inherit; outline:none; }
  .form-input:focus { border-color:var(--primary); box-shadow:0 0 0 2px rgba(59,130,246,0.1); }
  .input-row { display:flex; gap:6px; }
  .input-row .form-input { flex:1; }
  select.form-input { cursor:pointer; background:#fff; }
  .share-info-row { display:flex; gap:8px; padding:4px 0; font-size:13px; }
  .info-label { color:var(--text-secondary); min-width:50px; }

  /* ── 分享标签 ── */
  .share-badge { position:absolute; top:8px; right:8px; background:var(--success); color:#fff; font-size:10px; padding:2px 8px; border-radius:10px; font-weight:600; pointer-events:none; }
  .empty-state { grid-column:1/-1; text-align:center; padding:60px 20px; color:var(--text-secondary); }
  /* ── 多选 ── */
  .file-card.selected { border-color:var(--primary); background:#eff6ff; }
  .empty-state .empty-icon { font-size:56px; margin-bottom:12px; }

  @media (max-width:768px) {
    .topbar { padding:12px 16px; }
    .file-grid-wrap { padding:16px; }
    .file-grid { grid-template-columns:repeat(auto-fill, minmax(140px, 1fr)); }
  }
</style>
</head>
<body>

<!-- 顶栏 -->
<div class="topbar">
  <div class="breadcrumb" id="breadcrumb"></div>
  <div class="topbar-actions">
    <a href="/manage" class="btn btn-outline" style="text-decoration:none;">🔗 管理分享</a>
    <a href="/api/logout" class="btn btn-outline" style="text-decoration:none;">退出登录</a>
  </div>
</div>

<!-- 进度条 -->
<div class="upload-progress" id="uploadProgress">
  <div style="display:flex;align-items:center;justify-content:space-between;">
    <span id="uploadStatus" style="font-size:13px;">准备上传...</span>
    <button class="btn btn-sm btn-outline" id="btnCancelUpload" style="display:none;color:var(--danger);" onclick="cancelUpload()">✕ 取消</button>
  </div>
  <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
</div>

<!-- 文件网格 -->
<div class="file-grid-wrap" id="fileGridWrap">
  <div class="file-grid" id="fileGrid">
    <!-- + 按钮始终在第一位 -->
    <div class="add-card" id="addCard" onclick="toggleAddPopup(event)">
      <div class="add-icon">＋</div>
      <div class="add-text">新建或上传</div>
      <div class="add-popup" id="addPopup">
        <button class="add-popup-item" onclick="event.stopPropagation();createFolder()"><span class="popup-icon">📁</span> 新建文件夹</button>
        <button class="add-popup-item" onclick="event.stopPropagation();triggerUpload()"><span class="popup-icon">📤</span> 上传文件</button>
      </div>
    </div>
  </div>
</div>

<input type="file" id="fileInput" multiple style="display:none;">

<!-- 分享模态框 -->
<div class="modal-overlay" id="shareModal" style="display:none;">
  <div class="modal">
    <h3 id="shareModalTitle">🔗 分享链接</h3>
    <p style="font-size:14px;color:var(--text-secondary);">分享 <strong id="shareTargetName"></strong></p>

    <!-- 新建分享的表单 -->
    <div id="shareCreateForm">
      <div class="form-group">
        <label class="form-label">🔑 访问密码 <span class="form-hint">(可选，留空则无需密码)</span></label>
        <div class="input-row">
          <input type="text" class="form-input" id="sharePassword" placeholder="设置访问密码" autocomplete="off">
          <button class="btn btn-sm btn-outline" onclick="togglePasswordVisible('sharePassword')" title="显示/隐藏">👁</button>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">⏰ 过期时间</label>
        <select class="form-input" id="shareExpiry" onchange="onExpiryChange()">
          <option value="">永不过期</option>
          <option value="3600">1 小时后</option>
          <option value="86400">24 小时后</option>
          <option value="604800">7 天后</option>
          <option value="2592000">30 天后</option>
          <option value="custom">自定义 (天)</option>
        </select>
        <div id="customExpiryWrap" style="display:none;margin-top:6px;">
          <input type="number" class="form-input" id="shareExpiryCustom" placeholder="输入天数" min="1" value="1">
        </div>
      </div>
    </div>

    <!-- 已创建分享的详情 -->
    <div id="shareInfoPanel" style="display:none;">
      <div class="share-info-row"><span class="info-label">状态:</span> <span id="shareInfoStatus"></span></div>
      <div class="share-info-row"><span class="info-label">密码:</span> <span id="shareInfoPassword"></span></div>
      <div class="share-info-row"><span class="info-label">过期:</span> <span id="shareInfoExpiry"></span></div>
    </div>

    <input class="share-url" id="shareUrlInput" readonly onclick="this.select()">

    <div class="form-group" id="shareNewPasswordGroup" style="display:none;">
      <label class="form-label">🔑 新密码 <span class="form-hint">(留空则移除密码)</span></label>
      <div class="input-row">
        <input type="text" class="form-input" id="shareNewPassword" placeholder="输入新密码" autocomplete="off">
        <button class="btn btn-sm btn-outline" onclick="togglePasswordVisible('shareNewPassword')" title="显示/隐藏">👁</button>
      </div>
    </div>
    <div class="form-group" id="shareExtendGroup" style="display:none;">
      <label class="form-label">⏰ 续期</label>
      <select class="form-input" id="shareExtendExpiry">
        <option value="">永不过期</option>
        <option value="3600">延长 1 小时</option>
        <option value="86400">延长 24 小时</option>
        <option value="604800">延长 7 天</option>
        <option value="2592000">延长 30 天</option>
        <option value="custom">自定义 (天)</option>
      </select>
      <div id="customExtendWrap" style="display:none;margin-top:6px;">
        <input type="number" class="form-input" id="shareExtendCustom" placeholder="输入天数" min="1" value="1">
      </div>
    </div>

    <div class="modal-actions">
      <button class="btn btn-outline" onclick="closeShareModal()">关闭</button>
      <button class="btn btn-primary" id="btnCreateShare" onclick="createShareLink()">🔗 创建分享</button>
      <button class="btn btn-outline" id="btnUpdateShare" style="display:none;" onclick="updateShareSettings()">💾 保存修改</button>
      <button class="btn btn-outline" onclick="copyShareUrl()">📋 复制链接</button>
      <button class="btn btn-outline" id="btnCopyShareWithPw" style="display:none;" onclick="copyActiveShareUrlWithPw()" title="复制带密码的链接，访问时无需输入密码">🔐 复制带密码链接</button>
      <button class="btn btn-danger" id="btnCancelShare" style="display:none;" onclick="cancelShare()">❌ 取消分享</button>
    </div>
  </div>
</div>

<!-- 分享管理面板模态框 -->
<div class="modal-overlay" id="sharesManageModal" style="display:none;">
  <div class="modal" style="max-width:960px;">
    <h3>📋 分享管理</h3>
    <div id="sharesManageList" style="max-height:60vh;overflow-y:auto;"></div>
    <div class="modal-actions">
      <button class="btn btn-outline" onclick="document.getElementById('sharesManageModal').style.display='none'">关闭</button>
    </div>
  </div>
</div>

<!-- 通用弹窗 -->
<div class="modal-overlay" id="genericDialog" style="display:none;">
  <div class="modal" style="max-width:440px;">
    <h3 id="dialogTitle"></h3>
    <div id="dialogContent" style="margin:12px 0;"></div>
    <div class="modal-actions" id="dialogActions"></div>
  </div>
</div>

<!-- Toast -->
<div class="toast-container" id="toastContainer"></div>

<script>
// ── 通用弹窗组件 ──
// 用法: showDialog({title, content, type, placeholder, value, buttons})
//   type: 'text' | 'number' | 'info' (默认 info = 纯文本)
//   buttons: [{text, cls, value}]  — cls: 'primary'|'danger'|'outline', value: 返回值
// 返回 Promise<value>
function showDialog(opts) {
  return new Promise(resolve => {
    const overlay = document.getElementById('genericDialog');
    const closeDialog = (result) => {
      overlay.style.display = 'none';
      overlay.onclick = null;
      resolve(result);
    };
    overlay.onclick = (event) => {
      if (event.target === overlay) closeDialog({ value: null, input: null, cancelled: true });
    };
    document.getElementById('dialogTitle').textContent = opts.title || '';
    const contentEl = document.getElementById('dialogContent');
    if (opts.type === 'text' || opts.type === 'number') {
      contentEl.innerHTML = '<input type="' + opts.type + '" class="dialog-input" id="dialogInput" placeholder="' + escapeHtml(opts.placeholder || '') + '" value="' + escapeHtml(opts.value || '') + '" autofocus onkeydown="if(event.key===\\'Enter\\')document.getElementById(\\'dialogBtn0\\').click()">';
    } else {
      const p = document.createElement('p');
      p.className = 'dialog-text';
      p.textContent = opts.content || '';
      contentEl.replaceChildren(p);
    }
    const actionsEl = document.getElementById('dialogActions');
    actionsEl.innerHTML = '';
    (opts.buttons || [{text:'确定', cls:'primary', value:true}]).forEach((b, i) => {
      const btn = document.createElement('button');
      btn.id = 'dialogBtn' + i;
      btn.className = 'btn btn-' + (b.cls || 'primary');
      btn.textContent = b.text;
      btn.onclick = () => {
        const inputVal = document.getElementById('dialogInput');
        closeDialog({value: b.value, input: inputVal ? inputVal.value : null});
      };
      actionsEl.appendChild(btn);
    });
    overlay.style.display = 'flex';
    // Focus input if present
    setTimeout(() => { const inp = document.getElementById('dialogInput'); if (inp) inp.focus(); }, 100);
  });
}

// ── 状态 ──
let currentFolder = '';
let folderPath = []; // 面包屑路径栈 ['folder1', 'folder2']
let fileList = [];
let folderList = [];

// ── 初始化 ──
document.addEventListener('DOMContentLoaded', () => {
  setupDragDrop();
  document.getElementById('fileInput').addEventListener('change', () => uploadFiles(document.getElementById('fileInput').files));
  loadFiles();
  loadAllShares();
});

// ── 拖拽上传 ──
function setupDragDrop() {
  const wrap = document.getElementById('fileGridWrap');
  wrap.addEventListener('dragover', e => { e.preventDefault(); wrap.style.background = '#f8faff'; });
  wrap.addEventListener('dragleave', () => { wrap.style.background = ''; });
  wrap.addEventListener('drop', e => {
    e.preventDefault();
    wrap.style.background = '';
    uploadFiles(e.dataTransfer.files);
  });
}

function triggerUpload() {
  document.getElementById('addPopup').classList.remove('show');
  document.getElementById('fileInput').click();
}

function toggleAddPopup(e) {
  e.stopPropagation();
  document.getElementById('addPopup').classList.toggle('show');
}
document.addEventListener('click', () => document.getElementById('addPopup').classList.remove('show'));

const LARGE_FILE_THRESHOLD = 40 * 1024 * 1024;
const CHUNK_SIZE = 8 * 1024 * 1024; // R2 multipart parts must stay comfortably above 5MB.
const MAX_CONCURRENT = 2;
const HASH_CHUNK_SIZE = 4 * 1024 * 1024;
let uploadAbortController = null;

class Sha256Stream {
  constructor() {
    this.h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    this.k = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
    this.pending = new Uint8Array(0);
    this.bytes = 0;
  }
  rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
  process(block) {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      const j = i * 4;
      w[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = (this.rotr(w[i - 15], 7) ^ this.rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
      const s1 = (this.rotr(w[i - 2], 17) ^ this.rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = this.h;
    for (let i = 0; i < 64; i++) {
      const S1 = (this.rotr(e, 6) ^ this.rotr(e, 11) ^ this.rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + this.k[i] + w[i]) >>> 0;
      const S0 = (this.rotr(a, 2) ^ this.rotr(a, 13) ^ this.rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    this.h[0] = (this.h[0] + a) >>> 0; this.h[1] = (this.h[1] + b) >>> 0;
    this.h[2] = (this.h[2] + c) >>> 0; this.h[3] = (this.h[3] + d) >>> 0;
    this.h[4] = (this.h[4] + e) >>> 0; this.h[5] = (this.h[5] + f) >>> 0;
    this.h[6] = (this.h[6] + g) >>> 0; this.h[7] = (this.h[7] + h) >>> 0;
  }
  update(bytes) {
    this.bytes += bytes.length;
    const merged = new Uint8Array(this.pending.length + bytes.length);
    merged.set(this.pending);
    merged.set(bytes, this.pending.length);
    let offset = 0;
    while (offset + 64 <= merged.length) {
      this.process(merged.subarray(offset, offset + 64));
      offset += 64;
    }
    this.pending = merged.subarray(offset);
  }
  digest() {
    const bitLength = this.bytes * 8;
    const padLength = this.pending.length < 56 ? 64 : 128;
    const padded = new Uint8Array(padLength);
    padded.set(this.pending);
    padded[this.pending.length] = 0x80;
    const high = Math.floor(bitLength / 0x100000000);
    const low = bitLength >>> 0;
    padded[padLength - 8] = (high >>> 24) & 255; padded[padLength - 7] = (high >>> 16) & 255;
    padded[padLength - 6] = (high >>> 8) & 255; padded[padLength - 5] = high & 255;
    padded[padLength - 4] = (low >>> 24) & 255; padded[padLength - 3] = (low >>> 16) & 255;
    padded[padLength - 2] = (low >>> 8) & 255; padded[padLength - 1] = low & 255;
    for (let offset = 0; offset < padded.length; offset += 64) this.process(padded.subarray(offset, offset + 64));
    return Array.from(this.h).map(n => n.toString(16).padStart(8, '0')).join('');
  }
}

// SHA-256 哈希 (用于去重)
async function computeSHA256(file, onProgress, signal) {
  const hasher = new Sha256Stream();
  try {
    for (let offset = 0; offset < file.size; offset += HASH_CHUNK_SIZE) {
      if (signal?.aborted) throw new DOMException('Upload aborted', 'AbortError');
      const end = Math.min(offset + HASH_CHUNK_SIZE, file.size);
      hasher.update(new Uint8Array(await file.slice(offset, end).arrayBuffer()));
      if (onProgress) onProgress(file.size ? end / file.size : 1);
      await new Promise(resolve => setTimeout(resolve, 0));
    }
    if (file.size === 0 && onProgress) onProgress(1);
    return hasher.digest();
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    throw new Error('文件指纹计算失败: ' + (e.message || e));
  }
}

function uploadOverallPercent(uploaded, total) {
  return total > 0 ? Math.round(15 + uploaded / total * 80) : 95;
}

async function createDedupPointer(folder, file, sha256, signal) {
  const res = await fetch('/api/upload/dedup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      folder,
      filename: file.name,
      sha256,
      size: file.size,
      contentType: file.type || getMimeTypeFromName(file.name),
    }),
    signal,
  });
  const data = await res.json();
  if (!res.ok || !data.success) throw new Error(data.error || '去重检查失败');
  return data.exists ? data.file : null;
}

function getMimeTypeFromName(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  const map = { txt:'text/plain', html:'text/html', css:'text/css', js:'text/javascript', json:'application/json', png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', gif:'image/gif', webp:'image/webp', svg:'image/svg+xml', pdf:'application/pdf', zip:'application/zip', mp3:'audio/mpeg', wav:'audio/wav', mp4:'video/mp4' };
  return map[ext] || 'application/octet-stream';
}

function cancelUpload() {
  if (uploadAbortController) {
    uploadAbortController.abort();
    uploadAbortController = null;
  }
  const progress = document.getElementById('uploadProgress');
  const status = document.getElementById('uploadStatus');
  status.textContent = '⚠ 上传已取消';
  document.getElementById('btnCancelUpload').style.display = 'none';
  setTimeout(() => { progress.classList.remove('show'); document.getElementById('progressFill').style.width = '0%'; }, 1500);
}

async function uploadFiles(files) {
  if (!files.length) return;
  const folder = currentFolder || '';
  const progress = document.getElementById('uploadProgress');
  const fill = document.getElementById('progressFill');
  const status = document.getElementById('uploadStatus');
  const cancelBtn = document.getElementById('btnCancelUpload');
  progress.classList.add('show');
  fill.style.width = '2%';
  fill.style.transition = 'width 0.3s ease';
  cancelBtn.style.display = 'inline-flex';
  uploadAbortController = new AbortController();
  const signal = uploadAbortController.signal;

  let totalUploaded = 0;
  const totalSize = Array.from(files).reduce((s, f) => s + f.size, 0);
  const results = [];

  for (const file of files) {
    if (signal.aborted) break;
    try {
      status.textContent = '计算文件指纹: ' + file.name;
      const hash = await computeSHA256(file, (ratio) => {
        fill.style.width = Math.max(2, Math.round(2 + ratio * 8)) + '%';
      }, signal);
      if (signal.aborted) break;

      const existingFile = await createDedupPointer(folder, file, hash, signal);
      if (existingFile) {
        results.push(existingFile);
        totalUploaded += file.size;
        const pct = uploadOverallPercent(totalUploaded, totalSize);
        fill.style.width = pct + '%';
        status.textContent = '已秒传: ' + file.name;
        continue;
      }

      if (file.size <= LARGE_FILE_THRESHOLD) {
        status.textContent = '上传中: ' + file.name;
        fill.style.width = '15%';
        const formData = new FormData();
        formData.append('folder', folder);
        formData.append('files', file);
        formData.append('sha256', hash);
        const res = await fetch('/api/upload', { method: 'POST', body: formData, signal });
        const data = await res.json();
        if (data.success) {
          results.push(...data.files);
          totalUploaded += file.size;
          fill.style.width = uploadOverallPercent(totalUploaded, totalSize) + '%';
        } else throw new Error(data.error);
      } else {
        status.textContent = '分片上传中: ' + file.name + ' (0%)';
        const result = await uploadChunked(file, folder, (chunkUploaded) => {
          totalUploaded += chunkUploaded;
          const pct = uploadOverallPercent(totalUploaded, totalSize);
          fill.style.width = pct + '%';
          status.textContent = '分片上传中: ' + file.name + ' (' + pct + '%)';
        }, signal, hash);
        results.push(result);
      }
    } catch (e) {
      if (signal.aborted) break;
      status.textContent = '❌ 上传失败: ' + e.message;
      toast('上传失败: ' + e.message, 'error');
      cancelBtn.style.display = 'none';
      setTimeout(() => { progress.classList.remove('show'); fill.style.width = '0%'; }, 2000);
      return;
    }
  }

  if (signal.aborted) return;
  uploadAbortController = null;
  fill.style.width = '100%';
  status.textContent = '✅ 上传完成: ' + results.length + ' 个文件';
  cancelBtn.style.display = 'none';
  toast('上传成功', 'success');
  document.getElementById('fileInput').value = ''; // 重置以允许再次选择同名文件
  loadFiles();
  setTimeout(() => { progress.classList.remove('show'); fill.style.width = '0%'; }, 2000);
}

function uploadChunkWithProgress(uploadId, key, partNumber, chunk, signal, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    let uploaded = 0;
    const cleanup = () => signal?.removeEventListener('abort', abort);
    const abort = () => xhr.abort();

    if (signal?.aborted) {
      reject(new DOMException('Upload aborted', 'AbortError'));
      return;
    }
    signal?.addEventListener('abort', abort, { once: true });

    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable) return;
      const delta = event.loaded - uploaded;
      uploaded = event.loaded;
      if (delta > 0 && onProgress) onProgress(delta);
    };
    xhr.onload = () => {
      cleanup();
      try {
        const data = JSON.parse(xhr.responseText || '{}');
        if (xhr.status >= 200 && xhr.status < 300 && data.etag) {
          if (uploaded < chunk.size && onProgress) onProgress(chunk.size - uploaded);
          resolve(data);
        } else {
          reject(new Error(data.error || '分片上传失败: part ' + partNumber));
        }
      } catch (e) {
        reject(e);
      }
    };
    xhr.onerror = () => { cleanup(); reject(new Error('网络错误: part ' + partNumber)); };
    xhr.onabort = () => { cleanup(); reject(new DOMException('Upload aborted', 'AbortError')); };
    xhr.open('POST', '/api/upload/part?uploadId=' + encodeURIComponent(uploadId) + '&key=' + encodeURIComponent(key) + '&partNumber=' + partNumber);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.send(chunk);
  });
}

async function uploadChunked(file, folder, onProgress, signal, sha256) {
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  const initRes = await fetch('/api/upload/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ folder, filename: file.name, contentType: file.type, sha256 }), signal,
  });
  const initData = await initRes.json();
  if (initRes.ok && initData.exists) {
    const existingFile = await createDedupPointer(folder, file, sha256, signal);
    if (!existingFile) throw new Error('Dedup pointer creation failed');
    if (onProgress) onProgress(file.size);
    return existingFile;
  }
  if (!initRes.ok || !initData.uploadId) throw new Error(initData.error || '初始化分片上传失败');
  const { uploadId, key, targetKey } = initData;

  const parts = [];
  let nextPart = 1;
  const partAbortController = new AbortController();
  if (signal.aborted) {
    partAbortController.abort();
  } else {
    signal.addEventListener('abort', () => partAbortController.abort(), { once: true });
  }

  const uploadPart = async (partNumber) => {
    if (partAbortController.signal.aborted) throw new DOMException('Upload aborted', 'AbortError');
    const start = (partNumber - 1) * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const chunk = file.slice(start, end);
    const data = await uploadChunkWithProgress(uploadId, key, partNumber, chunk, partAbortController.signal, onProgress);
    parts.push({ partNumber: data.partNumber, etag: data.etag });
  };

  const abortMultipart = async () => {
    const abortRes = await fetch('/api/upload/abort', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uploadId, key }),
    });
    if (!abortRes.ok) {
      const data = await abortRes.json();
      throw new Error(data.error || '取消分片上传失败');
    }
  };

  try {
    const workers = Array.from({ length: Math.min(MAX_CONCURRENT, totalChunks) }, async () => {
      while (!partAbortController.signal.aborted) {
        const partNumber = nextPart++;
        if (partNumber > totalChunks) return;
        await uploadPart(partNumber);
      }
    });

    await Promise.all(workers);
    if (signal.aborted) throw new DOMException('Upload aborted', 'AbortError');

    parts.sort((a, b) => a.partNumber - b.partNumber);
    document.getElementById('uploadStatus').textContent = '合并分片中: ' + file.name;
    const completeRes = await fetch('/api/upload/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uploadId, key, targetKey, parts, sha256, size: file.size, contentType: file.type }),
      signal,
    });
    const completeData = await completeRes.json();
    if (!completeRes.ok || !completeData.success) {
      throw new Error(completeData.error || '完成上传失败');
    }
    return { name: file.name, folder, size: file.size, key: targetKey || key };
  } catch (e) {
    partAbortController.abort();
    try {
      await abortMultipart();
    } catch (abortError) {
      toast('取消分片上传失败: ' + abortError.message, 'error');
    }
    throw e;
  }
}

// ── 面包屑导航 ──
function renderBreadcrumb() {
  const el = document.getElementById('breadcrumb');
  let html = '<a href=\"javascript:void(0)\" onclick=\"navigateTo([])\">☁ 全部文件</a>';
  let accumulated = [];
  for (let i = 0; i < folderPath.length; i++) {
    const seg = folderPath[i];
    accumulated.push(seg);
    html += '<span class=\"sep\">›</span>';
    if (i === folderPath.length - 1) {
      // 最后一级用当前样式，不可点击
      html += '<span class=\"current\">📂 ' + escapeHtml(seg) + '</span>';
    } else {
      html += '<a href=\"javascript:void(0)\" onclick=\"navigateTo(' + JSON.stringify([...accumulated]).replace(/\"/g, '&quot;') + ')\">📂 ' + escapeHtml(seg) + '</a>';
    }
  }
  el.innerHTML = html;
}

function navigateTo(pathArr) {
  folderPath = pathArr;
  currentFolder = pathArr.join('/');
  const newUrl = currentFolder ? '/' + currentFolder : '/';
  history.pushState(null, '', newUrl);
  renderBreadcrumb();
  loadFiles();
}

async function createFolder() {
  document.getElementById('addPopup').classList.remove('show');
  const result = await showDialog({
    title: '📁 新建文件夹', 
    type: 'text', 
    placeholder: '请输入文件夹名称', 
    buttons: [{ text: '取消', cls: 'outline', value: null }, { text: '创建', cls: 'primary', value: 'ok' }]
  });
  if (!result || result.value !== 'ok' || !result.input || !result.input.trim()) return;
  
  const inputName = result.input.trim();
  try {
    const res = await fetch('/api/folders', { 
      method: 'POST', 
      headers: { 'Content-Type': 'application/json' }, 
      body: JSON.stringify({ 
        name: inputName, 
        currentFolder: typeof currentFolder !== 'undefined' ? currentFolder : '' 
      }) 
    });
    const data = await res.json();
    if (data.success) { 
      toast('文件夹已创建', 'success'); 
      loadFiles(); 
    } else {
      toast(data.error, 'error');
    }
  } catch (e) { 
    toast('创建失败', 'error'); 
  }
}

async function deleteFolder(name) {
  const fullName = currentFolder ? currentFolder + '/' + name : name;
  const result = await showDialog({title:'🗑 删除文件夹', content:'确定删除文件夹 ' + escapeHtml(name) + ' 及其所有文件？此操作不可撤销 !', buttons:[{text:'取消',cls:'outline',value:null},{text:'确认删除',cls:'danger',value:'ok'}]});
  if (!result || result.value !== 'ok') return;
  try {
    const res = await fetch('/api/folders/' + encodePath(fullName), { method:'DELETE' });
    const data = await res.json();
    if (data.success) { toast('文件夹已删除', 'success'); loadFiles(); }
    else toast(data.error, 'error');
  } catch (e) { toast('删除失败', 'error'); }
}

// ── 文件列表 ──
async function loadFiles() {
  try {
    // 获取当前目录下的文件和子文件夹
    const url = currentFolder ? '/api/files/' + encodePath(currentFolder) : '/api/files';
    const res = await fetch(url);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || '加载文件列表失败');
    fileList = data.files || [];
    folderList = data.folders || [];
    renderFileList();
    renderBreadcrumb();
  } catch (e) {
    toast('加载文件列表失败: ' + e.message, 'error');
    throw e;
  }
}

function renderFileList() {
  const grid = document.getElementById('fileGrid');
  const hasContent = fileList.length > 0 || folderList.length > 0;

  // + 卡片
  let html = '<div class="add-card" id="addCard" onclick="toggleAddPopup(event)">'
    + '<div class="add-icon">＋</div>'
    + '<div class="add-text">新建或上传</div>'
    + '<div class="add-popup" id="addPopup">'
    + '<button class="add-popup-item" onclick="event.stopPropagation();createFolder()"><span class="popup-icon">📁</span> 新建文件夹</button>'
    + '<button class="add-popup-item" onclick="event.stopPropagation();triggerUpload()"><span class="popup-icon">📤</span> 上传文件</button>'
    + '</div></div>';

  if (!hasContent) {
    html += '<div class="empty-state"><div class="empty-icon">📭</div><div class="empty-text" style="font-size:15px;">此文件夹为空，点击 ＋ 新建文件夹或上传文件</div></div>';
  }

  // 子文件夹卡片
  for (const f of folderList) {
    const safeFolderName = escapeJsArg(f.name);
    html += '<div class="file-card" style="cursor:pointer;" onclick="navigateToFolder(\\'' + safeFolderName + '\\')">'
      + '<div class="file-icon">📂</div>'
      + '<div class="file-name" title="' + escapeHtml(f.name) + '">' + escapeHtml(f.name) + '</div>'
      + '<div class="file-meta">文件夹</div>'
      + '<div class="card-actions">'
      + '<button class="btn-icon" title="分享文件夹" onclick="event.stopPropagation();shareFolder(\\'' + safeFolderName + '\\')">🔗</button>'
      + '<button class="btn-icon danger" title="删除文件夹" onclick="event.stopPropagation();deleteFolder(\\'' + safeFolderName + '\\')">🗑</button>'
      + '</div></div>';
  }

  // 文件卡片
  for (const f of fileList) {
    const safeFileName = escapeJsArg(f.name);
    const safeFileFolder = escapeJsArg(f.folder || currentFolder);
    const shared = shareMap.get(f.key);
    html += '<div class="file-card">'
      + (shared ? '<span class="share-badge">已分享</span>' : '')
      + '<div class="file-icon">' + fileIcon(f.name) + '</div>'
      + '<div class="file-name" title="' + escapeHtml(f.name) + '">' + escapeHtml(f.name) + '</div>'
      + '<div class="file-meta">' + formatSize(f.size) + '</div>'
      + '<div class="card-actions">'
      + '<button class="btn-icon" title="分享" onclick="event.stopPropagation();shareFile(\\'' + safeFileName + '\\',\\'' + safeFileFolder + '\\')">🔗</button>'
      + '<button class="btn-icon" title="下载" onclick="event.stopPropagation();downloadFile(\\'' + safeFileFolder + '\\',\\'' + safeFileName + '\\')">⬇</button>'
      + '<button class="btn-icon danger" title="删除" onclick="event.stopPropagation();deleteFile(\\'' + safeFileFolder + '\\',\\'' + safeFileName + '\\')">🗑</button>'
      + '</div></div>';
  }

  grid.innerHTML = html;
}

function navigateToFolder(name) {
  folderPath.push(name);
  currentFolder = folderPath.join('/');
  history.pushState(null, '', '/' + currentFolder);
  renderBreadcrumb();
  loadFiles();
}

// 浏览器前进/后退
window.addEventListener('popstate', () => {
  const path = location.pathname.slice(1);
  folderPath = path ? path.split('/') : [];
  currentFolder = path || '';
  renderBreadcrumb();
  loadFiles();
});

// 页面加载时从 URL 读取初始路径
(function initFromUrl() {
  const path = location.pathname.slice(1);
  if (path) {
    folderPath = path.split('/');
    currentFolder = path;
  }
})();

// ── 文件操作 ──
function downloadFile(folder, name) {
  const path = folder ? encodePath(folder) + '/' + encodeURIComponent(name) : encodeURIComponent(name);
  window.location.href = '/api/admin-download/' + path;
}

async function deleteFile(folder, name) {
  const delResult = await showDialog({
    title: '🗑 删除文件', 
    content: '确定删除 ' + escapeHtml(name) + '？', 
    buttons: [{ text: '取消', cls: 'outline', value: null }, { text: '确认删除', cls: 'danger', value: 'ok' }]
  });
  if (!delResult || delResult.value !== 'ok') return;
  try {
    const path = folder ? encodePath(folder) + '/' + encodeURIComponent(name) : encodeURIComponent(name);
    const url = \`/api/files/\${path}\`;
    
    const res = await fetch(url, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) { 
      toast('文件已删除', 'success'); 
      loadFiles(); 
    } else {
      toast(data.error, 'error');
    }
  } catch (e) { 
    toast('删除失败', 'error'); 
  }
}

// ── 分享 ──
let activeShareToken = null;
let activeShareType = null;  // 'file' | 'folder'
let activeSharePath = null;
let activeShareName = null;
let activeSharePassword = null; // 暂存密码，用于生成带密码链接
let shareMap = new Map(); // key → {token, ...}

async function loadAllShares() {
  try {
    const res = await fetch('/api/shares');
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || '加载分享失败');
    shareMap.clear();
    for (const s of (data.shares || [])) {
      shareMap.set(s.path, s);
    }
    if (fileList.length) renderFileList();
  } catch (e) {
    toast('加载分享状态失败: ' + e.message, 'error');
    throw e;
  }
}

function shareFile(name, folder) {
  const key = folder ? encodePath(folder) + '/' + encodeURIComponent(name) : encodeURIComponent(name);
  const existing = shareMap.get(key);
  activeShareType = 'file';
  activeSharePath = key;
  activeShareName = name;
  if (existing) {
    showShareDialog(name, existing.token, existing);
    return;
  }
  showShareDialogNew(name);
}

function shareFolder(name) {
  const fullPath = currentFolder ? currentFolder + '/' + name : name;
  const key = encodePath(fullPath);
  const existing = shareMap.get(key);
  activeShareType = 'folder';
  activeSharePath = key;
  activeShareName = name;
  if (existing) {
    showShareDialog(name, existing.token, existing);
    return;
  }
  showShareDialogNew(name);
}

// 新建分享的弹窗
function showShareDialogNew(name) {
  activeShareToken = null;
  document.getElementById('shareModalTitle').textContent = '🔗 创建分享';
  document.getElementById('shareTargetName').textContent = name;
  document.getElementById('shareUrlInput').value = '';
  document.getElementById('shareUrlInput').style.display = 'none';
  document.getElementById('shareCreateForm').style.display = 'block';
  document.getElementById('shareInfoPanel').style.display = 'none';
  document.getElementById('shareNewPasswordGroup').style.display = 'none';
  document.getElementById('shareExtendGroup').style.display = 'none';
  document.getElementById('btnCreateShare').style.display = 'inline-flex';
  document.getElementById('btnUpdateShare').style.display = 'none';
  document.getElementById('btnCancelShare').style.display = 'none';
  document.getElementById('btnCopyShareWithPw').style.display = 'none';
  document.getElementById('sharePassword').value = '';
  document.getElementById('shareExpiry').value = '';
  document.getElementById('shareModal').style.display = 'flex';
}

// 已有分享的弹窗
function showShareDialog(name, token, shareData) {
  activeShareToken = token;
  document.getElementById('shareModalTitle').textContent = '🔗 分享详情';
  document.getElementById('shareTargetName').textContent = name;
  document.getElementById('shareUrlInput').value = location.origin + '/s/' + token;
  document.getElementById('shareUrlInput').style.display = 'block';
  document.getElementById('shareCreateForm').style.display = 'none';
  document.getElementById('shareInfoPanel').style.display = 'block';
  document.getElementById('shareNewPasswordGroup').style.display = 'block';
  document.getElementById('shareExtendGroup').style.display = 'block';
  document.getElementById('btnCreateShare').style.display = 'none';
  document.getElementById('btnUpdateShare').style.display = 'inline-flex';
  document.getElementById('btnCancelShare').style.display = 'inline-flex';
  document.getElementById('btnCopyShareWithPw').style.display = shareData.hasPassword ? 'inline-flex' : 'none';
  document.getElementById('shareNewPassword').value = '';

  // 显示状态
  const expired = shareData.expiresAt && new Date(shareData.expiresAt) < new Date();
  document.getElementById('shareInfoStatus').innerHTML = expired
    ? '<span class="badge badge-expired">已过期</span>'
    : '<span class="badge badge-active">有效</span>';
  document.getElementById('shareInfoPassword').textContent = shareData.hasPassword ? '已设置' : '未设置';
  document.getElementById('shareInfoExpiry').textContent = shareData.expiresAt
    ? new Date(shareData.expiresAt).toLocaleString()
    : '永不过期';

  document.getElementById('shareModal').style.display = 'flex';
}

function closeShareModal() {
  document.getElementById('shareModal').style.display = 'none';
  activeShareToken = null;
  activeShareType = null;
  activeSharePath = null;
  activeShareName = null;
  activeSharePassword = null;
}

function copyShareUrl() {
  const input = document.getElementById('shareUrlInput');
  if (!input.value) { toast('请先创建分享', 'error'); return; }
  copyToClipboard(input.value);
  toast('链接已复制到剪贴板', 'success');
}

async function copyActiveShareUrlWithPw() {
  if (!activeShareToken) return;
  let pw = activeSharePassword;
  if (!pw) {
    const result = await showDialog({
      title: '🔐 输入分享密码',
      type: 'text',
      placeholder: '输入此分享的密码',
      content: '密码不会从服务端明文返回；输入后生成带密码的访问链接。',
      buttons: [{ text: '取消', cls: 'outline', value: null }, { text: '复制', cls: 'primary', value: 'ok' }]
    });
    if (!result || result.value !== 'ok' || !result.input) return;
    pw = result.input;
    activeSharePassword = pw;
  }
  const url = location.origin + '/s/' + activeShareToken + '?pw=' + encodeURIComponent(pw);
  copyToClipboard(url);
  toast('带密码链接已复制（访问时无需输入密码）', 'success');
}

function copyToClipboard(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text);
  } else {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta);
    ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
  }
}

function togglePasswordVisible(id) {
  const el = document.getElementById(id);
  el.type = el.type === 'password' ? 'text' : 'password';
}

function onExpiryChange() {
  const val = document.getElementById('shareExpiry').value;
  document.getElementById('customExpiryWrap').style.display = val === 'custom' ? 'block' : 'none';
}

function getExpiresIn() {
  const select = document.getElementById('shareExpiry');
  if (select.value === 'custom') {
    const days = parseInt(document.getElementById('shareExpiryCustom').value) || 0;
    return days > 0 ? days * 86400 : null;
  }
  return select.value ? parseInt(select.value) : null;
}

function getExtendExpiresIn() {
  const select = document.getElementById('shareExtendExpiry');
  if (select.value === 'custom') {
    const days = parseInt(document.getElementById('shareExtendCustom').value) || 0;
    return days > 0 ? days * 86400 : null;
  }
  return select.value ? parseInt(select.value) : null;
}

async function createShareLink() {
  const password = document.getElementById('sharePassword').value.trim() || null;
  const expiresIn = getExpiresIn();

  let body = { type: activeShareType, path: activeSharePath, name: activeShareName };
  if (password) body.password = password;
  if (expiresIn) body.expiresIn = expiresIn;

  try {
    const res = await fetch('/api/share', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (data.success) {
      shareMap.set(activeSharePath, data.share);
      activeSharePassword = password;
      showShareDialog(activeShareName, data.share.token, data.share);
      renderFileList();
      toast('分享创建成功', 'success');
    } else {
      toast(data.error, 'error');
    }
  } catch (e) { toast('创建分享失败', 'error'); }
}

async function updateShareSettings() {
  if (!activeShareToken) return;

  const newPassword = document.getElementById('shareNewPassword').value.trim();
  const extendExpiresIn = getExtendExpiresIn();

  try {
    // 修改密码
    if (newPassword !== '') {
      const res = await fetch('/api/share/' + activeShareToken, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'password', password: newPassword || null }),
      });
      const data = await res.json();
      if (!data.success) { toast(data.error, 'error'); return; }
    }

    // 续期
    if (extendExpiresIn !== null && document.getElementById('shareExtendExpiry').value !== '') {
      const res = await fetch('/api/share/' + activeShareToken, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'extend', expiresIn: extendExpiresIn || null }),
      });
      const data = await res.json();
      if (data.success) {
        // 更新 shareMap
        shareMap.set(activeSharePath, data.share);
        toast('设置已更新', 'success');
        closeShareModal();
        await loadAllShares();
        renderFileList();
      } else {
        toast(data.error, 'error');
      }
    } else if (newPassword !== '') {
      toast('密码已更新', 'success');
      await loadAllShares();
      renderFileList();
      closeShareModal();
    }
  } catch (e) { toast('更新失败', 'error'); }
}

async function cancelShare() {
  if (!activeShareToken) return;
  const cancelR = await showDialog({title:'❌ 取消分享', content:'确定取消此分享 ？分享链接将立即失效 !', buttons:[{text:'保留',cls:'outline',value:null},{text:'确认取消',cls:'danger',value:'ok'}]});
  if (!cancelR || cancelR.value !== 'ok') return;
  try {
    await fetch('/api/share/' + activeShareToken, { method: 'DELETE' });
    toast('分享已取消', 'success');
    closeShareModal();
    shareMap.clear();
    await loadAllShares();
    renderFileList();
  } catch (e) { toast('取消失败', 'error'); }
}

// ── 分享管理面板 ──
async function showSharesList() {
  try {
    const res = await fetch('/api/shares');
    const data = await res.json();
    const shares = data.shares || [];

    const list = document.getElementById('sharesManageList');
    if (shares.length === 0) {
      list.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-secondary);">📭 暂无分享链接</div>';
    } else {
      let html = '<table class="shares-table"><thead><tr><th>名称</th><th>类型</th><th>过期时间</th><th>密码</th><th>状态</th><th>操作</th></tr></thead><tbody>';
      for (const s of shares) {
        const expired = s.expiresAt && new Date(s.expiresAt) < new Date();
        html += '<tr>'
          + '<td><strong>' + escapeHtml(s.name) + '</strong></td>'
          + '<td><span class="badge ' + (s.type === 'folder' ? 'badge-folder' : 'badge-file') + '">' + (s.type === 'folder' ? '📂' : '📄') + ' ' + (s.type === 'folder' ? '文件夹' : '文件') + '</span></td>'
          + '<td>' + (s.expiresAt ? new Date(s.expiresAt).toLocaleString() : '<span style=\"color:var(--text-secondary);\">永不过期</span>') + '</td>'
          + '<td>' + (s.hasPassword ? '🔒 已设' : '<span style=\"color:var(--text-secondary);\">—</span>') + '</td>'
          + '<td>' + (expired ? '<span class="badge badge-expired">已过期</span>' : '<span class="badge badge-active">有效</span>') + '</td>'
          + '<td style="white-space:nowrap;">'
          + '<button class="btn-icon" onclick="copyShareUrlFromList(\\'' + s.token + '\\')" title="复制链接">🔗</button>'
          + (s.hasPassword ? '<button class="btn-icon" onclick="copyShareUrlWithPw(\\'' + s.token + '\\')" title="复制带密码链接">🔐</button>' : '')
          + '<button class="btn-icon" onclick="extendShareFromList(\\'' + s.token + '\\')" title="续期">🔄</button>'
          + '<button class="btn-icon" onclick="changePasswordFromList(\\'' + s.token + '\\')" title="修改密码">🔑</button>'
          + '<button class="btn-icon danger" onclick="cancelShareFromList(\\'' + s.token + '\\')" title="取消分享">❌</button>'
          + '</td></tr>';
      }
      html += '</tbody></table>';
      list.innerHTML = html;
    }
    document.getElementById('sharesManageModal').style.display = 'flex';
  } catch (e) { toast('获取分享列表失败', 'error'); }
}

function copyShareUrlFromList(token) {
  const url = location.origin + '/s/' + token;
  copyToClipboard(url);
  toast('链接已复制', 'success');
}

async function copyShareUrlWithPw(token) {
  const result = await showDialog({title:'🔐 输入密码', type:'text', placeholder:'输入此分享的密码', content:'输入密码后生成带密码的链接，访问时无需手动输入', buttons:[{text:'取消',cls:'outline',value:null},{text:'复制',cls:'primary',value:'ok'}]});
  if (result && result.value === 'ok' && result.input) {
    const url = location.origin + '/s/' + token + '?pw=' + encodeURIComponent(result.input);
    copyToClipboard(url);
    toast('带密码链接已复制', 'success');
  }
}

async function extendShareFromList(token) {
  const extResult = await showDialog({title:'🔄 续期分享', type:'number', placeholder:'输入天数 (0 = 永不过期)', value:'30', content:'输入续期天数 (0 或留空 = 永不过期)', buttons:[{text:'取消',cls:'outline',value:null},{text:'续期',cls:'primary',value:'ok'}]});
  if (!extResult || extResult.value !== 'ok') return;
  const days = extResult.input;
  const expiresIn = days && parseInt(days) > 0 ? parseInt(days) * 86400 : null;
  try {
    const res = await fetch('/api/share/' + token, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'extend', expiresIn }),
    });
    const data = await res.json();
    if (data.success) {
      toast('续期成功', 'success');
      showSharesList(); // 刷新列表
    } else {
      toast(data.error, 'error');
    }
  } catch (e) { toast('续期失败', 'error'); }
}

async function changePasswordFromList(token) {
  const pwResult = await showDialog({title:'🔑 修改密码', type:'text', placeholder:'输入新密码 (留空 = 移除密码)', content:'输入新密码 (留空 = 移除密码)', buttons:[{text:'取消',cls:'outline',value:null},{text:'保存',cls:'primary',value:'ok'}]});
  if (!pwResult || pwResult.value !== 'ok') return;
  const password = pwResult.input;
  try {
    const res = await fetch('/api/share/' + token, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'password', password: password || null }),
    });
    const data = await res.json();
    if (data.success) {
      toast(password ? '密码已设置' : '密码已移除', 'success');
      showSharesList();
    } else {
      toast(data.error, 'error');
    }
  } catch (e) { toast('修改密码失败', 'error'); }
}

async function cancelShareFromList(token) {
  const cxlResult = await showDialog({title:'❌ 取消分享', content:'确定取消此分享？', buttons:[{text:'保留',cls:'outline',value:null},{text:'确认取消',cls:'danger',value:'ok'}]});
  if (!cxlResult || cxlResult.value !== 'ok') return;
  try {
    await fetch('/api/share/' + token, { method: 'DELETE' });
    toast('分享已取消', 'success');
    shareMap.clear();
    await loadAllShares();
    renderFileList();
    showSharesList(); // 刷新列表
  } catch (e) { toast('取消失败', 'error'); }
}

// ── 工具函数 ──
function fileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();
  const map = {
    jpg:'🖼', jpeg:'🖼', png:'🖼', gif:'🖼', webp:'🖼', svg:'🖼',
    pdf:'📕', doc:'📝', docx:'📝', xls:'📊', xlsx:'📊', ppt:'📽', pptx:'📽',
    zip:'📦', rar:'📦', '7z':'📦', gz:'📦',
    mp3:'🎵', wav:'🎵', flac:'🎵',
    mp4:'🎬', avi:'🎬', mov:'🎬', mkv:'🎬',
    js:'💛', ts:'💙', py:'🐍', html:'🌐', css:'🎨', json:'📋',
    txt:'📄', md:'📝',
  };
  return map[ext] || '📎';
}

function formatSize(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const u = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(bytes)/Math.log(1024));
  return (bytes/Math.pow(1024,i)).toFixed(i>0?1:0) + ' ' + u[i];
}

function encodePath(path) {
  return (path || '').split('/').filter(Boolean).map(encodeURIComponent).join('/');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML.replace(/'/g, '&#39;');
}

function escapeJsArg(str) {
  return escapeHtml(String(str || '').replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'").replace(/\\r/g, '\\\\r').replace(/\\n/g, '\\\\n'));
}

function toast(msg, type) {
  const container = document.getElementById('toastContainer');
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}
</script>
</body>
</html>`;
}

// =============================================================================
// HTML 模板 - 分享访问页面
// =============================================================================

function sharePageHTML(token) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudShare</title>
<style>
  :root {
    --bg: #f0f2f5;
    --surface: #ffffff;
    --primary: #3b82f6;
    --primary-hover: #2563eb;
    --danger: #ef4444;
    --text: #1e293b;
    --text-secondary: #64748b;
    --border: #e2e8f0;
    --radius: 16px;
    --radius-sm: 10px;
    --shadow: 0 4px 16px rgba(0,0,0,0.06), 0 1px 4px rgba(0,0,0,0.04);
    --shadow-lg: 0 12px 40px rgba(0,0,0,0.1);
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    padding: 24px;
  }
  .card {
    background: var(--surface);
    border-radius: var(--radius);
    box-shadow: var(--shadow-lg);
    max-width: 640px;
    width: 100%;
    overflow: hidden;
    animation: slideUp 0.3s ease;
  }
  .card-header {
    background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
    padding: 32px 28px;
    color: #fff;
    text-align: center;
  }
  .card-header .share-icon { font-size: 48px; display: block; margin-bottom: 8px; }
  .card-header h2 { font-size: 22px; font-weight: 700; word-break: break-all; }
  .card-header .share-meta { font-size: 13px; opacity: 0.85; margin-top: 6px; }
  .card-body { padding: 24px 28px; }
  .card-footer { text-align: center; padding: 16px 28px 28px; color: var(--text-secondary); font-size: 12px; }

  /* ── 文件表格 ── */
  .file-table { width: 100%; border-collapse: collapse; }
  .file-table th { text-align: left; font-size: 11px; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.5px; padding: 8px 12px; border-bottom: 2px solid var(--border); }
  .file-table td { padding: 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  .file-table tr:last-child td { border-bottom: none; }
  .file-table tr:hover td { background: #f8fafc; }
  .file-icon { font-size: 28px; margin-right: 10px; vertical-align: middle; }
  .file-name { font-size: 14px; font-weight: 500; vertical-align: middle; word-break: break-all; color: var(--text); }
  .size-col { color: var(--text-secondary); font-size: 13px; white-space: nowrap; width: 80px; }
  .action-col { text-align: right; width: 100px; }

  .btn-download {
    display: inline-block; padding: 8px 18px; background: var(--primary); color: #fff;
    text-decoration: none; border-radius: 20px; font-size: 13px; font-weight: 500;
    transition: all 0.2s; border: none; cursor: pointer; white-space: nowrap;
  }
  .btn-download:hover { background: var(--primary-hover); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59,130,246,0.3); }

  .big-download {
    display: block; width: 100%; padding: 16px; background: var(--primary); color: #fff;
    text-align: center; text-decoration: none; border-radius: var(--radius-sm);
    font-size: 16px; font-weight: 600; margin-top: 8px; transition: all 0.2s; border: none; cursor: pointer;
  }
  .big-download:hover { background: var(--primary-hover); transform: translateY(-2px); box-shadow: 0 8px 24px rgba(59,130,246,0.3); }

  /* ── 密码表单 ── */
  .pw-form { text-align: center; padding: 8px 0; }
  .pw-form h3 { font-size: 16px; margin-bottom: 16px; color: var(--text); }
  .pw-input {
    width: 100%; padding: 12px 16px; border: 2px solid var(--border);
    border-radius: var(--radius-sm); font-size: 15px; text-align: center;
    outline: none; transition: border-color 0.2s; letter-spacing: 2px;
  }
  .pw-input:focus { border-color: var(--primary); }
  .pw-error { color: var(--danger); font-size: 13px; margin-top: 8px; display: none; }
  .pw-submit {
    margin-top: 16px; width: 100%; padding: 12px; background: var(--primary);
    color: #fff; border: none; border-radius: var(--radius-sm); font-size: 15px;
    font-weight: 500; cursor: pointer; transition: background 0.2s;
  }
  .pw-submit:hover { background: var(--primary-hover); }
  .pw-submit:disabled { opacity: 0.6; cursor: not-allowed; }

  /* ── 状态提示 ── */
  .status-box { text-align: center; padding: 20px; }
  .status-box .icon { font-size: 56px; }
  .status-box h3 { margin: 12px 0 6px; font-size: 18px; }
  .status-box p { color: var(--text-secondary); font-size: 14px; }
  .status-box .expiry-note { font-size: 13px; color: var(--text-secondary); margin-top: 4px; }
  .loader {
    display: inline-block; width: 36px; height: 36px;
    border: 3px solid var(--border); border-top-color: var(--primary);
    border-radius: 50%; animation: spin 0.6s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes slideUp { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }

  @media (max-width: 500px) {
    .card-header { padding: 24px 16px; }
    .card-body { padding: 16px; }
    .file-table { font-size: 12px; }
    .btn-download { padding: 6px 14px; font-size: 12px; }
  }
</style>
</head>
<body>

<div class="card">
  <div id="cardContent"></div>
  <div class="card-footer">Powered by <strong>CloudShare</strong></div>
</div>

<script>
const TOKEN = '${token}';
let SHARE_PASSWORD = new URLSearchParams(window.location.search).get('pw') || '';

function shareQuery() {
  return SHARE_PASSWORD ? '?pw=' + encodeURIComponent(SHARE_PASSWORD) : '';
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML.replace(/'/g, '&#39;');
}

function fmtSize(b) {
  if (!b || b === 0) return '0 B';
  const u = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(b)/Math.log(1024));
  return (b/Math.pow(1024,i)).toFixed(i>0?1:0) + ' ' + u[i];
}

function fileEmoji(n) {
  const ext = (n||'').split('.').pop()?.toLowerCase();
  const m = {jpg:'🖼',jpeg:'🖼',png:'🖼',gif:'🖼',webp:'🖼',svg:'🖼',pdf:'📕',doc:'📝',docx:'📝',xls:'📊',xlsx:'📊',ppt:'📽',pptx:'📽',zip:'📦',rar:'📦','7z':'📦',gz:'📦',mp3:'🎵',wav:'🎵',flac:'🎵',mp4:'🎬',avi:'🎬',mov:'🎬',mkv:'🎬',js:'💛',ts:'💙',py:'🐍',html:'🌐',css:'🎨',json:'📋',txt:'📄',md:'📝'};
  return m[ext] || '📎';
}

function renderLoading() {
  document.getElementById('cardContent').innerHTML = '<div class="card-header"><span class="share-icon">☁</span><h2>CloudShare</h2></div><div class="card-body"><div class="status-box"><div class="loader"></div><p style="margin-top:12px;">加载中...</p></div></div>';
}

function renderExpired(name) {
  document.getElementById('cardContent').innerHTML = '<div class="card-header"><span class="share-icon">⏰</span><h2>' + esc(name) + '</h2></div><div class="card-body"><div class="status-box"><div class="icon">⏰</div><h3>分享已过期</h3><p>此分享链接已超过有效期，请联系分享者重新获取。</p></div></div>';
}

function renderNotFound(msg) {
  document.getElementById('cardContent').innerHTML = '<div class="card-header"><span class="share-icon">🔗</span><h2>链接无效</h2></div><div class="card-body"><div class="status-box"><div class="icon">🔗</div><h3>' + esc(msg||'分享不存在') + '</h3><p>分享链接可能已被删除或从未存在。</p></div></div>';
}

function renderPasswordForm(name) {
  document.getElementById('cardContent').innerHTML = '<div class="card-header"><span class="share-icon">🔒</span><h2>' + esc(name) + '</h2><div class="share-meta">此分享需要密码访问</div></div><div class="card-body"><div class="pw-form"><h3>请输入访问密码</h3><input type="password" class="pw-input" id="pwInput" placeholder="输入密码" autofocus onkeydown="if(event.key===\\'Enter\\')verifyAndShow()"><div class="pw-error" id="pwError">密码错误，请重试</div><button class="pw-submit" id="pwSubmit" onclick="verifyAndShow()">🔓 验证并访问</button></div></div>';
}

async function verifyAndShow() {
  const pw = document.getElementById('pwInput').value;
  const btn = document.getElementById('pwSubmit');
  const err = document.getElementById('pwError');
  if (!pw) { err.style.display = 'block'; err.textContent = '请输入密码'; return; }
  btn.disabled = true;
  btn.textContent = '验证中...';
  try {
    const res = await fetch('/api/share/' + TOKEN + '/verify', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({password: pw}),
    });
    const data = await res.json();
    if (data.valid) {
      SHARE_PASSWORD = pw;
      await loadAndRender();
    } else {
      err.style.display = 'block';
      err.textContent = data.expired ? '分享已过期' : '密码错误，请重试';
      btn.disabled = false;
      btn.textContent = '🔓 验证并访问';
    }
  } catch (e) {
    err.style.display = 'block';
    err.textContent = '验证失败，请重试';
    btn.disabled = false;
    btn.textContent = '🔓 验证并访问';
  }
}

function renderFiles(shareData) {
  const { type, name, files } = shareData;
  const token = TOKEN;
  const expiryInfo = shareData.expiresAt
    ? (new Date(shareData.expiresAt) < new Date()
      ? '<span style="color:#fbbf24;">已过期</span>'
      : '将在 ' + new Date(shareData.expiresAt).toLocaleString() + ' 过期')
    : '永不过期';

  let bodyHtml = '';

  if (type === 'file' && files.length === 1) {
    bodyHtml = '<div style="text-align:center;">'
      + '<div style="font-size:64px;padding:24px;">' + fileEmoji(files[0].name) + '</div>'
      + '<div style="color:var(--text-secondary);margin-bottom:8px;">' + fmtSize(files[0].size) + '</div>'
      + '<a href="/dl/' + token + shareQuery() + '" class="big-download">⬇ 下载文件</a>'
      + '</div>';
  } else {
    bodyHtml = (type === 'folder' && files.length > 1
      ? '<div style="margin-bottom:16px;text-align:right;"><span style="font-size:13px;color:var(--text-secondary);">共 ' + files.length + ' 个文件 — 请逐个下载</span></div>'
      : '');
    bodyHtml += '<table class="file-table"><thead><tr><th>文件名</th><th>大小</th><th></th></tr></thead><tbody>';
    for (const f of files) {
      const dlUrl = type === 'file'
        ? '/dl/' + token + shareQuery()
        : '/dl/' + token + '/' + encodeURIComponent(f.name) + shareQuery();
      bodyHtml += '<tr><td><span class="file-icon">' + fileEmoji(f.name) + '</span><span class="file-name">' + esc(f.name) + '</span></td><td class="size-col">' + fmtSize(f.size) + '</td><td class="action-col"><a href="' + dlUrl + '" class="btn-download" download>⬇ 下载</a></td></tr>';
    }
    bodyHtml += '</tbody></table>';
  }

  document.getElementById('cardContent').innerHTML =
    '<div class="card-header">'
    + '<span class="share-icon">' + (type === 'folder' ? '📂' : '📄') + '</span>'
    + '<h2>' + esc(name) + '</h2>'
    + '<div class="share-meta">' + (type === 'folder' ? '共享文件夹' : '共享文件') + ' · ' + files.length + ' 个文件 · ' + expiryInfo + '</div>'
    + '</div>'
    + '<div class="card-body">' + bodyHtml + '</div>';
}

async function loadAndRender() {
  renderLoading();
  try {
    const res = await fetch('/api/share/' + TOKEN + shareQuery());
    if (res.status === 404) {
      const data = await res.json();
      renderNotFound(data.error);
      return;
    }
    const data = await res.json();
    if (data.error) {
      renderNotFound(data.error);
      return;
    }
    // 检查过期
    if (data.expired) {
      renderExpired(data.name);
      return;
    }
    // 检查密码
    if (data.hasPassword) {
      if (data.passwordRequired) {
        // 检测 URL 中是否带有密码参数
        const urlParams = new URLSearchParams(window.location.search);
        const pwFromUrl = urlParams.get('pw');
        if (pwFromUrl) {
          // 自动验证
          const vRes = await fetch('/api/share/' + TOKEN + '/verify', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({password: pwFromUrl}),
          });
          const vData = await vRes.json();
          if (vData.valid) {
            SHARE_PASSWORD = pwFromUrl;
            // 清除 URL 中的密码参数（美观）
            if (window.history && window.history.replaceState) {
              window.history.replaceState({}, '', '/s/' + TOKEN);
            }
            await loadAndRender();
            return;
          } else {
            renderPasswordForm(data.name);
            return;
          }
        } else {
          renderPasswordForm(data.name);
          return;
        }
      }
    }
    renderFiles(data);
  } catch (e) {
    renderNotFound('加载失败');
  }
}

// 页面加载
loadAndRender();
</script>
</body>
</html>`;
}

// =============================================================================
// 主路由 - fetch handler
// =============================================================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // CORS 预检
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    try {
      if (request.method === 'GET' && pathname === '/login') {
        const next = safeNextPath(url.searchParams.get('next') || '/');
        if (!getAdminSessionSecret(env)) return htmlResponse(loginPageHTML(next, 'ADMIN_PASSWORD 未配置'), 500);
        if (await verifyAdmin(request, env)) return redirectResponse(next);
        const error = url.searchParams.get('error') ? '凭据错误，请重试' : '';
        return htmlResponse(loginPageHTML(next, error));
      }

      if (request.method === 'POST' && pathname === '/api/login') {
        return await handleLogin(request, env);
      }

      if ((request.method === 'POST' || request.method === 'GET') && pathname === '/api/logout') {
        return handleLogout(request);
      }

      if (isAdminRoute(request.method, pathname)) {
        const authError = await requireAdmin(request, env);
        if (authError) return authError;
      }

      // ── 静态页面路由 ──

      // GET / - 管理主页
      if (request.method === 'GET' && pathname === '/') {
        return htmlResponse(mainPageHTML());
      }

      // GET /manage - 分享管理独立页面
      if (request.method === 'GET' && pathname === '/manage') {
        return htmlResponse(managePageHTML());
      }

      // GET /s/:token - 分享访问页面 (客户端动态渲染)
      if (request.method === 'GET' && pathname.startsWith('/s/')) {
        const token = pathname.slice(3).split('/')[0];
        if (!token || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) {
          return htmlResponse(notFoundHTML('无效的分享链接'), 404);
        }

        // 快速检查分享是否存在
        const shareData = await env.cloudshare_shares.get(`share:${token}`, 'json');
        if (!shareData) {
          return htmlResponse(notFoundHTML(), 404);
        }

        return htmlResponse(sharePageHTML(token));
      }

      // ── 下载路由 ──
      // GET /dl/:token
      // GET /dl/:token/:filename
      if (request.method === 'GET' && pathname.startsWith('/dl/')) {
        const parts = pathname.slice(4).split('/').filter(Boolean);
        const token = parts[0];
        if (!token || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) {
          return errorResponse('无效的下载链接', 404);
        }
        const filename = parts.length > 1 ? decodeURIComponent(parts.slice(1).join('/')) : null;
        return await handleDownload(request, env, token, filename);
      }

      // ── API 路由 ──

      // POST /api/upload
      if (request.method === 'POST' && pathname === '/api/upload') {
        return await handleUpload(request, env);
      }

      // POST /api/upload/dedup - 内容已存在时仅创建目录指针
      if (request.method === 'POST' && pathname === '/api/upload/dedup') {
        return await handleDedupUpload(request, env);
      }

      // POST /api/upload/init - 分片上传初始化
      if (request.method === 'POST' && pathname === '/api/upload/init') {
        return await handleChunkedInit(request, env);
      }

      // POST /api/upload/part - 上传分片
      if (request.method === 'POST' && pathname === '/api/upload/part') {
        return await handleChunkedPart(request, env);
      }

      // POST /api/upload/complete - 完成分片上传
      if (request.method === 'POST' && pathname === '/api/upload/complete') {
        return await handleChunkedComplete(request, env);
      }

      // DELETE /api/upload/abort - 取消分片上传
      if (request.method === 'DELETE' && pathname === '/api/upload/abort') {
        return await handleChunkedAbort(request, env);
      }

      // POST /api/folders
      if (request.method === 'POST' && pathname === '/api/folders') {
        return await handleCreateFolder(request, env);
      }

      // POST /api/share
      if (request.method === 'POST' && pathname === '/api/share') {
        return await handleCreateShare(request, env);
      }

      // GET /api/shares
      if (request.method === 'GET' && pathname === '/api/shares') {
        return await handleListShares(request, env);
      }

      // POST /api/share/:token/verify - 验证分享密码
      if (request.method === 'POST' && pathname.startsWith('/api/share/') && pathname.endsWith('/verify')) {
        const token = pathname.slice('/api/share/'.length, -'/verify'.length);
        return await handleVerifyPassword(request, env, token);
      }

      // PUT /api/share/:token - 更新分享设置
      if (request.method === 'PUT' && pathname.startsWith('/api/share/')) {
        const token = pathname.slice('/api/share/'.length);
        return await handleUpdateShare(request, env, token);
      }

      // GET /api/share/:token
      if (request.method === 'GET' && pathname.startsWith('/api/share/')) {
        const token = pathname.slice('/api/share/'.length);
        return await handleGetShare(request, env, token);
      }

      // DELETE /api/share/:token
      if (request.method === 'DELETE' && pathname.startsWith('/api/share/')) {
        const token = pathname.slice('/api/share/'.length);
        return await handleDeleteShare(request, env, token);
      }

      // GET /api/admin-download/:folder/:filename (管理端直链下载，folder 可多级，根目录文件=单段路径)
      if (request.method === 'GET' && pathname.startsWith('/api/admin-download/')) {
        const parts = pathname.slice('/api/admin-download/'.length).split('/').filter(Boolean);
        if (parts.length >= 1) {
          const filename = parts.pop();
          const folder = parts.join('/');
          return await handleAdminDownload(request, env, folder, filename);
        }
        return errorResponse('路径无效', 400);
      }

      // GET /api/files
      if (request.method === 'GET' && pathname === '/api/files') {
        return await handleListFiles(request, env, null);
      }

      // GET /api/files/:folder
      if (request.method === 'GET' && pathname.startsWith('/api/files/')) {
        const folder = pathname.slice('/api/files/'.length);
        if (folder) {
          return await handleListFiles(request, env, { folder });
        }
        return errorResponse('路径无效', 400);
      }

      // DELETE /api/files/:folder/:file (folder 可多级，根目录文件=单段路径)
      if (request.method === 'DELETE' && pathname.startsWith('/api/files/')) {
        const parts = pathname.slice('/api/files/'.length).split('/').filter(Boolean);
        if (parts.length >= 1) {
          const filename = parts.pop();
          const folder = parts.join('/');
          return await handleDeleteFile(request, env, folder, filename);
        }
        return errorResponse('路径无效', 400);
      }

      // DELETE /api/folders/:folder (folder 可多级)
      if (request.method === 'DELETE' && pathname.startsWith('/api/folders/')) {
        const folder = pathname.slice('/api/folders/'.length);
        if (folder) {
          return await handleDeleteFolder(request, env, folder);
        }
        return errorResponse('路径无效', 400);
      }

      // ── 文件夹路径 / GET 请求 → 返回主页（客户端从 URL 解析路径）──
      if (request.method === 'GET' && !pathname.startsWith('/api/')) {
        return htmlResponse(mainPageHTML());
      }
      // ── 其他 404 ──
      return htmlResponse(notFoundHTML('页面不存在'), 404);

    } catch (e) {
      console.error('Worker error:', e);
      return errorResponse('服务器内部错误: ' + e.message, 500);
    }
  },
};

// 404 页面
// =============================================================================
// 共享 JS 工具 — 多页面复用的客户端函数
// =============================================================================
const SHARED_JS = `
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML.replace(/'/g,'&#39;');}
function toast(m,t){const c=document.getElementById('toastContainer');const e=document.createElement('div');e.className='toast '+t;e.textContent=m;c.appendChild(e);setTimeout(()=>e.remove(),3000);}
function copyToClipboard(t){if(navigator.clipboard){navigator.clipboard.writeText(t)}else{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');document.body.removeChild(a)}}
function showDialog(o){return new Promise(r=>{const ov=document.getElementById('genericDialog');const done=v=>{ov.style.display='none';ov.onclick=null;r(v)};ov.onclick=e=>{if(e.target===ov)done({value:null,input:null,cancelled:true})};document.getElementById('dialogTitle').textContent=o.title||'';const ce=document.getElementById('dialogContent');if(o.type==='text'||o.type==='number'){ce.innerHTML='<input type=\"'+o.type+'\" class=\"dialog-input\" id=\"dialogInput\" placeholder=\"'+esc(o.placeholder||'')+'\" value=\"'+esc(o.value||'')+'\" autofocus onkeydown=\"if(event.key===\\'Enter\\')document.getElementById(\\'dialogBtn0\\').click()\">'}else{ce.innerHTML='<p class=\"dialog-text\">'+esc(o.content||'')+'</p>'}const ae=document.getElementById('dialogActions');ae.innerHTML='';(o.buttons||[{text:'确定',cls:'primary',value:!0}]).forEach((b,i)=>{const btn=document.createElement('button');btn.id='dialogBtn'+i;btn.className='btn btn-'+(b.cls||'primary');btn.textContent=b.text;btn.onclick=()=>{const inp=document.getElementById('dialogInput');done({value:b.value,input:inp?inp.value:null})};ae.appendChild(btn)});ov.style.display='flex';setTimeout(()=>{const inp=document.getElementById('dialogInput');if(inp)inp.focus()},100)})}
`;

// =============================================================================
// HTML 模板 - 分享管理独立页面 (/manage)
// =============================================================================

function managePageHTML() {
  return '<!DOCTYPE html>' + `
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>分享管理 - CloudShare</title>
<style>
  :root {
    --bg: #f0f2f5; --surface: #fff; --primary: #3b82f6; --primary-hover: #2563eb;
    --danger: #ef4444; --text: #1e293b; --text-secondary: #64748b; --border: #e2e8f0;
    --radius: 12px; --radius-sm: 8px;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; }
  .topbar { background:var(--surface); border-bottom:1px solid var(--border); padding:16px 32px; display:flex; align-items:center; justify-content:space-between; }
  .topbar h1 { font-size:20px; display:flex; align-items:center; gap:8px; }
  .topbar a { color:var(--primary); text-decoration:none; font-size:14px; }
  .container { max-width:1100px; margin:24px auto; padding:0 24px; }
  .shares-table { width:100%; border-collapse:collapse; background:var(--surface); border-radius:var(--radius); overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.06); }
  .shares-table th { text-align:left; padding:12px 16px; background:#f8fafc; border-bottom:2px solid var(--border); font-size:12px; text-transform:uppercase; color:var(--text-secondary); letter-spacing:0.5px; }
  .shares-table td { padding:14px 16px; border-bottom:1px solid var(--border); font-size:14px; }
  .shares-table tr:hover td { background:#f8fafc; }
  .badge { display:inline-block; padding:2px 10px; border-radius:10px; font-size:11px; font-weight:500; }
  .badge-active { background:#dcfce7; color:#166534; }
  .badge-expired { background:#fef2f2; color:#991b1b; }
  .badge-file { background:#eff6ff; color:#1d4ed8; }
  .badge-folder { background:#fefce8; color:#854d0e; }
  .btn-icon { width:36px; height:36px; border:none; background:transparent; border-radius:8px; cursor:pointer; font-size:17px; display:inline-flex; align-items:center; justify-content:center; transition:background 0.15s; margin:0 1px; }
  .btn-icon:hover { background:#f1f5f9; }
  .btn-icon.danger:hover { background:#fef2f2; }
  .btn { padding:8px 16px; border:none; border-radius:var(--radius-sm); cursor:pointer; font-size:13px; font-weight:500; }
  .btn-outline { background:#fff; color:var(--text); border:1px solid var(--border); }
  .btn-outline:hover { background:var(--bg); }
  .btn-primary { background:var(--primary); color:#fff; }
  .btn-primary:hover { background:var(--primary-hover); }
  .btn-danger { background:var(--danger); color:#fff; }
  .empty-state { text-align:center; padding:60px; color:var(--text-secondary); }
  .toast-container { position:fixed; bottom:24px; right:24px; z-index:200; }
  .toast { padding:12px 20px; background:#1e293b; color:#f1f5f9; border-radius:var(--radius-sm); font-size:13px; margin-top:8px; }
  .toast.success { border-left:3px solid #22c55e; }
  .toast.error { border-left:3px solid #ef4444; }
  /* Dialog overlay */
  .modal-overlay { position:fixed; top:0;left:0;right:0;bottom:0; background:rgba(0,0,0,0.5); display:flex; align-items:center; justify-content:center; z-index:100; }
  .modal { background:var(--surface); border-radius:var(--radius); padding:28px; max-width:440px; width:90vw; }
  .modal h3 { margin-bottom:12px; }
  .modal-actions { display:flex; gap:8px; margin-top:16px; justify-content:flex-end; }
  .dialog-input { width:100%; padding:10px 14px; border:2px solid var(--border); border-radius:var(--radius-sm); font-size:14px; outline:none; margin:8px 0; }
  .dialog-input:focus { border-color:var(--primary); }
  .dialog-text { font-size:14px; line-height:1.5; }
  @media (max-width:768px) { .topbar { padding:12px 16px; } .container { padding:0 12px; margin-top:12px; } .shares-table { font-size:12px; } .shares-table th,.shares-table td { padding:8px 10px; } }
</style>
</head>
<body>
<div class="topbar">
  <h1><span>☁</span> CloudShare <span style="font-size:14px;color:var(--text-secondary);font-weight:400;">分享管理</span></h1>
  <div style="display:flex;gap:8px;align-items:center;">
    <a href="/" class="btn btn-outline" style="text-decoration:none;">文件管理</a>
    <a href="/api/logout" class="btn btn-outline" style="text-decoration:none;">退出登录</a>
  </div>
</div>
<div class="container">
  <div id="sharesTable"></div>
</div>
<div class="toast-container" id="toastContainer"></div>
<div class="modal-overlay" id="genericDialog" style="display:none;">
  <div class="modal"><h3 id="dialogTitle"></h3><div id="dialogContent" style="margin:12px 0;"></div><div class="modal-actions" id="dialogActions"></div></div>
</div>
<script>
${SHARED_JS}
async function loadShares(){
  try{
    const res=await fetch('/api/shares');
    const data=await res.json();
    const shares=data.shares||[];
    const el=document.getElementById('sharesTable');
    if(!shares.length){el.innerHTML='<div class=\"empty-state\"><div style=\"font-size:48px;\">📭</div><p style=\"margin-top:12px;\">暂无分享链接</p></div>';return}
    let h='<table class=\"shares-table\"><thead><tr><th>名称</th><th>类型</th><th>过期时间</th><th>密码</th><th>状态</th><th>操作</th></tr></thead><tbody>';
    for(const s of shares){
      const expired=s.expiresAt&&new Date(s.expiresAt)<new Date();
      h+='<tr><td><strong>'+esc(s.name)+'</strong></td>'
        +'<td><span class=\"badge '+(s.type==='folder'?'badge-folder':'badge-file')+'\">'+(s.type==='folder'?'📂 文件夹':'📄 文件')+'</span></td>'
        +'<td>'+(s.expiresAt?new Date(s.expiresAt).toLocaleString():'<span style=\"color:var(--text-secondary);\">永不过期</span>')+'</td>'
        +'<td>'+(s.hasPassword?'🔒 已设':'<span style=\"color:var(--text-secondary);\">—</span>')+'</td>'
        +'<td>'+(expired?'<span class=\"badge badge-expired\">已过期</span>':'<span class=\"badge badge-active\">有效</span>')+'</td>'
        +'<td style=\"white-space:nowrap;\">'
        +'<button class=\"btn-icon\" onclick=\"copyUrl(\\''+s.token+'\\')\" title=\"复制链接\">🔗</button>'
        +(s.hasPassword?'<button class=\"btn-icon\" onclick=\"copyUrlWithPw(\\''+s.token+'\\')\" title=\"复制带密码链接\">🔐</button>':'')
        +'<button class=\"btn-icon\" onclick=\"extendShare(\\''+s.token+'\\')\" title=\"续期\">🔄</button>'
        +'<button class=\"btn-icon\" onclick=\"changePw(\\''+s.token+'\\')\" title=\"修改密码\">🔑</button>'
        +'<button class=\"btn-icon danger\" onclick=\"cancelSh(\\''+s.token+'\\')\" title=\"取消分享\">❌</button>'
        +'</td></tr>';
    }
    h+='</tbody></table>';
    el.innerHTML=h;
  }catch(e){toast('加载失败','error')}
}

function copyUrl(token){copyToClipboard(location.origin+'/s/'+token);toast('链接已复制','success')}
async function copyUrlWithPw(token){
  const r=await showDialog({title:'🔐 输入密码',type:'text',placeholder:'输入此分享的密码',content:'输入密码后生成带密码的链接',buttons:[{text:'取消',cls:'outline',value:null},{text:'复制',cls:'primary',value:'ok'}]});
  if(r&&r.value==='ok'&&r.input){copyToClipboard(location.origin+'/s/'+token+'?pw='+encodeURIComponent(r.input));toast('带密码链接已复制','success')}
}
async function extendShare(token){
  const r=await showDialog({title:'🔄 续期',type:'number',placeholder:'天数 (0=永不过期)',value:'30',buttons:[{text:'取消',cls:'outline',value:null},{text:'续期',cls:'primary',value:'ok'}]});
  if(!r||r.value!=='ok')return;
  const days=r.input;const ei=days&&parseInt(days)>0?parseInt(days)*86400:null;
  const res=await fetch('/api/share/'+token,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'extend',expiresIn:ei})});
  const d=await res.json();
  if(d.success){toast('续期成功','success');loadShares()}else toast(d.error,'error')
}
async function changePw(token){
  const r=await showDialog({title:'🔑 修改密码',type:'text',placeholder:'新密码 (留空=移除)',buttons:[{text:'取消',cls:'outline',value:null},{text:'保存',cls:'primary',value:'ok'}]});
  if(!r||r.value!=='ok')return;
  const res=await fetch('/api/share/'+token,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'password',password:r.input||null})});
  const d=await res.json();
  if(d.success){toast(r.input?'密码已设置':'密码已移除','success');loadShares()}else toast(d.error,'error')
}
async function cancelSh(token){
  const r=await showDialog({title:'❌ 取消分享',content:'确定取消此分享？',buttons:[{text:'保留',cls:'outline',value:null},{text:'确认取消',cls:'danger',value:'ok'}]});
  if(!r||r.value!=='ok')return;
  await fetch('/api/share/'+token,{method:'DELETE'});
  toast('已取消','success');loadShares()
}
loadShares();
</script>
</body>
</html>`;
}

function notFoundHTML(msg) {
  const message = escapeHtmlText(msg || '页面不存在');
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${message} - CloudShare</title>
<style>
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; margin: 0;
    background: #f0f2f5; color: #1e293b;
  }
  .error-card { text-align: center; }
  .error-card .icon { font-size: 64px; }
  .error-card h2 { font-size: 24px; margin: 16px 0; }
  .error-card p { color: #64748b; }
  .error-card a { color: #3b82f6; text-decoration: none; }
</style>
</head>
<body>
<div class="error-card">
  <div class="icon">🔗</div>
  <h2>${message}</h2>
  <p>分享链接可能已过期，或文件已被删除。</p>
  <p><a href="/">→ 返回 CloudShare 主页</a></p>
</div>
</body>
</html>`;
}
