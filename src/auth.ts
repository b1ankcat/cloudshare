/**
 * Admin session, login, and rate limiting.
 *
 * The admin secret (env.ADMIN_PASSWORD) doubles as the HMAC key for session
 * tokens. A session is `issuedAt.signature` where signature is HMAC-SHA256
 * over the issued-at timestamp. The token has no server-side record — the
 * signature + freshness window is the session. Changing ADMIN_PASSWORD
 * invalidates all live sessions.
 *
 * Rate limit records (login_fail:<ip>) live in KV with a 10-minute TTL.
 */

import { signAdminSession, timingSafeEqual } from "./crypto";
import { errorResponse, redirectResponse } from "./responses";
import { BadRequestError } from "./validation";
import type { Env } from "./types";

export const ADMIN_SESSION_COOKIE = "cloudshare_admin";
export const ADMIN_SESSION_MAX_AGE = 7 * 24 * 60 * 60; // 7 days
export const SESSION_CLOCK_SKEW_MS = 60 * 1000; // 1 minute
export const LOGIN_RATE_LIMIT_WINDOW = 10 * 60; // 10 minutes (seconds for KV TTL)
export const LOGIN_RATE_LIMIT_MAX_FAILURES = 5;

const enc = new TextEncoder();

/** Parse a Cookie header into a name->value map. */
export function parseCookies(request: Request): Record<string, string> {
  const cookies: Record<string, string> = {};
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name) cookies[name] = value;
  }
  return cookies;
}

/** Get the configured admin password (empty string means not configured). */
export function getAdminSessionSecret(env: Env): string {
  return env.ADMIN_PASSWORD || "";
}

/**
 * Sanitize a `next` redirect path. Reject protocol-relative URLs and any
 * path that points at the login flow itself.
 */
export function safeNextPath(value: string | null | undefined): string {
  const next = String(value || "/");
  if (
    !next.startsWith("/") ||
    next.startsWith("//") ||
    next.startsWith("/login") ||
    next.startsWith("/api/login")
  ) {
    return "/";
  }
  return next;
}

/** Build the Set-Cookie value for a session token. */
export function buildAdminCookie(
  request: Request,
  value: string,
  maxAge = ADMIN_SESSION_MAX_AGE,
): string {
  const isHttps = new URL(request.url).protocol === "https:";
  const secure = isHttps ? "; Secure" : "";
  return `${ADMIN_SESSION_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${secure}`;
}

/** Read the client IP from CF-Connecting-IP. Returns null if missing. */
export function getClientIp(request: Request): string | null {
  return request.headers.get("CF-Connecting-IP");
}

/** Compose a rate-limit key for a request's IP. */
export function loginRateLimitKey(request: Request): string {
  const ip = getClientIp(request) || "unknown";
  return `login_fail:${ip}`;
}

interface LoginFailure {
  count: number;
}

export async function getLoginFailures(
  request: Request,
  env: Env,
): Promise<LoginFailure> {
  const raw = await env.cloudshare_shares.get(loginRateLimitKey(request), "json");
  if (!raw || typeof raw !== "object") return { count: 0 };
  const count = Number((raw as LoginFailure).count) || 0;
  return { count };
}

export async function recordLoginFailure(
  request: Request,
  env: Env,
): Promise<void> {
  const key = loginRateLimitKey(request);
  const current = await getLoginFailures(request, env);
  await env.cloudshare_shares.put(
    key,
    JSON.stringify({ count: current.count + 1 }),
    { expirationTtl: LOGIN_RATE_LIMIT_WINDOW },
  );
}

export async function clearLoginFailures(
  request: Request,
  env: Env,
): Promise<void> {
  await env.cloudshare_shares.delete(loginRateLimitKey(request));
}

/** Create a new session token. Returns null if no admin password is set. */
export async function createAdminSession(env: Env): Promise<string | null> {
  const secret = getAdminSessionSecret(env);
  if (!secret) return null;
  const issuedAt = Date.now();
  const signature = await signAdminSession(secret, issuedAt);
  return `${issuedAt}.${signature}`;
}

/**
 * Verify a session token. Returns true iff the signature matches AND the
 * issuedAt is within the validity window (now - MAX_AGE .. now + skew).
 * Clock skew is intentionally tight (1 minute).
 */
export async function verifyAdminSession(
  value: string | undefined,
  env: Env,
): Promise<boolean> {
  const secret = getAdminSessionSecret(env);
  if (!secret || !value) return false;
  const dotIdx = value.indexOf(".");
  if (dotIdx === -1) return false;
  const issuedAtRaw = value.slice(0, dotIdx);
  const signature = value.slice(dotIdx + 1);
  if (!signature) return false;
  const issuedAt = Number(issuedAtRaw);
  if (!Number.isFinite(issuedAt)) return false;
  const now = Date.now();
  if (issuedAt > now + SESSION_CLOCK_SKEW_MS) return false;
  if (now - issuedAt > ADMIN_SESSION_MAX_AGE * 1000) return false;
  const expected = await signAdminSession(secret, issuedAt);
  return timingSafeEqual(signature, expected);
}

/** true iff the current request's session cookie is valid. */
export async function verifyAdmin(request: Request, env: Env): Promise<boolean> {
  return await verifyAdminSession(parseCookies(request)[ADMIN_SESSION_COOKIE], env);
}

/** Constant-time check of a login credential against the configured password. */
export function verifyAdminCredential(input: string, env: Env): boolean {
  const password = getAdminSessionSecret(env);
  if (!password) return false;
  return timingSafeEqual(String(input || ""), password);
}

/**
 * If the request is not authenticated, return a Response (302 to login or
 * 500 with config error). Returns null when authenticated.
 */
export async function requireAdmin(
  request: Request,
  env: Env,
): Promise<Response | null> {
  if (await verifyAdmin(request, env)) return null;
  if (!getAdminSessionSecret(env)) {
    return errorResponse(env, "ADMIN_PASSWORD 未配置", 500);
  }
  const url = new URL(request.url);
  const next = encodeURIComponent(url.pathname + url.search);
  return redirectResponse(env, `/login?next=${next}`);
}

/**
 * Routes that do NOT require admin auth. Anything else in the dispatch
 * table triggers `requireAdmin`.
 */
export function isAdminRoute(method: string, pathname: string): boolean {
  if (
    pathname === "/login" ||
    pathname === "/api/login" ||
    pathname === "/api/logout"
  ) {
    return false;
  }
  if (method === "GET" && (pathname.startsWith("/s/") || pathname.startsWith("/dl/"))) {
    return false;
  }
  if (method === "GET" && pathname.startsWith("/api/share/")) return false;
  if (
    method === "POST" &&
    pathname.startsWith("/api/share/") &&
    pathname.endsWith("/verify")
  ) {
    return false;
  }
  return true;
}

/** Re-export shared error for handler translation. */
export { BadRequestError };
