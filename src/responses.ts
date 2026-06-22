/**
 * Response builders. All responses include CORS headers (when an allowed
 * origin is configured) and a Cache-Control header appropriate for the kind
 * of content. Sensitive HTML pages set no-store to prevent the back button
 * from revealing stale authenticated content after logout.
 */

import type { Env } from "./types";

const PUBLIC_CACHE_CONTROL = "public, max-age=300, s-maxage=300";
const NO_STORE = "no-store, no-cache, must-revalidate, private";
const IMMUTABLE = "public, max-age=31536000, immutable";

/** Build CORS headers. If `allowedOrigin` is empty, returns empty Headers. */
export function corsHeaders(env: Env): Headers {
  const h = new Headers();
  const origin = env.ALLOWED_ORIGIN?.trim();
  if (!origin) return h;
  h.set("Access-Control-Allow-Origin", origin);
  h.set("Vary", "Origin");
  h.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type");
  h.set("Access-Control-Max-Age", "86400");
  return h;
}

/** Answer a CORS preflight. */
export function preflightResponse(env: Env): Response {
  return new Response(null, { status: 204, headers: corsHeaders(env) });
}

/** JSON response. */
export function jsonResponse(
  env: Env,
  data: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {},
): Response {
  const headers = corsHeaders(env);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", NO_STORE);
  for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  return new Response(JSON.stringify(data), { status, headers });
}

/** HTML response for sensitive pages (login, admin). */
export function htmlResponse(
  env: Env,
  html: string,
  status = 200,
  extraHeaders: Record<string, string> = {},
): Response {
  const headers = corsHeaders(env);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", NO_STORE);
  for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  return new Response(html, { status, headers });
}

/** HTML response for public share pages (cacheable for the duration set). */
export function publicHtmlResponse(
  env: Env,
  html: string,
  status = 200,
): Response {
  const headers = corsHeaders(env);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", PUBLIC_CACHE_CONTROL);
  return new Response(html, { status, headers });
}

/** Redirect response. */
export function redirectResponse(
  env: Env,
  location: string,
  status = 302,
  extraHeaders: Record<string, string> = {},
): Response {
  const headers = corsHeaders(env);
  headers.set("Location", location);
  for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  return new Response(null, { status, headers });
}

/** JSON error response with a caller-safe message (no internals). */
export function errorResponse(
  env: Env,
  message: string,
  status = 400,
): Response {
  return jsonResponse(env, { error: message }, status);
}

/** 404 response with optional message. */
export function notFoundResponse(env: Env, message?: string): Response {
  return errorResponse(env, message ?? "Not found", 404);
}

/** Headers for a 200 binary download (file body comes from the caller). */
export function immutableAssetHeaders(): Record<string, string> {
  return { "Cache-Control": IMMUTABLE };
}
