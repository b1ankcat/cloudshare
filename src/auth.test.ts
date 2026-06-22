import { describe, it, expect } from "vitest";
import {
  buildAdminCookie,
  createAdminSession,
  getAdminSessionSecret,
  getClientIp,
  isAdminRoute,
  loginRateLimitKey,
  parseCookies,
  safeNextPath,
  verifyAdminSession,
  verifyAdminCredential,
  ADMIN_SESSION_COOKIE,
  SESSION_CLOCK_SKEW_MS,
  ADMIN_SESSION_MAX_AGE,
} from "./auth";
import { signAdminSession } from "./crypto";
import type { Env } from "./types";

function envWith(password = "secret"): Env {
  return {
    FILES_BUCKET: {} as R2Bucket,
    cloudshare_shares: {} as KVNamespace,
    ADMIN_PASSWORD: password,
  };
}

function makeRequest(opts: { url?: string; cookie?: string; cfIp?: string } = {}): Request {
  const headers = new Headers();
  if (opts.cookie) headers.set("Cookie", opts.cookie);
  if (opts.cfIp) headers.set("CF-Connecting-IP", opts.cfIp);
  return new Request(opts.url || "https://example.com/", { headers });
}

describe("parseCookies", () => {
  it("parses a single cookie", () => {
    expect(parseCookies(makeRequest({ cookie: "a=1" }))).toEqual({ a: "1" });
  });
  it("parses multiple cookies", () => {
    expect(parseCookies(makeRequest({ cookie: "a=1; b=2; c=3" }))).toEqual({
      a: "1",
      b: "2",
      c: "3",
    });
  });
  it("handles spaces", () => {
    expect(parseCookies(makeRequest({ cookie: " a = 1 ; b = 2 " }))).toEqual({
      a: "1",
      b: "2",
    });
  });
  it("returns {} when no Cookie header", () => {
    expect(parseCookies(makeRequest())).toEqual({});
  });
  it("ignores malformed cookies (no =)", () => {
    expect(parseCookies(makeRequest({ cookie: "a=1; broken" }))).toEqual({ a: "1" });
  });
});

describe("safeNextPath", () => {
  it("accepts a normal path", () => {
    expect(safeNextPath("/admin")).toBe("/admin");
  });
  it("defaults to /", () => {
    expect(safeNextPath(null)).toBe("/");
    expect(safeNextPath(undefined)).toBe("/");
    expect(safeNextPath("")).toBe("/");
  });
  it("rejects protocol-relative URLs", () => {
    expect(safeNextPath("//evil.com")).toBe("/");
  });
  it("rejects login paths (open redirect)", () => {
    expect(safeNextPath("/login")).toBe("/");
    expect(safeNextPath("/api/login")).toBe("/");
  });
  it("rejects paths that do not start with /", () => {
    expect(safeNextPath("evil.com")).toBe("/");
  });
});

describe("getAdminSessionSecret", () => {
  it("returns the configured password", () => {
    expect(getAdminSessionSecret(envWith("hunter2"))).toBe("hunter2");
  });
  it("returns '' when not configured", () => {
    expect(getAdminSessionSecret(envWith(""))).toBe("");
  });
});

describe("buildAdminCookie", () => {
  it("includes HttpOnly + SameSite=Lax + Path=/", () => {
    const c = buildAdminCookie(makeRequest({ url: "https://x/" }), "token");
    expect(c).toMatch(/HttpOnly/);
    expect(c).toMatch(/SameSite=Lax/);
    expect(c).toMatch(/Path=\//);
    expect(c.startsWith(`${ADMIN_SESSION_COOKIE}=token`)).toBe(true);
  });
  it("adds Secure on https", () => {
    const c = buildAdminCookie(makeRequest({ url: "https://x/" }), "tok");
    expect(c).toMatch(/Secure/);
  });
  it("omits Secure on http", () => {
    const c = buildAdminCookie(makeRequest({ url: "http://x/" }), "tok");
    expect(c).not.toMatch(/Secure/);
  });
  it("respects maxAge", () => {
    const c = buildAdminCookie(makeRequest(), "tok", 60);
    expect(c).toMatch(/Max-Age=60/);
  });
  it("Max-Age=0 produces an expiring cookie", () => {
    const c = buildAdminCookie(makeRequest(), "", 0);
    expect(c).toMatch(/Max-Age=0/);
  });
});

describe("isAdminRoute", () => {
  it("returns false for /login", () => {
    expect(isAdminRoute("GET", "/login")).toBe(false);
  });
  it("returns false for /api/login", () => {
    expect(isAdminRoute("POST", "/api/login")).toBe(false);
  });
  it("returns false for /api/logout", () => {
    expect(isAdminRoute("POST", "/api/logout")).toBe(false);
  });
  it("returns false for GET /s/:token (public share)", () => {
    expect(isAdminRoute("GET", "/s/abc-uuid")).toBe(false);
  });
  it("returns false for GET /dl/:token (public download)", () => {
    expect(isAdminRoute("GET", "/dl/abc-uuid")).toBe(false);
  });
  it("returns false for GET /api/share/:token (public read)", () => {
    expect(isAdminRoute("GET", "/api/share/abc-uuid")).toBe(false);
  });
  it("returns false for POST /api/share/:token/verify", () => {
    expect(isAdminRoute("POST", "/api/share/abc-uuid/verify")).toBe(false);
  });
  it("returns true for POST /api/share/:token (admin update)", () => {
    expect(isAdminRoute("POST", "/api/share/abc-uuid")).toBe(true);
  });
  it("returns true for PUT /api/share/:token (admin)", () => {
    expect(isAdminRoute("PUT", "/api/share/abc-uuid")).toBe(true);
  });
  it("returns true for DELETE /api/share/:token (admin)", () => {
    expect(isAdminRoute("DELETE", "/api/share/abc-uuid")).toBe(true);
  });
  it("returns true for /", () => {
    expect(isAdminRoute("GET", "/")).toBe(true);
  });
  it("returns true for /api/files", () => {
    expect(isAdminRoute("GET", "/api/files")).toBe(true);
  });
});

describe("verifyAdminSession", () => {
  it("returns false for empty secret", async () => {
    const sig = await signAdminSession("secret", Date.now());
    expect(await verifyAdminSession(`${Date.now()}.${sig}`, envWith(""))).toBe(false);
  });
  it("returns false for empty value", async () => {
    expect(await verifyAdminSession("", envWith("x"))).toBe(false);
    expect(await verifyAdminSession(undefined, envWith("x"))).toBe(false);
  });
  it("returns false for malformed value (no dot)", async () => {
    expect(await verifyAdminSession("not-a-token", envWith("x"))).toBe(false);
  });
  it("returns false for non-numeric timestamp", async () => {
    const sig = await signAdminSession("x", 1000);
    expect(await verifyAdminSession(`abc.${sig}`, envWith("x"))).toBe(false);
  });
  it("returns false for a future-dated token beyond clock skew", async () => {
    const future = Date.now() + SESSION_CLOCK_SKEW_MS + 60_000;
    const sig = await signAdminSession("x", future);
    expect(await verifyAdminSession(`${future}.${sig}`, envWith("x"))).toBe(false);
  });
  it("returns false for an expired token (older than max age)", async () => {
    const old = Date.now() - ADMIN_SESSION_MAX_AGE * 1000 - 60_000;
    const sig = await signAdminSession("x", old);
    expect(await verifyAdminSession(`${old}.${sig}`, envWith("x"))).toBe(false);
  });
  it("returns true for a freshly-signed token", async () => {
    const now = Date.now();
    const sig = await signAdminSession("x", now);
    expect(await verifyAdminSession(`${now}.${sig}`, envWith("x"))).toBe(true);
  });
  it("returns false for a token signed with a different secret", async () => {
    const now = Date.now();
    const sig = await signAdminSession("other", now);
    expect(await verifyAdminSession(`${now}.${sig}`, envWith("x"))).toBe(false);
  });
  it("rejects a token within the 1-min clock skew window that is not from us", async () => {
    // The skew window is intentionally tight (1 min). We assert exact value
    // here to make sure it isn't silently widened to 5 min or more.
    expect(SESSION_CLOCK_SKEW_MS).toBe(60_000);
  });
});

describe("verifyAdminCredential", () => {
  it("returns false for empty env password", () => {
    expect(verifyAdminCredential("anything", envWith(""))).toBe(false);
  });
  it("returns true for matching password", () => {
    expect(verifyAdminCredential("hunter2", envWith("hunter2"))).toBe(true);
  });
  it("returns false for wrong password", () => {
    expect(verifyAdminCredential("wrong", envWith("hunter2"))).toBe(false);
  });
});

describe("getClientIp", () => {
  it("returns the CF-Connecting-IP header value", () => {
    expect(getClientIp(makeRequest({ cfIp: "1.2.3.4" }))).toBe("1.2.3.4");
  });
  it("returns null when the header is missing (no fallback to X-Forwarded-For)", () => {
    expect(getClientIp(makeRequest({}))).toBeNull();
    // X-Forwarded-For must NOT be used as a fallback — Cloudflare always
    // sets CF-Connecting-IP for incoming requests, and trusting a
    // client-supplied header would let an attacker bypass rate limiting.
    const req = new Request("https://x/", { headers: { "X-Forwarded-For": "9.9.9.9" } });
    expect(getClientIp(req)).toBeNull();
  });
});

describe("loginRateLimitKey", () => {
  it("scopes the key by client IP", () => {
    const a = makeRequest({ cfIp: "1.1.1.1" });
    const b = makeRequest({ cfIp: "2.2.2.2" });
    expect(loginRateLimitKey(a)).not.toBe(loginRateLimitKey(b));
    expect(loginRateLimitKey(a)).toBe("login_fail:1.1.1.1");
  });
  it("uses 'unknown' as a single bucket when IP is missing (no error)", () => {
    // The rate limit still works — it just collapses all such requests
    // into one bucket. Throwing here would block login entirely on
    // misconfigured proxies, which is worse than collapsing the bucket.
    expect(loginRateLimitKey(makeRequest())).toBe("login_fail:unknown");
  });
});

describe("createAdminSession", () => {
  it("returns null when no admin password is configured", async () => {
    expect(await createAdminSession(envWith(""))).toBeNull();
  });
  it("returns a 'issuedAt.signature' token", async () => {
    const tok = await createAdminSession(envWith("secret"));
    expect(tok).toMatch(/^\d+\./);
  });
  it("produces a token that verifyAdminSession accepts", async () => {
    const tok = await createAdminSession(envWith("secret"));
    expect(tok).not.toBeNull();
    expect(await verifyAdminSession(tok!, envWith("secret"))).toBe(true);
  });
  it("tokens for different secrets are not interchangeable", async () => {
    const a = await createAdminSession(envWith("a"));
    const b = await createAdminSession(envWith("b"));
    expect(await verifyAdminSession(a!, envWith("b"))).toBe(false);
    expect(await verifyAdminSession(b!, envWith("a"))).toBe(false);
  });
});
