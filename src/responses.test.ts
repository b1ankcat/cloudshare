import { describe, it, expect } from "vitest";
import {
  errorResponse,
  htmlResponse,
  jsonResponse,
  notFoundResponse,
  preflightResponse,
  publicHtmlResponse,
  redirectResponse,
} from "./responses";
import type { Env } from "./types";

function envWith(origin: string | null): Env {
  return {
    FILES_BUCKET: {} as R2Bucket,
    cloudshare_shares: {} as KVNamespace,
    ADMIN_PASSWORD: "x",
    ALLOWED_ORIGIN: origin ?? undefined,
  };
}

describe("cors headers", () => {
  it("emits no CORS headers when ALLOWED_ORIGIN is empty", async () => {
    const r = htmlResponse(envWith(null), "<html></html>");
    expect(r.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });
  it("emits CORS headers when ALLOWED_ORIGIN is set", async () => {
    const r = htmlResponse(envWith("https://share.example.com"), "<html></html>");
    expect(r.headers.get("Access-Control-Allow-Origin")).toBe("https://share.example.com");
    expect(r.headers.get("Vary")).toBe("Origin");
  });
  it("emits allowed methods when set", async () => {
    const r = preflightResponse(envWith("https://x"));
    expect(r.headers.get("Access-Control-Allow-Methods")).toBe(
      "GET, POST, PUT, DELETE, OPTIONS",
    );
  });
});

describe("cache headers", () => {
  it("sensitive HTML responses are no-store", async () => {
    const r = htmlResponse(envWith(null), "<html></html>");
    expect(r.headers.get("Cache-Control")).toBe(
      "no-store, no-cache, must-revalidate, private",
    );
  });
  it("JSON responses are no-store (data must be fresh)", async () => {
    const r = jsonResponse(envWith(null), { ok: true });
    expect(r.headers.get("Cache-Control")).toBe(
      "no-store, no-cache, must-revalidate, private",
    );
  });
  it("public share HTML is cacheable", async () => {
    const r = publicHtmlResponse(envWith(null), "<html></html>");
    expect(r.headers.get("Cache-Control")).toMatch(/^public, max-age=300/);
  });
});

describe("response status", () => {
  it("jsonResponse defaults to 200", async () => {
    expect(jsonResponse(envWith(null), {}).status).toBe(200);
  });
  it("jsonResponse respects custom status", async () => {
    expect(jsonResponse(envWith(null), {}, 201).status).toBe(201);
  });
  it("errorResponse defaults to 400", async () => {
    expect(errorResponse(envWith(null), "bad").status).toBe(400);
  });
  it("notFoundResponse is 404", async () => {
    expect(notFoundResponse(envWith(null)).status).toBe(404);
  });
  it("preflightResponse is 204", async () => {
    expect(preflightResponse(envWith(null)).status).toBe(204);
  });
  it("redirectResponse defaults to 302", async () => {
    const r = redirectResponse(envWith(null), "/x");
    expect(r.status).toBe(302);
    expect(r.headers.get("Location")).toBe("/x");
  });
});

describe("response body", () => {
  it("jsonResponse serializes data", async () => {
    const r = jsonResponse(envWith(null), { a: 1 });
    expect(await r.json()).toEqual({ a: 1 });
    expect(r.headers.get("Content-Type")).toBe("application/json; charset=utf-8");
  });
  it("htmlResponse sets content type", async () => {
    const r = htmlResponse(envWith(null), "<p>x</p>");
    expect(r.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await r.text()).toBe("<p>x</p>");
  });
});
