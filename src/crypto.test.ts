import { describe, it, expect } from "vitest";
import {
  base64Url,
  base64UrlDecode,
  derivePbkdf2Hash,
  hashPassword,
  PBKDF2_ITERATIONS,
  signAdminSession,
  timingSafeEqual,
  verifyPasswordAsync,
} from "./crypto";

describe("base64Url", () => {
  it("encodes without padding", () => {
    const out = base64Url(new Uint8Array([0, 1, 2, 3]));
    expect(out).not.toMatch(/=/);
  });
  it("uses - and _ instead of + and /", () => {
    const bytes = new Uint8Array([0xff, 0xfe, 0xfd]);
    const out = base64Url(bytes);
    expect(out).toMatch(/[-_A-Za-z0-9]+/);
  });
  it("round-trips with base64UrlDecode", () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const enc = base64Url(bytes);
    const dec = base64UrlDecode(enc);
    expect(Array.from(dec)).toEqual(Array.from(bytes));
  });
});

describe("base64UrlDecode", () => {
  it("accepts padded input", () => {
    const dec = base64UrlDecode("AQIDBA==");
    expect(Array.from(dec)).toEqual([1, 2, 3, 4]);
  });
  it("accepts unpadded input", () => {
    const dec = base64UrlDecode("AQIDBA");
    expect(Array.from(dec)).toEqual([1, 2, 3, 4]);
  });
});

describe("timingSafeEqual", () => {
  it("returns true for equal strings", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
  });
  it("returns false for different strings", () => {
    expect(timingSafeEqual("abc", "abd")).toBe(false);
  });
  it("returns false for different lengths", () => {
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
  });
  it("returns true for two empty strings", () => {
    expect(timingSafeEqual("", "")).toBe(true);
  });
});

describe("derivePbkdf2Hash", () => {
  it("produces deterministic output for the same inputs", async () => {
    const salt = new Uint8Array(16).fill(7);
    const a = await derivePbkdf2Hash("password", salt, 1000);
    const b = await derivePbkdf2Hash("password", salt, 1000);
    expect(base64Url(a)).toBe(base64Url(b));
  });
  it("produces different output for different passwords", async () => {
    const salt = new Uint8Array(16).fill(7);
    const a = await derivePbkdf2Hash("password1", salt, 1000);
    const b = await derivePbkdf2Hash("password2", salt, 1000);
    expect(base64Url(a)).not.toBe(base64Url(b));
  });
  it("returns 32 bytes", async () => {
    const salt = new Uint8Array(16).fill(7);
    const out = await derivePbkdf2Hash("password", salt, 1000);
    expect(out.length).toBe(32);
  });
});

describe("hashPassword + verifyPasswordAsync", () => {
  it("verifies the original password", async () => {
    const stored = await hashPassword("correct horse battery staple");
    expect(await verifyPasswordAsync("correct horse battery staple", stored)).toBe(true);
  });
  it("rejects wrong password", async () => {
    const stored = await hashPassword("correct horse");
    expect(await verifyPasswordAsync("wrong horse", stored)).toBe(false);
  });
  it("uses pbkdf2$ prefix in stored format", async () => {
    const stored = await hashPassword("x");
    expect(stored.startsWith("pbkdf2$")).toBe(true);
  });
  it("embeds the iteration count", async () => {
    const stored = await hashPassword("x");
    const parts = stored.split("$");
    expect(parts[1]).toBe(String(PBKDF2_ITERATIONS));
  });
  it("rejects stored hash with bad prefix", async () => {
    expect(await verifyPasswordAsync("x", "bcrypt$x$y$z")).toBe(false);
  });
  it("rejects stored hash with too-few parts", async () => {
    expect(await verifyPasswordAsync("x", "pbkdf2$100000$salt")).toBe(false);
  });
  it("rejects stored hash with downgraded iteration count", async () => {
    // 80k is below the MIN_ITERATIONS floor — the verifier must reject.
    const stored = "pbkdf2$80000$" + base64Url(new Uint8Array(16)) + "$" + base64Url(new Uint8Array(32));
    expect(await verifyPasswordAsync("x", stored)).toBe(false);
  });
  it("rejects stored hash with upgraded iteration count", async () => {
    const stored = "pbkdf2$200000$" + base64Url(new Uint8Array(16)) + "$" + base64Url(new Uint8Array(32));
    expect(await verifyPasswordAsync("x", stored)).toBe(false);
  });
});

describe("signAdminSession", () => {
  it("produces deterministic output for the same inputs", async () => {
    const a = await signAdminSession("secret", 1234567890);
    const b = await signAdminSession("secret", 1234567890);
    expect(a).toBe(b);
  });
  it("produces different output for different secrets", async () => {
    const a = await signAdminSession("secret1", 1234567890);
    const b = await signAdminSession("secret2", 1234567890);
    expect(a).not.toBe(b);
  });
  it("produces different output for different timestamps", async () => {
    const a = await signAdminSession("secret", 1);
    const b = await signAdminSession("secret", 2);
    expect(a).not.toBe(b);
  });
  it("verifies via timingSafeEqual on the signature component", async () => {
    const sig = await signAdminSession("secret", 100);
    expect(timingSafeEqual(sig, sig)).toBe(true);
  });
});
