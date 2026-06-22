import { describe, it, expect } from "vitest";
import { getMimeType, parseRangeHeader } from "./download";

describe("getMimeType", () => {
  it("returns octet-stream when no extension", () => {
    expect(getMimeType("README")).toBe("application/octet-stream");
  });
  it("maps common extensions", () => {
    expect(getMimeType("a.html")).toBe("text/html");
    expect(getMimeType("a.png")).toBe("image/png");
    expect(getMimeType("a.json")).toBe("application/json");
    expect(getMimeType("a.mp4")).toBe("video/mp4");
  });
  it("handles last dot only (a.tar.gz → gz)", () => {
    expect(getMimeType("a.tar.gz")).toBe("application/gzip");
  });
  it("is case-insensitive on the extension", () => {
    expect(getMimeType("A.PNG")).toBe("image/png");
  });
  it("returns octet-stream for unknown extensions", () => {
    expect(getMimeType("a.unknownext")).toBe("application/octet-stream");
  });
});

describe("parseRangeHeader", () => {
  it("returns null for empty input", () => {
    expect(parseRangeHeader(null, 1000)).toBeNull();
  });
  it("returns 'invalid' for malformed header", () => {
    expect(parseRangeHeader("chunks=0-100", 1000)).toBe("invalid");
  });
  it("parses bytes=0-499 (first 500)", () => {
    expect(parseRangeHeader("bytes=0-499", 1000)).toEqual({
      offset: 0,
      end: 499,
      length: 500,
    });
  });
  it("parses bytes=500- (from offset to end)", () => {
    expect(parseRangeHeader("bytes=500-", 1000)).toEqual({
      offset: 500,
      end: 999,
      length: 500,
    });
  });
  it("parses bytes=-500 (last 500 bytes)", () => {
    expect(parseRangeHeader("bytes=-500", 1000)).toEqual({
      offset: 500,
      end: 999,
      length: 500,
    });
  });
  it("clamps an overshooting end to size-1", () => {
    expect(parseRangeHeader("bytes=0-9999", 1000)).toEqual({
      offset: 0,
      end: 999,
      length: 1000,
    });
  });
  it("rejects start >= size", () => {
    expect(parseRangeHeader("bytes=1000-", 1000)).toBe("invalid");
  });
  it("rejects start > end", () => {
    expect(parseRangeHeader("bytes=500-100", 1000)).toBe("invalid");
  });
  it("rejects negative start", () => {
    expect(parseRangeHeader("bytes=-0", 1000)).toBe("invalid");
  });
  it("rejects suffix length of 0", () => {
    expect(parseRangeHeader("bytes=-0", 1000)).toBe("invalid");
  });
  it("rejects unknown range unit", () => {
    expect(parseRangeHeader("bits=0-100", 1000)).toBe("invalid");
  });
  it("tolerates surrounding whitespace", () => {
    expect(parseRangeHeader("  bytes=0-99  ", 1000)).toEqual({
      offset: 0,
      end: 99,
      length: 100,
    });
  });
});
