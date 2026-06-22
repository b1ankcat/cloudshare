import { describe, it, expect } from "vitest";
import {
  safeDecode,
  encodePathSegment,
  normalizeFolderPath,
  decodeFolderPath,
  buildR2Key,
  normalizeObjectKey,
  isValidSha256,
  isInternalR2Key,
  escapeHtml,
  jsAttrString,
  validateName,
  BLOB_PREFIX,
  ValidationError,
} from "./encoding";

describe("safeDecode", () => {
  it("decodes percent-encoded strings", () => {
    expect(safeDecode("hello%20world")).toBe("hello world");
  });
  it("throws on malformed input", () => {
    expect(() => safeDecode("%E0%A4%A")).toThrow();
  });
});

describe("encodePathSegment", () => {
  it("encodes slashes", () => {
    expect(encodePathSegment("a/b")).toBe("a%2Fb");
  });
  it("encodes unicode", () => {
    expect(encodePathSegment("文件.txt")).toBe("%E6%96%87%E4%BB%B6.txt");
  });
  it("round-trips with safeDecode", () => {
    const s = "spaces and 符号 & chars";
    expect(safeDecode(encodePathSegment(s))).toBe(s);
  });
});

describe("normalizeFolderPath", () => {
  it("returns '' for empty", () => {
    expect(normalizeFolderPath("")).toBe("");
  });
  it("strips leading/trailing slashes", () => {
    expect(normalizeFolderPath("/foo/bar/")).toBe("foo/bar");
  });
  it("encodes each segment", () => {
    expect(normalizeFolderPath("foo/文件 bar")).toBe("foo/%E6%96%87%E4%BB%B6%20bar");
  });
  it("filters empty segments", () => {
    expect(normalizeFolderPath("foo//bar")).toBe("foo/bar");
  });
});

describe("decodeFolderPath", () => {
  it("decodes a normalized path", () => {
    expect(decodeFolderPath("foo/%E6%96%87%E4%BB%B6")).toBe("foo/文件");
  });
});

describe("buildR2Key", () => {
  it("joins folder + encoded filename", () => {
    expect(buildR2Key("folder", "a b.txt")).toBe("folder/a%20b.txt");
  });
  it("omits folder for root", () => {
    expect(buildR2Key("", "file.txt")).toBe("file.txt");
  });
  it("encodes slashes in filename", () => {
    expect(buildR2Key("folder", "a/b.txt")).toBe("folder/a%2Fb.txt");
  });
});

describe("normalizeObjectKey", () => {
  it("returns '' for empty", () => {
    expect(normalizeObjectKey("")).toBe("");
  });
  it("splits and encodes a nested key", () => {
    expect(normalizeObjectKey("a/b.txt")).toBe("a/b.txt");
  });
  it("returns '' for trailing-slash only (no filename)", () => {
    expect(normalizeObjectKey("/")).toBe("");
    expect(normalizeObjectKey("a/")).toBe("a"); // "a" is a valid file name, not a folder
  });
});

describe("isValidSha256", () => {
  it("accepts a 64-char hex string", () => {
    const hex = "a".repeat(64);
    expect(isValidSha256(hex)).toBe(true);
  });
  it("rejects wrong length", () => {
    expect(isValidSha256("a".repeat(63))).toBe(false);
    expect(isValidSha256("a".repeat(65))).toBe(false);
  });
  it("rejects non-hex characters", () => {
    expect(isValidSha256("g".repeat(64))).toBe(false);
  });
  it("rejects non-strings", () => {
    expect(isValidSha256(123 as unknown as string)).toBe(false);
    expect(isValidSha256(null as unknown as string)).toBe(false);
  });
});

describe("isInternalR2Key", () => {
  it("recognizes blob prefix", () => {
    expect(isInternalR2Key(BLOB_PREFIX + "abc")).toBe(true);
  });
  it("recognizes .folder marker", () => {
    expect(isInternalR2Key(".folder")).toBe(true);
    expect(isInternalR2Key("foo/.folder")).toBe(true);
  });
  it("does not match user keys", () => {
    expect(isInternalR2Key("foo/bar.txt")).toBe(false);
  });
});

describe("escapeHtml", () => {
  it("escapes & < > \" '", () => {
    expect(escapeHtml(`<a href="x">&'</a>`)).toBe(
      "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;",
    );
  });
  it("handles null/undefined as empty", () => {
    expect(escapeHtml(null as unknown as string)).toBe("");
    expect(escapeHtml(undefined as unknown as string)).toBe("");
  });
  it("preserves unicode", () => {
    expect(escapeHtml("文件")).toBe("文件");
  });
});

describe("jsAttrString", () => {
  it("produces a JSON-stringified value", () => {
    expect(jsAttrString("hello")).toBe("&quot;hello&quot;");
  });
  it("escapes backslashes", () => {
    expect(jsAttrString("a\\b")).toBe("&quot;a\\\\b&quot;");
  });
  it("escapes inner double quotes for JSON", () => {
    expect(jsAttrString('a"b')).toBe("&quot;a\\&quot;b&quot;");
  });
  it("HTML-escapes the result for attribute context (XSS fix)", () => {
    // Old escapeJsArg produced this: a"onerror=alert(1) — breaking the attribute.
    // jsAttrString must produce: &quot;a&quot;onerror=alert(1) — so the " is
    // never seen as an attribute boundary by the HTML parser.
    const out = jsAttrString('a"><img src=x onerror=alert(1)>');
    expect(out).not.toMatch(/[^&]"/); // any " in the body must be entity-encoded
    expect(out).toBe(
      "&quot;a\\&quot;&gt;&lt;img src=x onerror=alert(1)&gt;&quot;",
    );
  });
  it("escapes ampersands to prevent entity confusion", () => {
    expect(jsAttrString("&amp;")).toBe("&quot;&amp;amp;&quot;");
  });
  it("handles empty string", () => {
    expect(jsAttrString("")).toBe("&quot;&quot;");
  });
  it("handles null/undefined as empty string", () => {
    expect(jsAttrString(null as unknown as string)).toBe("&quot;&quot;");
    expect(jsAttrString(undefined as unknown as string)).toBe("&quot;&quot;");
  });
});

describe("validateName", () => {
  it("accepts a normal file name", () => {
    expect(() => validateName("report.pdf", "file")).not.toThrow();
  });
  it("accepts unicode", () => {
    expect(() => validateName("文档.pdf", "file")).not.toThrow();
  });
  it("rejects empty", () => {
    expect(() => validateName("", "file")).toThrow(ValidationError);
    expect(() => validateName("   ", "file")).toThrow(ValidationError);
  });
  it("rejects . and ..", () => {
    expect(() => validateName(".", "file")).toThrow(ValidationError);
    expect(() => validateName("..", "file")).toThrow(ValidationError);
  });
  it("rejects slashes (path traversal)", () => {
    expect(() => validateName("a/b.txt", "file")).toThrow(ValidationError);
    expect(() => validateName("a\\b.txt", "file")).toThrow(ValidationError);
  });
  it("rejects HTML/XSS payload characters", () => {
    for (const c of ['<', '>', '"', "'", '|', '?', '*', ':']) {
      expect(() => validateName(`file${c}name`, "file")).toThrow(ValidationError);
    }
  });
  it("rejects control characters", () => {
    expect(() => validateName("file\x00name", "file")).toThrow(ValidationError);
    expect(() => validateName("file\x07name", "file")).toThrow(ValidationError);
    expect(() => validateName("file\x1fname", "file")).toThrow(ValidationError);
  });
  it("accepts a folder name with spaces and dots", () => {
    expect(() => validateName("My Documents (2024)", "folder")).not.toThrow();
  });
});
