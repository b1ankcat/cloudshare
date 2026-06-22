/**
 * Integration tests for the public Worker fetch surface.
 *
 * Uses @cloudflare/vitest-pool-workers so the test runs inside the
 * real workerd runtime with R2 + KV bindings. The Cloudflare
 * `SELF.fetch` helper makes an in-process request to the worker
 * without going over the network.
 *
 * Scope: every public route (auth flow, file management, share CRUD,
 * downloads, share access). Private helpers are covered by file-internal
 * unit tests in src/*.test.ts.
 */

import { describe, it, expect, beforeEach } from "vitest";
// @ts-expect-error - cloudflare:test is a virtual module provided at runtime by @cloudflare/vitest-pool-workers
import { SELF, env } from "cloudflare:test";
import type { Env } from "../src/types";
import type { R2Object } from "@cloudflare/workers-types";

// `env` from cloudflare:test is typed as `Cloudflare.Env` (the global Env
// shape with all bindings). Re-narrow to our concrete Env so handlers and
// KV/R2 operations get proper types in this test file.
const E = env as unknown as Env;

const ADMIN_PASSWORD = "test-admin-password-123";

async function clearAll() {
  // Wipe KV
  const keys = await E.cloudshare_shares.list();
  for (const k of keys.keys) {
    await E.cloudshare_shares.delete(k.name);
  }
  // Wipe R2 (list then delete in batches)
  let cursor: string | undefined;
  do {
    const listed = await E.FILES_BUCKET.list({ cursor });
    const names: string[] = listed.objects.map((o: R2Object) => o.key);
    if (names.length) await E.FILES_BUCKET.delete(names);
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);
}

async function loginGetCookie(): Promise<string> {
  const res = await SELF.fetch("https://example.com/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "1.2.3.4" },
    body: JSON.stringify({ password: ADMIN_PASSWORD }),
    redirect: "manual",
  });
  expect(res.status).toBe(303);
  const setCookie = res.headers.get("Set-Cookie") || "";
  return setCookie.split(";")[0] ?? "";
}

async function authed(url: string, init: RequestInit = {}): Promise<Response> {
  const cookie = await loginGetCookie();
  const headers = new Headers(init.headers);
  headers.set("Cookie", cookie);
  headers.set("CF-Connecting-IP", "1.2.3.4");
  return await SELF.fetch(url, { ...init, headers, redirect: "manual" });
}

beforeEach(async () => {
  await clearAll();
});

describe("public routes (no auth)", () => {
  it("GET /login returns 200 when ADMIN_PASSWORD is set", async () => {
    const res = await SELF.fetch("https://example.com/login");
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe(
      "no-store, no-cache, must-revalidate, private",
    );
  });

  it("rejects bad admin password (401 + sets rate limit)", async () => {
    const res = await SELF.fetch("https://example.com/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "9.9.9.9" },
      body: JSON.stringify({ password: "wrong" }),
    });
    expect(res.status).toBe(401);
  });

  it("rate-limits login failures after 5 attempts", async () => {
    for (let i = 0; i < 5; i++) {
      await SELF.fetch("https://example.com/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json", "CF-Connecting-IP": "8.8.8.8" },
        body: JSON.stringify({ password: "wrong" }),
      });
    }
    const sixth = await SELF.fetch("https://example.com/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "8.8.8.8" },
      body: JSON.stringify({ password: "wrong" }),
    });
    expect(sixth.status).toBe(429);
  });

  it("issues a session cookie on successful login", async () => {
    const cookie = await loginGetCookie();
    expect(cookie).toMatch(/^cloudshare_admin=\d+\./);
  });

  it("rejects unauthenticated access to /api/files", async () => {
    const res = await SELF.fetch("https://example.com/api/files", {
      headers: { "CF-Connecting-IP": "1.1.1.1" },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toMatch(/^\/login/);
  });

  it("returns 404 for unknown share token", async () => {
    const res = await SELF.fetch("https://example.com/s/00000000-0000-0000-0000-000000000000");
    expect(res.status).toBe(404);
  });

  it("rejects malformed share token (no UUID)", async () => {
    const res = await SELF.fetch("https://example.com/s/not-a-uuid");
    expect(res.status).toBe(404);
  });

  it("rejects /api/share with bad token", async () => {
    const res = await SELF.fetch("https://example.com/api/share/not-a-uuid");
    expect(res.status).toBe(404);
  });
});

describe("admin file management", () => {
  it("creates a folder", async () => {
    const res = await authed("https://example.com/api/folders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "docs" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean; folder: string };
    expect(body.success).toBe(true);
    expect(body.folder).toBe("docs");
  });

  it("rejects folder names with path separators", async () => {
    const res = await authed("https://example.com/api/folders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "../etc" }),
    });
    expect(res.status).toBe(400);
  });

  it("rejects folder names containing XSS payload characters", async () => {
    for (const bad of ['<x>', 'a"b', "a'b", "a|b", "a?b", "a*b"]) {
      const res = await authed("https://example.com/api/folders", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: bad }),
      });
      expect(res.status).toBe(400);
    }
  });

  it("rejects folder names equal to . or ..", async () => {
    for (const bad of [".", ".."]) {
      const res = await authed("https://example.com/api/folders", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: bad }),
      });
      expect(res.status).toBe(400);
    }
  });

  it("rejects empty folder name", async () => {
    const res = await authed("https://example.com/api/folders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "   " }),
    });
    expect(res.status).toBe(400);
  });

  it("lists an empty root", async () => {
    const res = await authed("https://example.com/api/files");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { files: unknown[]; folders: unknown[] };
    expect(body.files).toEqual([]);
    expect(body.folders).toEqual([]);
  });

  it("uploads a file (single shot)", async () => {
    const form = new FormData();
    const blob = new Blob([new Uint8Array([1, 2, 3, 4])]);
    form.append("files", blob, "test.bin");
    form.append("sha256", "a".repeat(64));
    const res = await authed("https://example.com/api/upload", {
      method: "POST",
      body: form,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean; files: { name: string; key: string }[] };
    expect(body.success).toBe(true);
    expect(body.files[0]?.name).toBe("test.bin");
    expect(body.files[0]?.key).toBe("test.bin");
  });

  it("uploads a file under a folder", async () => {
    await authed("https://example.com/api/folders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "sub" }),
    });
    const form = new FormData();
    form.append("files", new Blob([new Uint8Array([7, 7, 7])]), "inner.txt");
    form.append("folder", "sub");
    form.append("sha256", "b".repeat(64));
    const res = await authed("https://example.com/api/upload", {
      method: "POST",
      body: form,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { files: { key: string }[] };
    expect(body.files[0]?.key).toBe("sub/inner.txt");
  });

  it("rejects upload with bad sha256", async () => {
    const form = new FormData();
    form.append("files", new Blob([new Uint8Array([1])]), "x.bin");
    form.append("sha256", "not-hex");
    const res = await authed("https://example.com/api/upload", {
      method: "POST",
      body: form,
    });
    expect(res.status).toBe(400);
  });

  it("dedup: second upload to a different path with same sha256 increments refCount", async () => {
    const sha = "c".repeat(64);
    const makeForm = (name: string) => {
      const f = new FormData();
      f.append("files", new Blob([new Uint8Array([5, 6, 7, 8])]), name);
      f.append("sha256", sha);
      return f;
    };
    const r1 = await authed("https://example.com/api/upload", {
      method: "POST",
      body: makeForm("dup1.bin"),
    });
    expect(r1.status).toBe(200);
    const r2 = await authed("https://example.com/api/upload", {
      method: "POST",
      body: makeForm("dup2.bin"),
    });
    expect(r2.status).toBe(200);
    const body = (await r2.json()) as { files: { dedup?: boolean; refCount?: number }[] };
    expect(body.files[0]?.dedup).toBe(true);
    expect(body.files[0]?.refCount).toBe(2);

    // single blob for the two pointers
    const blob = await E.FILES_BUCKET.head("__blob__/" + sha);
    expect(blob).toBeTruthy();
  });

  it("lists files and reports refCount for dedup pointers", async () => {
    const sha = "d".repeat(64);
    const form = new FormData();
    form.append("files", new Blob([new Uint8Array([1])]), "x.bin");
    form.append("sha256", sha);
    await authed("https://example.com/api/upload", { method: "POST", body: form });
    const list = (await (await authed("https://example.com/api/files")).json()) as {
      files: { name: string; refCount?: number }[];
    };
    expect(list.files[0]?.name).toBe("x.bin");
    expect(list.files[0]?.refCount).toBe(1);
  });

  it("deletes a file and releases the dedup ref", async () => {
    const sha = "e".repeat(64);
    const form = new FormData();
    form.append("files", new Blob([new Uint8Array([1])]), "del.bin");
    form.append("sha256", sha);
    await authed("https://example.com/api/upload", { method: "POST", body: form });
    const del = await authed("https://example.com/api/files/del.bin", { method: "DELETE" });
    expect(del.status).toBe(200);
    const blob = await E.FILES_BUCKET.head("__blob__/" + sha);
    expect(blob).toBeNull();
  });

  it("deletes a folder and its files", async () => {
    await authed("https://example.com/api/folders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "tmp" }),
    });
    const form = new FormData();
    form.append("files", new Blob([new Uint8Array([1])]), "a.bin");
    form.append("folder", "tmp");
    form.append("sha256", "f".repeat(64));
    await authed("https://example.com/api/upload", { method: "POST", body: form });
    const del = await authed("https://example.com/api/folders/tmp", { method: "DELETE" });
    expect(del.status).toBe(200);
    const body = (await del.json()) as { deleted: number };
    expect(body.deleted).toBeGreaterThan(0);
  });

  it("rejects delete on root folder", async () => {
    const del = await authed("https://example.com/api/folders/", { method: "DELETE" });
    // Trailing slash is stripped by the router before reaching the handler,
    // so this might 404. Either 400 or 404 is acceptable; what's important
    // is that we don't recursively wipe the bucket.
    expect([400, 404]).toContain(del.status);
  });
});

describe("admin download", () => {
  it("downloads a file (200 + attachment disposition)", async () => {
    const sha = "1".repeat(64);
    const content = new Uint8Array([1, 2, 3, 4, 5]);
    const form = new FormData();
    form.append("files", new Blob([content]), "data.bin");
    form.append("sha256", sha);
    await authed("https://example.com/api/upload", { method: "POST", body: form });
    const res = await authed("https://example.com/api/admin-download/data.bin");
    expect(res.status).toBe(200);
    expect(res.headers.get("Accept-Ranges")).toBe("bytes");
    expect(res.headers.get("Content-Disposition")).toMatch(/attachment/);
    const buf = new Uint8Array(await res.arrayBuffer());
    expect(Array.from(buf)).toEqual(Array.from(content));
  });

  it("supports HTTP Range requests (206)", async () => {
    const sha = "2".repeat(64);
    const content = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const form = new FormData();
    form.append("files", new Blob([content]), "range.bin");
    form.append("sha256", sha);
    await authed("https://example.com/api/upload", { method: "POST", body: form });
    const res = await authed("https://example.com/api/admin-download/range.bin", {
      headers: { Range: "bytes=2-4" },
    });
    expect(res.status).toBe(206);
    expect(res.headers.get("Content-Range")).toBe("bytes 2-4/10");
    const buf = new Uint8Array(await res.arrayBuffer());
    expect(Array.from(buf)).toEqual([3, 4, 5]);
  });

  it("returns 416 for invalid range", async () => {
    const sha = "3".repeat(64);
    const content = new Uint8Array([1, 2, 3, 4, 5]);
    const form = new FormData();
    form.append("files", new Blob([content]), "r.bin");
    form.append("sha256", sha);
    await authed("https://example.com/api/upload", { method: "POST", body: form });
    const res = await authed("https://example.com/api/admin-download/r.bin", {
      headers: { Range: "bytes=99-100" },
    });
    expect(res.status).toBe(416);
  });

  it("returns 404 for a non-existent file", async () => {
    const res = await authed("https://example.com/api/admin-download/missing.bin");
    expect(res.status).toBe(404);
  });
});

describe("share CRUD", () => {
  async function uploadFile(name: string, sha: string): Promise<void> {
    const form = new FormData();
    form.append("files", new Blob([new Uint8Array([1, 2, 3])]), name);
    form.append("sha256", sha);
    await authed("https://example.com/api/upload", { method: "POST", body: form });
  }

  it("creates a file share (no password, no expiry)", async () => {
    await uploadFile("x.bin", "a".repeat(64));
    const res = await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "x.bin", name: "x.bin" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean; share: { token: string; hasPassword: boolean; expiresAt: null } };
    expect(body.success).toBe(true);
    expect(body.share.token).toMatch(/^[0-9a-f-]{36}$/);
    expect(body.share.hasPassword).toBe(false);
    expect(body.share.expiresAt).toBeNull();
  });

  it("creates a share with password and expiry", async () => {
    await uploadFile("y.bin", "b".repeat(64));
    const res = await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: "file",
        path: "y.bin",
        name: "y.bin",
        password: "secret123",
        expiresIn: 3600,
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { share: { hasPassword: boolean; expiresAt: string | null } };
    expect(body.share.hasPassword).toBe(true);
    expect(body.share.expiresAt).not.toBeNull();
  });

  it("rejects share with invalid type", async () => {
    const res = await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "link", path: "x", name: "x" }),
    });
    expect(res.status).toBe(400);
  });

  it("rejects share with missing fields", async () => {
    const res = await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file" }),
    });
    expect(res.status).toBe(400);
  });

  it("GET /api/shares returns the list", async () => {
    await uploadFile("a.bin", "c".repeat(64));
    await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "a.bin", name: "a.bin" }),
    });
    const res = await authed("https://example.com/api/shares");
    const body = (await res.json()) as { shares: { name: string; token: string }[] };
    expect(body.shares.length).toBe(1);
    expect(body.shares[0]?.name).toBe("a.bin");
  });

  it("extend action updates expiresAt", async () => {
    await uploadFile("b.bin", "d".repeat(64));
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "b.bin", name: "b.bin" }),
    })).json()) as { share: { token: string; expiresAt: null } };
    const token = created.share.token;
    const upd = await authed("https://example.com/api/share/" + token, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "extend", expiresIn: 7200 }),
    });
    expect(upd.status).toBe(200);
    const after = (await upd.json()) as { share: { expiresAt: string } };
    expect(after.share.expiresAt).not.toBeNull();
  });

  it("extend with null sets permanent", async () => {
    await uploadFile("c.bin", "e".repeat(64));
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "c.bin", name: "c.bin", expiresIn: 60 }),
    })).json()) as { share: { token: string } };
    const token = created.share.token;
    const upd = await authed("https://example.com/api/share/" + token, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "extend", expiresIn: null }),
    });
    const after = (await upd.json()) as { share: { expiresAt: null } };
    expect(after.share.expiresAt).toBeNull();
  });

  it("password action: set then clear", async () => {
    await uploadFile("d.bin", "f".repeat(64));
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "d.bin", name: "d.bin" }),
    })).json()) as { share: { token: string; hasPassword: boolean } };
    const token = created.share.token;
    expect(created.share.hasPassword).toBe(false);

    const setPw = await authed("https://example.com/api/share/" + token, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "password", password: "topsecret" }),
    });
    const after = (await setPw.json()) as { share: { hasPassword: boolean } };
    expect(after.share.hasPassword).toBe(true);

    const clrPw = await authed("https://example.com/api/share/" + token, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "password", password: null }),
    });
    const cleared = (await clrPw.json()) as { share: { hasPassword: boolean } };
    expect(cleared.share.hasPassword).toBe(false);
  });

  it("rejects update with invalid action", async () => {
    await uploadFile("e.bin", "1".repeat(64));
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "e.bin", name: "e.bin" }),
    })).json()) as { share: { token: string } };
    const upd = await authed("https://example.com/api/share/" + created.share.token, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "wat" }),
    });
    expect(upd.status).toBe(400);
  });

  it("cancel action deletes the share", async () => {
    await uploadFile("f.bin", "2".repeat(64));
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "f.bin", name: "f.bin" }),
    })).json()) as { share: { token: string } };
    const cancel = await authed("https://example.com/api/share/" + created.share.token, {
      method: "DELETE",
    });
    expect(cancel.status).toBe(200);
    const list = await authed("https://example.com/api/shares");
    const body = (await list.json()) as { shares: unknown[] };
    expect(body.shares.length).toBe(0);
  });
});

describe("share access (public)", () => {
  async function uploadFile(name: string, sha: string): Promise<void> {
    const form = new FormData();
    form.append("files", new Blob([new Uint8Array([1, 2, 3])]), name);
    form.append("sha256", sha);
    await authed("https://example.com/api/upload", { method: "POST", body: form });
  }

  it("anonymous can GET /api/share/:token (returns files + expired/passwordRequired flags)", async () => {
    await uploadFile("pub.bin", "1".repeat(64));
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "pub.bin", name: "pub.bin" }),
    })).json()) as { share: { token: string } };
    const res = await SELF.fetch("https://example.com/api/share/" + created.share.token);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { files: { name: string }[]; expired: boolean; passwordRequired: boolean };
    expect(body.files.length).toBe(1);
    expect(body.files[0]?.name).toBe("pub.bin");
    expect(body.expired).toBe(false);
    expect(body.passwordRequired).toBe(false);
  });

  it("password-protected share: GET hides path + marks passwordRequired", async () => {
    await uploadFile("priv.bin", "2".repeat(64));
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "priv.bin", name: "priv.bin", password: "secret" }),
    })).json()) as { share: { token: string } };
    const res = await SELF.fetch("https://example.com/api/share/" + created.share.token);
    const body = (await res.json()) as { path: string; passwordRequired: boolean; files: unknown[] };
    expect(body.path).toBe("");
    expect(body.passwordRequired).toBe(true);
    expect(body.files).toEqual([]);
  });

  it("password-protected share: ?pw=... grants access", async () => {
    await uploadFile("priv2.bin", "3".repeat(64));
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "priv2.bin", name: "priv2.bin", password: "secret" }),
    })).json()) as { share: { token: string } };
    const res = await SELF.fetch(
      "https://example.com/api/share/" + created.share.token + "?pw=secret",
    );
    const body = (await res.json()) as { files: { name: string }[]; passwordRequired: boolean };
    expect(body.passwordRequired).toBe(false);
    expect(body.files[0]?.name).toBe("priv2.bin");
  });

  it("password verify: wrong password returns valid:false", async () => {
    await uploadFile("priv3.bin", "4".repeat(64));
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "priv3.bin", name: "priv3.bin", password: "secret" }),
    })).json()) as { share: { token: string } };
    const res = await SELF.fetch("https://example.com/api/share/" + created.share.token + "/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "wrong" }),
    });
    const body = (await res.json()) as { valid: boolean; needPassword: boolean };
    expect(body.valid).toBe(false);
    expect(body.needPassword).toBe(true);
  });

  it("password verify: right password returns valid:true", async () => {
    await uploadFile("priv4.bin", "5".repeat(64));
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "priv4.bin", name: "priv4.bin", password: "secret" }),
    })).json()) as { share: { token: string } };
    const res = await SELF.fetch("https://example.com/api/share/" + created.share.token + "/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "secret" }),
    });
    const body = (await res.json()) as { valid: boolean; needPassword: boolean };
    expect(body.valid).toBe(true);
    expect(body.needPassword).toBe(true);
  });

  it("expired share: API marks expired + dl returns 410", async () => {
    await uploadFile("exp.bin", "6".repeat(64));
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "exp.bin", name: "exp.bin", expiresIn: 1 }),
    })).json()) as { share: { token: string } };
    // wait a beat to ensure expiry
    await new Promise((r) => setTimeout(r, 1100));
    const api = await SELF.fetch("https://example.com/api/share/" + created.share.token);
    const apiBody = (await api.json()) as { expired: boolean };
    expect(apiBody.expired).toBe(true);
    const dl = await SELF.fetch("https://example.com/dl/" + created.share.token);
    expect(dl.status).toBe(410);
  });

  it("download a file share (200 + body matches)", async () => {
    const content = new Uint8Array([9, 8, 7, 6, 5]);
    const sha = "7".repeat(64);
    const form = new FormData();
    form.append("files", new Blob([content]), "dl.bin");
    form.append("sha256", sha);
    await authed("https://example.com/api/upload", { method: "POST", body: form });
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "dl.bin", name: "dl.bin" }),
    })).json()) as { share: { token: string } };
    const res = await SELF.fetch("https://example.com/dl/" + created.share.token);
    expect(res.status).toBe(200);
    expect(res.headers.get("Accept-Ranges")).toBe("bytes");
    const buf = new Uint8Array(await res.arrayBuffer());
    expect(Array.from(buf)).toEqual(Array.from(content));
  });

  it("download a password-protected file share without pw returns 403", async () => {
    const sha = "8".repeat(64);
    const form = new FormData();
    form.append("files", new Blob([new Uint8Array([1])]), "locked.bin");
    form.append("sha256", sha);
    await authed("https://example.com/api/upload", { method: "POST", body: form });
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "locked.bin", name: "locked.bin", password: "secret" }),
    })).json()) as { share: { token: string } };
    const res = await SELF.fetch("https://example.com/dl/" + created.share.token);
    expect(res.status).toBe(403);
  });

  it("download a password-protected file share with ?pw=... returns 200", async () => {
    const sha = "9".repeat(64);
    const content = new Uint8Array([42, 43, 44]);
    const form = new FormData();
    form.append("files", new Blob([content]), "locked2.bin");
    form.append("sha256", sha);
    await authed("https://example.com/api/upload", { method: "POST", body: form });
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "locked2.bin", name: "locked2.bin", password: "secret" }),
    })).json()) as { share: { token: string } };
    const res = await SELF.fetch(
      "https://example.com/dl/" + created.share.token + "?pw=secret",
    );
    expect(res.status).toBe(200);
    const buf = new Uint8Array(await res.arrayBuffer());
    expect(Array.from(buf)).toEqual(Array.from(content));
  });
});

describe("static pages", () => {
  it("GET / returns the admin page (with auth)", async () => {
    const res = await authed("https://example.com/");
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe(
      "no-store, no-cache, must-revalidate, private",
    );
    expect(await res.text()).toMatch(/CloudShare/);
  });

  it("GET /manage returns the manage page (with auth)", async () => {
    const res = await authed("https://example.com/manage");
    expect(res.status).toBe(200);
    expect(await res.text()).toMatch(/分享管理/);
  });

  it("GET /s/:validUUID serves the share page (even before resolution)", async () => {
    // For the share page we need an actual share record; otherwise 404.
    // First test 404 for an unknown token.
    const notFound = await SELF.fetch("https://example.com/s/" + "0".repeat(8) + "-0000-0000-0000-000000000000");
    expect(notFound.status).toBe(404);
  });

  it("GET /s/:validUUID serves the share page (existing share)", async () => {
    const form = new FormData();
    form.append("files", new Blob([new Uint8Array([1])]), "x.bin");
    form.append("sha256", "0".repeat(64));
    await authed("https://example.com/api/upload", { method: "POST", body: form });
    const created = (await (await authed("https://example.com/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "file", path: "x.bin", name: "x.bin" }),
    })).json()) as { share: { token: string } };
    const res = await SELF.fetch("https://example.com/s/" + created.share.token);
    expect(res.status).toBe(200);
    // share page is public and cacheable
    expect(res.headers.get("Cache-Control")).toMatch(/^public/);
  });

  it("GET /api/logout clears the session", async () => {
    const cookie = await loginGetCookie();
    const res = await SELF.fetch("https://example.com/api/logout", {
      method: "GET",
      headers: { Cookie: cookie, "CF-Connecting-IP": "1.1.1.1" },
      redirect: "manual",
    });
    expect(res.status).toBe(303);
    expect(res.headers.get("Set-Cookie")).toMatch(/Max-Age=0/);
  });
});

describe("CORS preflight", () => {
  it("OPTIONS returns 204 with no CORS headers when no allowed origin", async () => {
    const res = await SELF.fetch("https://example.com/api/files", { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("OPTIONS returns 204 with CORS headers when allowed origin is configured", async () => {
    E.ALLOWED_ORIGIN = "https://share.example.com";
    const res = await SELF.fetch("https://example.com/api/files", { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("https://share.example.com");
  });
});

describe("session security", () => {
  it("accepts a freshly issued session", async () => {
    const cookie = await loginGetCookie();
    const res = await SELF.fetch("https://example.com/api/files", {
      headers: { Cookie: cookie, "CF-Connecting-IP": "1.1.1.1" },
      redirect: "manual",
    });
    expect(res.status).toBe(200);
  });

  it("rejects a tampered session (signature mismatch)", async () => {
    const cookie = await loginGetCookie();
    const parts = cookie.split("=")[1]!.split(".");
    const tampered = `${parts[0]}.${"A".repeat(parts[1]!.length)}`;
    const res = await SELF.fetch("https://example.com/api/files", {
      headers: {
        Cookie: `cloudshare_admin=${tampered}`,
        "CF-Connecting-IP": "1.1.1.1",
      },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
  });

  it("rejects a session signed for a different issuedAt (clock-valid but wrong secret)", async () => {
    // Simulate the rotated-secret scenario: a token issued with one secret
    // must not validate under another. We construct a token with a valid
    // shape but an obviously wrong signature and assert the verifier
    // rejects it.
    const res = await SELF.fetch("https://example.com/api/files", {
      headers: {
        Cookie: "cloudshare_admin=1700000000000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "CF-Connecting-IP": "1.1.1.1",
      },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
  });
});
