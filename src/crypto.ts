/**
 * Password hashing (PBKDF2-SHA256), HMAC session signing, base64url,
 * constant-time comparison.
 *
 * PBKDF2 iterations are pinned at 100k on both hash and verify; the stored
 * format encodes the iteration count so old hashes are still verifiable.
 * No upgrade path is implemented — on iteration count change, old hashes
 * must be re-derived explicitly.
 */

export const PBKDF2_ITERATIONS = 100_000;
export const PBKDF2_MIN_ITERATIONS = 90_000;
const PBKDF2_KEY_BITS = 256;
const SALT_BYTES = 16;

const encoder = new TextEncoder();

/** base64url encode (RFC 4648 §5) without padding. */
export function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] as number);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64url decode. Throws if value contains invalid characters. */
export function base64UrlDecode(value: string): Uint8Array {
  const padded =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Constant-time equality on two strings of the same length. */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** PBKDF2-SHA256(password, salt, iterations) -> 32-byte derived key. */
export async function derivePbkdf2Hash(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    PBKDF2_KEY_BITS,
  );
  return new Uint8Array(bits);
}

/** Hash a password. Returns `pbkdf2$<iter>$<saltB64u>$<hashB64u>`. */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await derivePbkdf2Hash(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${base64Url(salt)}$${base64Url(hash)}`;
}

/**
 * Verify a password against a stored hash. Rejects stored hashes whose
 * iteration count falls outside [MIN, MAX] — a no-fallback policy: an
 * attacker who can tamper with the stored hash cannot downgrade iterations
 * to make brute force cheap.
 */
export async function verifyPasswordAsync(
  input: string,
  storedHash: string,
): Promise<boolean> {
  if (!storedHash?.startsWith("pbkdf2$")) return false;
  const parts = storedHash.split("$");
  if (parts.length !== 4) return false;
  const [, iterRaw, saltRaw, hashRaw] = parts;
  const iterations = Number(iterRaw);
  if (
    !Number.isInteger(iterations) ||
    iterations < PBKDF2_MIN_ITERATIONS ||
    iterations > PBKDF2_ITERATIONS ||
    !saltRaw ||
    !hashRaw
  ) {
    return false;
  }
  const salt = base64UrlDecode(saltRaw);
  const candidate = await derivePbkdf2Hash(input, salt, iterations);
  return timingSafeEqual(base64Url(candidate), hashRaw);
}

/** HMAC-SHA256(secret, issuedAt) -> base64url. */
export async function signAdminSession(
  secret: string,
  issuedAt: number,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(String(issuedAt)),
  );
  return base64Url(new Uint8Array(signature));
}
