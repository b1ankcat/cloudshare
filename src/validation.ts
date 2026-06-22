/**
 * Lightweight request input parsers. Each helper either returns a parsed
 * value or throws. No silent fallbacks: callers that need a default must
 * apply it explicitly.
 */

import { safeDecode, validateName, ValidationError } from "./encoding";

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class BadRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BadRequestError";
  }
}

export function isValidUuid(value: string): boolean {
  return UUID_RE.test(value);
}

/** Read a text field from a FormData. Throws if absent. */
export function requireFormText(form: FormData, key: string): string {
  const v = form.get(key);
  if (typeof v !== "string") throw new BadRequestError(`缺少字段: ${key}`);
  return v;
}

/** Read a JSON body field. Throws on invalid JSON. */
export async function readJson(request: Request): Promise<unknown> {
  return await request.json();
}

/** Read a FormData body. Throws on invalid form. */
export async function readForm(request: Request): Promise<FormData> {
  return await request.formData();
}

/** Coerce a value to a non-negative integer. Throws on invalid input. */
export function toNonNegativeInt(value: unknown, field: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) {
    throw new BadRequestError(`字段 ${field} 必须是非负整数`);
  }
  return n;
}

/** Coerce a value to an integer. Throws on invalid input. */
export function toInt(value: unknown, field: string): number {
  const n = Number(value);
  if (!Number.isInteger(n)) {
    throw new BadRequestError(`字段 ${field} 必须是整数`);
  }
  return n;
}

/** Re-export the encode helpers used by route handlers. */
export { safeDecode, ValidationError, validateName };
