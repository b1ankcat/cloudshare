import { describe, it, expect } from "vitest";
import { isValidUuid, toInt, toNonNegativeInt, BadRequestError } from "./validation";

describe("isValidUuid", () => {
  it("accepts a valid v4-ish UUID", () => {
    expect(isValidUuid("550e8400-e29b-41d4-a716-446655440000")).toBe(true);
  });
  it("accepts uppercase", () => {
    expect(isValidUuid("550E8400-E29B-41D4-A716-446655440000")).toBe(true);
  });
  it("rejects wrong segment lengths", () => {
    expect(isValidUuid("550e8400-e29b-41d4-a716-44665544000")).toBe(false);
  });
  it("rejects non-hex", () => {
    expect(isValidUuid("550e8400-e29b-41d4-a716-44665544000g")).toBe(false);
  });
  it("rejects missing dashes", () => {
    expect(isValidUuid("550e8400e29b41d4a7164466554400000")).toBe(false);
  });
});

describe("toInt", () => {
  it("accepts integer strings", () => {
    expect(toInt("42", "x")).toBe(42);
  });
  it("accepts integer numbers", () => {
    expect(toInt(42, "x")).toBe(42);
  });
  it("rejects floats", () => {
    expect(() => toInt(1.5, "x")).toThrow(BadRequestError);
  });
  it("rejects non-numeric", () => {
    expect(() => toInt("abc", "x")).toThrow(BadRequestError);
  });
  it("rejects NaN", () => {
    expect(() => toInt(NaN, "x")).toThrow(BadRequestError);
  });
});

describe("toNonNegativeInt", () => {
  it("accepts 0", () => {
    expect(toNonNegativeInt(0, "x")).toBe(0);
  });
  it("accepts positive ints", () => {
    expect(toNonNegativeInt(7, "x")).toBe(7);
  });
  it("rejects negative", () => {
    expect(() => toNonNegativeInt(-1, "x")).toThrow(BadRequestError);
  });
  it("rejects floats", () => {
    expect(() => toNonNegativeInt(1.5, "x")).toThrow(BadRequestError);
  });
});
