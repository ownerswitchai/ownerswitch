import { describe, expect, it } from "vitest";
import { cborDecodeExact, cborDecodeFirst } from "./cbor.js";
import { cborEncode } from "./cbor-fixture.js";

describe("cborDecode — the strict WebAuthn subset", () => {
  it("round-trips the shapes a registration actually contains", () => {
    const attestation = new Map<unknown, unknown>([
      ["fmt", "none"],
      ["attStmt", new Map()],
      ["authData", new Uint8Array([1, 2, 3])],
    ]);
    const decoded = cborDecodeExact(new Uint8Array(cborEncode(attestation)));
    expect(decoded).toEqual({ fmt: "none", attStmt: {}, authData: new Uint8Array([1, 2, 3]) });

    const cose = new Map<unknown, unknown>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, new Uint8Array(32)],
      [-3, new Uint8Array(32).fill(1)],
    ]);
    const key = cborDecodeExact(new Uint8Array(cborEncode(cose))) as Record<string, unknown>;
    expect(key["1"]).toBe(2);
    expect(key["3"]).toBe(-7);
    expect(key["-2"]).toEqual(new Uint8Array(32));
  });

  it("refuses indefinite lengths, tags, floats, and 64-bit lengths", () => {
    expect(() => cborDecodeExact(new Uint8Array([0x5f]))).toThrow(/indefinite/); // bstr, indefinite
    expect(() => cborDecodeExact(new Uint8Array([0x9f, 0xff]))).toThrow(/indefinite/); // array
    expect(() => cborDecodeExact(new Uint8Array([0xc0, 0x00]))).toThrow(/tags/); // tag 0
    expect(() => cborDecodeExact(new Uint8Array([0xf9, 0x3c, 0x00]))).toThrow(/simple|float/); // half float
    expect(() => cborDecodeExact(new Uint8Array([0x1b, 0, 0, 0, 0, 0, 0, 0, 1]))).toThrow(/subset/); // u64 len
  });

  it("PROTO INJECTION: __proto__/constructor/prototype keys are refused, and maps have no prototype", () => {
    for (const name of ["__proto__", "constructor", "prototype"]) {
      const hostile = cborEncode(new Map([[name, 1]]));
      expect(() => cborDecodeExact(new Uint8Array(hostile))).toThrow(/prototype pollution/);
    }
    // and a decoded map cannot INHERIT anything: null prototype
    const clean = cborDecodeExact(new Uint8Array(cborEncode(new Map([["a", 1]]))));
    expect(Object.getPrototypeOf(clean)).toBeNull();
    expect((clean as Record<string, unknown>).hasOwnProperty).toBeUndefined();
  });

  it("refuses duplicate map keys — a validator that keeps either copy can be steered by the other", () => {
    // {"a":1,"a":2}
    const dup = Buffer.from([0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02]);
    expect(() => cborDecodeExact(new Uint8Array(dup))).toThrow(/duplicate/);
    // {1:2, "1":3} — an integer key and its decimal-string twin must collide
    const twin = Buffer.concat([
      Buffer.from([0xa2, 0x01, 0x02]),
      Buffer.from([0x61, 0x31, 0x03]),
    ]);
    expect(() => cborDecodeExact(new Uint8Array(twin))).toThrow(/duplicate/);
  });

  it("refuses truncated input, trailing bytes, invalid UTF-8, and depth bombs", () => {
    expect(() => cborDecodeExact(new Uint8Array([0x58, 0x05, 0x01]))).toThrow(/truncated/); // bstr shorter than its length
    expect(() => cborDecodeExact(new Uint8Array([0x01, 0x02]))).toThrow(/trailing/); // two ints, exact-decode
    const { bytesRead } = cborDecodeFirst(new Uint8Array([0x01, 0x02]));
    expect(bytesRead).toBe(1); // first-decode reports honest consumption
    expect(() => cborDecodeExact(new Uint8Array([0x61, 0xff]))).toThrow(); // invalid UTF-8 in tstr
    // [[[[[[[[[[]]]]]]]]]] — ten deep, over the bound of 8
    expect(() => cborDecodeExact(new Uint8Array([...Array(10).fill(0x81), 0x80]))).toThrow(/deep/);
  });
});
