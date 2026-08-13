/**
 * Test-only CBOR ENCODER for building synthetic WebAuthn registrations —
 * the strict decoder (cbor.ts) is the product; this exists so test vectors
 * are legible instead of hand-hexed. Lives outside *.test.ts so importing
 * it never re-registers another file's tests.
 */
/** Tiny CBOR ENCODER for test vectors only (the decoder is the product). */
export function cborEncode(value: unknown): Buffer {
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return value >= 0 ? encodeHead(0, value) : encodeHead(1, -1 - value);
  }
  if (value instanceof Uint8Array) {
    return Buffer.concat([encodeHead(2, value.length), Buffer.from(value)]);
  }
  if (typeof value === "string") {
    const raw = Buffer.from(value, "utf8");
    return Buffer.concat([encodeHead(3, raw.length), raw]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([encodeHead(4, value.length), ...value.map(cborEncode)]);
  }
  if (typeof value === "boolean") return Buffer.from([value ? 0xf5 : 0xf4]);
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === "object" && value !== null) {
    // Map input preserves non-string (integer) keys for COSE
    const entries =
      value instanceof Map ? [...value.entries()] : Object.entries(value as Record<string, unknown>);
    return Buffer.concat([
      encodeHead(5, entries.length),
      ...entries.flatMap(([k, v]) => [cborEncode(typeof k === "string" ? maybeInt(k) : k), cborEncode(v)]),
    ]);
  }
  throw new Error(`cannot encode ${typeof value}`);
}
const maybeInt = (k: string): unknown => (/^-?\d+$/.test(k) ? Number(k) : k);
function encodeHead(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 256) return Buffer.from([(major << 5) | 24, length]);
  if (length < 65536) return Buffer.from([(major << 5) | 25, length >> 8, length & 0xff]);
  return Buffer.from([
    (major << 5) | 26,
    (length >>> 24) & 0xff,
    (length >>> 16) & 0xff,
    (length >>> 8) & 0xff,
    length & 0xff,
  ]);
}

