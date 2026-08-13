/**
 * A deliberately TINY, STRICT CBOR decoder — exactly the subset a WebAuthn
 * registration needs (RFC 8152 COSE keys and the RFC 8949 attestation map),
 * and not one construct more. This parses ATTACKER-SUPPLIED bytes at the
 * enrolment boundary, so everything permissive about general CBOR is
 * refused here by construction:
 *  - definite lengths ONLY — indefinite-length items (0x1f additional info)
 *    are refused, so there is no streaming state to confuse;
 *  - major types: unsigned int, negative int, byte string, text string,
 *    array, map. NO tags, NO floats, NO simple values beyond false/true/
 *    null — a registration contains none of them, so none are accepted;
 *  - duplicate map keys are refused (RFC 8949 §5.6 leaves them "not valid";
 *    a validator that keeps either copy can be steered by the other);
 *  - depth and item-count bounded, string/bstr lengths bounded by the input
 *    size, so a hostile header cannot allocate beyond the request itself;
 *  - map keys may be text strings or integers only (WebAuthn/COSE use both,
 *    nothing else) — integer keys are returned as canonical decimal
 *    strings, colliding representations impossible;
 *  - decode() reports how many bytes it consumed; callers that require
 *    exact consumption (the attestation object, the trailing COSE key)
 *    check it and refuse trailing bytes.
 */

export type CborValue =
  | number
  | string
  | Uint8Array
  | boolean
  | null
  | CborValue[]
  | { [key: string]: CborValue };

const MAX_DEPTH = 8;
const MAX_ITEMS = 1024;

class Reader {
  offset = 0;
  items = 0;
  constructor(readonly bytes: Uint8Array) {}

  need(count: number): void {
    if (this.offset + count > this.bytes.length) {
      throw new Error("CBOR: truncated input");
    }
  }

  u8(): number {
    this.need(1);
    return this.bytes[this.offset++];
  }

  take(count: number): Uint8Array {
    this.need(count);
    const out = this.bytes.subarray(this.offset, this.offset + count);
    this.offset += count;
    return out;
  }

  countItem(): void {
    this.items += 1;
    if (this.items > MAX_ITEMS) throw new Error("CBOR: too many items");
  }
}

/** The definite length/value for a header byte; refuses indefinite (31). */
function readLength(reader: Reader, additional: number): number {
  if (additional < 24) return additional;
  if (additional === 24) return reader.u8();
  if (additional === 25) {
    const bytes = reader.take(2);
    return (bytes[0] << 8) | bytes[1];
  }
  if (additional === 26) {
    const bytes = reader.take(4);
    // >>> 0 keeps the value an unsigned 32-bit integer
    return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  }
  // 27 would be a 64-bit length: nothing in a WebAuthn registration is
  // anywhere near 2^32 bytes, and Number cannot hold it exactly — refuse.
  throw new Error("CBOR: length encoding not in the accepted subset");
}

function decodeItem(reader: Reader, depth: number): CborValue {
  if (depth > MAX_DEPTH) throw new Error("CBOR: nesting too deep");
  reader.countItem();
  const initial = reader.u8();
  const major = initial >> 5;
  const additional = initial & 0x1f;
  if (additional === 31) throw new Error("CBOR: indefinite lengths are refused");

  switch (major) {
    case 0: // unsigned integer
      return readLength(reader, additional);
    case 1: // negative integer: -1 - n
      return -1 - readLength(reader, additional);
    case 2: // byte string
      return new Uint8Array(reader.take(readLength(reader, additional)));
    case 3: {
      // text string — must be valid UTF-8; TextDecoder(fatal) enforces it
      const raw = reader.take(readLength(reader, additional));
      return new TextDecoder("utf-8", { fatal: true }).decode(raw);
    }
    case 4: {
      const count = readLength(reader, additional);
      const out: CborValue[] = [];
      for (let i = 0; i < count; i++) out.push(decodeItem(reader, depth + 1));
      return out;
    }
    case 5: {
      const count = readLength(reader, additional);
      // NULL-PROTOTYPE object: on a plain {}, assigning the "__proto__" key
      // hits the prototype SETTER — it swaps the object's prototype, creates
      // no own property, bypasses the duplicate check, and hands the caller
      // an object whose fmt/attStmt/authData can be INHERITED from
      // attacker-chosen values. Object.create(null) has no such setter, so
      // every assignment below is a plain own property. The setter-hazard
      // keys are refused outright as a second, independent belt.
      const out: Record<string, CborValue> = Object.create(null) as Record<string, CborValue>;
      for (let i = 0; i < count; i++) {
        const key = decodeItem(reader, depth + 1);
        let name: string;
        if (typeof key === "string") {
          // a TEXT key that spells an integer would collide with the decimal
          // form INTEGER keys decode to — a text "3" could impersonate COSE
          // label 3. No legitimate WebAuthn/COSE text key is numeric; refuse.
          if (/^-?\d+$/.test(key)) {
            throw new Error(`CBOR: text map key ${JSON.stringify(key)} impersonates an integer label`);
          }
          name = key;
        } else if (typeof key === "number" && Number.isSafeInteger(key)) name = String(key);
        else throw new Error("CBOR: map keys must be text strings or integers");
        if (name === "__proto__" || name === "constructor" || name === "prototype") {
          throw new Error(`CBOR: map key ${JSON.stringify(name)} is refused (prototype pollution)`);
        }
        if (Object.prototype.hasOwnProperty.call(out, name)) {
          throw new Error(`CBOR: duplicate map key ${JSON.stringify(name)}`);
        }
        out[name] = decodeItem(reader, depth + 1);
      }
      return out;
    }
    case 7: {
      // simple values: exactly false/true/null; floats and everything else refused
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      throw new Error("CBOR: simple/float values are not in the accepted subset");
    }
    default:
      throw new Error("CBOR: tags are not in the accepted subset");
  }
}

export interface CborDecodeResult {
  value: CborValue;
  /** bytes consumed from the input — callers refuse trailing bytes themselves */
  bytesRead: number;
}

export function cborDecodeFirst(bytes: Uint8Array): CborDecodeResult {
  const reader = new Reader(bytes);
  const value = decodeItem(reader, 0);
  return { value, bytesRead: reader.offset };
}

/** Decode ONE item that must consume the whole input — trailing bytes refuse. */
export function cborDecodeExact(bytes: Uint8Array): CborValue {
  const { value, bytesRead } = cborDecodeFirst(bytes);
  if (bytesRead !== bytes.length) {
    throw new Error(`CBOR: ${bytes.length - bytesRead} trailing byte(s) after the value`);
  }
  return value;
}
