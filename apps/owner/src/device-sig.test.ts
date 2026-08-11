import { describe, expect, it } from "vitest";
import { base64urlDecode, base64urlEncode, lengthPrefixed, sha256, utf8 } from "./bytes.js";
import { deviceSigPreimage, enrollPopTranscript } from "./device-sig.js";
import { DEVICE_SIG_LABEL, ENROLL_POP_LABEL } from "./types.js";

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

describe("lengthPrefixed", () => {
  it("prefixes each field with a 4-byte big-endian length", () => {
    expect(hex(lengthPrefixed([]))).toBe("");
    expect(hex(lengthPrefixed([new Uint8Array([0xaa])]))).toBe("00000001aa");
    expect(hex(lengthPrefixed([utf8("hi")]))).toBe("000000026869");
  });

  it("is injective — field boundaries cannot be shifted (the classic ambiguity)", () => {
    const a = hex(lengthPrefixed([utf8("ab"), utf8("")]));
    const b = hex(lengthPrefixed([utf8("a"), utf8("b")]));
    const c = hex(lengthPrefixed([utf8(""), utf8("ab")]));
    expect(new Set([a, b, c]).size).toBe(3);
  });

  it("refuses a field too long to count in four bytes", () => {
    const huge = { length: 0x1_0000_0000 } as unknown as Uint8Array;
    expect(() => lengthPrefixed([huge])).toThrow(/4 bytes/);
  });
});

describe("base64url", () => {
  it("round-trips and matches known vectors, no padding", () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
    const encoded = base64urlEncode(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(hex(base64urlDecode(encoded))).toBe(hex(bytes));
    expect(base64urlEncode(new Uint8Array([0xff, 0xff, 0xff]))).toBe("____");
    expect(base64urlEncode(new Uint8Array([0xfb]))).toBe("-w");
    expect(base64urlEncode(new Uint8Array(0))).toBe("");
  });

  it("refuses non-alphabet input instead of guessing", () => {
    expect(() => base64urlDecode("has space")).toThrow(/base64url/);
    expect(() => base64urlDecode("pad=ding")).toThrow(/base64url/);
    expect(() => base64urlDecode("plus+slash/")).toThrow(/base64url/);
  });
});

describe("sha256", () => {
  it("matches known NIST vectors, empty input included", async () => {
    expect(hex(await sha256(new Uint8Array(0)))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(hex(await sha256(utf8("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("deviceSigPreimage", () => {
  const bodyHash = new Uint8Array(32).fill(0); // stand-in 32-byte digest
  const base = {
    deviceId: "dev-1",
    method: "get",
    pathAndQuery: "/veto/w1",
    bodyHash,
    timestamp: 1_700_000_000_000,
    nonce: "n1",
  };

  it("opens with the domain label and signs the method upper-cased", () => {
    const preimage = deviceSigPreimage(base);
    const label = utf8(DEVICE_SIG_LABEL);
    // first field: the 4-byte length prefix, then the label bytes
    expect(hex(preimage.slice(4, 4 + label.length))).toBe(hex(label));
    // "get" and "GET" produce the same preimage
    expect(hex(deviceSigPreimage(base))).toBe(hex(deviceSigPreimage({ ...base, method: "GET" })));
  });

  it("binds method, path, body, timestamp, and nonce — each changes the preimage", () => {
    const ref = hex(deviceSigPreimage(base));
    expect(hex(deviceSigPreimage({ ...base, method: "post" }))).not.toBe(ref);
    expect(hex(deviceSigPreimage({ ...base, pathAndQuery: "/veto/w2" }))).not.toBe(ref);
    expect(hex(deviceSigPreimage({ ...base, bodyHash: new Uint8Array(32).fill(1) }))).not.toBe(ref);
    expect(hex(deviceSigPreimage({ ...base, timestamp: base.timestamp + 1 }))).not.toBe(ref);
    expect(hex(deviceSigPreimage({ ...base, nonce: "n2" }))).not.toBe(ref);
  });

  it("an empty body binds as the hash of zero bytes (present, not omitted)", async () => {
    const emptyBodyHash = await sha256(new Uint8Array(0));
    const withEmpty = deviceSigPreimage({ ...base, bodyHash: emptyBodyHash });
    // it is a real 32-byte digest, so the body-less GET is still fully bound...
    expect(withEmpty.length).toBeGreaterThan(0);
    // ...and differs from a different body
    expect(hex(withEmpty)).not.toBe(hex(deviceSigPreimage(base)));
  });

  it("rejects a body hash that is not 32 bytes and a non-integer timestamp", () => {
    expect(() => deviceSigPreimage({ ...base, bodyHash: new Uint8Array(16) })).toThrow(/32-byte/);
    expect(() => deviceSigPreimage({ ...base, timestamp: 1.5 })).toThrow(/integer/);
  });
});

describe("enrollPopTranscript", () => {
  const base = {
    inviteId: "inv-1",
    ownerId: "owner-1",
    credentialId: new Uint8Array([1, 2, 3]),
    spki: new Uint8Array([9, 9, 9, 9]),
  };

  it("opens with the enrolment label", () => {
    const transcript = enrollPopTranscript(base);
    const label = utf8(ENROLL_POP_LABEL);
    expect(hex(transcript.slice(4, 4 + label.length))).toBe(hex(label));
  });

  it("is injective — a shifted field boundary changes the transcript", () => {
    const ref = hex(enrollPopTranscript(base));
    // move a character from ownerId into inviteId: same concatenation, different framing
    expect(hex(enrollPopTranscript({ ...base, inviteId: "inv-1o", ownerId: "wner-1" }))).not.toBe(
      ref,
    );
    // and the raw-byte fields bind too
    expect(
      hex(enrollPopTranscript({ ...base, credentialId: new Uint8Array([1, 2, 3, 4]) })),
    ).not.toBe(ref);
  });
});
