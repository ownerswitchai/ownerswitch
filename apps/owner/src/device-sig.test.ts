import {
  ENROLL_POP_LABEL as sharedEnrollLabel,
  ownerEnrollPopPreimage,
  enrollmentInviteFromWire,
  type EnrollmentInviteContract,
  type EnrollmentInviteWire,
} from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
import { base64urlDecode, base64urlEncode, lengthPrefixed, sha256, utf8 } from "./bytes.js";
import { deviceSigPreimage, enrollPopTranscript } from "./device-sig.js";
import {
  DEVICE_SIG_LABEL,
  ENROLL_POP_LABEL,
  type EnrollmentInvite,
  type EnrollmentRequest,
  type InviteMintRequest,
} from "./types.js";

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

  it("is canonically strict — one accepted spelling per byte string", () => {
    // canonical spellings decode...
    expect(hex(base64urlDecode("AA"))).toBe("00");
    expect(hex(base64urlDecode("-w"))).toBe("fb");
    // ...their pad-bit variants (same bytes, different spelling) are refused
    expect(() => base64urlDecode("AB")).toThrow(/non-canonical/);
    expect(() => base64urlDecode("AC")).toThrow(/non-canonical/);
    expect(() => base64urlDecode("AD")).toThrow(/non-canonical/);
    expect(() => base64urlDecode("-x")).toThrow(/non-canonical/);
    // and a length that no byte string encodes to is refused outright
    expect(() => base64urlDecode("A")).toThrow(/length/);
    expect(() => base64urlDecode("AAAAB")).toThrow(/length/);
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

  it("rejects a body hash that is not 32 bytes and a non-safe-integer timestamp", () => {
    expect(() => deviceSigPreimage({ ...base, bodyHash: new Uint8Array(16) })).toThrow(/32-byte/);
    expect(() => deviceSigPreimage({ ...base, timestamp: 1.5 })).toThrow(/integer/);
    expect(() => deviceSigPreimage({ ...base, timestamp: 2 ** 53 })).toThrow(/integer/);
  });

  it("accepts only the serialized ASCII request target for pathAndQuery", () => {
    // canonical, already-percent-encoded targets sign
    expect(() =>
      deviceSigPreimage({ ...base, pathAndQuery: "/x?q=%C3%A9" }),
    ).not.toThrow();
    // raw Unicode would sign bytes the wire never carries ("/x?q=é" is SENT
    // as "/x?q=%C3%A9") — refused, not silently UTF-8'd
    expect(() => deviceSigPreimage({ ...base, pathAndQuery: "/x?q=é" })).toThrow(/ASCII/);
    // lowercase percent-hex is a second spelling of the same target — refused
    expect(() => deviceSigPreimage({ ...base, pathAndQuery: "/x?q=%c3%a9" })).toThrow(
      /non-canonical percent/,
    );
    // incomplete escapes, fragments, spaces, and non-origin-form are refused
    expect(() => deviceSigPreimage({ ...base, pathAndQuery: "/x?q=%C" })).toThrow(/percent/);
    expect(() => deviceSigPreimage({ ...base, pathAndQuery: "/x?q=%ZZ" })).toThrow(/percent/);
    expect(() => deviceSigPreimage({ ...base, pathAndQuery: "/x#frag" })).toThrow(/fragment/);
    expect(() => deviceSigPreimage({ ...base, pathAndQuery: "/x?a b" })).toThrow(/ASCII/);
    expect(() => deviceSigPreimage({ ...base, pathAndQuery: "veto/w1" })).toThrow(/origin-form/);
  });

  it("refuses strings the WHATWG URL serializer would rewrite (signed bytes must be wire bytes)", () => {
    // the serializer re-encodes these before they ever reach the wire, so a
    // signature over the raw form binds bytes that are never transmitted.
    // These vectors are stable across the spec's history:
    for (const raw of [
      '/x"y?q=1', // "  -> %22
      "/x<y", //      <  -> %3C
      "/x>y", //      >  -> %3E
      "/x`y", //      `  -> %60
      "/x{y}", //     { } -> %7B %7D in a path
      "/x\\y", //     \  -> / (path separator rewrite)
      "/x?q=<z>", //  < > -> %3C %3E in a query too
      '/x?q="z"', //  "  -> %22 in a query too
      "//evil", //    protocol-relative: serializes to "/" on another host
    ]) {
      expect(() => deviceSigPreimage({ ...base, pathAndQuery: raw }), raw).toThrow(
        /serialized request-target|request target/,
      );
    }
    // ...and accepts exactly what the serializer transmits verbatim. Canonical
    // percent-encoded spellings are wire bytes on every engine, and the query
    // percent-encode set has never contained ^ or { }:
    for (const wire of ["/x%5Ey", "/x?q=^v", "/x?q={z}", "/x%7By%7D", "/x?q=%3Cz%3E"]) {
      expect(() => deviceSigPreimage({ ...base, pathAndQuery: wire }), wire).not.toThrow();
    }
  });

  it("^ in a PATH follows the running serializer — the fixpoint decides, not a punctuation list", () => {
    // The WHATWG path percent-encode set gained U+005E (^): engines tracking
    // the current spec (Node 24+) rewrite "/x^y" to "/x%5Ey", while older
    // engines (Node 20/22) transmit it verbatim. The validator's contract is
    // "signed bytes are THIS runtime's wire bytes", so the expectation is
    // derived from the active serializer rather than pinned — either way the
    // validator fails closed on anything the wire would not carry as-is.
    // https://url.spec.whatwg.org/#path-percent-encode-set
    const url = new URL("/x^y", "http://canonical.invalid");
    const isFixpoint = url.pathname + url.search === "/x^y";
    if (isFixpoint) {
      expect(() => deviceSigPreimage({ ...base, pathAndQuery: "/x^y" })).not.toThrow();
    } else {
      expect(url.pathname).toBe("/x%5Ey");
      expect(() => deviceSigPreimage({ ...base, pathAndQuery: "/x^y" })).toThrow(
        /serialized request-target/,
      );
    }
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

  it("matches @ownerswitchai/shared's ownerEnrollPopPreimage byte-for-byte (drift guard)", () => {
    // the phone signs THIS transcript; the control plane verifies SHARED's —
    // they are one contract, held identical here the same way the device-sig
    // preimage is pinned above
    expect(sharedEnrollLabel).toBe(ENROLL_POP_LABEL);
    expect(hex(ownerEnrollPopPreimage(base))).toBe(hex(enrollPopTranscript(base)));
  });
});

describe("the pinned invite wire contract (drift guard for the control-plane core)", () => {
  it("InviteMintRequest is the hash-commitment mint: tokenHash, never a secret", () => {
    // a COMPILE-TIME pin: these literals type-check against the pinned
    // contract, so renaming or removing a field breaks this file
    const mint: InviteMintRequest = { tokenHash: "c29tZS1oYXNo", deviceName: "Adam's phone" };
    expect(Object.keys(mint).sort()).toEqual(["deviceName", "tokenHash"]);
  });

  it("EnrollmentRequest carries BOTH proofs: the registration AND the possession assertion", () => {
    const shape: Record<keyof EnrollmentRequest, true> = {
      inviteId: true,
      token: true,
      deviceName: true,
      registration: true,
      possessionAssertion: true,
      cheapLaneKey: true,
      cheapLaneKeyProof: true,
    };
    expect(Object.keys(shape)).toContain("possessionAssertion");
  });

  it("EnrollmentInvite carries BOTH ceremony challenges", () => {
    const keys: Array<keyof EnrollmentInvite> = ["challenge", "assertionChallenge", "token"];
    expect(keys).toContain("assertionChallenge");
  });

  it("the SHARED wire validator and the pinned EnrollmentInvite are the SAME contract (compile-time, both directions)", () => {
    // shared -> app: whatever the validator returns IS a pinned invite
    const fromWire = (wire: EnrollmentInviteWire): EnrollmentInvite => wire;
    // app -> shared: a pinned invite passes as the wire shape (no missing fields)
    const toWire = (invite: EnrollmentInvite): EnrollmentInviteWire => invite;
    // the server's secret-free mint response is EXACTLY the invite minus token
    const contractToInvite = (contract: EnrollmentInviteContract, token: string): EnrollmentInvite => ({
      ...contract,
      token,
    });
    const inviteToContract = (invite: EnrollmentInvite): EnrollmentInviteContract => invite;
    expect([fromWire, toWire, contractToInvite, inviteToContract].every((f) => typeof f === "function")).toBe(
      true,
    );
    // and the runtime validator agrees with the compile-time story: a
    // fully-populated pinned invite round-trips it unchanged
    const invite: EnrollmentInvite = {
      inviteId: "inv_pin",
      token: Buffer.from("t".repeat(24)).toString("base64url"),
      expiresAt: 1,
      ownerId: "owner-adam",
      rpId: "owner.example",
      rpName: "OwnerSwitch",
      user: {
        id: Buffer.from("u".repeat(32)).toString("base64url"),
        name: "owner-adam",
        displayName: "owner-adam",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "preferred",
        userVerification: "required",
      },
      challenge: Buffer.from("c".repeat(24)).toString("base64url"),
      assertionChallenge: Buffer.from("a".repeat(24)).toString("base64url"),
      deviceName: "Adam's phone",
    };
    const validated = enrollmentInviteFromWire(invite);
    expect(validated).not.toBeNull();
    expect(validated).toEqual(invite);
    // an extra key is NOT the contract
    expect(enrollmentInviteFromWire({ ...invite, extra: true })).toBeNull();
    // a missing creation-contract field is NOT the contract
    const { authenticatorSelection: _dropped, ...withoutSelection } = invite;
    expect(enrollmentInviteFromWire(withoutSelection)).toBeNull();
  });
});
