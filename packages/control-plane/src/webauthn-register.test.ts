import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { cborEncode } from "./cbor-fixture.js";
import { verifyOwnerRegistration, type WebAuthnRegistrationWire } from "./webauthn-register.js";

/**
 * Build a SYNTHETIC registration exactly as a platform authenticator would —
 * every byte under test control, so each refusal case flips one fact.
 */
const RP_ID = "owner.example";
const ORIGIN = "https://owner.example";
const CHALLENGE = Buffer.from("c".repeat(32)).toString("base64url");

const keypair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const jwk = keypair.publicKey.export({ format: "jwk" }) as { x: string; y: string };
const X = Buffer.from(jwk.x, "base64url");
const Y = Buffer.from(jwk.y, "base64url");

interface BuildOptions {
  type?: string;
  challenge?: string;
  origin?: string;
  crossOrigin?: boolean;
  topOrigin?: string;
  rpId?: string;
  flags?: number;
  fmt?: string;
  attStmt?: unknown;
  credentialId?: Buffer;
  wireCredentialId?: string;
  coseOverrides?: Map<number, unknown>;
  trailingCoseBytes?: Buffer;
  signCount?: number;
}

function buildRegistration(over: BuildOptions = {}): WebAuthnRegistrationWire {
  const credentialId = over.credentialId ?? Buffer.from("credential-id-bytes-0001");
  const clientData: Record<string, unknown> = {
    type: over.type ?? "webauthn.create",
    challenge: over.challenge ?? CHALLENGE,
    origin: over.origin ?? ORIGIN,
  };
  if (over.crossOrigin !== undefined) clientData.crossOrigin = over.crossOrigin;
  if (over.topOrigin !== undefined) clientData.topOrigin = over.topOrigin;

  const cose = new Map<number, unknown>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, new Uint8Array(X)],
    [-3, new Uint8Array(Y)],
  ]);
  for (const [k, v] of over.coseOverrides ?? []) cose.set(k, v);

  const flags = over.flags ?? 0x45; // UP | UV | AT
  const signCount = over.signCount ?? 7;
  const authData = Buffer.concat([
    createHash("sha256").update(over.rpId ?? RP_ID, "utf8").digest(), // rpIdHash
    Buffer.from([flags]),
    Buffer.from([
      (signCount >>> 24) & 0xff,
      (signCount >>> 16) & 0xff,
      (signCount >>> 8) & 0xff,
      signCount & 0xff,
    ]),
    Buffer.alloc(16), // AAGUID
    Buffer.from([(credentialId.length >> 8) & 0xff, credentialId.length & 0xff]),
    credentialId,
    cborEncode(cose),
    over.trailingCoseBytes ?? Buffer.alloc(0),
  ]);

  const attestation = new Map<unknown, unknown>([
    ["fmt", over.fmt ?? "none"],
    ["attStmt", over.attStmt ?? new Map()],
    ["authData", new Uint8Array(authData)],
  ]);
  return {
    credentialId: over.wireCredentialId ?? credentialId.toString("base64url"),
    clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString("base64url"),
    attestationObject: cborEncode(attestation).toString("base64url"),
  };
}

const OPTS = { rpId: RP_ID, expectedOrigin: ORIGIN, expectedChallenge: CHALLENGE };

describe("verifyOwnerRegistration — the enrolment ceremony's registration half", () => {
  it("accepts a well-formed registration and returns the CANONICAL credential", () => {
    const verdict = verifyOwnerRegistration(buildRegistration(), OPTS);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      expect(verdict.credentialId).toBe(Buffer.from("credential-id-bytes-0001").toString("base64url"));
      expect(verdict.signCount).toBe(7);
      // the returned PEM is the CANONICAL re-export of the same P-256 point
      expect(verdict.publicKeyPem).toBe(
        keypair.publicKey.export({ type: "spki", format: "pem" }).toString(),
      );
    }
  });

  it("refuses every clientDataJSON lie: type, challenge, origin, crossOrigin, topOrigin", () => {
    const cases: Array<[BuildOptions, RegExp]> = [
      [{ type: "webauthn.get" }, /assertion cannot enroll/],
      [{ challenge: Buffer.from("x".repeat(32)).toString("base64url") }, /challenge/],
      [{ origin: "https://evil.example" }, /origin/],
      [{ crossOrigin: true }, /cross-origin/],
      [{ topOrigin: "https://framer.example" }, /top-level origin/],
    ];
    for (const [over, why] of cases) {
      const verdict = verifyOwnerRegistration(buildRegistration(over), OPTS);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(why);
    }
  });

  it('refuses any attestation format other than "none", and a non-empty attStmt', () => {
    const packed = verifyOwnerRegistration(buildRegistration({ fmt: "packed" }), OPTS);
    expect(packed.ok).toBe(false);
    if (!packed.ok) expect(packed.reason).toMatch(/not supported/);

    const smuggled = verifyOwnerRegistration(
      buildRegistration({ attStmt: new Map([["sig", new Uint8Array(8)]]) }),
      OPTS,
    );
    expect(smuggled.ok).toBe(false);
    if (!smuggled.ok) expect(smuggled.reason).toMatch(/empty attStmt/);
  });

  it("refuses authenticatorData lies: rpIdHash, missing UP/UV/AT, ED set", () => {
    const wrongRp = verifyOwnerRegistration(buildRegistration({ rpId: "other.example" }), OPTS);
    expect(wrongRp.ok).toBe(false);
    if (!wrongRp.ok) expect(wrongRp.reason).toMatch(/rpIdHash/);

    for (const [flags, why] of [
      [0x44, /user-presence/], // UV|AT, no UP
      [0x41, /user-verification/], // UP|AT, no UV
      [0x05, /attested-credential-data/], // UP|UV, no AT
      [0xc5, /extension-data/], // UP|UV|AT|ED
    ] as Array<[number, RegExp]>) {
      const verdict = verifyOwnerRegistration(buildRegistration({ flags }), OPTS);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(why);
    }
  });

  it("refuses a wire credentialId that differs from the attested bytes", () => {
    const verdict = verifyOwnerRegistration(
      buildRegistration({ wireCredentialId: Buffer.from("some-other-id").toString("base64url") }),
      OPTS,
    );
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/does not match the attested/);
  });

  it("refuses trailing bytes after the COSE key — no smuggling room in authenticatorData", () => {
    const verdict = verifyOwnerRegistration(
      buildRegistration({ trailingCoseBytes: Buffer.from([0x00]) }),
      OPTS,
    );
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/trailing bytes/);
  });

  it("refuses every COSE lie: kty, alg, curve, coordinate sizes, off-curve point", () => {
    const cases: Array<[Map<number, unknown>, RegExp]> = [
      [new Map([[1, 1]]), /not EC2/], // OKP
      [new Map([[3, -257]]), /not ES256/], // RS256
      [new Map([[-1, 2]]), /not P-256/], // P-384
      [new Map([[-2, new Uint8Array(31)]]), /32 bytes/],
      [new Map([[-2, new Uint8Array(32).fill(0xff)]]), /valid P-256 point/], // x=all-ff with our y: off-curve
    ];
    for (const [coseOverrides, why] of cases) {
      const verdict = verifyOwnerRegistration(buildRegistration({ coseOverrides }), OPTS);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(why);
    }
  });
});
