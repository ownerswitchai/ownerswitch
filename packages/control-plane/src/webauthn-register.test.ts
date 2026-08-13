import { createHash, generateKeyPairSync, randomBytes, sign as ecSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { cborEncode } from "./cbor-fixture.js";
import { verifyOwnerAssertion } from "./webauthn.js";
import { spkiToPem, verifyOwnerRegistration, type WebAuthnRegistrationWire } from "./webauthn-register.js";

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
  it("accepts a well-formed registration and returns the CANONICAL credential (SPKI DER base64url)", () => {
    const verdict = verifyOwnerRegistration(buildRegistration(), OPTS);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      expect(verdict.credentialId).toBe(Buffer.from("credential-id-bytes-0001").toString("base64url"));
      expect(verdict.signCount).toBe(7);
      // THE stored representation: base64url of the canonical SPKI DER…
      expect(verdict.publicKeySpki).toBe(
        (keypair.publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64url"),
      );
      // …and the one conversion to PEM at the assertion-verify edge round-trips
      expect(spkiToPem(verdict.publicKeySpki)).toBe(
        keypair.publicKey.export({ type: "spki", format: "pem" }).toString(),
      );
    }
  });

  it("NEVER THROWS on raw request JSON: null, numbers, arrays, extra keys, oversize — all refusal reasons", () => {
    const cases: unknown[] = [
      null,
      undefined,
      42,
      "registration",
      [buildRegistration()],
      {},
      { credentialId: "AA" }, // missing fields
      { ...buildRegistration(), extra: "x" }, // unexpected property
      { ...buildRegistration(), clientDataJSON: null },
      { ...buildRegistration(), credentialId: 42 },
      { ...buildRegistration(), attestationObject: { nested: true } },
      { ...buildRegistration(), attestationObject: "A".repeat(129 * 1024) }, // oversize
      { ...buildRegistration(), clientDataJSON: "!!!not-base64url!!!" },
    ];
    for (const wire of cases) {
      const verdict = verifyOwnerRegistration(wire, OPTS);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(typeof verdict.reason).toBe("string");
    }
  });

  it("PROTO INJECTION: __proto__ maps cannot smuggle fmt/attStmt/authData or COSE fields", () => {
    // outer attestation: { "__proto__": {fmt:"none", attStmt:{}, authData:...} }
    // — with a setter-based decoder this would INHERIT a passing shape
    const good = buildRegistration();
    const authData = (() => {
      // reuse the good registration's real authData bytes for the payload
      const decodedGood = Buffer.from(good.attestationObject, "base64url");
      return decodedGood; // opaque — the hostile map below carries it nested
    })();
    const hostileOuter = cborEncode(
      new Map([["__proto__", new Map<unknown, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", new Uint8Array(authData)]])]]),
    ).toString("base64url");
    const outer = verifyOwnerRegistration({ ...good, attestationObject: hostileOuter }, OPTS);
    expect(outer.ok).toBe(false);
    if (!outer.ok) expect(outer.reason).toMatch(/prototype pollution|__proto__|exactly fmt/);

    // attStmt as { "__proto__": {...} } — must not read as "empty"
    const smuggledStmt = verifyOwnerRegistration(
      buildRegistration({ attStmt: new Map([["__proto__", new Map([["sig", 1]])]]) }),
      OPTS,
    );
    expect(smuggledStmt.ok).toBe(false);

    // COSE { "__proto__": {1:2,3:-7,-1:1,-2:x,-3:y} } — must not inherit a key
    const hostileCose = new Map<unknown, unknown>([
      [
        "__proto__",
        new Map<unknown, unknown>([
          [1, 2],
          [3, -7],
          [-1, 1],
          [-2, new Uint8Array(X)],
          [-3, new Uint8Array(Y)],
        ]),
      ],
    ]);
    // splice the hostile COSE into otherwise-valid authData
    const credentialId = Buffer.from("credential-id-bytes-0001");
    const hostileAuthData = Buffer.concat([
      createHash("sha256").update(RP_ID, "utf8").digest(),
      Buffer.from([0x45]),
      Buffer.from([0, 0, 0, 7]),
      Buffer.alloc(16),
      Buffer.from([(credentialId.length >> 8) & 0xff, credentialId.length & 0xff]),
      credentialId,
      cborEncode(hostileCose),
    ]);
    const attestation = new Map<unknown, unknown>([
      ["fmt", "none"],
      ["attStmt", new Map()],
      ["authData", new Uint8Array(hostileAuthData)],
    ]);
    const cose = verifyOwnerRegistration(
      { ...good, attestationObject: cborEncode(attestation).toString("base64url") },
      OPTS,
    );
    expect(cose.ok).toBe(false);
  });

  it("DIRECTION B composition: registration + a FRESH assertion with the new credential = possession proof; a wrong key fails it", () => {
    // 1. the registration verifies structurally and yields the canonical key
    const verdict = verifyOwnerRegistration(buildRegistration(), OPTS);
    expect(verdict.ok).toBe(true);
    if (!verdict.ok) throw new Error("unreachable");

    // 2. the ceremony's SECOND challenge: a webauthn.get assertion signed by
    //    the NEW credential's private key, verified against the key the
    //    registration verdict returned — THIS is what proves possession + UV
    const assertionChallenge = randomBytes(32).toString("base64url");
    const makeAssertion = (privateKey: typeof keypair.privateKey) => {
      const clientData = Buffer.from(
        JSON.stringify({ type: "webauthn.get", challenge: assertionChallenge, origin: ORIGIN }),
      );
      const authenticatorData = Buffer.concat([
        createHash("sha256").update(RP_ID, "utf8").digest(),
        Buffer.from([0x05]), // UP | UV
        Buffer.from([0, 0, 0, 8]),
      ]);
      const signed = Buffer.concat([authenticatorData, createHash("sha256").update(clientData).digest()]);
      return {
        credentialId: verdict.credentialId,
        clientDataJSON: clientData.toString("base64url"),
        authenticatorData: authenticatorData.toString("base64url"),
        signature: ecSign("sha256", signed, privateKey).toString("base64url"), // DER, as verifyOwnerAssertion takes
      };
    };
    const passkey = { credentialId: verdict.credentialId, publicKeyPem: spkiToPem(verdict.publicKeySpki) };
    const possession = verifyOwnerAssertion(makeAssertion(keypair.privateKey), {
      passkey,
      rpId: RP_ID,
      expectedOrigin: ORIGIN,
      expectedChallenge: assertionChallenge,
      lastSignCount: 0,
    });
    expect(possession.ok).toBe(true);

    // 3. a client that does NOT hold the new private key cannot complete the pair
    const thief = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const forged = verifyOwnerAssertion(makeAssertion(thief.privateKey), {
      passkey,
      rpId: RP_ID,
      expectedOrigin: ORIGIN,
      expectedChallenge: assertionChallenge,
      lastSignCount: 0,
    });
    expect(forged.ok).toBe(false);
  });

  it("refuses every clientDataJSON lie: type, challenge, origin, crossOrigin, topOrigin", () => {
    const cases: Array<[BuildOptions, RegExp]> = [
      [{ type: "webauthn.get" }, /assertion cannot enroll/],
      [{ challenge: Buffer.from("x".repeat(32)).toString("base64url") }, /challenge/],
      [{ origin: "https://evil.example" }, /origin/],
      [{ crossOrigin: true }, /cross-origin/],
      [{ crossOrigin: "yes" as unknown as boolean }, /cross-origin/], // non-boolean lie
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
