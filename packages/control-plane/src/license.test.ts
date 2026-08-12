import { createPublicKey } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  generateLicenseKeys,
  mintLicense,
  OWNERSWITCH_VENDOR_LICENSE_PUBLIC_KEY_PEM,
  RESTORE_GRACE_MS,
  verifyLicense,
  type LicensePayload,
} from "./license.js";

const keys = generateLicenseKeys();
const payload = (overrides: Partial<LicensePayload> = {}): LicensePayload => ({
  v: 1,
  jti: "lic_1",
  plan: "team",
  licensee: "Example Co.",
  issuedAt: 1_000,
  expiresAt: 1_000 + 365 * 86_400_000,
  ...overrides,
});

describe("license mint + verify", () => {
  it("a minted license verifies and reports valid until expiry", () => {
    const token = mintLicense(payload(), keys.privateKeyPem);
    expect(token).toMatch(/^osl1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    const verdict = verifyLicense(token, keys.publicKeyPem, 2_000);
    expect(verdict).toEqual({ ok: true, license: payload(), state: "valid" });
  });

  it("expiry enters the 72 h anti-ransom grace, then refuses with a renewal message", () => {
    const token = mintLicense(payload(), keys.privateKeyPem);
    const expiry = payload().expiresAt;
    expect(verifyLicense(token, keys.publicKeyPem, expiry + 1).ok && "grace").toBeTruthy();
    expect(verifyLicense(token, keys.publicKeyPem, expiry + RESTORE_GRACE_MS - 1)).toMatchObject({
      ok: true,
      state: "grace",
    });
    const dead = verifyLicense(token, keys.publicKeyPem, expiry + RESTORE_GRACE_MS + 1);
    expect(dead.ok).toBe(false);
    if (!dead.ok) {
      expect(dead.reason).toMatch(/renew/);
      expect(dead.reason).toMatch(/stopping is unaffected and free/);
    }
  });

  it("a tampered payload or a foreign key fails the signature", () => {
    const token = mintLicense(payload(), keys.privateKeyPem);
    const [prefix, body, sig] = token.split(".");
    const forged = JSON.parse(Buffer.from(body, "base64url").toString()) as LicensePayload;
    forged.plan = "enterprise";
    const forgedToken = `${prefix}.${Buffer.from(JSON.stringify(forged)).toString("base64url")}.${sig}`;
    expect(verifyLicense(forgedToken, keys.publicKeyPem, 2_000).ok).toBe(false);

    const otherKeys = generateLicenseKeys();
    expect(verifyLicense(token, otherKeys.publicKeyPem, 2_000).ok).toBe(false);
    expect(verifyLicense(token, "not a pem", 2_000)).toMatchObject({ ok: false });
  });

  it("garbage tokens and future-dated licenses are refused with named reasons", () => {
    expect(verifyLicense("", keys.publicKeyPem, 0)).toMatchObject({ ok: false });
    expect(verifyLicense("jwt.looking.thing", keys.publicKeyPem, 0).ok).toBe(false);
    const future = mintLicense(payload({ issuedAt: 5_000, expiresAt: 9_000 }), keys.privateKeyPem);
    const verdict = verifyLicense(future, keys.publicKeyPem, 1_000);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/not yet valid/);
  });

  it("a deployment-bound license verifies only where the ids match — theft containment", () => {
    const bound = mintLicense(payload({ deploymentId: "dep-alpha" }), keys.privateKeyPem);

    // the rightful deployment
    expect(verifyLicense(bound, keys.publicKeyPem, 2_000, "dep-alpha")).toMatchObject({
      ok: true,
      state: "valid",
    });
    // stolen: replayed on another deployment, or one with no id at all
    const wrong = verifyLicense(bound, keys.publicKeyPem, 2_000, "dep-bravo");
    expect(wrong.ok).toBe(false);
    if (!wrong.ok) expect(wrong.reason).toMatch(/bound to deployment/);
    expect(verifyLicense(bound, keys.publicKeyPem, 2_000).ok).toBe(false);

    // an UNBOUND license still works anywhere (the opt-out stays possible)
    const unbound = mintLicense(payload(), keys.privateKeyPem);
    expect(verifyLicense(unbound, keys.publicKeyPem, 2_000, "dep-alpha").ok).toBe(true);
    expect(verifyLicense(unbound, keys.publicKeyPem, 2_000).ok).toBe(true);
  });

  it("the pinned vendor key is a real Ed25519 key, and self-minted tokens die against it", () => {
    expect(createPublicKey(OWNERSWITCH_VENDOR_LICENSE_PUBLIC_KEY_PEM).asymmetricKeyType).toBe(
      "ed25519",
    );
    // protected by default: a token signed with ANY other key — including a
    // fresh keygen on the deployment's own host — does not verify
    const selfMinted = mintLicense(payload(), keys.privateKeyPem);
    const verdict = verifyLicense(selfMinted, OWNERSWITCH_VENDOR_LICENSE_PUBLIC_KEY_PEM, 2_000);
    expect(verdict).toMatchObject({ ok: false });
    if (!verdict.ok) expect(verdict.reason).toMatch(/signature/);
  });

  it("mint refuses malformed payloads outright", () => {
    expect(() => mintLicense(payload({ plan: "gold" as never }), keys.privateKeyPem)).toThrow(/plan/);
    expect(() => mintLicense(payload({ licensee: "" }), keys.privateKeyPem)).toThrow(/licensee/);
    expect(() =>
      mintLicense(payload({ expiresAt: 500 }), keys.privateKeyPem),
    ).toThrow(/after issuedAt/);
  });
});
