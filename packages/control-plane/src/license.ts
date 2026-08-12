import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, generateKeyPairSync } from "node:crypto";

/**
 * OwnerSwitch licenses — the paid half of "one press to stop, two GOs to
 * start".
 *
 * THE PRICING DOCTRINE, stated once and load-bearing everywhere:
 *
 *   STOPPING IS FREE, FOREVER, FOR EVERYONE. The kill switch, the veto
 *   tap, the escalation ladder's stops, the delivery ack, the status
 *   surfaces — no code path in the deny direction may ever consult a
 *   license, and none does: this module is imported by exactly one
 *   enforcement point, the 2GO restore ceremony's START (server.ts,
 *   postCeremonyStart). The safety layer must never be a sales lever.
 *
 *   RESTORING IS THE PRODUCT. 2GO — the ceremony that turns a killed
 *   fleet back on — is what a TEAM/ENTERPRISE license buys. Restart
 *   authority is the expensive, ceremonial direction by design
 *   (THREAT-MODEL doctrine: stops cheap, starts expensive), so the
 *   paywall sits exactly where the ceremony already does.
 *
 *   THE PAYWALL MUST NEVER BECOME A RANSOM NOTE. A license that expired
 *   while your fleet was killed still restores for RESTORE_GRACE_MS
 *   (72 h) past its expiry — a lapsed card cannot hold a production
 *   incident hostage. Past the grace, renewal is required; the fleet
 *   stays safely stopped meanwhile, which is the fail-closed direction
 *   this system always degrades toward.
 *
 * Format — `osl1.<base64url payload JSON>.<base64url Ed25519 signature>`:
 * offline-verifiable against the vendor's PUBLIC key, no phone-home, no
 * telemetry, works air-gapped. The repo is source-available under
 * FSL-1.1-ALv2; this check keeps honest deployments honest and the
 * license terms do the rest — it is integrity enforcement, not DRM.
 */

export const LICENSE_PREFIX = "osl1";

/**
 * The OFFICIAL OwnerSwitch vendor license-verifying key, pinned. This is the
 * PUBLIC half — committing it is the point: every production launcher arms
 * the 2GO gate against it by default, so a fresh production deployment is
 * born protected (unlicensed restores answer 402) with zero configuration.
 * The signing half exists only offline with the vendor. Rotation is a code
 * change (replace this constant), which is exactly the auditability a
 * pinned trust root should have; self-hosted forks may override it via
 * OWNERSWITCH_LICENSE_PUBLIC_KEY_FILE — the FSL license terms, not this
 * constant, are what bind a fork.
 */
export const OWNERSWITCH_VENDOR_LICENSE_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAqwfjngoxSBib0t+TnWLgXDU4hKuiYKRpynv0jVYvenw=
-----END PUBLIC KEY-----
`;

/** How long past expiry a restore still works. A floor, not a knob. */
export const RESTORE_GRACE_MS = 72 * 3_600_000;

export type LicensePlan = "team" | "enterprise";

export interface LicensePayload {
  v: 1;
  /** unique license id, for support and revocation lists */
  jti: string;
  plan: LicensePlan;
  /** who this was issued to — a company or a person, shown in errors/logs */
  licensee: string;
  /**
   * THEFT CONTAINMENT, opt-in: when present, the license verifies ONLY on
   * the control plane configured with the same OWNERSWITCH_DEPLOYMENT_ID
   * (the same immutable id the honeytoken registry pins). A leaked token
   * then licenses nothing anywhere else. Worth stating what theft can and
   * cannot do either way: a license is NOT an authorization credential —
   * restoring YOUR fleet still demands YOUR owner session, passkey and the
   * 2GO ceremony; a stolen token at most runs a STRANGER'S deployment
   * under your name (piracy, handled by binding + the license terms),
   * never a restore of yours.
   */
  deploymentId?: string;
  /** unix ms */
  issuedAt: number;
  /** unix ms; restores keep working until expiresAt + RESTORE_GRACE_MS */
  expiresAt: number;
}

export type LicenseVerdict =
  | { ok: true; license: LicensePayload; state: "valid" | "grace" }
  | { ok: false; reason: string };

const b64url = (buf: Buffer) => buf.toString("base64url");

/** Vendor tooling: a fresh Ed25519 keypair, PEM (PKCS8 private, SPKI public). */
export function generateLicenseKeys(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  };
}

/** Vendor-side: sign a license. Throws on a malformed payload. */
export function mintLicense(payload: LicensePayload, privateKeyPem: string): string {
  assertPayload(payload);
  const body = Buffer.from(JSON.stringify(payload));
  const signature = edSign(null, body, createPrivateKey(privateKeyPem));
  return `${LICENSE_PREFIX}.${b64url(body)}.${b64url(signature)}`;
}

/**
 * Deployment-side: verify a token against the vendor public key. Signature
 * and shape only plus the grace rule — callers get a named state ("valid"
 * until expiry, "grace" until expiry + RESTORE_GRACE_MS) or a named
 * refusal. Reasons are safe to show an owner mid-incident: they say what
 * to do, not what to guess.
 */
export function verifyLicense(
  token: string,
  vendorPublicKeyPem: string,
  now: number,
  /** this deployment's OWNERSWITCH_DEPLOYMENT_ID, for bound licenses */
  expectedDeploymentId?: string,
): LicenseVerdict {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== LICENSE_PREFIX) {
    return { ok: false, reason: `not an OwnerSwitch license (expected "${LICENSE_PREFIX}.…")` };
  }
  const body = Buffer.from(parts[1], "base64url");
  const signature = Buffer.from(parts[2], "base64url");
  let verified: boolean;
  try {
    verified = edVerify(null, body, createPublicKey(vendorPublicKeyPem), signature);
  } catch {
    return { ok: false, reason: "license verification key is not a valid Ed25519 public key" };
  }
  if (!verified) return { ok: false, reason: "license signature does not verify" };

  let payload: LicensePayload;
  try {
    payload = JSON.parse(body.toString()) as LicensePayload;
    assertPayload(payload);
  } catch (err) {
    return { ok: false, reason: `license payload invalid: ${err instanceof Error ? err.message : "malformed"}` };
  }
  if (payload.deploymentId !== undefined && payload.deploymentId !== expectedDeploymentId) {
    // a stolen bound token dies here: right signature, wrong deployment
    return {
      ok: false,
      reason:
        `license is bound to deployment "${payload.deploymentId}" — this control plane is ` +
        (expectedDeploymentId === undefined
          ? "not configured with a deployment id (set OWNERSWITCH_DEPLOYMENT_ID)"
          : `"${expectedDeploymentId}"`),
    };
  }
  if (now < payload.issuedAt) {
    return { ok: false, reason: "license is not yet valid (issuedAt is in the future)" };
  }
  if (now < payload.expiresAt) return { ok: true, license: payload, state: "valid" };
  if (now < payload.expiresAt + RESTORE_GRACE_MS) {
    // expired, inside the anti-ransom grace: restores still work, loudly
    return { ok: true, license: payload, state: "grace" };
  }
  return {
    ok: false,
    reason:
      `license for "${payload.licensee}" expired ${new Date(payload.expiresAt).toISOString()} ` +
      "and the 72 h restore grace has passed — renew to restore (stopping is unaffected and free)",
  };
}

function assertPayload(payload: LicensePayload): void {
  if (payload.v !== 1) throw new Error("v must be 1");
  if (typeof payload.jti !== "string" || payload.jti === "") throw new Error("jti required");
  if (payload.plan !== "team" && payload.plan !== "enterprise") {
    throw new Error('plan must be "team" or "enterprise"');
  }
  if (typeof payload.licensee !== "string" || payload.licensee === "") {
    throw new Error("licensee required");
  }
  if (payload.deploymentId !== undefined && (typeof payload.deploymentId !== "string" || payload.deploymentId === "")) {
    throw new Error("deploymentId must be a non-empty string when present");
  }
  if (!Number.isInteger(payload.issuedAt) || !Number.isInteger(payload.expiresAt)) {
    throw new Error("issuedAt/expiresAt must be integer unix ms");
  }
  if (payload.expiresAt <= payload.issuedAt) throw new Error("expiresAt must be after issuedAt");
}
