import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createControlPlane } from "@ownerswitchai/control-plane";
import { loadOwnerPasskeyPublicKey } from "./passkey-key.js";

/**
 * PRODUCTION control-plane launcher — `dev: false`, an enrolled owner
 * approval passkey, and a hardened kill-state path. This is the process the
 * live/production procedure runs (packages/executor/MANUAL-VERIFICATION.md),
 * NOT dev-control-plane.ts (which is the quickstart and can only do
 * session-only approval).
 *
 * Everything sensitive is read from FILES into this process's environment or
 * from paths, never argv: the two HMAC keys (grant, kill-state) and the
 * enrolled passkey's SPKI public key. Run it under its own uid, isolated
 * from the agent, from a root-owned installed artifact (see the manual).
 *
 * Required environment:
 *   OWNERSWITCH_CONTROL_PLANE_PORT           listen port (default 4600)
 *   OWNERSWITCH_CONTROL_PLANE_HOST           bind host (default 127.0.0.1)
 *   OWNERSWITCH_DEVICE_SECRET                device-signing shared secret
 *   OWNERSWITCH_KILL_STATE_FILE              absolute, protected kill-state path
 *   OWNERSWITCH_GRANT_KEY                    grant-signing key (>=32 bytes)
 *   OWNERSWITCH_KILL_STATE_KEY               kill-state channel key (>=32 bytes)
 *   OWNERSWITCH_OWNER_PASSKEY_CREDENTIAL_ID  base64url credential id (enrolment)
 *   OWNERSWITCH_OWNER_PASSKEY_PUBLIC_KEY_FILE  path to the SPKI PEM public key
 *   OWNERSWITCH_OWNER_PASSKEY_RP_ID          relying-party id (e.g. owner.example)
 *   OWNERSWITCH_OWNER_PASSKEY_ORIGIN         exact https:// origin of the owner app
 *
 * Optional — 2GO licensing (the paid gate; every stop path is free forever,
 * see control-plane/src/license.ts):
 *   OWNERSWITCH_LICENSE_PUBLIC_KEY_FILE      vendor Ed25519 SPKI PEM; presence
 *                                            arms the gate (402 on unlicensed
 *                                            restore-ceremony starts)
 *   OWNERSWITCH_LICENSE                      this deployment's osl1 token
 */

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}

/**
 * Refuse to start if a Node PRELOAD vector is present in the environment.
 * `NODE_OPTIONS=--import=…`/`--require=…` and `NODE_PATH` run attacker code
 * BEFORE this script — and this process holds the grant key, the kill-state
 * key, and mints owner authority. This is a tripwire: the preload has already
 * run by the time we look, so the real defense is a clean service environment
 * (the MANUAL's systemd unit clears it). But a misconfigured unit then fails
 * LOUDLY here instead of silently serving with injected code in-process.
 */
function assertCleanRuntimeEnv(): void {
  for (const name of ["NODE_OPTIONS", "NODE_PATH"]) {
    const value = process.env[name]?.trim();
    if (value !== undefined && value !== "") {
      throw new Error(
        `${name} is set — refusing to start. This control plane holds the grant and kill-state keys ` +
          `and must run in a clean environment; ${name} can preload code before it. Clear it in the ` +
          `service definition (systemd: Environment=/unset it), then restart.`,
      );
    }
  }
}

function main(): void {
  assertCleanRuntimeEnv();
  const port = Number(process.env.OWNERSWITCH_CONTROL_PLANE_PORT ?? 4600);
  const host = process.env.OWNERSWITCH_CONTROL_PLANE_HOST ?? "127.0.0.1";
  const deviceSecret = required("OWNERSWITCH_DEVICE_SECRET");
  const killStateFile = required("OWNERSWITCH_KILL_STATE_FILE");
  const grantKey = required("OWNERSWITCH_GRANT_KEY");
  const killStateKey = required("OWNERSWITCH_KILL_STATE_KEY");

  const credentialId = required("OWNERSWITCH_OWNER_PASSKEY_CREDENTIAL_ID");
  const publicKeyFile = required("OWNERSWITCH_OWNER_PASSKEY_PUBLIC_KEY_FILE");
  const rpId = required("OWNERSWITCH_OWNER_PASSKEY_RP_ID");
  const origin = required("OWNERSWITCH_OWNER_PASSKEY_ORIGIN");
  // The passkey PUBLIC key is the authorization ROOT for owner approval:
  // whoever can rewrite it enrolls their own authenticator and self-approves
  // a merge. Load it with the same integrity hardening as the App PEM —
  // absolute/canonical path, trusted ancestry, O_NOFOLLOW, regular file,
  // size-capped, no untrusted write bits — and require it to parse as the
  // P-256 SPKI key the assertion verifier accepts, rather than plain
  // readFileSync of an attacker-writable path.
  const publicKeyPem = loadOwnerPasskeyPublicKey(publicKeyFile).pem;

  // 2GO licensing arms only when the verifying key is provisioned. The key
  // must parse as an Ed25519 public key HERE, at boot — a corrupt file must
  // fail the start, not silently turn every future restore into a 402. It
  // gates the paid direction only; a bad license never touches a stop path.
  const licenseKeyFile = process.env.OWNERSWITCH_LICENSE_PUBLIC_KEY_FILE?.trim();
  let licensing: { vendorPublicKeyPem: string; token?: string } | undefined;
  if (licenseKeyFile !== undefined && licenseKeyFile !== "") {
    const vendorPublicKeyPem = readFileSync(licenseKeyFile, "utf8");
    if (createPublicKey(vendorPublicKeyPem).asymmetricKeyType !== "ed25519") {
      throw new Error(
        `OWNERSWITCH_LICENSE_PUBLIC_KEY_FILE (${licenseKeyFile}) is not an Ed25519 public key — ` +
          "provision the vendor's license-verifying.pub.pem",
      );
    }
    const token = process.env.OWNERSWITCH_LICENSE?.trim();
    licensing = { vendorPublicKeyPem, ...(token !== undefined && token !== "" ? { token } : {}) };
  }

  // dev:false — createControlPlane enforces the production kill-state path
  // guard, the >=256-bit key floors, and the https-origin requirement, and
  // (with a passkey enrolled) the approve handler requires a fresh WebAuthn
  // assertion. A misconfiguration refuses to start with a named reason.
  const controlPlane = createControlPlane({
    deviceSecret,
    killStateFile,
    dev: false,
    grantKey,
    killStateKey,
    ownerPasskey: { credentialId, publicKeyPem, rpId, origin },
    ...(licensing !== undefined ? { licensing } : {}),
  });

  createServer(controlPlane.handler).listen(port, host, () => {
    // No secrets, no owner token: this is production, not the quickstart.
    console.error(
      `[ownerswitch] production control plane on ${host}:${port} — passkey approval enrolled ` +
        `(rpId ${rpId}), kill state at ${killStateFile}`,
    );
  });
}

main();
