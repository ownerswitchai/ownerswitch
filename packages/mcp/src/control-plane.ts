import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import {
  createControlPlane,
  loadOwnerDeviceKeysFile,
  OWNERSWITCH_VENDOR_LICENSE_PUBLIC_KEY_PEM,
} from "@ownerswitchai/control-plane";
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
 * 2GO licensing — ALWAYS ARMED in production (control-plane/src/license.ts;
 * every stop path is free forever). The gate verifies against the pinned
 * official vendor key by default, so an unlicensed production plane is born
 * protected: POST /restore/ceremony answers 402 until OWNERSWITCH_LICENSE is
 * provisioned. Dev/quickstart (dev-control-plane.ts) stays ungated.
 *   OWNERSWITCH_LICENSE                      this deployment's osl1 token
 *   OWNERSWITCH_LICENSE_PUBLIC_KEY_FILE      optional override of the pinned
 *                                            vendor key (self-hosted forks)
 *   OWNERSWITCH_DEPLOYMENT_ID                required by deployment-bound
 *                                            licenses (theft containment)
 *
 * Owner-app delivery ack (apps/owner):
 *   OWNERSWITCH_OWNER_DEVICE_KEYS_FILE       JSON {deviceId: ECDSA P-256 SPKI
 *                                            PEM} enrolling the owner app's
 *                                            device public keys — the only
 *                                            credential that may confirm
 *                                            delivery; absent → /veto/:id/seen
 *                                            is 501 (fail closed)
 *   OWNERSWITCH_OWNER_DEVICE_STANDING_FILE   durable {generation, revokedAt}
 *                                            registry — REQUIRED when device
 *                                            keys are enrolled, so a
 *                                            revocation survives a restart;
 *                                            shared with the escalation
 *                                            service
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
  // Enrolled owner-app devices — the ONLY credential that may flip the
  // release-permitting delivered bit (POST /veto/:id/seen). ASYMMETRIC:
  // a JSON file mapping deviceId → ECDSA P-256 SPKI PEM (the phone's PUBLIC
  // key; the private half never leaves the device). Optional: absent,
  // delivery confirmation is 501 and windows walk to passkey approval (fail
  // closed). No shared secret exists here to leak or to collide with the
  // fleet secret — that whole failure mode is gone by construction.
  const ownerDeviceKeysFile = process.env.OWNERSWITCH_OWNER_DEVICE_KEYS_FILE?.trim();
  const ownerDeviceKeys =
    ownerDeviceKeysFile !== undefined && ownerDeviceKeysFile !== ""
      ? loadOwnerDeviceKeysFile(ownerDeviceKeysFile)
      : {};
  // Durable owner-device STANDING ({generation, revokedAt}) — REQUIRED by
  // createControlPlane whenever owner devices are enrolled (dev:false): a
  // revocation must survive a restart, or a stolen phone resurrects on the
  // next boot. The escalation service points at the SAME file.
  const ownerDeviceStandingFile = process.env.OWNERSWITCH_OWNER_DEVICE_STANDING_FILE?.trim();
  // 0640 publication for the distinct-UID model (escalation in a dedicated
  // read-only group); default 0600 when CP and escalation share a user.
  const standingGroupReadable = process.env.OWNERSWITCH_OWNER_DEVICE_STANDING_GROUP_READABLE === "1";
  // The escalation read-only group's numeric gid — fchowned onto the file
  // before publication and verified after; without it, 0640 grants read to
  // whatever the CP's default group is, not the escalation service's.
  const standingGidRaw = process.env.OWNERSWITCH_OWNER_DEVICE_STANDING_GID?.trim();
  let standingGid: number | undefined;
  if (standingGidRaw !== undefined && standingGidRaw !== "") {
    standingGid = Number(standingGidRaw);
    if (!Number.isInteger(standingGid) || standingGid < 0) {
      throw new Error("OWNERSWITCH_OWNER_DEVICE_STANDING_GID must be a non-negative integer gid");
    }
  }
  // ALL-OR-NOTHING (also enforced inside createControlPlane): half a 0640
  // configuration is a silent failure in one of two directions — refuse the
  // boot HERE with the env names the operator actually typed.
  if (standingGroupReadable && standingGid === undefined) {
    throw new Error(
      "OWNERSWITCH_OWNER_DEVICE_STANDING_GROUP_READABLE=1 requires OWNERSWITCH_OWNER_DEVICE_STANDING_GID — " +
        "0640 without an explicit gid grants read to the control plane's default group, not the escalation's",
    );
  }
  if (standingGid !== undefined && !standingGroupReadable) {
    throw new Error(
      "OWNERSWITCH_OWNER_DEVICE_STANDING_GID without OWNERSWITCH_OWNER_DEVICE_STANDING_GROUP_READABLE=1 " +
        "does nothing — the file stays 0600 and the named group cannot read it; set both or neither",
    );
  }
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

  // 2GO licensing is ALWAYS ARMED in production: the pinned official vendor
  // key by default, or an explicit override for self-hosted forks. An
  // override must parse as an Ed25519 public key HERE, at boot — a corrupt
  // file must fail the start, not silently turn every future restore into a
  // 402. The gate covers the paid direction only; no license state ever
  // touches a stop path.
  const licenseKeyFile = process.env.OWNERSWITCH_LICENSE_PUBLIC_KEY_FILE?.trim();
  let vendorPublicKeyPem = OWNERSWITCH_VENDOR_LICENSE_PUBLIC_KEY_PEM;
  if (licenseKeyFile !== undefined && licenseKeyFile !== "") {
    vendorPublicKeyPem = readFileSync(licenseKeyFile, "utf8");
    if (createPublicKey(vendorPublicKeyPem).asymmetricKeyType !== "ed25519") {
      throw new Error(
        `OWNERSWITCH_LICENSE_PUBLIC_KEY_FILE (${licenseKeyFile}) is not an Ed25519 public key — ` +
          "provision the vendor's license-verifying.pub.pem",
      );
    }
  }
  const token = process.env.OWNERSWITCH_LICENSE?.trim();
  // deployment-bound licenses need this to match what the vendor minted;
  // the honeytoken registry already treats it as the deployment's
  // immutable name, so licensing reuses it rather than inventing another
  const deploymentId = process.env.OWNERSWITCH_DEPLOYMENT_ID?.trim();
  const licensing = {
    vendorPublicKeyPem,
    ...(token !== undefined && token !== "" ? { token } : {}),
    ...(deploymentId !== undefined && deploymentId !== "" ? { deploymentId } : {}),
  };

  // dev:false — createControlPlane enforces the production kill-state path
  // guard, the >=256-bit key floors, and the https-origin requirement, and
  // (with a passkey enrolled) the approve handler requires a fresh WebAuthn
  // assertion. A misconfiguration refuses to start with a named reason.
  const controlPlane = createControlPlane({
    deviceSecret,
    ...(Object.keys(ownerDeviceKeys).length > 0 ? { ownerDeviceKeys } : {}),
    ...(ownerDeviceStandingFile !== undefined && ownerDeviceStandingFile !== ""
      ? { ownerDeviceStandingFile }
      : {}),
    ...(standingGroupReadable ? { ownerDeviceStandingGroupReadable: true } : {}),
    ...(standingGid !== undefined ? { ownerDeviceStandingGid: standingGid } : {}),
    killStateFile,
    dev: false,
    grantKey,
    killStateKey,
    ownerPasskey: { credentialId, publicKeyPem, rpId, origin },
    licensing,
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
