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
 */

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}

function main(): void {
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
