import { isIP } from "node:net";

/**
 * Startup validation for the console CLI, matched to what the RUNTIME will
 * actually accept (post-merge audit #10) — a config that passes here must
 * not die later inside the signer or resolve somewhere unexpected.
 */

/**
 * True only for NUMERIC loopback: "::1" or a VALID dotted-quad in
 * 127.0.0.0/8. Resolver names are out — "localhost" included: the hosts
 * file or DNS decides what a name means, and a "loopback" bind must not
 * depend on that decision (the old regex even accepted 127.999.999.999,
 * which is not an IP literal at all).
 */
export function isLoopbackBind(bind: string): boolean {
  if (bind === "::1") return true;
  return isIP(bind) === 4 && bind.startsWith("127.");
}

/**
 * The device id grammar the signing lane enforces (device-sig.ts: dot-free,
 * non-empty — one signed string must never parse as two credentials),
 * tightened to printable ASCII with a bound. Checked at startup so a bad id
 * fails HERE, loudly — not inside the first signed call, where it would
 * silently disable VETO and kill attribution (the signer throws before any
 * fetch happens).
 */
export function validateDeviceId(id: string): void {
  if (id === "" || id.includes(".") || id.length > 128 || !/^[\x21-\x7e]+$/.test(id)) {
    throw new Error(
      'OWNERSWITCH_DEVICE_ID must be 1-128 printable ASCII characters with no "." — ' +
        "the device-HMAC payload is dot-joined and the signer refuses ambiguous ids",
    );
  }
}
