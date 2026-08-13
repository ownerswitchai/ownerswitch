/**
 * The DEVICE-TO-DEVICE enrolment invite payload — the ONE runtime validator
 * both ends of the QR/typed-code hop use (apps/owner/src/types.ts
 * EnrollmentInvite is the pinned documentation; apps/owner/src/device-sig.test.ts
 * pins the two shapes against each other at compile time):
 *
 *  - the host CLI (packages/control-plane/src/bootstrap-invite-cli.ts)
 *    REFUSES to print a payload this validator rejects — a contract the
 *    phone cannot run never reaches a QR code;
 *  - the owner app validates what it scanned with the same function before
 *    calling navigator.credentials.create().
 *
 * Validation is EXACT at every level: own keys only, no extras, no
 * inherited-property smuggling, canonical base64url by round-trip for every
 * binary field, and the WebAuthn creation constants pinned literally
 * (ES256-only pubKeyCredParams; platform/preferred/required selection).
 */

/** The complete payload, token included — see types.ts EnrollmentInvite. */
export interface EnrollmentInviteWire {
  inviteId: string;
  /** the locally generated single-use secret, in transit between phones only */
  token: string;
  expiresAt: number;
  ownerId: string;
  rpId: string;
  rpName: string;
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: ReadonlyArray<{ type: "public-key"; alg: -7 }>;
  authenticatorSelection: {
    authenticatorAttachment: "platform";
    residentKey: "preferred";
    userVerification: "required";
  };
  challenge: string;
  assertionChallenge: string;
  /** the mint-committed display label — repeated verbatim in EnrollmentRequest.deviceName */
  deviceName: string;
}

/** The secret-free mint response: everything the server may say. */
export type EnrollmentInviteContract = Omit<EnrollmentInviteWire, "token">;

const TOP_KEYS = [
  "inviteId",
  "token",
  "expiresAt",
  "ownerId",
  "rpId",
  "rpName",
  "user",
  "pubKeyCredParams",
  "authenticatorSelection",
  "challenge",
  "assertionChallenge",
  "deviceName",
] as const;

function own(record: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined;
}

function exactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const present = Object.keys(record);
  if (present.length !== keys.length) return false;
  const expected = new Set(keys);
  return present.every((key) => expected.has(key)) && keys.every((key) => own(record, key) !== undefined);
}

function boundedString(value: unknown, max: number): value is string {
  return typeof value === "string" && value !== "" && value.length <= max;
}

function canonicalB64url(value: unknown, minBytes: number, maxBytes: number): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const decoded = base64urlDecode(value);
  return decoded !== null && decoded.length >= minBytes && decoded.length <= maxBytes;
}

/** environment-neutral canonical decode (Node Buffer or browser atob) */
function base64urlDecode(value: string): Uint8Array | null {
  try {
    if (typeof Buffer !== "undefined") {
      const decoded = Buffer.from(value, "base64url");
      return decoded.toString("base64url") === value ? new Uint8Array(decoded) : null;
    }
    const padded = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
    const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
    // canonical round-trip
    let re = "";
    for (const b of bytes) re += String.fromCharCode(b);
    const canonical = btoa(re).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return canonical === value ? bytes : null;
  } catch {
    return null;
  }
}

/**
 * Parse an unknown value as the exact device-to-device invite payload.
 * Returns null on ANY deviation — the caller treats that as "not an invite",
 * never as something to repair.
 */
export function enrollmentInviteFromWire(value: unknown): EnrollmentInviteWire | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, TOP_KEYS)) return null;
  const inviteId = own(record, "inviteId");
  const token = own(record, "token");
  const expiresAt = own(record, "expiresAt");
  const ownerId = own(record, "ownerId");
  const rpId = own(record, "rpId");
  const rpName = own(record, "rpName");
  const userRaw = own(record, "user");
  const paramsRaw = own(record, "pubKeyCredParams");
  const selectionRaw = own(record, "authenticatorSelection");
  const challenge = own(record, "challenge");
  const assertionChallenge = own(record, "assertionChallenge");
  const deviceName = own(record, "deviceName");

  if (!boundedString(inviteId, 256)) return null;
  // the secret: canonical base64url of >=16 bytes (>=128 bits), the mint contract
  if (!canonicalB64url(token, 16, 96)) return null;
  if (typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt) || expiresAt <= 0) return null;
  if (!boundedString(ownerId, 256)) return null;
  if (!boundedString(rpId, 256)) return null;
  if (!boundedString(rpName, 256)) return null;
  if (!boundedString(deviceName, 200)) return null;
  if (!canonicalB64url(challenge, 16, 96)) return null;
  if (!canonicalB64url(assertionChallenge, 16, 96)) return null;

  if (typeof userRaw !== "object" || userRaw === null || Array.isArray(userRaw)) return null;
  const user = userRaw as Record<string, unknown>;
  if (!exactKeys(user, ["id", "name", "displayName"])) return null;
  const userId = own(user, "id");
  const userName = own(user, "name");
  const userDisplayName = own(user, "displayName");
  // the WebAuthn user.id bound: 1..64 bytes; per this design also NEVER the
  // ownerId string re-encoded — it is an opaque handle, not an identifier
  if (!canonicalB64url(userId, 1, 64)) return null;
  if (!boundedString(userName, 256) || !boundedString(userDisplayName, 256)) return null;

  if (!Array.isArray(paramsRaw) || paramsRaw.length !== 1) return null;
  const param = paramsRaw[0] as Record<string, unknown>;
  if (typeof param !== "object" || param === null || Array.isArray(param)) return null;
  if (!exactKeys(param, ["type", "alg"])) return null;
  if (own(param, "type") !== "public-key" || own(param, "alg") !== -7) return null;

  if (typeof selectionRaw !== "object" || selectionRaw === null || Array.isArray(selectionRaw)) return null;
  const selection = selectionRaw as Record<string, unknown>;
  if (!exactKeys(selection, ["authenticatorAttachment", "residentKey", "userVerification"])) return null;
  if (
    own(selection, "authenticatorAttachment") !== "platform" ||
    own(selection, "residentKey") !== "preferred" ||
    own(selection, "userVerification") !== "required"
  ) {
    return null;
  }

  return {
    inviteId: inviteId as string,
    token: token as string,
    expiresAt: expiresAt as number,
    ownerId: ownerId as string,
    rpId: rpId as string,
    rpName: rpName as string,
    user: {
      id: userId as string,
      name: userName as string,
      displayName: userDisplayName as string,
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "preferred",
      userVerification: "required",
    },
    challenge: challenge as string,
    assertionChallenge: assertionChallenge as string,
    deviceName: deviceName as string,
  };
}
