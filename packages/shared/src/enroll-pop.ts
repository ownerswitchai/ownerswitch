/**
 * The enrolment proof-of-possession transcript — the byte string a new
 * device's cheap-lane PRIVATE key signs to prove, inside the enrolment
 * ceremony itself, that the submitted public key is not dead weight
 * (apps/owner/DESIGN.md §2 step 4). Verified BEFORE the invite is consumed:
 * a key the client cannot sign with is refused and the invite survives — a
 * root-of-trust ceremony must not accept a credential that cannot act.
 *
 * The transcript binds the key to THIS ceremony: the invite being spent,
 * the owner it enrolls for, and the WebAuthn credential it will share a
 * device record with — so a captured proof cannot be replayed into another
 * invite, another owner, or grafted next to a different passkey. Encoding
 * is the same injective length-prefixed concatenation as the device-sig
 * preimage (owner-device-sig.ts): 4-byte big-endian byte counts, fields in
 * a fixed order, so no two field tuples share an encoding.
 *
 * Pinned CONTRACT (mirrored, import-free, in apps/owner/src/types.ts as
 * ENROLL_POP_LABEL — a drift test holds the two identical): ECDSA P-256
 * with SHA-256, signature is WebCrypto's raw IEEE P1363 r||s (64 bytes,
 * never DER), base64url. Fields, in order: this label (UTF-8), inviteId
 * (UTF-8), ownerId (UTF-8), the WebAuthn credentialId (RAW bytes,
 * base64url-decoded), the SPKI public key (RAW DER bytes).
 */
import { lengthPrefixed, utf8 } from "./owner-device-sig.js";

export const ENROLL_POP_LABEL = "ownerswitch/enroll-cheap-lane/v1";

export interface EnrollPopFields {
  inviteId: string;
  ownerId: string;
  /** RAW WebAuthn credential id bytes (base64url-decoded by the caller) */
  credentialId: Uint8Array;
  /** RAW SPKI DER of the cheap-lane public key being enrolled */
  spki: Uint8Array;
}

export function ownerEnrollPopPreimage(fields: EnrollPopFields): Uint8Array {
  if (fields.inviteId === "") throw new Error("enroll PoP requires a non-empty inviteId");
  if (fields.ownerId === "") throw new Error("enroll PoP requires a non-empty ownerId");
  if (fields.credentialId.length === 0) throw new Error("enroll PoP requires the credentialId bytes");
  if (fields.spki.length === 0) throw new Error("enroll PoP requires the SPKI bytes");
  return lengthPrefixed([
    utf8(ENROLL_POP_LABEL),
    utf8(fields.inviteId),
    utf8(fields.ownerId),
    fields.credentialId,
    fields.spki,
  ]);
}
