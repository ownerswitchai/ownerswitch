/** See enroll-invite.mjs — drift-pinned to @ownerswitchai/shared enrollment-invite.ts. */
import type { EnrollmentInvite } from "../src/types.js";

export function base64urlToBytes(value: unknown): Uint8Array | null;

export function parseEnrollmentInvite(value: unknown): EnrollmentInvite | null;

export interface EnrollmentCreationOptions {
  rp: { id: string; name: string };
  user: { id: Uint8Array; name: string; displayName: string };
  challenge: Uint8Array;
  pubKeyCredParams: Array<{ type: "public-key"; alg: -7 }>;
  authenticatorSelection: {
    authenticatorAttachment: "platform";
    residentKey: "preferred";
    userVerification: "required";
  };
  attestation: "none";
}

export function creationOptionsFromInvite(invite: EnrollmentInvite): EnrollmentCreationOptions;

export type BeginEnrollmentResult =
  | {
      ok: true;
      credential: unknown;
      inviteId: string;
      token: string;
      ownerId: string;
      deviceName: string;
      assertionChallenge: string;
      rpId: string;
    }
  | { ok: false; reason: string };

export function beginEnrollmentCeremony(
  payload: unknown,
  credentials: { create(options: { publicKey: EnrollmentCreationOptions }): Promise<unknown> },
): Promise<BeginEnrollmentResult>;
