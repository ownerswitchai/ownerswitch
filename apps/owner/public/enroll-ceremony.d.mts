/** See enroll-ceremony.mjs — drift-pinned to @ownerswitchai/shared enroll-pop.ts. */
export const ENROLL_POP_LABEL: "ownerswitch/enroll-cheap-lane/v1";

export function enrollPopPreimage(fields: {
  inviteId: string;
  ownerId: string;
  credentialIdBytes: Uint8Array;
  spkiBytes: Uint8Array;
}): Uint8Array;

export type CompleteEnrollmentResult =
  | { ok: true; deviceId: string }
  | { ok: false; reason: string; inviteSurvives?: boolean; outcome?: "unknown" };

export function completeEnrollmentCeremony(
  payload: unknown,
  deps: {
    credentials: unknown;
    cheapLane: { privateKey: CryptoKey; publicKey: CryptoKey };
    fetchImpl: typeof fetch;
    baseUrl: string;
    now?: () => number;
  },
): Promise<CompleteEnrollmentResult>;
