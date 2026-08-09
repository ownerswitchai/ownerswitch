/**
 * @ownerswitchai/owner-app — the owner's phone in the loop (see DESIGN.md).
 *
 * Scaffold: wire types and the endpoint contract only. The static shell
 * lives in public/; nothing here runs, sends, or receives anything yet.
 */
export type {
  Base64Url,
  UnixMs,
  EnrollmentInvite,
  WebAuthnRegistration,
  EnrollmentRequest,
  EnrollmentResponse,
  EnrolledDevice,
  PushSubscriptionRecord,
  OwnerAlertPush,
  HeldWindowDetail,
  SeenAck,
  VetoTap,
  AssertionPurpose,
  AssertionChallengeRequest,
  AssertionChallenge,
  WebAuthnAssertion,
  BoundAssertion,
  MintedSession,
  OwnerAppEndpoint,
} from "./types.js";
export { OWNER_APP_ENDPOINTS } from "./types.js";
