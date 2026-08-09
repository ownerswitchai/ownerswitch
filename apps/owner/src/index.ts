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
  DeviceSummary,
  VetoWireStatus,
  WindowRevision,
  Delivery,
  AckEvidence,
  OwnerAlertPush,
  VetoWindowDetail,
  SeenAck,
  VetoTap,
  AssertionBinding,
  AssertionPurpose,
  AssertionChallengeRequest,
  AssertionChallenge,
  WebAuthnAssertion,
  BoundAssertion,
  MintedSession,
  OwnerAppEndpoint,
} from "./types.js";
export {
  OWNER_APP_ENDPOINTS,
  ENROLL_POP_LABEL,
  DEVICE_SIG_LABEL,
  MIN_VETO_RESPONSE_MS_DEFAULT,
  RENDERABLE_ALERT_V1_LIMITS,
} from "./types.js";
