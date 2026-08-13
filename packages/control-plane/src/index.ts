/**
 * @ownerswitchai/control-plane — kill state, veto windows, 2GO restore.
 */
export { KillSwitch, KILL_SOURCES } from "./kill.js";
export type { KillSource, KillEvent, AlertEvent, AuditEntry, KillSwitchOptions } from "./kill.js";

export { KillStateFileStore } from "./kill-state.js";
export type { KillStateStore, KillStateLoad, PersistedKillState, SaveResult } from "./kill-state.js";

export { VetoWindow } from "./veto.js";
export type { VetoStatus, VetoOptions, VetoPurpose, VetoWireStatus } from "./veto.js";

export { RestoreCeremony } from "./twogo.js";
export type { RestoreAuthorization, CeremonyState, TwoGoOptions } from "./twogo.js";

export { createControlPlane, DEFAULT_KILL_STATE_FILE, MIN_VETO_RESPONSE_MS } from "./server.js";

export {
  generateLicenseKeys,
  LICENSE_PREFIX,
  mintLicense,
  OWNERSWITCH_VENDOR_LICENSE_PUBLIC_KEY_PEM,
  RESTORE_GRACE_MS,
  verifyLicense,
} from "./license.js";
export type { LicensePayload, LicensePlan, LicenseVerdict } from "./license.js";
export type { ControlPlane, ControlPlaneOptions } from "./server.js";

export { verifyOwnerAssertion } from "./webauthn.js";
export type {
  AssertionVerdict,
  OwnerPasskey,
  VerifyAssertionOptions,
  WebAuthnAssertion,
} from "./webauthn.js";

export {
  createOwnerSession,
  isLoopbackAddress,
  signDeviceRequest,
  verifyDeviceSignature,
  verifyOwnerSession,
} from "./auth.js";

export {
  enrolledOwnerDeviceFromSpki,
  verifyEnrollProofOfPossession,
  verifyOwnerDeviceSignature,
} from "./owner-device.js";
export { cborDecodeExact, cborDecodeFirst } from "./cbor.js";
export type { CborDecodeResult, CborValue } from "./cbor.js";
export { storedSpkiToPem, verifyOwnerRegistration } from "./webauthn-register.js";
export type {
  RegistrationVerdict,
  VerifyRegistrationOptions,
  WebAuthnRegistrationWire,
} from "./webauthn-register.js";
// NOTE: there is deliberately NO spend API on InviteStore — the burn is an
// ECMAScript #private method whose only accessor is module-scoped inside
// invite.ts, and performEnrollment (defined in that same module) is the one
// function that reaches it, after the full proof chain. Nothing here — and
// no deep import — hands out a spend capability to claim or forge.
export { InviteStore } from "./invite.js";
export type {
  InviteConsume,
  InviteFate,
  InviteOrigin,
  InviteRecord,
  InviteSpendWitness,
  InviteStoreOptions,
} from "./invite.js";
export { performEnrollment } from "./enrollment.js";
export type { EnrollmentOutcome, PerformEnrollmentOptions } from "./enrollment.js";
export {
  EnrolledDeviceFileStore,
  EnrolledDeviceRegistry,
  MAX_ACTIVE_DEVICES,
  MAX_ENROLLED_DEVICES_FILE_BYTES,
} from "./enrolled-devices.js";
export type {
  CommitEnrollmentOptions,
  CommitEnrollmentOutcome,
  EnrolledDeviceRegistryOptions,
  EnrolledDevicesLoad,
  EnrolledDeviceStoreOptions,
  LiveKillState,
  MintInviteRequest,
  PersistedEnrolledDevice,
  PersistedEnrolledDevices,
} from "./enrolled-devices.js";
export type {
  EnrolledOwnerDevice,
  OwnerDeviceCredential,
  OwnerDeviceVerifyOptions,
} from "./owner-device.js";
export { loadOwnerDeviceKeysFile } from "./owner-device-file.js";
export type { LoadOwnerDeviceKeysOptions } from "./owner-device-file.js";
export {
  canonicalTrustedStandingPath,
  DeviceStandingFileStore,
  MAX_DEVICE_STANDING_FILE_BYTES,
} from "./device-standing.js";
export type {
  DeviceStanding,
  DeviceStandingLoad,
  DeviceStandingStoreOptions,
  PersistedDeviceStanding,
  TrustedStandingPathOptions,
} from "./device-standing.js";
export type { DeviceCredential, DeviceVerifyOptions, OwnerSession, SessionOptions } from "./auth.js";
