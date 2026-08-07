/**
 * @ownerswitchai/control-plane — kill state, veto windows, 2GO restore.
 */
export { KillSwitch } from "./kill.js";
export type { KillSource, KillEvent, AuditEntry } from "./kill.js";

export { VetoWindow } from "./veto.js";
export type { VetoStatus, VetoOptions } from "./veto.js";

export { RestoreCeremony } from "./twogo.js";
export type { RestoreAuthorization, CeremonyState, TwoGoOptions } from "./twogo.js";

export { createControlPlane } from "./server.js";
export type { ControlPlane, ControlPlaneOptions } from "./server.js";

export {
  createOwnerSession,
  isLoopbackAddress,
  signDeviceRequest,
  verifyDeviceSignature,
  verifyOwnerSession,
} from "./auth.js";
export type { DeviceCredential, DeviceVerifyOptions, OwnerSession, SessionOptions } from "./auth.js";
