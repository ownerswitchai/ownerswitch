/**
 * @ownerswitchai/control-plane — kill state, veto windows, 2GO restore.
 */
export { KillSwitch, KILL_SOURCES } from "./kill.js";
export type { KillSource, KillEvent, AlertEvent, AuditEntry, KillSwitchOptions } from "./kill.js";

export { KillStateFileStore } from "./kill-state.js";
export type { KillStateStore, KillStateLoad, PersistedKillState, SaveResult } from "./kill-state.js";

export { VetoWindow } from "./veto.js";
export type { VetoStatus, VetoOptions, VetoWireStatus } from "./veto.js";

export { RestoreCeremony } from "./twogo.js";
export type { RestoreAuthorization, CeremonyState, TwoGoOptions } from "./twogo.js";

export { createControlPlane, DEFAULT_KILL_STATE_FILE } from "./server.js";
export type { ControlPlane, ControlPlaneOptions } from "./server.js";

export {
  createOwnerSession,
  isLoopbackAddress,
  signDeviceRequest,
  verifyDeviceSignature,
  verifyOwnerSession,
} from "./auth.js";
export type { DeviceCredential, DeviceVerifyOptions, OwnerSession, SessionOptions } from "./auth.js";
