/**
 * @ownerswitchai/workspace-app — the owner's Workspace console (see README.md).
 *
 * The browser-side logic lives in public/workspace-core.mjs (plain ESM,
 * imported directly by the tests); this package entry exports the console
 * server pieces for embedding and for the test suite.
 */
export { createConsoleApi } from "./console-api.js";
export type {
  ActionResult,
  ConsoleApi,
  ListReading,
  StatusReading,
  UpstreamOptions,
} from "./console-api.js";
export { createConsoleServer } from "./console-server.js";
export type { ConsoleServerOptions, ListeningConsole } from "./console-server.js";
export { deviceSignedHeaders, newNonce, signDeviceRequest } from "./device-sig.js";
export type { DeviceSigFields } from "./device-sig.js";
