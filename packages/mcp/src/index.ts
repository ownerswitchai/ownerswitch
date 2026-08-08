/**
 * @ownerswitchai/mcp — the OwnerSwitch MCP gateway: an MCP server that fronts
 * another MCP server and enforces OwnerSwitch policy on every tool call.
 */
export { createOwnerSwitchProxy, PROXY_NAME, PROXY_VERSION } from "./proxy.js";
export type { OwnerSwitchProxy, ProxyOptions } from "./proxy.js";

export { OwnerSwitchErrorCode, OwnerSwitchRefusal } from "./errors.js";
export type { OwnerSwitchErrorCodeName, RefusalData } from "./errors.js";

export { ConfigError, loadConfig, parseConfig } from "./config.js";
export type { OwnerSwitchMcpConfig, UpstreamConfig } from "./config.js";

export { createVetoClient, VetoClientError } from "./veto-client.js";
export type { DeviceIdentity, VetoClient, VetoClientOptions } from "./veto-client.js";
