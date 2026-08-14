#!/usr/bin/env node
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createConsoleApi, sanitizeControlPlaneUrl } from "./console-api.js";
import { createConsoleServer } from "./console-server.js";
import { isLoopbackBind, validateDeviceId } from "./startup.js";

/**
 * ownerswitch-workspace-console — serve the Workspace console against a
 * running control plane.
 *
 * Env contract (the repo's existing names where one exists; secrets from env
 * ONLY — never argv, per CONTRIBUTING.md):
 *   OWNERSWITCH_CONTROL_PLANE_URL   default http://127.0.0.1:4181; validated
 *                                   origin only — no userinfo/path/query, and
 *                                   plaintext http only to literal loopback
 *   OWNERSWITCH_DEVICE_ID           default "workspace-console"; validated
 *                                   against the signer's grammar at startup
 *   OWNERSWITCH_DEVICE_SECRET       optional — enables the pending list, the
 *                                   VETO button, and kill attribution
 *   OWNERSWITCH_OWNER_TOKEN         optional — enables the devices panel
 *   OWNERSWITCH_CONSOLE_PORT        default 4490
 *   OWNERSWITCH_CONSOLE_BIND        default 127.0.0.1; loopback ONLY. The
 *                                   old ALLOW_NONLOCAL escape hatch is gone
 *                                   (audit #1): this surface has no caller
 *                                   auth and no TLS, so a LAN bind was an
 *                                   unauthenticated kill/veto proxy. Remote
 *                                   access needs a real TLS+auth front.
 */

async function main(): Promise<void> {
  const env = process.env;
  // parse ONCE into the only shape ever dialed or printed (audit #6)
  const controlPlaneUrl = sanitizeControlPlaneUrl(
    env.OWNERSWITCH_CONTROL_PLANE_URL?.trim() || "http://127.0.0.1:4181",
  );
  const deviceId = env.OWNERSWITCH_DEVICE_ID?.trim() || "workspace-console";
  validateDeviceId(deviceId);
  const deviceSecret = env.OWNERSWITCH_DEVICE_SECRET;
  const ownerToken = env.OWNERSWITCH_OWNER_TOKEN;
  const port = Number(env.OWNERSWITCH_CONSOLE_PORT?.trim() || "4490");
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("OWNERSWITCH_CONSOLE_PORT must be an integer port");
  }
  const bind = env.OWNERSWITCH_CONSOLE_BIND?.trim() || "127.0.0.1";
  if (!isLoopbackBind(bind)) {
    throw new Error(
      `refusing to bind ${bind}: the console has no caller auth and no TLS, and its verbs reach the ` +
        'control plane — it binds NUMERIC loopback only (127.0.0.1 or ::1; "localhost" is a resolver ' +
        "name). Put a TLS+auth front in front for remote use.",
    );
  }

  const api = createConsoleApi({
    controlPlaneUrl,
    deviceId,
    ...(deviceSecret !== undefined && deviceSecret !== "" ? { deviceSecret } : {}),
    ...(ownerToken !== undefined && ownerToken !== "" ? { ownerToken } : {}),
  });
  const publicDir = join(dirname(fileURLToPath(import.meta.url)), "..", "public");
  const { listen } = createConsoleServer({ api, publicDir });
  const listening = await listen(port, bind);

  const lanes = api.lanes();
  // names only — no secret value is ever printed (IPv6 hosts bracketed)
  const printableBind = bind.includes(":") ? `[${bind}]` : bind;
  console.log(`workspace console: http://${printableBind}:${listening.port}`);
  console.log(`control plane:     ${controlPlaneUrl}`);
  console.log(`device lane:       ${lanes.device ? `configured (${deviceId})` : "absent — pending list and VETO disabled"}`);
  console.log(`owner session:     ${lanes.ownerSession ? "configured" : "absent — devices panel disabled"}`);

  const shutdown = (): void => {
    void listening.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
