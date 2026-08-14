#!/usr/bin/env node
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createConsoleApi } from "./console-api.js";
import { createConsoleServer } from "./console-server.js";

/**
 * ownerswitch-workspace-console — serve the Workspace console against a
 * running control plane.
 *
 * Env contract (the repo's existing names where one exists; secrets from env
 * ONLY — never argv, per CONTRIBUTING.md):
 *   OWNERSWITCH_CONTROL_PLANE_URL   default http://127.0.0.1:4181
 *   OWNERSWITCH_DEVICE_ID           default "workspace-console"
 *   OWNERSWITCH_DEVICE_SECRET       optional — enables the pending list, the
 *                                   VETO button, and kill attribution
 *   OWNERSWITCH_OWNER_TOKEN         optional — enables the devices panel
 *   OWNERSWITCH_CONSOLE_PORT        default 4490
 *   OWNERSWITCH_CONSOLE_BIND        default 127.0.0.1; a non-loopback bind is
 *                                   REFUSED unless OWNERSWITCH_CONSOLE_ALLOW_NONLOCAL=1
 *                                   (the console's own callers are unauthenticated)
 */

function isLoopbackBind(bind: string): boolean {
  if (bind === "localhost" || bind === "::1") return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bind);
}

async function main(): Promise<void> {
  const env = process.env;
  const controlPlaneUrl = env.OWNERSWITCH_CONTROL_PLANE_URL?.trim() || "http://127.0.0.1:4181";
  const deviceId = env.OWNERSWITCH_DEVICE_ID?.trim() || "workspace-console";
  const deviceSecret = env.OWNERSWITCH_DEVICE_SECRET;
  const ownerToken = env.OWNERSWITCH_OWNER_TOKEN;
  const port = Number(env.OWNERSWITCH_CONSOLE_PORT?.trim() || "4490");
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("OWNERSWITCH_CONSOLE_PORT must be an integer port");
  }
  const bind = env.OWNERSWITCH_CONSOLE_BIND?.trim() || "127.0.0.1";
  if (!isLoopbackBind(bind) && env.OWNERSWITCH_CONSOLE_ALLOW_NONLOCAL !== "1") {
    throw new Error(
      `refusing to bind ${bind}: the console's callers are unauthenticated and its verbs reach the ` +
        "control plane — bind loopback, or set OWNERSWITCH_CONSOLE_ALLOW_NONLOCAL=1 to accept that exposure",
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
  // names only — no secret value is ever printed
  console.log(`workspace console: http://${bind}:${listening.port}`);
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
