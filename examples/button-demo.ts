/**
 * Interactive demo: control plane + physical kill button in one process.
 *
 * Starts the control-plane server with a provisioned device secret, arms the
 * button daemon against it over real HTTP (keyboard source), and prints the
 * audit trail once the kill lands — straight from the control plane's own
 * state, so you can see the press arrive attributed as source "button" with
 * a verified signature (no `unauthenticated` flag).
 *
 * Run with: pnpm demo:button   — then press <space> to kill, Ctrl+C to exit.
 */
import { createServer } from "node:http";
import { createButtonDaemon } from "../packages/button/src/daemon.js";
import { createKeyboardSource } from "../packages/button/src/input.js";
import { createControlPlane } from "../packages/control-plane/src/index.js";

const DEVICE_ID = "big-red-button";
const DEVICE_SECRET = "demo-device-secret";

async function main(): Promise<void> {
  // Dev + ephemeral on purpose: the demo must reset fully on every run. A
  // real deployment omits dev and must configure a protected killStateFile.
  const controlPlane = createControlPlane({ deviceSecret: DEVICE_SECRET, dev: true, killStateFile: null });
  const server = createServer(controlPlane.handler);
  const baseUrl = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") throw new Error("no address");
      resolve(`http://127.0.0.1:${addr.port}`);
    });
  });

  const source = createKeyboardSource(); // spacebar
  const daemon = createButtonDaemon({
    controlPlaneUrl: baseUrl,
    deviceId: DEVICE_ID,
    secret: DEVICE_SECRET,
    onPress: source.onPress,
    onKill: () => {
      console.log("\naudit log, straight from the control plane's state:");
      for (const entry of controlPlane.killSwitch.auditLog()) {
        console.log(`  ${JSON.stringify(entry)}`);
      }
      console.log('\nsource is "button" with no unauthenticated flag — the HMAC verified.');
      console.log("(restore needs a 2GO ceremony — Ctrl+C to exit)");
    },
  });

  daemon.start();
  await source.start();

  console.log(`control plane listening at ${baseUrl} (device secret provisioned)`);
  console.log(`button daemon armed: device "${DEVICE_ID}", ${source.describe()}`);
  console.log("\nREADY — press <space> to kill, Ctrl+C to exit\n");

  const shutdown = (): void => {
    daemon.stop();
    server.close();
    void source.stop().finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
