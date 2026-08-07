#!/usr/bin/env node
import { parseArgs } from "node:util";
import { createButtonDaemon, type KillConfirmation } from "./daemon.js";
import {
  createHttpSource,
  createKeyboardSource,
  DEFAULT_HTTP_PORT,
  type PressSource,
} from "./input.js";

const USAGE = `Usage: ownerswitch-button --url <control-plane> --device-id <id> --secret <secret> [options]

Options:
  --url <url>        control plane base URL, e.g. http://localhost:4000
  --device-id <id>   this button's provisioned device id (no "." allowed)
  --secret <secret>  shared device secret; or set OWNERSWITCH_DEVICE_SECRET
  --source <kind>    "keyboard" (default) or "http"
  --key <key>        keyboard source: "space" (default), "enter", or one character
  --port <port>      http source: POST /press port (default ${DEFAULT_HTTP_PORT})
  --help             show this help`;

function fail(message: string): never {
  console.error(`ownerswitch-button: ${message}\n\n${USAGE}`);
  process.exit(1);
}

async function main(): Promise<void> {
  let values;
  try {
    ({ values } = parseArgs({
      options: {
        url: { type: "string" },
        "device-id": { type: "string" },
        secret: { type: "string" },
        source: { type: "string", default: "keyboard" },
        key: { type: "string", default: "space" },
        port: { type: "string" },
        help: { type: "boolean", default: false },
      },
    }));
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }

  if (values.help) {
    console.log(USAGE);
    return;
  }

  const url = values.url ?? fail("--url is required");
  const deviceId = values["device-id"] ?? fail("--device-id is required");
  const secret =
    values.secret ?? process.env.OWNERSWITCH_DEVICE_SECRET ?? fail("--secret (or OWNERSWITCH_DEVICE_SECRET) is required");
  const sourceKind = values.source;
  if (sourceKind !== "keyboard" && sourceKind !== "http") {
    fail(`--source must be "keyboard" or "http", got "${sourceKind}"`);
  }
  const port = values.port === undefined ? DEFAULT_HTTP_PORT : Number(values.port);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    fail(`--port must be an integer between 0 and 65535, got "${values.port}"`);
  }

  const source: PressSource =
    sourceKind === "keyboard"
      ? createKeyboardSource({ key: values.key })
      : createHttpSource({ port });

  // The kill acknowledgement is in hand; re-read /status for the audit detail.
  const printConfirmation = async (confirmation: KillConfirmation): Promise<void> => {
    console.log(
      `\n■ KILL CONFIRMED — control plane acknowledged (HTTP ${confirmation.status}, attempt ${confirmation.attempts})`,
    );
    try {
      const res = await fetch(new URL("/status", url));
      const status = (await res.json()) as { killed?: boolean; reason?: string; at?: number };
      if (status.killed) {
        const at = status.at === undefined ? "unknown time" : new Date(status.at).toISOString();
        console.log(`  audit: killed=true reason=${JSON.stringify(status.reason ?? "")} at=${at}`);
      }
    } catch {
      console.log("  (audit re-check via GET /status failed — the kill itself was acknowledged)");
    }
  };

  const daemon = createButtonDaemon({
    controlPlaneUrl: url,
    deviceId,
    secret,
    onPress: source.onPress,
    onKill: (confirmation) => void printConfirmation(confirmation),
  });

  daemon.start();
  await source.start();

  console.log("┌──────────────────────────────────────────────");
  console.log("│  🔴 OwnerSwitch — physical kill button");
  console.log(`│  control plane : ${url}`);
  console.log(`│  device        : ${deviceId}`);
  console.log(`│  input         : ${source.describe()}`);
  console.log("│");
  console.log("│  READY — press to kill   (Ctrl+C to exit)");
  console.log("└──────────────────────────────────────────────");

  const shutdown = (): void => {
    daemon.stop();
    void source.stop().finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
