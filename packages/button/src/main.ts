import { parseArgs } from "node:util";
import { createFaultReporter } from "./alert.js";
import { createButtonDaemon, type KillConfirmation } from "./daemon.js";
import {
  createHttpSource,
  createKeyboardSource,
  createSerialSource,
  DEFAULT_HTTP_PORT,
  type PressSource,
} from "./input.js";
import { resolveDeviceSecret } from "./secret.js";

const USAGE = `Usage: ownerswitch-button --url <control-plane> --device-id <id> [options]

Options:
  --url <url>        control plane base URL, e.g. http://localhost:4000
  --device-id <id>   this button's provisioned device id (no "." allowed)
  --source <kind>    "keyboard" (default), "http", or "serial"
  --key <key>        keyboard source: "space" (default), "enter", or one character
  --port <port>      http source: POST /press port (default ${DEFAULT_HTTP_PORT})
  --device <path>    serial source: the button's serial device, e.g. /dev/ttyACM0
  --trigger <line>   serial source: the line that means "pressed" (default "KILL")
  --help             show this help

The device secret (signs every kill request) comes from OWNERSWITCH_DEVICE_SECRET
or an interactive, echo-suppressed prompt — never a flag, which would leak it
into shell history and process listings.`;

/** GET /status after a confirmed kill is a best-effort audit nicety, not the confirmation itself. */
const AUDIT_FETCH_TIMEOUT_MS = 2_000;

function fail(message: string): never {
  console.error(`ownerswitch-button: ${message}\n\n${USAGE}`);
  process.exit(1);
}

/**
 * Refuses `--secret`/`--secret=...` before any other argument is parsed or
 * any config is resolved — mirrors the `--owner-token` refusal in
 * packages/mcp/src/verify.ts. The device secret signs every kill request, so
 * a copy on the command line lets anyone who can read shell history or a
 * process listing forge an attributed kill.
 */
export function checkSecretFlag(argv: string[]): string | undefined {
  for (const arg of argv) {
    if (arg === "--secret" || arg.startsWith("--secret=")) {
      return (
        "--secret was removed: it puts the device HMAC key on the command line, which leaks into " +
        "shell history and process listings — and that key signs every kill request, so anyone who " +
        "can read either could forge an attributed kill. Set OWNERSWITCH_DEVICE_SECRET, or run " +
        "ownerswitch-button in a terminal and paste the secret at the prompt."
      );
    }
  }
  return undefined;
}

/**
 * Re-reads GET /status after a kill lands, for the audit line in the CLI
 * banner. Bounded by an AbortController so a hung connection can't stall the
 * process — the kill itself is already confirmed by the time this runs, so a
 * timeout here just means a shorter audit line, never a stuck CLI.
 */
export async function fetchAuditStatus(
  url: string,
  fetchImpl: typeof fetch = fetch,
  timeoutMs = AUDIT_FETCH_TIMEOUT_MS,
): Promise<{ killed?: boolean; reason?: string; at?: number } | undefined> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // /status is live security state — never accept a cached answer
    const res = await fetchImpl(new URL("/status", url), {
      signal: controller.signal,
      cache: "no-store",
    });
    return (await res.json()) as { killed?: boolean; reason?: string; at?: number };
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

export async function main(
  argv: string[] = process.argv.slice(2),
  env: Record<string, string | undefined> = process.env,
): Promise<void> {
  const secretFlagError = checkSecretFlag(argv);
  if (secretFlagError !== undefined) fail(secretFlagError);

  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        url: { type: "string" },
        "device-id": { type: "string" },
        source: { type: "string", default: "keyboard" },
        key: { type: "string", default: "space" },
        port: { type: "string" },
        device: { type: "string" },
        trigger: { type: "string" },
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
    (await resolveDeviceSecret(env)) ??
    fail(
      "no device secret available — set OWNERSWITCH_DEVICE_SECRET (export it for this shell, unset it " +
        "when done), or run ownerswitch-button in a terminal and paste it at the prompt. It signs every " +
        "kill request and is never accepted as a CLI flag.",
    );
  const sourceKind = values.source;
  if (sourceKind !== "keyboard" && sourceKind !== "http" && sourceKind !== "serial") {
    fail(`--source must be "keyboard", "http", or "serial", got "${sourceKind}"`);
  }
  const port = values.port === undefined ? DEFAULT_HTTP_PORT : Number(values.port);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    fail(`--port must be an integer between 0 and 65535, got "${values.port}"`);
  }

  let source: PressSource;
  if (sourceKind === "keyboard") {
    source = createKeyboardSource({ key: values.key });
  } else if (sourceKind === "http") {
    source = createHttpSource({ port });
  } else {
    const device =
      values.device ?? fail("--device is required for --source serial (e.g. /dev/ttyACM0)");
    // Dual-channel firmware (hardware/pico, issue #40) prints FAULT while
    // its NC/NO cross-check disagrees; report each episode to the owner via
    // POST /alert. A fault is never a press — and never suppresses one.
    const faultReporter = createFaultReporter({ controlPlaneUrl: url, deviceId, secret });
    source = createSerialSource({
      device,
      trigger: values.trigger,
      onFault: () => faultReporter.faultSignal(),
    });
  }

  // The kill acknowledgement is in hand; re-read /status for the audit detail.
  const printConfirmation = async (confirmation: KillConfirmation): Promise<void> => {
    console.log(
      `\n■ KILL CONFIRMED — control plane acknowledged (HTTP ${confirmation.status}, attempt ${confirmation.attempts})`,
    );
    const status = await fetchAuditStatus(url);
    if (status === undefined) {
      console.log("  (audit re-check via GET /status failed — the kill itself was acknowledged)");
    } else if (status.killed) {
      const at = status.at === undefined ? "unknown time" : new Date(status.at).toISOString();
      console.log(`  audit: killed=true reason=${JSON.stringify(status.reason ?? "")} at=${at}`);
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
