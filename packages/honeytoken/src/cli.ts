#!/usr/bin/env node
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { plantHoneytokens } from "./plant.js";
import { loadRegistry, requireCanaryKey, requireDeploymentId } from "./registry.js";
import { createTripReporter, type TripTier } from "./report.js";
import { fsReportsReads, watchHoneytokenFiles } from "./watch.js";

const USAGE = `Usage: ownerswitch-honeytoken <plant|watch> --dir <path> [options]

Commands:
  plant   write decoy credential files (.env.backup, credentials.json) and a
          signed registry of their values
  watch   arm tripwires on every file in --dir; a touch ALERTS (does not kill)

Recognition is by membership in a per-deployment registry, so plant and watch
(and the gateway) must all use the SAME dedicated canary key and deployment id.
The canary key is NOT the device secret — provision a separate random secret.

Options (plant):
  --dir <path>            directory to plant decoys into (created if missing)
  --canary-key <secret>   dedicated per-deployment canary key; or OWNERSWITCH_CANARY_KEY
  --deployment-id <id>    immutable deployment id; or OWNERSWITCH_DEPLOYMENT_ID
  --registry <file>       where to write the signed registry (keep it OUT of --dir)
  --force                 replace existing files with the decoy names

Options (watch):
  --dir <path>            directory whose files to arm
  --registry <file>       the signed registry written by plant
  --canary-key <secret>   canary key to verify the registry; or OWNERSWITCH_CANARY_KEY
  --deployment-id <id>    deployment id the registry must be for; or OWNERSWITCH_DEPLOYMENT_ID
  --url <url>             control plane base URL, e.g. http://localhost:4000
  --device-id <id>        this tripwire's provisioned device id (no "." allowed)
  --secret <secret>       device secret for signing; or OWNERSWITCH_DEVICE_SECRET
  --DANGER-kill-on-touch  DANGEROUS: escalate every file touch to a GLOBAL KILL.
                          Off by default — a decoy read has innocent causes and
                          an attacker can induce one, so a touch normally ALERTS.
  --poll-ms <n>           read-detection sampling interval in ms (default 500)
  --help                  show this help`;

function fail(message: string): never {
  console.error(`ownerswitch-honeytoken: ${message}\n\n${USAGE}`);
  process.exit(1);
}

interface CliValues {
  dir?: string;
  force: boolean;
  registry?: string;
  "canary-key"?: string;
  "deployment-id"?: string;
  url?: string;
  "device-id"?: string;
  secret?: string;
  "DANGER-kill-on-touch": boolean;
  "poll-ms"?: string;
}

/** Resolve the canary identity from flags/env, validating loudly. */
function canaryIdentity(values: CliValues): { canaryKey: string; deploymentId: string } {
  const canaryKey =
    values["canary-key"] ??
    process.env.OWNERSWITCH_CANARY_KEY ??
    fail("--canary-key (or OWNERSWITCH_CANARY_KEY) is required — a dedicated secret, not the device secret");
  const deploymentId =
    values["deployment-id"] ??
    process.env.OWNERSWITCH_DEPLOYMENT_ID ??
    fail("--deployment-id (or OWNERSWITCH_DEPLOYMENT_ID) is required");
  try {
    requireCanaryKey(canaryKey, deploymentId);
    requireDeploymentId(deploymentId);
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
  return { canaryKey, deploymentId };
}

function plant(values: CliValues): void {
  const dir = values.dir ?? fail("--dir is required");
  const registryPath = values.registry ?? fail("--registry <file> is required (where to write the signed registry)");
  const { canaryKey, deploymentId } = canaryIdentity(values);

  const result = plantHoneytokens({ dir, canaryKey, deploymentId, force: values.force });

  console.log(`🍯 planted ${result.planted.length} decoy credentials in ${resolve(dir)}`);
  for (const file of result.files) {
    console.log(`\n  ${file}`);
    for (const p of result.planted.filter((entry) => entry.file === file)) {
      console.log(`    ${p.key.padEnd(24)} ${p.token.kind.padEnd(8)} canary ${p.token.canaryId}`);
    }
  }

  if (resolve(dirname(registryPath)) === resolve(dir)) {
    console.error(
      "⚠ the registry is INSIDE the planted directory — it contains the decoy values, i.e. a map of exactly what to avoid. Move it.",
    );
  }
  writeFileSync(registryPath, result.registry.serialize());
  console.log(`\nSigned registry written to ${registryPath} (deployment "${deploymentId}").`);
  console.log(
    `Arm them (same key + id): ownerswitch-honeytoken watch --dir ${dir} --registry ${registryPath} --url <control-plane> ...`,
  );
}

async function watchCommand(values: CliValues): Promise<void> {
  const dir = values.dir ?? fail("--dir is required");
  const registryPath = values.registry ?? fail("--registry <file> is required");
  const url = values.url ?? fail("--url is required");
  const deviceId = values["device-id"] ?? fail("--device-id is required");
  const secret =
    values.secret ??
    process.env.OWNERSWITCH_DEVICE_SECRET ??
    fail("--secret (or OWNERSWITCH_DEVICE_SECRET) is required");
  const { canaryKey, deploymentId } = canaryIdentity(values);
  const tier: TripTier = values["DANGER-kill-on-touch"] ? "kill" : "alert";
  const pollMs = values["poll-ms"] === undefined ? undefined : Number(values["poll-ms"]);
  if (pollMs !== undefined && (!Number.isInteger(pollMs) || pollMs <= 0)) {
    fail(`--poll-ms must be a positive integer, got "${values["poll-ms"]}"`);
  }

  let registry;
  try {
    registry = loadRegistry(readFileSync(registryPath, "utf8"), { canaryKey, deploymentId });
  } catch (err) {
    fail(`cannot load registry ${registryPath}: ${err instanceof Error ? err.message : String(err)}`);
  }

  let paths: string[];
  try {
    paths = readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => join(dir, entry.name));
  } catch (err) {
    fail(`cannot read --dir ${dir}: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (paths.length === 0) fail(`no files to arm in ${dir} — plant decoys there first`);

  const readsVisible = fsReportsReads(dir);
  const reporter = createTripReporter({ controlPlaneUrl: url, deviceId, secret });
  const watcher = watchHoneytokenFiles({
    paths,
    registry,
    pollMs,
    onTrip: (trip) => reporter.report({ tier, canaryIds: trip.canaryIds, how: trip.detail }),
  });

  console.log("┌──────────────────────────────────────────────");
  console.log("│  🍯 OwnerSwitch — honeytoken tripwires");
  console.log(`│  control plane : ${url}`);
  console.log(`│  device        : ${deviceId}`);
  console.log(`│  deployment    : ${deploymentId} (${registry.size} tokens)`);
  console.log(`│  armed on      : ${paths.length} file(s) in ${resolve(dir)}`);
  console.log(
    tier === "kill"
      ? "│  on touch      : ⚠ KILL — every touch engages the switch (--DANGER-kill-on-touch)"
      : "│  on touch      : ALERT — flagged to the control plane, NOT a kill (default)",
  );
  console.log(
    readsVisible
      ? "│  reads visible : yes (atime advances on this mount)"
      : "│  reads visible : NO — this mount does not record reads (noatime); writes,",
  );
  if (!readsVisible) {
    console.log("│                  replaces and deletes still trip, reads will NOT");
  }
  console.log("│");
  console.log(
    tier === "kill"
      ? "│  ARMED — any touch KILLS   (Ctrl+C to exit)"
      : "│  ARMED — any touch alerts  (Ctrl+C to exit)",
  );
  console.log("└──────────────────────────────────────────────");

  let shuttingDown = false;
  const shutdown = async (): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    watcher.close();
    // Block on a bounded flush so a tripped-but-unconfirmed report is not lost
    // when the process exits. flush() gives up loudly after a bounded number
    // of retries so exit can't be blocked forever.
    const { delivered, pending } = await reporter.flush();
    reporter.stop();
    if (!delivered) {
      console.error(`⚠ exiting with ${pending} honeytoken report(s) UNCONFIRMED`);
    }
    process.exit(delivered ? 0 : 1);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
  // hold the process open even after every tripwire has fired and closed
  await new Promise<never>(() => undefined);
}

async function main(): Promise<void> {
  let values;
  let positionals;
  try {
    ({ values, positionals } = parseArgs({
      allowPositionals: true,
      options: {
        dir: { type: "string" },
        force: { type: "boolean", default: false },
        registry: { type: "string" },
        "canary-key": { type: "string" },
        "deployment-id": { type: "string" },
        url: { type: "string" },
        "device-id": { type: "string" },
        secret: { type: "string" },
        "DANGER-kill-on-touch": { type: "boolean", default: false },
        "poll-ms": { type: "string" },
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

  const command = positionals[0];
  if (command === "plant") return plant(values);
  if (command === "watch") return watchCommand(values);
  fail(command === undefined ? "a command is required" : `unknown command "${command}"`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
