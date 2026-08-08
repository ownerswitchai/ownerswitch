#!/usr/bin/env node
import { readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { plantHoneytokens } from "./plant.js";
import { createTripReporter, type TripTier } from "./report.js";
import { fsReportsReads, watchHoneytokenFiles } from "./watch.js";

const USAGE = `Usage: ownerswitch-honeytoken <plant|watch> --dir <path> [options]

Commands:
  plant   write decoy credential files (.env.backup, credentials.json) into --dir
  watch   arm tripwires on every file in --dir; a touch ALERTS (does not kill)

The canary checksum is keyed on a per-deployment secret, so plant, watch and
the gateway must all use the SAME secret or the gateway will not recognise the
planted tokens. Reuse the device secret (OWNERSWITCH_DEVICE_SECRET).

Options (plant):
  --dir <path>         directory to plant decoys into (created if missing)
  --secret <secret>    canary key to mint with; or set OWNERSWITCH_DEVICE_SECRET
  --canary-secret <s>  dedicated canary key, if you don't want to reuse --secret
  --force              replace existing files with the decoy names
  --manifest <file>    also save the canaryId → file/key mapping as JSON
                       (keep it OUT of --dir — it is a map of what to avoid)

Options (watch):
  --dir <path>         directory whose files to arm
  --url <url>          control plane base URL, e.g. http://localhost:4000
  --device-id <id>     this tripwire's provisioned device id (no "." allowed)
  --secret <secret>    shared device secret; or set OWNERSWITCH_DEVICE_SECRET
  --canary-secret <s>  canary key for id labeling, if different from --secret
  --kill-on-touch      escalate file touches from ALERT to KILL (default: alert)
  --poll-ms <n>        read-detection sampling interval in ms (default 500)
  --help               show this help`;

function fail(message: string): never {
  console.error(`ownerswitch-honeytoken: ${message}\n\n${USAGE}`);
  process.exit(1);
}

interface CliValues {
  dir?: string;
  force: boolean;
  manifest?: string;
  url?: string;
  "device-id"?: string;
  secret?: string;
  "canary-secret"?: string;
  "kill-on-touch": boolean;
  "poll-ms"?: string;
}

function plant(values: CliValues): void {
  const dir = values.dir ?? fail("--dir is required");
  const secret =
    values["canary-secret"] ??
    values.secret ??
    process.env.OWNERSWITCH_DEVICE_SECRET ??
    fail("--secret / --canary-secret (or OWNERSWITCH_DEVICE_SECRET) is required to mint tokens");
  const result = plantHoneytokens({ dir, secret, force: values.force });

  console.log(`🍯 planted ${result.planted.length} decoy credentials in ${resolve(dir)}`);
  for (const file of result.files) {
    console.log(`\n  ${file}`);
    for (const p of result.planted.filter((entry) => entry.file === file)) {
      console.log(`    ${p.key.padEnd(24)} ${p.token.kind.padEnd(8)} canary ${p.token.canaryId}`);
    }
  }
  console.log(
    "\nKeep this mapping somewhere the decoys are not — a trip names only the canary id.",
  );
  console.log(
    `Arm them (same secret!): ownerswitch-honeytoken watch --dir ${dir} --url <control-plane> ...`,
  );

  if (values.manifest !== undefined) {
    if (resolve(dirname(values.manifest)) === resolve(dir)) {
      console.error(
        "⚠ the manifest is INSIDE the planted directory — it tells a reader exactly what to avoid. Move it.",
      );
    }
    // ids and locations only, never the values: the manifest must not double
    // as a grep list of the exact strings to steer around.
    writeFileSync(
      values.manifest,
      `${JSON.stringify(
        {
          plantedAt: new Date().toISOString(),
          dir: resolve(dir),
          tokens: result.planted.map((p) => ({
            canaryId: p.token.canaryId,
            kind: p.token.kind,
            file: p.file,
            key: p.key,
          })),
        },
        null,
        2,
      )}\n`,
    );
    console.log(`Manifest saved to ${values.manifest}`);
  }
}

async function watchCommand(values: CliValues): Promise<void> {
  const dir = values.dir ?? fail("--dir is required");
  const url = values.url ?? fail("--url is required");
  const deviceId = values["device-id"] ?? fail("--device-id is required");
  const secret =
    values.secret ??
    process.env.OWNERSWITCH_DEVICE_SECRET ??
    fail("--secret (or OWNERSWITCH_DEVICE_SECRET) is required");
  const canarySecret = values["canary-secret"] ?? secret;
  const tier: TripTier = values["kill-on-touch"] ? "kill" : "alert";
  const pollMs = values["poll-ms"] === undefined ? undefined : Number(values["poll-ms"]);
  if (pollMs !== undefined && (!Number.isInteger(pollMs) || pollMs <= 0)) {
    fail(`--poll-ms must be a positive integer, got "${values["poll-ms"]}"`);
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
    secret: canarySecret,
    pollMs,
    onTrip: (trip) => reporter.report({ tier, canaryIds: trip.canaryIds, how: trip.detail }),
  });

  console.log("┌──────────────────────────────────────────────");
  console.log("│  🍯 OwnerSwitch — honeytoken tripwires");
  console.log(`│  control plane : ${url}`);
  console.log(`│  device        : ${deviceId}`);
  console.log(`│  armed on      : ${paths.length} file(s) in ${resolve(dir)}`);
  console.log(
    tier === "kill"
      ? "│  on touch      : KILL — every touch engages the switch (--kill-on-touch)"
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
      ? "│  ARMED — any touch kills   (Ctrl+C to exit)"
      : "│  ARMED — any touch alerts  (Ctrl+C to exit)",
  );
  console.log("└──────────────────────────────────────────────");

  let shuttingDown = false;
  const shutdown = async (): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    watcher.close();
    // Block on a bounded flush so a tripped-but-unconfirmed report is not lost
    // when the process exits (an agent that can trigger shutdown must not be
    // able to swallow the evidence). flush() gives up loudly after a bounded
    // number of retries so exit can't be blocked forever.
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
        manifest: { type: "string" },
        url: { type: "string" },
        "device-id": { type: "string" },
        secret: { type: "string" },
        "canary-secret": { type: "string" },
        "kill-on-touch": { type: "boolean", default: false },
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
