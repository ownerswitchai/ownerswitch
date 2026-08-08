import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControlPlane } from "@ownerswitchai/control-plane";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { plantHoneytokens } from "./plant.js";
import { createTripReporter, type TripTier } from "./report.js";
import { watchHoneytokenFiles, type HoneytokenWatcher } from "./watch.js";

/**
 * End-to-end against a real control plane: a decoy file read must ALERT by
 * default (never kill), and only the explicit kill-on-touch opt-in escalates
 * it — the two-tier split the review asked to see proven.
 */
const SECRET = "integration-device-secret";
const CANARY_KEY = "canary-key-integration-00112233445566";
const DEPLOY = "deploy-integration";

let dir: string;
let server: Server | undefined;
let watcher: HoneytokenWatcher | undefined;

const silence = () => {
  const original = console.error;
  console.error = () => {};
  return () => {
    console.error = original;
  };
};

const startControlPlane = () => {
  const restore = silence();
  try {
    const cp = createControlPlane({ now: Date.now, deviceSecret: SECRET, dev: true, killStateFile: null });
    server = createServer(cp.handler);
    return cp;
  } finally {
    restore();
  }
};

const listen = (): Promise<string> =>
  new Promise((resolve) => {
    server!.listen(0, "127.0.0.1", () => {
      const addr = server!.address();
      if (addr === null || typeof addr === "string") throw new Error("no address");
      resolve(`http://127.0.0.1:${addr.port}`);
    });
  });

const waitFor = async (pred: () => boolean, ms = 3_000): Promise<void> => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (pred()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
};

/** Plant, arm at the given tier, read the first decoy, wait for delivery. */
async function readADecoyAt(tier: TripTier, cp: ReturnType<typeof createControlPlane>, url: string) {
  const { files, registry } = plantHoneytokens({ dir, canaryKey: CANARY_KEY, deploymentId: DEPLOY });
  const reporter = createTripReporter({ controlPlaneUrl: url, deviceId: "honeypot-1", secret: SECRET, log: () => undefined });
  watcher = watchHoneytokenFiles({
    paths: files,
    registry,
    pollMs: 20,
    log: () => undefined,
    onTrip: (trip) => reporter.report({ tier, canaryIds: trip.canaryIds, how: trip.detail }),
  });

  readFileSync(files[0]); // the sweep touching the bait
  await waitFor(() => reporter.pending() === 0 && cp.killSwitch.auditLog().length > 0);
  await reporter.flush();
  reporter.stop();
}

const counts = (cp: ReturnType<typeof createControlPlane>) => {
  const log = cp.killSwitch.auditLog();
  return {
    kills: log.filter((e) => e.type === "kill").length,
    alerts: log.filter((e) => e.type === "alert").length,
  };
};

describe("file-tripwire tier split (integration)", () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "oswt-int-"));
  });
  afterEach(() => {
    watcher?.close();
    watcher = undefined;
    server?.close();
    server = undefined;
    rmSync(dir, { recursive: true, force: true });
  });

  it("a default file read produces one /alert and zero /kill, and leaves killed:false", async () => {
    const cp = startControlPlane();
    const url = await listen();

    await readADecoyAt("alert", cp, url);

    expect(counts(cp)).toEqual({ kills: 0, alerts: 1 });
    expect(cp.killSwitch.killed).toBe(false);
    const status = (await (await fetch(`${url}/status`)).json()) as { killed: boolean };
    expect(status.killed).toBe(false);
  });

  it("the kill-on-touch opt-in ALONE changes the same read into a /kill", async () => {
    const cp = startControlPlane();
    const url = await listen();

    await readADecoyAt("kill", cp, url);

    expect(counts(cp)).toMatchObject({ kills: 1 });
    expect(cp.killSwitch.killed).toBe(true);
    const status = (await (await fetch(`${url}/status`)).json()) as { killed: boolean };
    expect(status.killed).toBe(true);
  });
});
