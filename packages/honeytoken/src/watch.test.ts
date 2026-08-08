import {
  appendFileSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateHoneytoken } from "./generate.js";
import { plantHoneytokens } from "./plant.js";
import { HoneytokenRegistry } from "./registry.js";
import { fsReportsReads, watchHoneytokenFiles, type FileTrip } from "./watch.js";

/**
 * Real timers and a real (temp) filesystem: these exercise the actual fs.watch
 * + atime-sampling mechanics. Reads only surface as atime advances where the
 * mount records them (relatime/strictatime — the Linux defaults); the one test
 * needing a REAL read skips itself, loudly, on a noatime mount.
 */
const POLL_MS = 25;
const CANARY_KEY = "canary-key-watch-test-00112233445566";
const DEPLOY = "deploy-watch";

const readsVisible = fsReportsReads(tmpdir());

let dir: string;
let trips: FileTrip[];
let close: (() => void) | null;

const plantIn = (target: string) =>
  plantHoneytokens({ dir: target, canaryKey: CANARY_KEY, deploymentId: DEPLOY });

const arm = (paths: string[], registry?: HoneytokenRegistry): void => {
  ({ close } = watchHoneytokenFiles({
    paths,
    ...(registry !== undefined ? { registry } : {}),
    onTrip: (trip) => trips.push(trip),
    pollMs: POLL_MS,
    log: () => undefined,
  }));
};

const tripped = async (count = 1): Promise<void> => {
  await vi.waitFor(() => expect(trips.length).toBeGreaterThanOrEqual(count), { timeout: 4_000, interval: 10 });
};
const quiet = () => new Promise((resolve) => setTimeout(resolve, POLL_MS * 6));

describe("watchHoneytokenFiles", () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "oswt-"));
    trips = [];
    close = null;
  });
  afterEach(() => {
    close?.();
    rmSync(dir, { recursive: true, force: true });
  });

  it.skipIf(!readsVisible)("a planted token trips on read, labelled from the registry", async () => {
    const { files, planted, registry } = plantIn(dir);
    const envPath = files[0];
    arm([envPath], registry);

    readFileSync(envPath); // the sweep touching the bait

    await tripped();
    const trip = trips[0];
    expect(trip.cause).toBe("read");
    expect(trip.path).toBe(envPath);
    expect(trip.canaryIds).toEqual(
      planted.filter((p) => p.file === envPath).map((p) => p.token.canaryId),
    );
  });

  it("an atime advance alone trips as a read — the poller needs no fs event help", async () => {
    const token = generateHoneytoken({ kind: "openai" });
    const registry = new HoneytokenRegistry(CANARY_KEY, DEPLOY);
    registry.add(token);
    const path = join(dir, ".env.backup");
    writeFileSync(path, `OPENAI_API_KEY=${token.value}\n`);
    arm([path], registry);

    const st = statSync(path);
    utimesSync(path, new Date(), new Date(st.mtimeMs)); // atime forward, mtime untouched

    await tripped();
    expect(trips[0].cause).toBe("read");
    expect(trips[0].canaryIds).toEqual([token.canaryId]);
  });

  it("a write trips", async () => {
    const { files } = plantIn(dir);
    arm([files[0]]);
    appendFileSync(files[0], "PGPASSWORD=hunter2\n");
    await tripped();
    expect(trips[0].cause).toBe("write");
  });

  it("deleting the decoy trips", async () => {
    const { files } = plantIn(dir);
    arm([files[1]]);
    rmSync(files[1]);
    await tripped();
    expect(trips[0].cause).toBe("unlink");
  });

  it("replacing the decoy with another file trips as a rename", async () => {
    const { files } = plantIn(dir);
    const impostor = join(dir, "impostor");
    writeFileSync(impostor, "clean\n");
    arm([files[0]]);
    renameSync(impostor, files[0]);
    await tripped();
    expect(trips[0].cause).toBe("rename");
  });

  it("one trip per path — the first touch disarms that tripwire", async () => {
    const { files } = plantIn(dir);
    arm([files[0]]);
    appendFileSync(files[0], "X=1\n");
    await tripped();
    appendFileSync(files[0], "Y=2\n");
    rmSync(files[0]);
    await quiet();
    expect(trips).toHaveLength(1);
  });

  it("paths trip independently, and close() disarms everything", async () => {
    const { files } = plantIn(dir);
    arm(files);
    appendFileSync(files[0], "X=1\n");
    await tripped(1);
    expect(trips[0].path).toBe(files[0]);
    close?.();
    close = null;
    appendFileSync(files[1], "Y=2\n");
    await quiet();
    expect(trips).toHaveLength(1);
  });

  it("with no registry a touch still trips, with empty canaryIds", async () => {
    const { files } = plantIn(dir);
    arm([files[0]]); // no registry passed
    appendFileSync(files[0], "touched\n");
    await tripped();
    expect(trips[0].canaryIds).toEqual([]);
  });

  it("arming a missing file or a directory throws — an unarmed tripwire must fail loudly", () => {
    expect(() => arm([join(dir, "does-not-exist")])).toThrow();
    expect(() =>
      watchHoneytokenFiles({ paths: [dir], onTrip: () => undefined, log: () => undefined }),
    ).toThrow(/not a regular file|EISDIR/);
  });
});

describe("fsReportsReads", () => {
  it("answers without leaving probe files behind", () => {
    const probeDir = mkdtempSync(join(tmpdir(), "oswt-probe-"));
    try {
      expect(typeof fsReportsReads(probeDir)).toBe("boolean");
      expect(readdirSync(probeDir)).toEqual([]);
    } finally {
      rmSync(probeDir, { recursive: true, force: true });
    }
  });

  it("reports false for an unwritable location instead of throwing", () => {
    expect(fsReportsReads(join(dir ?? tmpdir(), "no-such-subdir"))).toBe(false);
  });
});
