import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { KillStateFileStore, MAX_KILL_STATE_FILE_BYTES, type PersistedKillState } from "./kill-state.js";

/**
 * Arms a one-shot short write for the NEXT writeSync(fd, buffer, ...) call
 * kill-state.ts's own import makes (mocked at module resolution, not by
 * mutating the frozen node:fs namespace object, which vi.spyOn cannot do for
 * a native builtin's exports). Every other call, and every other test in
 * this file, goes through the real implementation unchanged: the mock
 * delegates to `importOriginal()` unless armed.
 */
let armShortWriteOnce = false;

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    writeSync: (fd: number, buffer: Uint8Array, offset?: number, length?: number, position?: number | null) => {
      if (!armShortWriteOnce) return actual.writeSync(fd, buffer, offset, length, position);
      armShortWriteOnce = false; // one-shot: only the first call after arming is short
      const requested = length ?? buffer.length;
      const short = Math.max(1, Math.floor(requested / 2));
      return actual.writeSync(fd, buffer, offset, short, position);
    },
  };
});

const tempPath = () => join(mkdtempSync(join(tmpdir(), "ownerswitch-killstate-")), "kill.json");

const killedState: PersistedKillState = {
  version: 1,
  killed: true,
  epoch: 4,
  lastKill: { source: "button", reason: "pressed", at: 1234 },
};

describe("KillStateFileStore", () => {
  it("a missing file is a first boot, not corruption", () => {
    expect(new KillStateFileStore(tempPath()).load()).toEqual({ outcome: "absent" });
  });

  it("round-trips killed and not-killed state", () => {
    const store = new KillStateFileStore(tempPath());
    expect(store.save(killedState)).toEqual({ durable: true }); // every fsync succeeded
    expect(store.load()).toEqual({ outcome: "loaded", state: killedState });

    store.save({ version: 1, killed: false, epoch: 4 });
    expect(store.load()).toEqual({
      outcome: "loaded",
      state: { version: 1, killed: false, epoch: 4 },
    });
  });

  it("creates missing parent directories and leaves no temp file behind", () => {
    const path = join(mkdtempSync(join(tmpdir(), "ownerswitch-killstate-")), "deep", "er", "kill.json");
    const store = new KillStateFileStore(path);
    store.save(killedState);
    expect(existsSync(path)).toBe(true);
    // the random-named temp file was renamed into place, not left as a twin
    expect(readdirSync(dirname(path)).filter((name) => name.endsWith(".tmp"))).toEqual([]);
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual(killedState); // plain JSON, auditable with cat
    expect(statSync(path).mode & 0o777).toBe(0o600); // the state is nobody else's to read or replace
  });

  it("save provisions the initialisation marker; a missing state file then loads as corrupt, not first boot", () => {
    const path = tempPath();
    const store = new KillStateFileStore(path);
    store.save(killedState);
    expect(existsSync(store.markerPath)).toBe(true);

    rmSync(path); // the state file vanishes — deleted, tampered with, or lost
    const loaded = store.load();
    expect(loaded.outcome).toBe("corrupt"); // NOT "absent": this store has history
    if (loaded.outcome === "corrupt") expect(loaded.detail).toMatch(/missing.*initialised/);
  });

  it("loading a marker-less state file heals the marker onto it (stores written before the marker existed)", () => {
    const path = tempPath();
    writeFileSync(path, `${JSON.stringify(killedState)}\n`, "utf8"); // a pre-marker store
    const store = new KillStateFileStore(path);
    expect(existsSync(store.markerPath)).toBe(false);
    expect(store.load().outcome).toBe("loaded");
    expect(existsSync(store.markerPath)).toBe(true); // from now on, missing != first boot
  });

  it("a symlink at the state path is refused, whatever it points at", () => {
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-killstate-"));
    const target = join(dir, "target.json");
    writeFileSync(target, `${JSON.stringify({ version: 1, killed: false, epoch: 0 })}\n`, "utf8");
    const path = join(dir, "kill.json");
    symlinkSync(target, path); // an attacker aims the state path somewhere else
    const loaded = new KillStateFileStore(path).load();
    expect(loaded.outcome).toBe("corrupt"); // boots killed — the link is never followed
    if (loaded.outcome === "corrupt") expect(loaded.detail).toMatch(/symlink|not a regular file/);
  });

  it("degrade() quarantines stale state and reports success: next load fails closed", () => {
    const path = tempPath();
    const store = new KillStateFileStore(path);
    store.save({ version: 1, killed: false, epoch: 2 }); // stale not-killed state on disk
    expect(store.degrade()).toBe(true); // called after a failed save of a NEWER state
    const loaded = store.load();
    expect(loaded.outcome).toBe("corrupt"); // never "loaded { killed: false }", never "absent"
    expect(existsSync(store.markerPath)).toBe(true);
  });

  it("degrade() reports FAILURE when the stale state cannot be removed", () => {
    // a non-empty directory at the state path cannot be unlinked — the stale
    // "state" stays put, and degrade() must say so instead of pretending
    const dirAsFile = mkdtempSync(join(tmpdir(), "ownerswitch-killstate-"));
    writeFileSync(join(dirAsFile, "occupied"), "", "utf8");
    const store = new KillStateFileStore(dirAsFile);
    expect(store.degrade()).toBe(false);
    expect(existsSync(dirAsFile)).toBe(true); // and indeed it is still there
  });

  it("unparseable content loads as corrupt, with the why", () => {
    const path = tempPath();
    writeFileSync(path, "{torn wri", "utf8");
    const loaded = new KillStateFileStore(path).load();
    expect(loaded.outcome).toBe("corrupt");
    if (loaded.outcome === "corrupt") expect(loaded.detail).toMatch(/cannot parse/);
  });

  it("valid JSON of the wrong shape loads as corrupt — surprises fail closed", () => {
    const path = tempPath();
    const store = new KillStateFileStore(path);
    const wrongShapes = [
      "null",
      "[]",
      '"killed"',
      "{}",
      '{"version":2,"killed":true,"epoch":1,"lastKill":{"source":"button","at":1}}',
      '{"version":1,"killed":"yes","epoch":1}',
      '{"version":1,"killed":true,"epoch":-1,"lastKill":{"source":"button","at":1}}',
      '{"version":1,"killed":false,"epoch":9007199254740993}', // beyond Number.isSafeInteger
      '{"version":1,"killed":true,"epoch":1}', // killed without the attributing event
      '{"version":1,"killed":false,"epoch":1,"lastKill":{"source":"button","at":1}}',
      '{"version":1,"killed":true,"epoch":1,"lastKill":{"source":"meteor","at":1}}',
      '{"version":1,"killed":true,"epoch":1,"lastKill":{"source":"button","at":"1"}}',
      '{"version":1,"killed":true,"epoch":1,"lastKill":{"source":"button","at":1,"extra":1}}',
      '{"version":1,"killed":false,"epoch":1,"extra":true}',
    ];
    for (const raw of wrongShapes) {
      writeFileSync(path, raw, "utf8");
      expect(store.load().outcome, `should reject: ${raw}`).toBe("corrupt");
    }
  });

  it("a non-regular file (a directory where the file should be) loads as corrupt", () => {
    const dirAsFile = mkdtempSync(join(tmpdir(), "ownerswitch-killstate-"));
    const loaded = new KillStateFileStore(dirAsFile).load();
    expect(loaded.outcome).toBe("corrupt");
    if (loaded.outcome === "corrupt") expect(loaded.detail).toMatch(/not a regular file/);
  });

  it("loads a file right up to MAX_KILL_STATE_FILE_BYTES — the cap is a ceiling, not an off-by-one", () => {
    const path = tempPath();
    const state: PersistedKillState = { version: 1, killed: false, epoch: 0 };
    const json = JSON.stringify(state);
    // JSON.parse ignores trailing whitespace, so padding lets the file land
    // at exactly the cap while still being state the store actually wrote.
    const padded = json + " ".repeat(MAX_KILL_STATE_FILE_BYTES - Buffer.byteLength(json, "utf8"));
    expect(Buffer.byteLength(padded, "utf8")).toBe(MAX_KILL_STATE_FILE_BYTES);
    writeFileSync(path, padded, "utf8");
    expect(new KillStateFileStore(path).load()).toEqual({ outcome: "loaded", state });
  });

  it("rejects a file over MAX_KILL_STATE_FILE_BYTES without trusting a pre-read fstat size", () => {
    const path = tempPath();
    writeFileSync(path, "x".repeat(MAX_KILL_STATE_FILE_BYTES + 1), "utf8");
    const loaded = new KillStateFileStore(path).load();
    expect(loaded.outcome).toBe("corrupt");
    if (loaded.outcome === "corrupt") {
      expect(loaded.detail).toMatch(new RegExp(`over the ${MAX_KILL_STATE_FILE_BYTES}-byte kill-state limit`));
    }
  });

  it("rejects a file many times over the cap — enforcement isn't tied to the exact +1 boundary", () => {
    const path = tempPath();
    writeFileSync(path, "x".repeat(MAX_KILL_STATE_FILE_BYTES * 4), "utf8");
    const loaded = new KillStateFileStore(path).load();
    expect(loaded.outcome).toBe("corrupt");
    if (loaded.outcome === "corrupt") {
      expect(loaded.detail).toMatch(new RegExp(`over the ${MAX_KILL_STATE_FILE_BYTES}-byte kill-state limit`));
    }
  });

  it("survives a short writeSync() — the whole buffer lands, not a truncated prefix", () => {
    const path = tempPath();
    const store = new KillStateFileStore(path);
    store.save({ version: 1, killed: false, epoch: 0 }); // establish the marker first

    armShortWriteOnce = true; // the next writeSync() call — save()'s main write — returns short
    const result = store.save(killedState);

    // The published file is COMPLETE — not the truncated first chunk a naive
    // single-call write would have fsynced and rename-published as if it had
    // succeeded, which would boot killed forever after on a corrupt parse.
    expect(result).toEqual({ durable: true });
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual(killedState);
    expect(store.load()).toEqual({ outcome: "loaded", state: killedState });
  });
});
