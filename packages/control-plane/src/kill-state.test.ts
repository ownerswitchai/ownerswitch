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
import { describe, expect, it } from "vitest";
import { KillStateFileStore, type PersistedKillState } from "./kill-state.js";

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
});
