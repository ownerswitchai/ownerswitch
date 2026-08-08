import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
    store.save(killedState);
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
    expect(existsSync(`${path}.tmp`)).toBe(false); // temp file was renamed, not left as a twin
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual(killedState); // plain JSON, auditable with cat
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

  it("an unreadable path (a directory where the file should be) loads as corrupt", () => {
    const dirAsFile = mkdtempSync(join(tmpdir(), "ownerswitch-killstate-"));
    const loaded = new KillStateFileStore(dirAsFile).load();
    expect(loaded.outcome).toBe("corrupt");
    if (loaded.outcome === "corrupt") expect(loaded.detail).toMatch(/cannot read/);
  });
});
