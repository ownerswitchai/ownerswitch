import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { KillStateFileStore, type KillStateLoad, type KillStateStore, type PersistedKillState } from "./kill-state.js";
import { KillSwitch } from "./kill.js";

const auth = { ceremonyId: "c1", ownerId: "adam", completedAt: 2000 };

/** In-memory store: records every save, serves whatever load is scripted. */
class FakeStore implements KillStateStore {
  saved: PersistedKillState[] = [];
  loadResult: KillStateLoad = { outcome: "absent" };
  failSaves = false;
  degradeCalls = 0;
  load(): KillStateLoad {
    return this.loadResult;
  }
  save(state: PersistedKillState): void {
    if (this.failSaves) throw new Error("disk full");
    this.saved.push(state);
  }
  degrade(): void {
    this.degradeCalls += 1;
  }
}

describe("KillSwitch", () => {
  it("starts armed (not killed)", () => {
    expect(new KillSwitch().killed).toBe(false);
  });

  it("any source can engage, idempotently", () => {
    const k = new KillSwitch(() => 1000);
    k.engage("honeytoken", "decoy key touched");
    k.engage("button");
    expect(k.killed).toBe(true);
    expect(k.auditLog()).toHaveLength(2);
  });

  it("every engage bumps the kill epoch, even while already killed", () => {
    const k = new KillSwitch(() => 1000);
    expect(k.epoch).toBe(0);
    k.engage("button");
    expect(k.epoch).toBe(1);
    k.engage("api"); // already killed — a repeat trigger still opens a new epoch
    expect(k.epoch).toBe(2);
    k.restore(auth);
    expect(k.epoch).toBe(2); // restoring does not
  });

  it("restore needs a ceremony-shaped authorization", () => {
    const k = new KillSwitch(() => 1000);
    k.engage("app");
    expect(() => k.restore({ ceremonyId: "", ownerId: "", completedAt: 0 })).toThrow(/2GO/);
    expect(k.killed).toBe(true);
    k.restore(auth);
    expect(k.killed).toBe(false);
  });

  it("cannot restore when not killed", () => {
    expect(() => new KillSwitch().restore(auth)).toThrow(/nothing to restore/);
  });

  it("audit log records both directions and is a copy", () => {
    const k = new KillSwitch(() => 5);
    k.engage("voice", "owner pressed 1");
    k.restore(auth);
    const log = k.auditLog();
    expect(log.map((e) => e.type)).toEqual(["kill", "restore"]);
    (log as unknown[]).push("tamper");
    expect(k.auditLog()).toHaveLength(2);
  });

  it("every transition persists: engage saves killed+epoch+event, restore saves not-killed", () => {
    const store = new FakeStore();
    const k = new KillSwitch(() => 1000, { store });

    k.engage("button", "pressed");
    expect(store.saved.at(-1)).toEqual({
      version: 1,
      killed: true,
      epoch: 1,
      lastKill: { source: "button", reason: "pressed", at: 1000 },
    });

    k.restore(auth);
    expect(store.saved.at(-1)).toEqual({ version: 1, killed: false, epoch: 1 });
  });

  it("boots from persisted killed state: same epoch, and the kill event re-seated in the log", () => {
    const store = new FakeStore();
    store.loadResult = {
      outcome: "loaded",
      state: {
        version: 1,
        killed: true,
        epoch: 7,
        lastKill: { source: "honeytoken", reason: "decoy key touched", at: 42 },
      },
    };
    const k = new KillSwitch(() => 1000, { store });
    expect(k.killed).toBe(true);
    expect(k.epoch).toBe(7);
    expect(k.auditLog()).toEqual([
      { type: "kill", event: { source: "honeytoken", reason: "decoy key touched", at: 42 } },
    ]);
  });

  it("boots from persisted not-killed state with the epoch intact", () => {
    const store = new FakeStore();
    store.loadResult = { outcome: "loaded", state: { version: 1, killed: false, epoch: 3 } };
    const k = new KillSwitch(() => 1000, { store });
    expect(k.killed).toBe(false);
    expect(k.epoch).toBe(3);
    k.engage("api");
    expect(k.epoch).toBe(4); // epochs stay monotonic across restarts
  });

  it("a corrupt store FAILS CLOSED: boots killed, audited, and logged loudly", () => {
    const store = new FakeStore();
    store.loadResult = { outcome: "corrupt", detail: "cannot parse it" };
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const k = new KillSwitch(() => 1000, { store });
      expect(k.killed).toBe(true);
      expect(k.epoch).toBe(1); // the fail-closed boot is a real engage
      expect(errors).toHaveBeenCalled();
      const [entry] = k.auditLog();
      expect(entry.type === "kill" && entry.event.reason).toMatch(/failed closed/);
      expect(store.saved.at(-1)?.killed).toBe(true); // and the file is rewritten valid
    } finally {
      errors.mockRestore();
    }
  });

  it("a failing save never blocks the transition, but is never swallowed: degraded is recorded, the store degraded", () => {
    const store = new FakeStore();
    store.failSaves = true;
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const k = new KillSwitch(() => 1000, { store });
      expect(k.persistenceDegraded).toBe(false);
      expect(() => k.engage("button")).not.toThrow();
      expect(k.killed).toBe(true); // the in-memory kill is in force no matter what
      expect(k.persistenceDegraded).toBe(true); // ...but durability is admitted lost
      expect(store.degradeCalls).toBe(1); // and the stale on-disk state was quarantined
      expect(errors).toHaveBeenCalled();

      // the next persist that succeeds clears the degradation
      store.failSaves = false;
      k.engage("api");
      expect(k.persistenceDegraded).toBe(false);
      expect(store.saved.at(-1)?.killed).toBe(true);
    } finally {
      errors.mockRestore();
    }
  });

  it("a kill whose save fails still fails CLOSED on restart: stale not-killed state cannot survive", () => {
    const path = join(mkdtempSync(join(tmpdir(), "ownerswitch-kill-")), "kill-state.json");
    const real = new KillStateFileStore(path);

    // provision a healthy, initialised, NOT-killed store (as after a restore)
    const k1 = new KillSwitch(() => 1000, { store: real });
    k1.engage("button");
    k1.restore(auth);
    expect(new KillStateFileStore(path).load()).toMatchObject({
      outcome: "loaded",
      state: { killed: false },
    });

    // now a kill whose persist fails: the on-disk file still says not-killed
    const failing: KillStateStore = {
      load: () => real.load(),
      save: () => {
        throw new Error("disk full");
      },
      degrade: () => real.degrade(),
    };
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const k2 = new KillSwitch(() => 2000, { store: failing });
      expect(k2.killed).toBe(false); // booted from the healthy file
      k2.engage("honeytoken", "incident");
      expect(k2.killed).toBe(true);
      expect(k2.persistenceDegraded).toBe(true);

      // the restart: it must NOT boot not-killed off the stale file
      const k3 = new KillSwitch(() => 3000, { store: new KillStateFileStore(path) });
      expect(k3.killed).toBe(true); // degraded store reads as untrustworthy -> fail closed
    } finally {
      errors.mockRestore();
    }
  });

  it("lastKill tracks the newest kill directly — no audit-log scan on hot paths", () => {
    const k = new KillSwitch(() => 1000);
    expect(k.lastKill).toBeUndefined();
    k.engage("button", "first");
    k.engage("api", "second");
    expect(k.lastKill?.reason).toBe("second");
    k.restore(auth);
    expect(k.lastKill?.reason).toBe("second"); // survives restore for the audit surface
  });
});
