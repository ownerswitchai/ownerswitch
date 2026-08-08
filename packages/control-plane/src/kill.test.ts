import { describe, expect, it, vi } from "vitest";
import type { KillStateLoad, KillStateStore, PersistedKillState } from "./kill-state.js";
import { KillSwitch } from "./kill.js";

const auth = { ceremonyId: "c1", ownerId: "adam", completedAt: 2000 };

/** In-memory store: records every save, serves whatever load is scripted. */
class FakeStore implements KillStateStore {
  saved: PersistedKillState[] = [];
  loadResult: KillStateLoad = { outcome: "absent" };
  failSaves = false;
  load(): KillStateLoad {
    return this.loadResult;
  }
  save(state: PersistedKillState): void {
    if (this.failSaves) throw new Error("disk full");
    this.saved.push(state);
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

  it("a failing save never blocks the transition — the kill still engages, loudly", () => {
    const store = new FakeStore();
    store.failSaves = true;
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const k = new KillSwitch(() => 1000, { store });
      expect(() => k.engage("button")).not.toThrow();
      expect(k.killed).toBe(true);
      expect(errors).toHaveBeenCalled();
    } finally {
      errors.mockRestore();
    }
  });
});
