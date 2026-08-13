import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  KillStateFileStore,
  type KillStateLoad,
  type KillStateStore,
  type PersistedKillState,
  type SaveResult,
} from "./kill-state.js";
import {
  isValidAgentId,
  KillSwitch,
  MAX_KILLED_AGENTS,
  MAX_SCOPED_KILL_REASON_CHARS,
  sanitizeScopedKillReason,
} from "./kill.js";

const auth = { ceremonyId: "c1", ownerId: "adam", completedAt: 2000 };

/** In-memory store: records every save, serves whatever load/outcomes are scripted. */
class FakeStore implements KillStateStore {
  saved: PersistedKillState[] = [];
  loadResult: KillStateLoad = { outcome: "absent" };
  failSaves = false;
  saveResult: SaveResult = { durable: true };
  degradeResult = true;
  degradeCalls = 0;
  load(): KillStateLoad {
    return this.loadResult;
  }
  save(state: PersistedKillState): SaveResult {
    if (this.failSaves) throw new Error("disk full");
    this.saved.push(state);
    return this.saveResult;
  }
  degrade(): boolean {
    this.degradeCalls += 1;
    return this.degradeResult;
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

  it("alert() records a flagged event WITHOUT engaging the switch", () => {
    const k = new KillSwitch(() => 42);
    k.alert("honeytoken", "read of /decoys/.env.backup");
    expect(k.killed).toBe(false); // the whole point of the DoS fix
    const log = k.auditLog();
    expect(log).toHaveLength(1);
    expect(log[0]).toEqual({
      type: "alert",
      event: { source: "honeytoken", reason: "read of /decoys/.env.backup", at: 42 },
    });
  });

  it("alerts and kills share one timeline, in order", () => {
    const k = new KillSwitch(() => 7);
    k.alert("honeytoken", "decoy file read");
    k.engage("honeytoken", "decoy value in tool call");
    expect(k.killed).toBe(true);
    expect(k.auditLog().map((e) => e.type)).toEqual(["alert", "kill"]);
  });

  it("alert() flags the unauthenticated case like engage() does", () => {
    const k = new KillSwitch(() => 1);
    k.alert("api", "loopback", { unauthenticated: true });
    const [entry] = k.auditLog();
    expect(entry.type === "alert" && entry.event.unauthenticated).toBe(true);
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

      // the quarantine succeeded (degrade returned true), so the plane is
      // degraded but not unhealthy: a restart fails closed, not open
      expect(k.quarantineFailed).toBe(false);

      // the next persist that succeeds clears the degradation
      store.failSaves = false;
      k.engage("api");
      expect(k.persistenceDegraded).toBe(false);
      expect(store.saved.at(-1)?.killed).toBe(true);
    } finally {
      errors.mockRestore();
    }
  });

  it("a failed QUARANTINE marks the switch unhealthy until a persist succeeds", () => {
    const store = new FakeStore();
    store.failSaves = true;
    store.degradeResult = false; // the stale state cannot be neutralised either
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const k = new KillSwitch(() => 1000, { store });
      k.engage("button");
      expect(k.killed).toBe(true); // the in-memory kill always lands
      expect(k.persistenceDegraded).toBe(true);
      expect(k.quarantineFailed).toBe(true); // a restart may boot from stale state

      // owner intervention repairs the store; the next successful persist IS
      // the repair — correct state on disk means no stale state to fear
      store.failSaves = false;
      k.engage("api");
      expect(k.quarantineFailed).toBe(false);
      expect(k.persistenceDegraded).toBe(false);
    } finally {
      errors.mockRestore();
    }
  });

  it("a save that published but did not fsync reports degraded persistence, not silence", () => {
    const store = new FakeStore();
    store.saveResult = { durable: false, detail: "directory fsync unavailable" };
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const k = new KillSwitch(() => 1000, { store });
      k.engage("button");
      expect(k.killed).toBe(true);
      expect(store.saved.at(-1)?.killed).toBe(true); // the state WAS published...
      expect(k.persistenceDegraded).toBe(true); // ...but durability is not claimed
      expect(k.quarantineFailed).toBe(false); // published state is correct — no stale hazard
      expect(errors).toHaveBeenCalled();

      // a fully durable save clears it
      store.saveResult = { durable: true };
      k.engage("api");
      expect(k.persistenceDegraded).toBe(false);
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

describe("scoped (per-agent) kills", () => {
  it("stops one agent without stopping the fleet, audited and attributed", () => {
    const k = new KillSwitch(() => 1000);
    k.engageAgent("agent-7", "app", "looping on stripe.payout");
    expect(k.killed).toBe(false); // the global switch is untouched
    expect(k.agentKilled("agent-7")).toBe(true);
    expect(k.agentKilled("agent-8")).toBe(false);
    expect(k.killedAgents).toEqual(["agent-7"]);
    expect(k.auditLog()).toEqual([
      {
        type: "agent-kill",
        agentId: "agent-7",
        event: { source: "app", reason: "looping on stripe.payout", at: 1000 },
      },
    ]);
  });

  it("bumps the GLOBAL epoch — scoped kills inherit the epoch invalidation story", () => {
    const k = new KillSwitch(() => 1000);
    k.engageAgent("agent-7", "api");
    expect(k.epoch).toBe(1);
    k.engageAgent("agent-7", "api"); // idempotent re-kill still opens a new epoch
    expect(k.epoch).toBe(2);
    expect(k.killedAgents).toEqual(["agent-7"]);
  });

  it("scoped restore needs a ceremony, is single-use, and never bumps the epoch", () => {
    const k = new KillSwitch(() => 1000);
    k.engageAgent("agent-7", "app");
    const epochAtKill = k.epoch;
    expect(() => k.restoreAgent("agent-7", { ceremonyId: "", ownerId: "", completedAt: 0 })).toThrow(
      /2GO/,
    );
    k.restoreAgent("agent-7", auth);
    expect(k.agentKilled("agent-7")).toBe(false);
    expect(k.epoch).toBe(epochAtKill);
    // the spent ceremony cannot restore a second scoped kill either
    k.engageAgent("agent-7", "app");
    expect(() => k.restoreAgent("agent-7", auth)).toThrow(/single-use/);
  });

  it("cannot scope-restore an agent that is not scope-killed", () => {
    expect(() => new KillSwitch().restoreAgent("agent-7", auth)).toThrow(/nothing to restore/);
  });

  it("global kill and restore leave scoped kills intact — the tiers are independent", () => {
    const k = new KillSwitch(() => 1000);
    k.engageAgent("agent-7", "app");
    k.engage("button");
    expect(k.killed).toBe(true);
    expect(k.agentKilled("agent-7")).toBe(true);
    k.restore(auth);
    expect(k.killed).toBe(false);
    expect(k.agentKilled("agent-7")).toBe(true); // its own kill was never restored
  });

  it("persists scoped kills exactly when non-empty and reboots with them re-seated", () => {
    const store = new FakeStore();
    const k = new KillSwitch(() => 1000, { store });
    k.engageAgent("agent-7", "app", "incident");
    expect(store.saved.at(-1)).toEqual({
      version: 1,
      killed: false,
      epoch: 1,
      agentKills: { "agent-7": { source: "app", reason: "incident", at: 1000 } },
    });

    const rebootStore = new FakeStore();
    rebootStore.loadResult = { outcome: "loaded", state: store.saved.at(-1) as PersistedKillState };
    const k2 = new KillSwitch(() => 2000, { store: rebootStore });
    expect(k2.killed).toBe(false);
    expect(k2.agentKilled("agent-7")).toBe(true);
    expect(k2.epoch).toBe(1);
    expect(k2.auditLog()).toEqual([
      {
        type: "agent-kill",
        agentId: "agent-7",
        event: { source: "app", reason: "incident", at: 1000 },
      },
    ]);

    // scoped restore drops the field from the file again
    k2.restoreAgent("agent-7", auth);
    expect(rebootStore.saved.at(-1)).toEqual({ version: 1, killed: false, epoch: 1 });
  });

  it("bounds the persisted reason — scoped entries must never outgrow the state file", () => {
    const store = new FakeStore();
    const k = new KillSwitch(() => 1000, { store });
    k.engageAgent("agent-7", "app", "x".repeat(10_000));
    const saved = store.saved.at(-1)?.agentKills?.["agent-7"];
    expect(saved?.reason).toHaveLength(MAX_SCOPED_KILL_REASON_CHARS);
  });

  it("sanitizes the persisted reason: control characters become spaces, never \\u escapes", () => {
    // A control char JSON-escapes to 6 bytes; 128 of them would triple the
    // per-entry byte budget the state-file ceiling is sized for. Stripping
    // at write time keeps the worst case in BYTES known, and keeps log
    // lines and owner surfaces injection-free.
    const store = new FakeStore();
    const k = new KillSwitch(() => 1000, { store });
    k.engageAgent("agent-7", "app", "line1\nline2\u0000\u001b[31mred\u007f");
    const saved = store.saved.at(-1)?.agentKills?.["agent-7"];
    expect(saved?.reason).toBe("line1 line2  [31mred ");
    expect(sanitizeScopedKillReason("\u0007".repeat(300))).toBe(" ".repeat(MAX_SCOPED_KILL_REASON_CHARS));
  });

  it("reports which switch flipped: scoped kills return escalated:false, the cap overflow true", () => {
    const k = new KillSwitch(() => 1000);
    expect(k.engageAgent("agent-0", "api")).toEqual({ escalated: false });
    for (let i = 1; i < MAX_KILLED_AGENTS; i += 1) k.engageAgent(`agent-${i}`, "api");
    expect(k.engageAgent("agent-0", "api")).toEqual({ escalated: false }); // re-kill: no new entry
    expect(k.engageAgent("agent-overflow", "api")).toEqual({ escalated: true });
    expect(k.agentKilled("agent-overflow")).toBe(false); // the GLOBAL switch answered instead
    expect(k.killed).toBe(true);
  });

  it("at capacity a scoped kill is NEVER refused — it escalates to the global kill", () => {
    const k = new KillSwitch(() => 1000);
    for (let i = 0; i < MAX_KILLED_AGENTS; i += 1) k.engageAgent(`agent-${i}`, "api");
    expect(k.killed).toBe(false);
    // an already-killed agent re-kills fine at capacity (no new entry)
    k.engageAgent("agent-0", "api");
    expect(k.killed).toBe(false);
    // one more DISTINCT agent has nowhere to go but everywhere
    k.engageAgent("agent-overflow", "honeytoken", "decoy crossed the gateway");
    expect(k.killed).toBe(true);
    expect(k.lastKill?.reason).toMatch(/capacity/);
    expect(k.lastKill?.reason).toContain("agent-overflow");
    expect(k.lastKill?.reason).toContain("decoy crossed the gateway");
  });

  it("validates agent ids for the HTTP layer: printable ASCII, 1–128, no edge spaces", () => {
    expect(isValidAgentId("agent-7")).toBe(true);
    expect(isValidAgentId("a")).toBe(true);
    expect(isValidAgentId("two words")).toBe(true);
    expect(isValidAgentId("")).toBe(false);
    expect(isValidAgentId(" padded ")).toBe(false);
    expect(isValidAgentId("a".repeat(129))).toBe(false);
    expect(isValidAgentId("newline\nagent")).toBe(false);
    expect(isValidAgentId("ütközés")).toBe(false);
    // prototype-footgun names are refused even though the charset fits:
    // agent ids are object keys in JS consumers (state file, id-indexed
    // clients), where these names pollute or shadow
    expect(isValidAgentId("__proto__")).toBe(false);
    expect(isValidAgentId("constructor")).toBe(false);
    expect(isValidAgentId("prototype")).toBe(false);
  });
});
