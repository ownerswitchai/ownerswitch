import { describe, expect, it } from "vitest";
// The DEPLOYED browser module, imported directly (plain ESM, runs in Node too).
import {
  classifyKillState,
  closedWindowText,
  closedWindowTone,
  countdown,
  createJournal,
  DEFAULT_VETO_WINDOW_MS,
  devicesModel,
  diffWindowIds,
  formatClock,
  formatCountdown,
  isSafeId,
  isStatusStale,
  killConfirmation,
  killStateTransitionEvents,
  reduceKillView,
  staleKillView,
  pendingModel,
  validatePendingWindow,
  vetoResultAction,
} from "../public/workspace-core.mjs";

const armedStatus = { killed: false, epoch: 4, killedAgents: [] };
const reachable = (status: unknown) => ({ reachable: true, status });

describe("classifyKillState — fail closed on every doubt", () => {
  it("treats a missing / malformed reading as unreachable = killed", () => {
    for (const bad of [null, undefined, "armed", 42, [], {}]) {
      const view = classifyKillState(bad);
      expect(view.state).toBe("unreachable");
      expect(view.badge).toBe("UNREACHABLE");
      expect(view.treatAsKilled).toBe(true);
      expect(view.detail).toContain("treated as killed");
    }
  });

  it("treats reachable:false as unreachable and carries the error into the detail", () => {
    const view = classifyKillState({ reachable: false, error: "control plane timed out" });
    expect(view.state).toBe("unreachable");
    expect(view.detail).toContain("control plane timed out");
  });

  it("refuses a status without an explicit killed flag", () => {
    expect(classifyKillState(reachable({ epoch: 1, killedAgents: [] })).state).toBe("unreachable");
    expect(classifyKillState(reachable({ killed: "no", epoch: 1, killedAgents: [] })).state).toBe(
      "unreachable",
    );
  });

  it("never defaults a missing or malformed epoch — that would make stale approvals look current", () => {
    for (const epoch of [undefined, null, -1, 1.5, "4", Number.NaN]) {
      const view = classifyKillState(reachable({ killed: false, epoch, killedAgents: [] }));
      expect(view.state).toBe("unreachable");
      expect(view.detail).toContain("epoch");
    }
  });

  it("treats a missing killedAgents list as an untrustworthy answer (the GET /status contract)", () => {
    expect(classifyKillState(reachable({ killed: false, epoch: 1 })).state).toBe("unreachable");
    expect(
      classifyKillState(reachable({ killed: false, epoch: 1, killedAgents: "none" })).state,
    ).toBe("unreachable");
    expect(
      classifyKillState(reachable({ killed: false, epoch: 1, killedAgents: ["ok", "has space"] }))
        .state,
    ).toBe("unreachable");
  });

  it("classifies a healthy live plane as armed", () => {
    const view = classifyKillState(reachable(armedStatus));
    expect(view).toMatchObject({
      state: "armed",
      badge: "ARMED",
      treatAsKilled: false,
      epoch: 4,
      scopedKills: [],
      warnings: [],
    });
    expect(view.detail).toBe("fleet live");
  });

  it("surfaces scoped kills on an armed plane", () => {
    const view = classifyKillState(
      reachable({ killed: false, epoch: 2, killedAgents: ["deploy-bot"] }),
    );
    expect(view.state).toBe("armed");
    expect(view.scopedKills).toEqual(["deploy-bot"]);
    expect(view.detail).toContain("1 agent scope-killed");
  });

  it("classifies killed with and without a reason", () => {
    const withReason = classifyKillState(
      reachable({ killed: true, epoch: 5, killedAgents: [], reason: "workspace console e-stop" }),
    );
    expect(withReason.state).toBe("killed");
    expect(withReason.treatAsKilled).toBe(true);
    expect(withReason.detail).toContain("workspace console e-stop");
    const bare = classifyKillState(reachable({ killed: true, epoch: 5, killedAgents: [] }));
    expect(bare.detail).toBe("kill switch engaged");
  });

  it("carries degraded-persistence warnings without weakening the state", () => {
    const view = classifyKillState(
      reachable({ ...armedStatus, persistenceDegraded: true, unhealthy: "stale kill state" }),
    );
    expect(view.state).toBe("armed");
    expect(view.warnings).toHaveLength(2);
    expect(view.warnings[0]).toContain("persistence degraded");
    expect(view.warnings[1]).toContain("stale kill state");
  });
});

describe("countdowns", () => {
  it("formats and clamps", () => {
    expect(formatCountdown(0)).toBe("00:00");
    expect(formatCountdown(-5000)).toBe("00:00");
    expect(formatCountdown(999)).toBe("00:00");
    expect(formatCountdown(1000)).toBe("00:01");
    expect(formatCountdown(61_000)).toBe("01:01");
    expect(formatCountdown(Number.NaN)).toBe("00:00");
    expect(formatCountdown(12 * 3_600_000)).toBe("99:59");
  });

  it("computes remaining, label and a 0..1 bar fraction", () => {
    const halfWindow = DEFAULT_VETO_WINDOW_MS / 2;
    expect(countdown(1000 + halfWindow, 1000)).toEqual({
      msRemaining: halfWindow,
      label: "02:00",
      fraction: 0.5,
    });
    expect(countdown(1000, 5000).msRemaining).toBe(0);
    expect(countdown(1000, 5000).fraction).toBe(0);
    expect(countdown(10 * DEFAULT_VETO_WINDOW_MS, 0).fraction).toBe(1);
  });

  it("formats UTC wall-clock time deterministically", () => {
    expect(formatClock(0)).toBe("00:00:00");
    expect(formatClock(Date.UTC(2026, 0, 2, 14, 2, 39))).toBe("14:02:39");
    expect(formatClock(Number.NaN)).toBe("00:00:00");
  });
});

describe("pending windows", () => {
  const good = {
    id: "veto_8c21aa04",
    status: "pending",
    agentId: "deploy-bot",
    tool: "github.merge_pr",
    deadline: 240_000,
    delivered: false,
  };

  it("validates a well-formed entry and refuses each malformation", () => {
    expect(validatePendingWindow(good)).toEqual(good);
    const bad: unknown[] = [
      null,
      "window",
      { ...good, id: "has space" },
      { ...good, id: "a".repeat(129) },
      { ...good, status: "vetoed" },
      { ...good, agentId: "" },
      { ...good, agentId: "a".repeat(257) },
      { ...good, tool: 42 },
      { ...good, deadline: 1.5 },
      { ...good, deadline: -1 },
      { ...good, deadline: "soon" },
      { ...good, delivered: "yes" },
    ];
    for (const entry of bad) expect(validatePendingWindow(entry)).toBeNull();
  });

  it("safe ids refuse separators and traversal characters", () => {
    expect(isSafeId("veto_8c21")).toBe(true);
    for (const id of ["", "a/b", "a.b", "a b", "a\nb", null, 7]) expect(isSafeId(id)).toBe(false);
  });

  it("fails closed on missing / refused / malformed readings — never an empty happy list", () => {
    expect(pendingModel(null, 0).kind).toBe("unreachable");
    expect(pendingModel({ kind: "unreachable", error: "x" }, 0).kind).toBe("unreachable");
    expect(pendingModel({ kind: "refused", upstreamStatus: 401, error: "x" }, 0).kind).toBe(
      "unreachable",
    );
    expect(pendingModel({ kind: "ok", windows: "none" }, 0).kind).toBe("unreachable");
    expect(pendingModel({ kind: "unconfigured", missing: "OWNERSWITCH_DEVICE_SECRET" }, 0).kind).toBe(
      "unconfigured",
    );
  });

  it("sorts by deadline, attaches countdowns, and counts (never hides) dropped entries", () => {
    const later = { ...good, id: "veto_later", deadline: 240_000 };
    const sooner = { ...good, id: "veto_sooner", deadline: 120_000, status: "extended" };
    const model = pendingModel(
      { kind: "ok", windows: [later, { garbage: true }, sooner] },
      60_000,
    );
    expect(model.kind).toBe("ok");
    expect(model.dropped).toBe(1);
    expect(model.windows.map((w) => w.id)).toEqual(["veto_sooner", "veto_later"]);
    expect(model.windows[0]).toMatchObject({ label: "01:00", msRemaining: 60_000 });
    expect(model.windows[1]).toMatchObject({ label: "03:00", msRemaining: 180_000 });
  });
});

describe("vetoResultAction — STOPPED only on the server's explicit word", () => {
  const confirmed = { ok: true, upstreamStatus: 200, body: { status: "vetoed" } };

  it("stops only on ok + status:vetoed", () => {
    expect(vetoResultAction("veto_a", "veto_a", confirmed)).toBe("stopped");
  });

  it("everything else is retry — a 4xx/5xx is NOT success", () => {
    for (const result of [
      null,
      undefined,
      {},
      { ok: false, upstreamStatus: 409, body: { error: "too late" } },
      { ok: true, upstreamStatus: 200, body: { status: "pending" } },
      { ok: true, upstreamStatus: 200, body: null },
      { ok: false, unreachable: true, error: "down" },
    ]) {
      expect(vetoResultAction("veto_a", "veto_a", result)).toBe("retry");
    }
  });

  it("a response for a window the view no longer shows paints nothing", () => {
    expect(vetoResultAction("veto_a", "veto_b", confirmed)).toBe("superseded");
    expect(vetoResultAction("veto_a", null, confirmed)).toBe("superseded");
  });
});

describe("window diffs and closing narration", () => {
  it("diffs id lists in order", () => {
    expect(diffWindowIds(["a", "b"], ["b", "c", "d"])).toEqual({
      appeared: ["c", "d"],
      disappeared: ["a"],
    });
    expect(diffWindowIds([], [])).toEqual({ appeared: [], disappeared: [] });
  });

  it("narrates a known final status and admits an unknown one", () => {
    expect(closedWindowText("veto_x", "vetoed")).toBe("veto window veto_x closed — vetoed");
    expect(closedWindowText("veto_x", "released")).toContain("released");
    expect(closedWindowText("veto_x", null)).toContain("final status unknown");
    expect(closedWindowText("veto_x", "surprise")).toContain("final status unknown");
  });

  it("tones: stops read as stops, releases as ok, the unknown as warn", () => {
    expect(closedWindowTone("vetoed")).toBe("stop");
    expect(closedWindowTone("held")).toBe("stop");
    expect(closedWindowTone("released")).toBe("ok");
    expect(closedWindowTone("spent")).toBe("warn");
    expect(closedWindowTone(null)).toBe("warn");
  });
});

describe("devicesModel", () => {
  const device = {
    deviceId: "dev_console_a1",
    name: "owner phone",
    enrolledAt: Date.UTC(2026, 7, 8),
    pushRegistered: false,
  };

  it("maps unconfigured / refused / unreachable readings honestly", () => {
    expect(devicesModel(null).kind).toBe("unreachable");
    expect(devicesModel({ kind: "unconfigured", missing: "OWNERSWITCH_OWNER_TOKEN" }).kind).toBe(
      "unconfigured",
    );
    const refused = devicesModel({ kind: "refused", upstreamStatus: 501, error: "not configured" });
    expect(refused).toMatchObject({ kind: "refused", upstreamStatus: 501, error: "not configured" });
    expect(devicesModel({ kind: "ok", devices: "nope" }).kind).toBe("unreachable");
  });

  it("renders a valid list with revocation and enrolment date", () => {
    const model = devicesModel({
      kind: "ok",
      devices: [device, { ...device, deviceId: "dev_console_b2", name: "field phone", revokedAt: 5 }],
    });
    expect(model.kind).toBe("ok");
    expect(model.devices[0]).toMatchObject({
      name: "owner phone",
      enrolledOn: "2026-08-08",
      revoked: false,
      pushRegistered: false,
    });
    expect(model.devices[1]).toMatchObject({ name: "field phone", revoked: true });
  });

  it("one malformed entry fails the whole reading closed — no half-true list", () => {
    for (const rotten of [
      { ...device, deviceId: "has space" },
      { ...device, name: "" },
      { ...device, enrolledAt: "yesterday" },
      null,
    ]) {
      expect(devicesModel({ kind: "ok", devices: [device, rotten] }).kind).toBe("unreachable");
    }
  });
});

describe("the console journal", () => {
  it("keeps newest first and collapses consecutive repeats into a count", () => {
    const journal = createJournal(10);
    journal.push(1000, "poll", "pending list unavailable", "warn");
    journal.push(2000, "poll", "pending list unavailable", "warn");
    journal.push(3000, "veto", "veto veto_a — stopped", "stop");
    const entries = journal.entries();
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ kind: "veto", count: 1 });
    expect(entries[1]).toMatchObject({ kind: "poll", count: 2, at: 2000 });
  });

  it("a repeat after an intervening entry is a new row, not a merged one", () => {
    const journal = createJournal(10);
    journal.push(1, "a", "x", "info");
    journal.push(2, "b", "y", "info");
    journal.push(3, "a", "x", "info");
    expect(journal.entries().map((e) => e.kind)).toEqual(["a", "b", "a"]);
  });

  it("is bounded — a chatty poller cannot grow it forever", () => {
    const journal = createJournal(3);
    for (let i = 0; i < 10; i++) journal.push(i, `k${i}`, `t${i}`, "info");
    const entries = journal.entries();
    expect(entries).toHaveLength(3);
    expect(entries[0]?.kind).toBe("k9");
  });

  it("entries() returns a copy — mutating it changes nothing", () => {
    const journal = createJournal(5);
    journal.push(1, "a", "x", "info");
    journal.entries().length = 0;
    expect(journal.entries()).toHaveLength(1);
  });
});

describe("killStateTransitionEvents", () => {
  const armed = classifyKillState(reachable(armedStatus));
  const killed = classifyKillState(reachable({ killed: true, epoch: 5, killedAgents: [] }));
  const unreachable = classifyKillState(null);

  it("journals the initial state as a console start", () => {
    const events = killStateTransitionEvents(null, armed);
    expect(events).toHaveLength(1);
    expect(events[0]?.text).toContain("console started");
    expect(events[0]?.tone).toBe("ok");
  });

  it("journals only transitions, with the tone of the NEW state", () => {
    expect(killStateTransitionEvents(armed, armed)).toEqual([]);
    expect(killStateTransitionEvents(armed, killed)[0]).toMatchObject({ tone: "stop" });
    expect(killStateTransitionEvents(killed, armed)[0]).toMatchObject({ tone: "ok" });
    expect(killStateTransitionEvents(armed, unreachable)[0]).toMatchObject({ tone: "warn" });
    expect(killStateTransitionEvents(null, null)).toEqual([]);
  });
});

describe("reduceKillView — the monotonic epoch reducer (audit #2)", () => {
  const view = (state: "armed" | "killed" | "unreachable", epoch: number | null) =>
    ({
      state,
      badge: state.toUpperCase(),
      treatAsKilled: state !== "armed",
      epoch,
      scopedKills: [],
      warnings: [],
      detail: "x",
    }) as Parameters<typeof reduceKillView>[1];

  it("refuses an epoch regression as unreachable — a stale ARMED cannot downgrade a newer KILLED", () => {
    const prev = view("killed", 3);
    const next = view("armed", 2);
    const reduced = reduceKillView(prev, next);
    expect(reduced.state).toBe("unreachable");
    expect(reduced.treatAsKilled).toBe(true);
    expect(reduced.epoch).toBe(3);
    expect(reduced.detail).toContain("regressed");
  });

  it("passes equal and advancing epochs, first readings, and epoch-less views through", () => {
    expect(reduceKillView(view("killed", 3), view("armed", 3)).state).toBe("armed");
    expect(reduceKillView(view("killed", 3), view("armed", 4)).state).toBe("armed");
    expect(reduceKillView(null, view("armed", 0)).state).toBe("armed");
    expect(reduceKillView(view("unreachable", null), view("armed", 0)).state).toBe("armed");
    expect(reduceKillView(view("armed", 2), view("unreachable", null)).state).toBe("unreachable");
  });
});

describe("status freshness (audit #2)", () => {
  it("no reading yet, or one older than the TTL, is stale", () => {
    expect(isStatusStale(null, 1_000)).toBe(true);
    expect(isStatusStale(0, 9_000)).toBe(true);
    expect(isStatusStale(5_000, 12_000)).toBe(false);
    expect(isStatusStale(5_000, 13_001)).toBe(true);
  });

  it("the stale view is treated as killed and keeps the last accepted epoch", () => {
    const stale = staleKillView({ epoch: 7 });
    expect(stale.treatAsKilled).toBe(true);
    expect(stale.state).toBe("unreachable");
    expect(stale.epoch).toBe(7);
    expect(staleKillView(null).epoch).toBeNull();
  });
});

describe("killConfirmation — confirmed is a schema, not an HTTP 200 (audit #4)", () => {
  it("confirms only killed:true with a usable epoch", () => {
    expect(killConfirmation({ ok: true, upstreamStatus: 200, body: { killed: true, epoch: 1 } })).toEqual({
      kind: "confirmed",
      text: "kill engaged — control plane confirmed (epoch 1)",
    });
  });

  it("a {} body, killed:false, a bad epoch, or a refusal is unconfirmed", () => {
    for (const result of [
      null,
      {},
      { ok: true, upstreamStatus: 200, body: {} },
      { ok: true, upstreamStatus: 200, body: { killed: false, epoch: 1 } },
      { ok: true, upstreamStatus: 200, body: { killed: true } },
      { ok: true, upstreamStatus: 200, body: { killed: true, epoch: -1 } },
      { ok: false, upstreamStatus: 503, body: { error: "kill refused by the control plane" } },
      { ok: false, unreachable: true, error: "control plane timed out" },
    ]) {
      expect(killConfirmation(result).kind, JSON.stringify(result)).toBe("unconfirmed");
    }
  });

  it("a degraded persistence is stated, never silently folded into confirmed", () => {
    const degraded = killConfirmation({
      ok: true,
      upstreamStatus: 200,
      body: { killed: true, epoch: 2, persistenceDegraded: true },
    });
    expect(degraded.kind).toBe("confirmed-degraded");
    expect(degraded.text).toContain("DEGRADED");
  });
});
