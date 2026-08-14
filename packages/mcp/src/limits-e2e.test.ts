/**
 * The limit-kill pipeline, end to end against a REAL control plane: a
 * tripped budget → device-signed POST /kill {agentId, source:"limit"} →
 * the agent listed on /status.killedAgents → the owner's scoped 2GO
 * restore → the tracker's latch releases and the budget re-arms. This is
 * the wiring the unit tests each prove in isolation, connected once for
 * real — including the design's central claim that the DURABLE latch
 * authority is the control plane's persisted scoped kill, not any
 * gateway-side state.
 */
import { createServer, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControlPlane, createOwnerSession } from "@ownerswitchai/control-plane";
import { LimitTracker, limitTripReason, type LimitTrip } from "@ownerswitchai/gateway";
import { createTripReporter } from "@ownerswitchai/honeytoken";
import type { LimitRule } from "@ownerswitchai/shared";
import {
  isLimitKillConfirmation,
  parseLimitKillConfirmation,
} from "./limit-kill-confirmation.js";
import { afterEach, describe, expect, it, vi } from "vitest";

const DEVICE_SECRET = "limits-e2e-device-secret";
const AGENT_ID = "agent-e2e";

const clock = (start = 0) => {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
};

describe("limits end to end: trip → signed scoped kill → killedAgents → 2GO restore → release", () => {
  let server: Server | undefined;

  afterEach(() => {
    server?.close();
    server = undefined;
  });

  it("runs the whole pipeline against a real control plane", async () => {
    const c = clock(1_000);
    // A REAL kill-state file: the scoped kill this pipeline lands must be
    // provably durable — the control-plane-restart leg below depends on it.
    const killStateFile = join(mkdtempSync(join(tmpdir(), "ownerswitch-limits-e2e-")), "kill.json");
    const silenceDevWarning = vi.spyOn(console, "error").mockImplementation(() => {});
    const cp = createControlPlane({
      now: c.now,
      dev: true,
      killStateFile,
      deviceSecret: DEVICE_SECRET,
      acceptSessionOnlyApprovalRisk: true,
    });
    silenceDevWarning.mockRestore();
    server = createServer(cp.handler);
    const url = await new Promise<string>((resolveUrl) => {
      server!.listen(0, "127.0.0.1", () => {
        const addr = server!.address();
        if (addr === null || typeof addr === "string") throw new Error("no address");
        resolveUrl(`http://127.0.0.1:${addr.port}`);
      });
    });

    const rule: LimitRule = { id: "e2e-budget", tool: "*", metric: "calls", max: 0, action: "kill" };
    const tracker = new LimitTracker([rule]);
    const reporter = createTripReporter({
      controlPlaneUrl: url,
      deviceId: "gw-e2e",
      secret: DEVICE_SECRET,
      // the signed timestamp must fall inside the control plane's device
      // skew window, so the reporter runs on the same injected clock
      now: c.now,
      log: () => {},
    });

    // 1. the budget trips on the crossing call, anchored — as the proxy does
    // it — to the kill epoch THIS call saw before dispatch
    const epochAtCall = (
      (await (await fetch(`${url}/status`)).json()) as { epoch: number }
    ).epoch;
    const trips = tracker.observeCall(
      { agentId: AGENT_ID, tool: "stripe.payout" },
      { epoch: epochAtCall },
    );
    expect(trips).toHaveLength(1);
    expect(tracker.killTripped?.confirmed).toBe(false);

    // 2. synchronous delivery — the same shape the CLI's reportKill uses,
    // including the per-report confirmation bound to THIS latch generation
    const trip: LimitTrip = trips[0];
    reporter.report({
      tier: "kill",
      canaryIds: [],
      how: "",
      source: "limit",
      agentId: AGENT_ID,
      reason: limitTripReason(trip, AGENT_ID),
      // the REAL chain the CLI runs: response → parser → exact commit epoch
      // → tracker. Nothing here stands in for production code.
      onDelivered: (confirmation) => {
        const parsed = parseLimitKillConfirmation(confirmation.body, AGENT_ID);
        expect(parsed).not.toBeNull();
        if (parsed !== null) tracker.confirmKillDelivered(parsed.epoch, trip.latchGeneration);
      },
      // the PRODUCTION predicate, not a test stand-in: this run proves the
      // real control plane's answer satisfies what the CLI demands
      confirmDelivery: (body) => isLimitKillConfirmation(body, AGENT_ID),
    });
    const { delivered } = await reporter.flush({ maxAttempts: 4 });
    expect(delivered).toBe(true);
    expect(tracker.killTripped?.confirmed).toBe(true); // onDelivered advanced the lifecycle

    // 3. the DURABLE authority holds the scoped kill, attributed to "limit"
    const status = (await (await fetch(`${url}/status`)).json()) as {
      killed: boolean;
      killedAgents: string[];
      epoch: number;
    };
    expect(status.killed).toBe(false); // the fleet is running
    expect(status.killedAgents).toEqual([AGENT_ID]);
    const killEntry = cp.killSwitch.auditLog().find((e) => e.type === "agent-kill");
    expect(killEntry?.type === "agent-kill" && killEntry.event.source).toBe("limit");
    expect(killEntry?.type === "agent-kill" && killEntry.event.reason).toContain('"e2e-budget"');

    // ...and the tracker, observing the same /status a gateway would (epoch
    // included — that is what orders the answers), stays latched
    tracker.observeKillState(status.killedAgents, { epoch: status.epoch });
    expect(tracker.killTripped?.ruleId).toBe("e2e-budget");

    // 3b. THE DURABILITY LEG: restart the control plane onto the same state
    // file — the scoped kill must come back, because THIS record is the
    // durable latch the whole design leans on. (A gateway crash-restart is
    // covered by the same fact: a fresh gateway polls /status and sees the
    // agent listed.)
    server.close();
    server = undefined;
    const silenceReboot = vi.spyOn(console, "error").mockImplementation(() => {});
    const cp2 = createControlPlane({
      now: c.now,
      dev: true,
      killStateFile,
      deviceSecret: DEVICE_SECRET,
      acceptSessionOnlyApprovalRisk: true,
    });
    silenceReboot.mockRestore();
    expect(cp2.killSwitch.agentKilled(AGENT_ID)).toBe(true); // survived the restart
    server = createServer(cp2.handler);
    const url2 = await new Promise<string>((resolveUrl) => {
      server!.listen(0, "127.0.0.1", () => {
        const addr = server!.address();
        if (addr === null || typeof addr === "string") throw new Error("no address");
        resolveUrl(`http://127.0.0.1:${addr.port}`);
      });
    });
    const statusAfterReboot = (await (await fetch(`${url2}/status`)).json()) as {
      killedAgents: string[];
      epoch: number;
    };
    expect(statusAfterReboot.killedAgents).toEqual([AGENT_ID]);

    // a STALE pre-kill answer arriving late must not read as the restore
    tracker.observeKillState([], { epoch: status.epoch - 1 });
    expect(tracker.killTripped?.ruleId).toBe("e2e-budget");
    // ...and the latch is anchored to OUR kill's commit epoch, which is
    // exactly the epoch /status now reports
    expect(tracker.killTripped?.confirmed).toBe(true);

    // 4. the owner's scoped 2GO restore over the real HTTP surface
    const session = createOwnerSession("adam", { now: c.now });
    const ceremony = await fetch(`${url2}/restore/ceremony`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${session.token}` },
      body: JSON.stringify({ agentId: AGENT_ID }),
    });
    expect(ceremony.status).toBe(201);
    const { id } = (await ceremony.json()) as { id: string };
    c.advance(30_000); // the mandatory 2GO cooldown
    const restore = await fetch(`${url2}/restore`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${session.token}` },
      body: JSON.stringify({ ceremonyId: id }),
    });
    expect(restore.status).toBe(200);
    expect(await restore.json()).toEqual({ killed: false, restoredAgent: AGENT_ID });

    // 5. the tracker sees the restore on /status and releases — budgets re-armed
    const after = (await (await fetch(`${url2}/status`)).json()) as {
      killedAgents: string[];
      epoch: number;
    };
    expect(after.killedAgents).toEqual([]);
    tracker.observeKillState(after.killedAgents, { epoch: after.epoch });
    expect(tracker.killTripped).toBeUndefined();
    expect(tracker.observeCall({ agentId: AGENT_ID, tool: "stripe.payout" })).toHaveLength(1); // fresh crossing

    reporter.stop();
  });
});
