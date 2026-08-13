import { describe, expect, it } from "vitest";
import {
  isLimitKillConfirmation,
  parseLimitKillConfirmation,
} from "./limit-kill-confirmation.js";

const AGENT = "agent-7";

describe("parseLimitKillConfirmation — the full response matrix", () => {
  it("accepts the control plane's real answers, returning the COMMIT epoch", () => {
    // the normal scoped kill
    expect(parseLimitKillConfirmation({ killed: false, epoch: 4, killedAgent: AGENT }, AGENT)).toEqual({
      epoch: 4,
    });
    // ...even while a global kill is concurrently in force: our scoped
    // record was still made, and `killed` reflects that unrelated stop
    expect(parseLimitKillConfirmation({ killed: true, epoch: 9, killedAgent: AGENT }, AGENT)).toEqual({
      epoch: 9,
    });
    // the capacity fallback: escalation to the global kill, actually engaged
    expect(
      parseLimitKillConfirmation({ killed: true, epoch: 12, escalatedToGlobal: true }, AGENT),
    ).toEqual({ epoch: 12 });
    // epoch 0 is a genuine value (a deployment's very first kill answers 1,
    // but the parser must not treat 0 as falsy-missing)
    expect(
      parseLimitKillConfirmation({ killed: false, epoch: 0, killedAgent: AGENT }, AGENT),
    ).toEqual({ epoch: 0 });
  });

  it("rejects anything that does not ANCHOR a durable record for this agent", () => {
    for (const [label, body] of [
      ["not an object", "ok"],
      ["null", null],
      ["array", []],
      ["empty", {}],
      ["killed not a boolean", { killed: "yes", epoch: 1, killedAgent: AGENT }],
      ["another agent's kill", { killed: false, epoch: 1, killedAgent: "someone-else" }],
      ["degraded persistence", { killed: false, epoch: 1, killedAgent: AGENT, persistenceDegraded: true }],
      ["unhealthy store", { killed: false, epoch: 1, killedAgent: AGENT, unhealthy: "repair it" }],
      ["escalation that engaged nothing", { killed: false, epoch: 1, escalatedToGlobal: true }],
      ["escalation without killed", { epoch: 1, escalatedToGlobal: true }],
      // the anchor itself must be real: without it, a neighbouring kill's
      // epoch could later pass for this kill's world
      ["no epoch at all", { killed: false, killedAgent: AGENT }],
      ["epoch not a number", { killed: false, epoch: "3", killedAgent: AGENT }],
      ["epoch fractional", { killed: false, epoch: 3.5, killedAgent: AGENT }],
      ["epoch negative", { killed: false, epoch: -1, killedAgent: AGENT }],
      ["epoch beyond safe integer", { killed: false, epoch: 2 ** 53, killedAgent: AGENT }],
      // the control plane answers exactly one of the two shapes
      ["both shapes at once", { killed: true, epoch: 1, killedAgent: AGENT, escalatedToGlobal: true }],
      ["neither shape", { killed: true, epoch: 1 }],
      ["a cheerful 200 from something else", { ok: true, status: "accepted" }],
    ] as const) {
      expect(parseLimitKillConfirmation(body, AGENT), label).toBeNull();
      expect(isLimitKillConfirmation(body, AGENT), label).toBe(false);
    }
  });
});
