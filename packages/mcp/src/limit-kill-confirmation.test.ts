import { describe, expect, it } from "vitest";
import { isLimitKillConfirmation } from "./limit-kill-confirmation.js";

const AGENT = "agent-7";

describe("isLimitKillConfirmation — the full response matrix", () => {
  it("accepts the control plane's real answers for THIS scoped kill", () => {
    // the normal scoped kill
    expect(isLimitKillConfirmation({ killed: false, killedAgent: AGENT }, AGENT)).toBe(true);
    // ...even while a global kill is concurrently in force: our scoped
    // record was still made, and `killed` reflects that unrelated stop
    expect(isLimitKillConfirmation({ killed: true, killedAgent: AGENT }, AGENT)).toBe(true);
    // the capacity fallback: escalation to the global kill, actually engaged
    expect(isLimitKillConfirmation({ killed: true, escalatedToGlobal: true }, AGENT)).toBe(true);
  });

  it("rejects anything that does not prove a DURABLE record for this agent", () => {
    for (const [label, body] of [
      ["not an object", "ok"],
      ["null", null],
      ["array", []],
      ["empty", {}],
      ["bare killed", { killed: false }],
      ["another agent's kill", { killed: false, killedAgent: "someone-else" }],
      ["degraded persistence", { killed: false, killedAgent: AGENT, persistenceDegraded: true }],
      ["unhealthy store", { killed: false, killedAgent: AGENT, unhealthy: "repair the store" }],
      ["escalation that engaged nothing", { killed: false, escalatedToGlobal: true }],
      ["escalation without killed", { escalatedToGlobal: true }],
      ["escalation, degraded", { killed: true, escalatedToGlobal: true, persistenceDegraded: true }],
      ["a cheerful 200 from something else", { ok: true, status: "accepted" }],
    ] as const) {
      expect(isLimitKillConfirmation(body, AGENT), label).toBe(false);
    }
  });
});
