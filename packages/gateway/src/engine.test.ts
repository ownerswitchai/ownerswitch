import { describe, expect, it } from "vitest";
import type { Policy } from "@ownerswitchai/shared";
import { evaluate } from "./engine.js";

const policy: Policy = {
  rules: [
    { id: "r1", tool: "stripe.*", decision: "approve", description: "money moves need the owner" },
    { id: "r2", tool: "github.merge_pr", decision: "veto" },
    { id: "r3", tool: "bash", argsPattern: "rm\\s+-rf", decision: "approve", description: "destructive shell" },
    { id: "r4", tool: "bash", decision: "veto" },
    { id: "r5", tool: "search.*", decision: "allow" },
  ],
  defaultDecision: "approve",
};

describe("evaluate", () => {
  it("kill switch denies everything, even allowed tools", () => {
    const v = evaluate({ agentId: "a1", tool: "search.web" }, policy, { killed: true, reason: "honeytoken tripped" });
    expect(v.decision).toBe("deny");
    expect(v.reason).toContain("honeytoken");
  });

  it("money movement requires approval", () => {
    expect(evaluate({ agentId: "a1", tool: "stripe.payout" }, policy).decision).toBe("approve");
  });

  it("merges go through the veto window", () => {
    expect(evaluate({ agentId: "a1", tool: "github.merge_pr" }, policy).decision).toBe("veto");
  });

  it("args pattern escalates destructive bash", () => {
    const v = evaluate({ agentId: "a1", tool: "bash", args: { cmd: "rm -rf /prod" } }, policy);
    expect(v.decision).toBe("approve");
    expect(v.ruleId).toBe("r3");
  });

  it("plain bash only needs the veto window", () => {
    expect(evaluate({ agentId: "a1", tool: "bash", args: { cmd: "ls" } }, policy).decision).toBe("veto");
  });

  it("reads are allowed instantly", () => {
    expect(evaluate({ agentId: "a1", tool: "search.web" }, policy).decision).toBe("allow");
  });

  it("unknown tools hit the fail-closed default", () => {
    const v = evaluate({ agentId: "a1", tool: "totally.new.tool" }, policy);
    expect(v.decision).toBe("approve");
    expect(v.ruleId).toBeNull();
  });
});
