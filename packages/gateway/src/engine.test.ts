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
    expect(evaluate({ agentId: "a1", tool: "stripe.payout" }, policy, { killed: false }).decision).toBe("approve");
  });

  it("merges go through the veto window", () => {
    expect(evaluate({ agentId: "a1", tool: "github.merge_pr" }, policy, { killed: false }).decision).toBe("veto");
  });

  it("args pattern escalates destructive bash", () => {
    const v = evaluate({ agentId: "a1", tool: "bash", args: { cmd: "rm -rf /prod" } }, policy, { killed: false });
    expect(v.decision).toBe("approve");
    expect(v.ruleId).toBe("r3");
  });

  it("plain bash only needs the veto window", () => {
    expect(evaluate({ agentId: "a1", tool: "bash", args: { cmd: "ls" } }, policy, { killed: false }).decision).toBe("veto");
  });

  it("reads are allowed instantly", () => {
    expect(evaluate({ agentId: "a1", tool: "search.web" }, policy, { killed: false }).decision).toBe("allow");
  });

  it("unknown tools hit the fail-closed default", () => {
    const v = evaluate({ agentId: "a1", tool: "totally.new.tool" }, policy, { killed: false });
    expect(v.decision).toBe("approve");
    expect(v.ruleId).toBeNull();
  });
});

describe("kill state is required", () => {
  it("a bare { killed: true } denies even an allowed tool", () => {
    const v = evaluate({ agentId: "a1", tool: "search.web" }, policy, { killed: true });
    expect(v.decision).toBe("deny");
    expect(v.ruleId).toBeNull();
  });

  it("evaluate() cannot be called without stating kill state", () => {
    // Function.length counts parameters before the first default — 3 proves
    // no parameter regained a default value.
    expect(evaluate.length).toBe(3);
    const omitted = () =>
      // @ts-expect-error kill state is required; omitting it must not compile
      evaluate({ agentId: "a1", tool: "search.web" }, policy);
    // Untyped (JS) callers crash instead of silently getting permission.
    expect(omitted).toThrow(TypeError);
  });
});
