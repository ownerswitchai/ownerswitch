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
    const v = evaluate({ agentId: "a1", tool: "search.web" }, policy, { killed: true, reason: "honeytoken tripped", killedAgents: [] });
    expect(v.decision).toBe("deny");
    expect(v.reason).toContain("honeytoken");
  });

  it("money movement requires approval", () => {
    expect(evaluate({ agentId: "a1", tool: "stripe.payout" }, policy, { killed: false, killedAgents: [] }).decision).toBe("approve");
  });

  it("merges go through the veto window", () => {
    expect(evaluate({ agentId: "a1", tool: "github.merge_pr" }, policy, { killed: false, killedAgents: [] }).decision).toBe("veto");
  });

  it("args pattern escalates destructive bash", () => {
    const v = evaluate({ agentId: "a1", tool: "bash", args: { cmd: "rm -rf /prod" } }, policy, { killed: false, killedAgents: [] });
    expect(v.decision).toBe("approve");
    expect(v.ruleId).toBe("r3");
  });

  it("plain bash only needs the veto window", () => {
    expect(evaluate({ agentId: "a1", tool: "bash", args: { cmd: "ls" } }, policy, { killed: false, killedAgents: [] }).decision).toBe("veto");
  });

  it("reads are allowed instantly", () => {
    expect(evaluate({ agentId: "a1", tool: "search.web" }, policy, { killed: false, killedAgents: [] }).decision).toBe("allow");
  });

  it("unknown tools hit the fail-closed default", () => {
    const v = evaluate({ agentId: "a1", tool: "totally.new.tool" }, policy, { killed: false, killedAgents: [] });
    expect(v.decision).toBe("approve");
    expect(v.ruleId).toBeNull();
  });
});

describe("scoped kill", () => {
  it("denies everything from a scope-killed agent, even allowed tools", () => {
    const v = evaluate(
      { agentId: "a1", tool: "search.web" },
      policy,
      { killed: false, killedAgents: ["a1"] },
    );
    expect(v.decision).toBe("deny");
    expect(v.ruleId).toBeNull();
    expect(v.reason).toContain('"a1"');
    expect(v.reason).toContain("scope-killed");
  });

  it("leaves other agents running under normal policy", () => {
    const kill = { killed: false, killedAgents: ["a1"] };
    expect(evaluate({ agentId: "a2", tool: "search.web" }, policy, kill).decision).toBe("allow");
    expect(evaluate({ agentId: "a2", tool: "stripe.payout" }, policy, kill).decision).toBe("approve");
  });

  it("outranks an allow rule but is outranked by the global kill", () => {
    const v = evaluate(
      { agentId: "a1", tool: "search.web" },
      policy,
      { killed: true, reason: "button pressed", killedAgents: ["a1"] },
    );
    // global kill wins the attribution — its reason, not the scoped one
    expect(v.decision).toBe("deny");
    expect(v.reason).toContain("kill switch engaged");
  });

  it("an empty list scopes nothing out", () => {
    expect(
      evaluate({ agentId: "a1", tool: "search.web" }, policy, { killed: false, killedAgents: [] })
        .decision,
    ).toBe("allow");
  });

  it("the list cannot be omitted — same compile-error stance as kill state itself", () => {
    // An optional list would let a caller that forgot to thread it through
    // silently un-scope every scoped kill. "No scoped state" must be an
    // explicit `killedAgents: []` at the call site.
    const omitted = () =>
      // @ts-expect-error killedAgents is required enforcement input
      evaluate({ agentId: "a1", tool: "search.web" }, policy, { killed: false });
    // Untyped (JS) callers crash instead of silently getting permission.
    expect(omitted).toThrow(TypeError);
  });
});

describe("kill state is required", () => {
  it("a bare { killed: true } denies even an allowed tool", () => {
    const v = evaluate({ agentId: "a1", tool: "search.web" }, policy, { killed: true, killedAgents: [] });
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
