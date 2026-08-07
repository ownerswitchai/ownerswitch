import { describe, expect, it } from "vitest";
import type { Policy } from "@ownerswitchai/shared";
import {
  createControlPlaneClient,
  evaluateRemote,
  type ControlPlaneClient,
} from "./client.js";

const FAIL_CLOSED = {
  killed: true,
  reason: "control plane unreachable — fail closed",
};

const jsonResponse =
  (body: unknown, status = 200): typeof fetch =>
  async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });

const rejectingFetch: typeof fetch = async () => {
  throw new Error("ECONNREFUSED");
};

/** Never resolves; rejects only when the client's timeout aborts the signal. */
const hangingFetch: typeof fetch = (_input, init) =>
  new Promise((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
  });

const client = (fetchImpl: typeof fetch, timeoutMs?: number): ControlPlaneClient =>
  createControlPlaneClient({ baseUrl: "http://control-plane.test", timeoutMs, fetchImpl });

describe("createControlPlaneClient", () => {
  it("passes a healthy killed:false through", async () => {
    await expect(client(jsonResponse({ killed: false })).fetchKillState()).resolves.toEqual({
      killed: false,
    });
  });

  it("passes a healthy killed:true through, reason intact", async () => {
    const state = await client(
      jsonResponse({ killed: true, reason: "honeytoken tripped", at: 1_000 }),
    ).fetchKillState();
    expect(state).toEqual({ killed: true, reason: "honeytoken tripped" });
  });

  it("fails closed on network rejection instead of throwing", async () => {
    await expect(client(rejectingFetch).fetchKillState()).resolves.toEqual(FAIL_CLOSED);
  });

  it("fails closed on a non-2xx response", async () => {
    await expect(
      client(jsonResponse({ error: "internal error" }, 500)).fetchKillState(),
    ).resolves.toEqual(FAIL_CLOSED);
  });

  it("fails closed on timeout", async () => {
    await expect(client(hangingFetch, 10).fetchKillState()).resolves.toEqual(FAIL_CLOSED);
  });

  it("fails closed on a malformed JSON body", async () => {
    const badBody: typeof fetch = async () => new Response("<html>oops", { status: 200 });
    await expect(client(badBody).fetchKillState()).resolves.toEqual(FAIL_CLOSED);
  });

  it("fails closed on a 2xx body without a boolean `killed`", async () => {
    await expect(client(jsonResponse({ status: "ok" })).fetchKillState()).resolves.toEqual(
      FAIL_CLOSED,
    );
  });
});

describe("evaluateRemote", () => {
  const policy: Policy = {
    rules: [{ id: "reads", tool: "search.*", decision: "allow" }],
    defaultDecision: "approve",
  };

  it("delegates to evaluate() when the control plane is healthy", async () => {
    const v = await evaluateRemote(
      { agentId: "a1", tool: "search.web" },
      policy,
      client(jsonResponse({ killed: false })),
    );
    expect(v.decision).toBe("allow");
  });

  it("denies when the control plane reports killed", async () => {
    const v = await evaluateRemote(
      { agentId: "a1", tool: "search.web" },
      policy,
      client(jsonResponse({ killed: true, reason: "red button pressed" })),
    );
    expect(v.decision).toBe("deny");
    expect(v.reason).toContain("red button pressed");
  });

  it("denies everything when the control plane is down, even an allowed tool", async () => {
    const v = await evaluateRemote(
      { agentId: "a1", tool: "search.web" },
      policy,
      client(rejectingFetch),
    );
    expect(v.decision).toBe("deny");
    expect(v.reason).toContain("control plane unreachable — fail closed");
  });
});
