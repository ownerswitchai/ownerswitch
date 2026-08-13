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
  killedAgents: [],
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
  it("passes a healthy killed:false through, epoch intact", async () => {
    await expect(
      client(jsonResponse({ killed: false, epoch: 0, killedAgents: [] })).fetchKillState(),
    ).resolves.toEqual({ killed: false, epoch: 0, killedAgents: [] });
  });

  it("requests /status with caching defeated — no-store, at the fetch layer and on the wire", async () => {
    // a cached {killed:false, epoch:N} replayed after a kill would defeat
    // every check this lookup exists for; the request must say so explicitly
    let captured: RequestInit | undefined;
    const capturing: typeof fetch = async (_input, init) => {
      captured = init;
      return new Response(JSON.stringify({ killed: false, epoch: 0, killedAgents: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
    await client(capturing).fetchKillState();
    expect(captured?.cache).toBe("no-store");
    const headers = new Headers(captured?.headers);
    expect(headers.get("cache-control")).toContain("no-store");
    expect(headers.get("pragma")).toBe("no-cache");
  });

  it("passes a healthy killed:true through, reason and epoch intact", async () => {
    const state = await client(
      jsonResponse({ killed: true, reason: "honeytoken tripped", at: 1_000, epoch: 3, killedAgents: [] }),
    ).fetchKillState();
    expect(state).toEqual({ killed: true, reason: "honeytoken tripped", epoch: 3, killedAgents: [] });
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
    await expect(
      client(jsonResponse({ status: "ok", epoch: 0, killedAgents: [] })).fetchKillState(),
    ).resolves.toEqual(FAIL_CLOSED);
  });

  describe("epoch: a missing or unparseable value must never be treated as epoch 0", () => {
    it("fails closed when epoch is absent from an otherwise-healthy killed:false body", async () => {
      await expect(client(jsonResponse({ killed: false, killedAgents: [] })).fetchKillState()).resolves.toEqual(
        FAIL_CLOSED,
      );
    });

    it("fails closed when epoch is absent from an otherwise-healthy killed:true body", async () => {
      await expect(
        client(jsonResponse({ killed: true, reason: "red button pressed", killedAgents: [] })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed when epoch is a non-integer number", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: 1.5, killedAgents: [] })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed when epoch is negative", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: -1, killedAgents: [] })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed when epoch is a numeric string, not a number", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: "0", killedAgents: [] })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed when epoch is null", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: null, killedAgents: [] })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("a genuine epoch of 0 (first boot, never killed) is accepted", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: 0, killedAgents: [] })).fetchKillState(),
      ).resolves.toEqual({ killed: false, epoch: 0, killedAgents: [] });
    });
  });

  describe("killedAgents: a missing or malformed list must never read as 'nobody is scope-killed'", () => {
    it("passes a populated scoped-kill list through", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: 2, killedAgents: ["agent-7"] })).fetchKillState(),
      ).resolves.toEqual({ killed: false, epoch: 2, killedAgents: ["agent-7"] });
    });

    it("fails closed when killedAgents is absent from an otherwise-healthy body", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: 0 })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed when killedAgents is not an array", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: 0, killedAgents: "agent-7" })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed when an entry is not a string", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: 0, killedAgents: [7] })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed when an entry is empty", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: 0, killedAgents: [""] })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed on a hostile-sized list rather than reading it into policy", async () => {
      await expect(
        client(
          jsonResponse({ killed: false, epoch: 0, killedAgents: Array(5000).fill("a") }),
        ).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed on a hostile-length agent id", async () => {
      await expect(
        client(
          jsonResponse({ killed: false, epoch: 0, killedAgents: ["x".repeat(2000)] }),
        ).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("accepts only the shared wire contract: over-cap counts and invalid ids fail closed", async () => {
      // 65 entries: one past MAX_KILLED_AGENTS — no real control plane emits it
      await expect(
        client(
          jsonResponse({
            killed: false,
            epoch: 0,
            killedAgents: Array.from({ length: 65 }, (_, i) => `agent-${i}`),
          }),
        ).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
      for (const bad of ["__proto__", "ütközés", " padded ", "a".repeat(129)]) {
        await expect(
          client(jsonResponse({ killed: false, epoch: 0, killedAgents: [bad] })).fetchKillState(),
        ).resolves.toEqual(FAIL_CLOSED);
      }
    });

    it("fails closed on a response body too large to be a real /status answer", async () => {
      const huge: typeof fetch = async () =>
        new Response(`{"killed":false,"epoch":0,"killedAgents":[],"pad":"${"x".repeat(300 * 1024)}"}`, {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      await expect(client(huge).fetchKillState()).resolves.toEqual(FAIL_CLOSED);
    });
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
      client(jsonResponse({ killed: false, epoch: 0, killedAgents: [] })),
    );
    expect(v.decision).toBe("allow");
  });

  it("denies when the control plane reports killed", async () => {
    const v = await evaluateRemote(
      { agentId: "a1", tool: "search.web" },
      policy,
      client(jsonResponse({ killed: true, reason: "red button pressed", epoch: 1, killedAgents: [] })),
    );
    expect(v.decision).toBe("deny");
    expect(v.reason).toContain("red button pressed");
  });

  it("denies even a healthy killed:false when the epoch cannot be trusted", async () => {
    const v = await evaluateRemote(
      { agentId: "a1", tool: "search.web" },
      policy,
      client(jsonResponse({ killed: false, killedAgents: [] })), // epoch missing
    );
    expect(v.decision).toBe("deny");
    expect(v.reason).toContain("control plane unreachable — fail closed");
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

  it("denies a scope-killed agent's call while another agent still passes", async () => {
    const scoped = client(jsonResponse({ killed: false, epoch: 4, killedAgents: ["a1"] }));
    const denied = await evaluateRemote({ agentId: "a1", tool: "search.web" }, policy, scoped);
    expect(denied.decision).toBe("deny");
    expect(denied.reason).toContain("scope-killed");
    const allowed = await evaluateRemote({ agentId: "a2", tool: "search.web" }, policy, scoped);
    expect(allowed.decision).toBe("allow");
  });
});
