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
  it("passes a healthy killed:false through, epoch intact", async () => {
    await expect(
      client(jsonResponse({ killed: false, epoch: 0 })).fetchKillState(),
    ).resolves.toEqual({ killed: false, epoch: 0 });
  });

  it("passes a healthy killed:true through, reason and epoch intact", async () => {
    const state = await client(
      jsonResponse({ killed: true, reason: "honeytoken tripped", at: 1_000, epoch: 3 }),
    ).fetchKillState();
    expect(state).toEqual({ killed: true, reason: "honeytoken tripped", epoch: 3 });
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
      client(jsonResponse({ status: "ok", epoch: 0 })).fetchKillState(),
    ).resolves.toEqual(FAIL_CLOSED);
  });

  describe("epoch: a missing or unparseable value must never be treated as epoch 0", () => {
    it("fails closed when epoch is absent from an otherwise-healthy killed:false body", async () => {
      await expect(client(jsonResponse({ killed: false })).fetchKillState()).resolves.toEqual(
        FAIL_CLOSED,
      );
    });

    it("fails closed when epoch is absent from an otherwise-healthy killed:true body", async () => {
      await expect(
        client(jsonResponse({ killed: true, reason: "red button pressed" })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed when epoch is a non-integer number", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: 1.5 })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed when epoch is negative", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: -1 })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed when epoch is a numeric string, not a number", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: "0" })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("fails closed when epoch is null", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: null })).fetchKillState(),
      ).resolves.toEqual(FAIL_CLOSED);
    });

    it("a genuine epoch of 0 (first boot, never killed) is accepted", async () => {
      await expect(
        client(jsonResponse({ killed: false, epoch: 0 })).fetchKillState(),
      ).resolves.toEqual({ killed: false, epoch: 0 });
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
      client(jsonResponse({ killed: false, epoch: 0 })),
    );
    expect(v.decision).toBe("allow");
  });

  it("denies when the control plane reports killed", async () => {
    const v = await evaluateRemote(
      { agentId: "a1", tool: "search.web" },
      policy,
      client(jsonResponse({ killed: true, reason: "red button pressed", epoch: 1 })),
    );
    expect(v.decision).toBe("deny");
    expect(v.reason).toContain("red button pressed");
  });

  it("denies even a healthy killed:false when the epoch cannot be trusted", async () => {
    const v = await evaluateRemote(
      { agentId: "a1", tool: "search.web" },
      policy,
      client(jsonResponse({ killed: false })), // epoch missing
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
});
