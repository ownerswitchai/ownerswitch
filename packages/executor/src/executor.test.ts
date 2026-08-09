import { describe, expect, it } from "vitest";
import { Executor, type ExecutorBackend, type LiveKillState } from "./executor.js";
import type { ActionTicket } from "./ticket.js";

const TICKET: ActionTicket = {
  agentId: "a1",
  sourceTool: "github.merge_pr",
  decision: "veto",
  ruleId: "merge",
  connector: "github",
  operation: "merge_pull_request",
  canonicalArgs: '{"owner":"ownerswitchai","pullNumber":7,"repo":"ownerswitch"}',
  resourceId: "github:pr:ownerswitchai/ownerswitch#7",
  policyVersion: "sha256:test",
  killEpoch: 3,
  expiresAt: 2_000,
  nonce: "n-1",
  singleUse: true,
};

function recordingBackend() {
  const calls: ActionTicket[] = [];
  const backend: ExecutorBackend = {
    execute: async (ticket) => {
      calls.push(ticket);
      return { resourceId: ticket.resourceId, detail: { merged: true } };
    },
  };
  return { calls, backend };
}

describe("Executor", () => {
  it("refuses a ticket from a previous kill epoch before the backend is ever called", async () => {
    const { calls, backend } = recordingBackend();

    // Minted in epoch 3; a kill (and restore) happened since — live epoch is 4,
    // killed is false again. The approval must not survive the kill.
    const executor = new Executor(backend, {
      fetchLiveKillState: async () => ({ killed: false, epoch: 4 }),
      now: () => 1_000,
    });

    const outcome = await executor.run(TICKET);

    expect(outcome.status).toBe("refused");
    if (outcome.status === "refused") {
      expect(outcome.refusal.code).toBe("epoch-mismatch");
    }
    expect(calls).toHaveLength(0);
  });

  it("a kill landing between the re-check and dispatch is caught by the pre-dispatch check", async () => {
    const { calls, backend } = recordingBackend();

    // First fetch (the re-check) sees a healthy world; the kill lands before
    // the second, pre-dispatch fetch. The pre-dispatch check NARROWS this
    // race — a kill after it, or mid-flight, is out of reach by design: not
    // yet dispatched → refused; already dispatched → not recallable.
    const answers: LiveKillState[] = [
      { killed: false, epoch: 3 },
      { killed: true, epoch: 4 },
    ];
    const executor = new Executor(backend, {
      fetchLiveKillState: async () => answers.shift() ?? { killed: true, epoch: -1 },
      now: () => 1_000,
    });

    const outcome = await executor.run(TICKET);
    expect(outcome.status).toBe("refused");
    if (outcome.status === "refused") expect(outcome.refusal.code).toBe("kill-engaged");
    expect(calls).toHaveLength(0); // never dispatched
  });

  it("a late refusal still spends the ticket: burn happens before dispatch, not after", async () => {
    const { calls, backend } = recordingBackend();

    // The control plane vanishes between the re-check and dispatch (fetch #2
    // throws → fail closed), then recovers unchanged. The first attempt burned
    // the nonce before dispatch, so the replay in the recovered — otherwise
    // valid — world is refused on the nonce: the owner re-approves, the
    // executor never retries an irreversible action by itself.
    let fetches = 0;
    const executor = new Executor(backend, {
      fetchLiveKillState: async (): Promise<LiveKillState> => {
        fetches += 1;
        if (fetches === 2) throw new Error("ECONNREFUSED");
        return { killed: false, epoch: 3 };
      },
      now: () => 1_000,
    });

    const first = await executor.run(TICKET);
    expect(first.status).toBe("refused");
    if (first.status === "refused") expect(first.refusal.code).toBe("kill-engaged");

    const replay = await executor.run(TICKET);
    expect(replay.status).toBe("refused");
    if (replay.status === "refused") expect(replay.refusal.code).toBe("nonce-consumed");
    expect(calls).toHaveLength(0); // the backend was never reached, either time
  });
});
