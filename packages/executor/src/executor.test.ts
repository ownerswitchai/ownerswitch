import { describe, expect, it } from "vitest";
import {
  Executor,
  type ExecutionOutcome,
  type ExecutorBackend,
  type LiveKillState,
} from "./executor.js";
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
    // the second, pre-dispatch fetch — so THAT check observes it and
    // refuses. A kill landing after this check resolves, or mid-flight, is
    // out of reach by design: it races with dispatch instead of being caught.
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

  it("pins the order: nonce burn, then pre-dispatch re-check, then dispatch", async () => {
    let fetches = 0;
    let fetchesAtDispatch = -1;
    const calls: ActionTicket[] = [];
    let replayDuringPreDispatch: ExecutionOutcome | undefined;

    const backend: ExecutorBackend = {
      execute: async (ticket) => {
        fetchesAtDispatch = fetches;
        calls.push(ticket);
        return { resourceId: ticket.resourceId, detail: { merged: true } };
      },
    };
    const executor: Executor = new Executor(backend, {
      fetchLiveKillState: async () => {
        fetches += 1;
        if (fetches === 2) {
          // The pre-dispatch re-check is IN FLIGHT. If (and only if) the
          // burn precedes it, a concurrent replay of the SAME ticket must
          // already refuse on the nonce — this pins burn-before-re-check,
          // not just burn-before-dispatch. (The replay performs fetch #3
          // for its own first check, then refuses without dispatching.)
          replayDuringPreDispatch = await executor.run(TICKET);
        }
        return { killed: false, epoch: 3 };
      },
      now: () => 1_000,
    });

    const outcome = await executor.run(TICKET);
    expect(outcome.status).toBe("executed");
    expect(calls).toHaveLength(1); // dispatched exactly once, ever

    // burn ordered BEFORE the pre-dispatch re-check completed
    expect(replayDuringPreDispatch?.status).toBe("refused");
    if (replayDuringPreDispatch?.status === "refused") {
      expect(replayDuringPreDispatch.refusal.code).toBe("nonce-consumed");
    }
    // dispatch ordered AFTER the pre-dispatch re-check resolved: by the time
    // the backend ran, all three fetches (two for this run, one for the
    // replay's own first check) had already happened
    expect(fetchesAtDispatch).toBe(3);
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
