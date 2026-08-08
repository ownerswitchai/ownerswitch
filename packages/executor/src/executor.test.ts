import { describe, expect, it } from "vitest";
import { Executor, type ExecutorBackend } from "./executor.js";
import type { ActionTicket } from "./ticket.js";

describe("Executor", () => {
  it("refuses a ticket from a previous kill epoch before the backend is ever called", async () => {
    const backendCalls: ActionTicket[] = [];
    const backend: ExecutorBackend = {
      execute: async (ticket) => {
        backendCalls.push(ticket);
        return { resourceId: ticket.resourceId, detail: { merged: true } };
      },
    };

    // Minted in epoch 3; a kill (and restore) happened since — live epoch is 4,
    // killed is false again. The approval must not survive the kill.
    const executor = new Executor(backend, {
      fetchLiveKillState: async () => ({ killed: false, epoch: 4 }),
      now: () => 1_000,
    });
    const ticket: ActionTicket = {
      agentId: "a1",
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

    const outcome = await executor.run(ticket);

    expect(outcome.status).toBe("refused");
    if (outcome.status === "refused") {
      expect(outcome.refusal.code).toBe("epoch-mismatch");
    }
    expect(backendCalls).toHaveLength(0);
  });
});
