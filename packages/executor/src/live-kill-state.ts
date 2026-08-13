import type { ControlPlaneClient } from "@ownerswitchai/gateway";
import type { LiveKillState } from "./executor.js";

/**
 * The executor's live kill-state reader, backed by the gateway's
 * control-plane client — the same fail-closed `/status` lookup every other
 * decision in the system uses (see packages/gateway/src/client.ts). The
 * client already reads `epoch` off `/status` and fails the whole lookup
 * closed when it is missing or unparseable; this adapter only narrows the
 * gateway's `KillState` (epoch optional, for hand-built values) to the
 * executor's `LiveKillState` (epoch required).
 *
 * The narrowing is itself fail-closed: an answer that says "not killed" but
 * carries no epoch cannot support the ticket-epoch check, so it reads as
 * killed. With `createControlPlaneClient` that case never happens — fetched
 * answers always carry an epoch or come back `killed: true` — but a
 * hand-built client must not be able to slip an epoch-less "go" past the
 * re-check. A killed answer's epoch is irrelevant (killed refuses before the
 * epoch is compared), so `-1` stands in when absent.
 */
export function liveKillStateFromControlPlane(
  client: ControlPlaneClient,
): () => Promise<LiveKillState> {
  return async () => {
    const state = await client.fetchKillState();
    if (state.killed) return { killed: true, epoch: state.epoch ?? -1 };
    if (state.epoch === undefined) return { killed: true, epoch: -1 };
    // The scoped-kill list rides through so refuseTicket can hold a ticket
    // against ITS agent's kill state directly, not only via the epoch.
    return { killed: false, epoch: state.epoch, killedAgents: state.killedAgents };
  };
}
