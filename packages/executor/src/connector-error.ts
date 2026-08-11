/**
 * A connector call failed — with the one fact the agent and the operator
 * need most attached: did the action definitively not happen, or is the
 * outcome unknown?
 *
 * The nonce burns before the connector call (DESIGN.md §3), so ANY failure
 * after the yes spends the ticket. But "spent" does not mean "ambiguous":
 * a request GitHub received and refused (4xx) definitively did not merge
 * anything, while a request that died on the wire may have. The proxy maps
 * this onto the agent-facing ExecutionFailed error so the agent is told
 * "it did NOT run" only when that is actually known
 * (packages/mcp/src/errors.ts).
 */
export type ConnectorOutcome = "not-performed" | "unknown";

export class ConnectorCallError extends Error {
  constructor(
    message: string,
    readonly outcome: ConnectorOutcome,
  ) {
    super(message);
    this.name = "ConnectorCallError";
  }
}
