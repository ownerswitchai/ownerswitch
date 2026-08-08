import { createTripReporter, type TripReporterOptions } from "./report.js";
import { scanForHoneytokens, type HoneytokenMatch } from "./scan.js";

/**
 * Ready-made wiring for the MCP gateway: scan every outbound tool call's
 * arguments, and on a hit, report a kill. Scanning is pattern + checksum
 * based, so the gateway needs no registry of planted tokens — any
 * OwnerSwitch honeytoken trips, wherever it was minted.
 */

export interface ToolCallTrip {
  canaryIds: string[];
  tool: string;
  agentId: string;
}

export interface Tripwire {
  /** scanForHoneytokens — matches of decoy values in the text; [] when clean. */
  scan(text: string): HoneytokenMatch[];
  /** Fire-and-forget: queues a signed POST /kill that retries forever. Never throws. */
  report(trip: ToolCallTrip): void;
  /** Trips whose kill the control plane has not confirmed yet. */
  pending(): number;
  stop(): void;
}

export function createTripwire(opts: TripReporterOptions): Tripwire {
  const reporter = createTripReporter(opts);
  return {
    scan: scanForHoneytokens,
    report(trip: ToolCallTrip): void {
      reporter.report({
        canaryIds: trip.canaryIds,
        how: `decoy value appeared in tool-call arguments (tool "${trip.tool}", agent "${trip.agentId}")`,
      });
    },
    pending: reporter.pending,
    stop: reporter.stop,
  };
}
