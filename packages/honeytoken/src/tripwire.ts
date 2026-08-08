import { createTripReporter, type TripReporterOptions } from "./report.js";
import { scanForHoneytokens, type HoneytokenMatch } from "./scan.js";

/**
 * Ready-made wiring for the MCP gateway: scan every outbound tool call's
 * arguments, and on a hit, report a KILL. A decoy value crossing the gateway
 * has no innocent explanation, so this tier engages the switch (unlike a file
 * touch, which only alerts — see watch.ts).
 *
 * Scanning is pattern + keyed-checksum based: the tripwire holds this
 * deployment's canary secret, so the gateway needs no registry of planted
 * tokens and never trips on another deployment's bait. The canary key
 * defaults to the device secret already used to sign kills; pass
 * `canarySecret` to decouple them.
 */
export interface TripwireOptions extends TripReporterOptions {
  /** Per-deployment canary key the scanner verifies against; defaults to `secret`. */
  canarySecret?: string;
}

export interface ToolCallTrip {
  canaryIds: string[];
  tool: string;
  agentId: string;
}

export interface Tripwire {
  /** Matches of decoy values in the text; [] when clean. Keyed to this deployment. */
  scan(text: string): HoneytokenMatch[];
  /** Fire-and-forget: queues a signed POST /kill that retries. Never throws. */
  report(trip: ToolCallTrip): void;
  /** Block until queued reports confirm or exhaust their retry budget. */
  flush(opts?: { maxAttempts?: number }): Promise<{ delivered: boolean; pending: number }>;
  /** Reports whose delivery the control plane has not confirmed yet. */
  pending(): number;
  stop(): void;
}

export function createTripwire(opts: TripwireOptions): Tripwire {
  const canarySecret = opts.canarySecret ?? opts.secret;
  const reporter = createTripReporter(opts);
  return {
    scan: (text: string) => scanForHoneytokens(text, canarySecret),
    report(trip: ToolCallTrip): void {
      reporter.report({
        tier: "kill",
        canaryIds: trip.canaryIds,
        how: `decoy value appeared in tool-call arguments (tool "${trip.tool}", agent "${trip.agentId}")`,
      });
    },
    flush: reporter.flush,
    pending: reporter.pending,
    stop: reporter.stop,
  };
}
