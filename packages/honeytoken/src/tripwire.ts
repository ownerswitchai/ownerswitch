import { createTripReporter, type TripReporterOptions } from "./report.js";
import type { HoneytokenMatch, HoneytokenRegistry } from "./registry.js";
import { scanForHoneytokens } from "./scan.js";

/**
 * Gateway wiring: scan a call's arguments against the deployment registry, and
 * report the result at the right tier.
 *
 *  - reportKill — a decoy value is about to be FORWARDED across the boundary
 *    (the call passed policy). That is exfiltration in progress: engage the
 *    switch.
 *  - reportAlert — a decoy value showed up in a call that will NOT be
 *    forwarded (policy denied it, or it is still held). Nothing crossed the
 *    boundary, so this only flags a suspicious event; it never kills.
 *
 * The proxy decides which to call by evaluating policy FIRST and scanning only
 * where the call would actually be forwarded — so a decoy dropped into a call
 * policy would deny can never be used as a remote kill primitive.
 */
export interface TripwireOptions extends TripReporterOptions {
  /** The deployment's loaded, verified honeytoken registry. Required — no registry, no scanning. */
  registry: HoneytokenRegistry;
}

export interface ToolCallTrip {
  canaryIds: string[];
  tool: string;
  agentId: string;
  /** For an alert: why the call was not forwarded (e.g. the policy decision). */
  note?: string;
}

export interface Tripwire {
  /** Matches of decoy values in the text; [] when clean. Scoped to this deployment's registry. */
  scan(text: string): HoneytokenMatch[];
  /** A decoy about to be forwarded → signed POST /kill (retries in the background). */
  reportKill(trip: ToolCallTrip): void;
  /** A decoy in a call that will NOT be forwarded → POST /alert. Never kills. */
  reportAlert(trip: ToolCallTrip): void;
  /** Block until queued reports confirm or exhaust their retry budget. */
  flush(opts?: { maxAttempts?: number }): Promise<{ delivered: boolean; pending: number }>;
  pending(): number;
  stop(): void;
}

export function createTripwire(opts: TripwireOptions): Tripwire {
  const { registry } = opts;
  const reporter = createTripReporter(opts);
  return {
    scan: (text: string) => scanForHoneytokens(text, registry),
    reportKill(trip: ToolCallTrip): void {
      reporter.report({
        tier: "kill",
        canaryIds: trip.canaryIds,
        how: `decoy value about to be forwarded in tool-call arguments (tool "${trip.tool}", agent "${trip.agentId}")`,
      });
    },
    reportAlert(trip: ToolCallTrip): void {
      const why = trip.note ? `, ${trip.note}` : "";
      reporter.report({
        tier: "alert",
        canaryIds: trip.canaryIds,
        how: `decoy value in a call that was NOT forwarded (tool "${trip.tool}", agent "${trip.agentId}"${why})`,
      });
    },
    flush: reporter.flush,
    pending: reporter.pending,
    stop: reporter.stop,
  };
}
