/**
 * @ownerswitchai/honeytoken — decoy credentials that trip an automatic kill.
 *
 * Threat model, honestly: honeytokens catch curiosity and broad sweeps, not
 * a targeted attacker who knows to avoid them. See README.md before relying
 * on them for anything.
 */
export {
  CANARY_ID_LENGTH,
  CANARY_MARKER,
  generateHoneytoken,
  HONEYTOKEN_KINDS,
  newCanaryId,
  verifyCanaryId,
} from "./generate.js";
export type { GenerateOptions, Honeytoken, HoneytokenKind } from "./generate.js";

export { scanForHoneytokens } from "./scan.js";
export type { HoneytokenMatch } from "./scan.js";

export { fsReportsReads, watchHoneytokenFiles } from "./watch.js";
export type { FileTrip, HoneytokenWatcher, TripCause, WatchHoneytokenFilesOptions } from "./watch.js";

export { createTripReporter, killReason } from "./report.js";
export type { KillConfirmation, Trip, TripReporter, TripReporterOptions } from "./report.js";

export { createTripwire } from "./tripwire.js";
export type { ToolCallTrip, Tripwire } from "./tripwire.js";

export { DECOY_FILENAMES, plantHoneytokens } from "./plant.js";
export type { PlantOptions, PlantResult, PlantedToken } from "./plant.js";
