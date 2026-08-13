/**
 * What counts as PROOF that a limit's scoped kill actually landed — and, as
 * part of the same answer, WHERE on the control plane's epoch line it
 * landed.
 *
 * The limit tracker's latch lifecycle turns on this: a confirmed latch may
 * later release on the agent's absence from `/status` (the owner's 2GO
 * restore). So a confirmation must pin two things, not one:
 *
 *  1. THAT the control plane durably recorded THIS agent's kill;
 *  2. the exact `epoch` it recorded it in. The epoch line is SHARED — every
 *     kill in the deployment bumps it — so "the next epoch after I looked"
 *     is not this kill's epoch: another agent's kill can occupy it, and a
 *     status snapshot from that neighbour's epoch (where our agent is
 *     legitimately absent, because our kill has not landed yet) would then
 *     look exactly like the owner's restore. Only the commit epoch the
 *     control plane reports back can anchor the latch.
 *
 * Every rejection below is a case where a lie or an accident could
 * otherwise re-arm a budget with no owner ceremony:
 *
 *  - not an object, or `killed` not a boolean → nothing was asserted;
 *  - `persistenceDegraded` / `unhealthy` present → the kill is in force in
 *    memory but may not survive a restart; a restart would then erase it,
 *    and the next answer's absence would look exactly like a restore;
 *  - no `epoch`, or one that is not a POSITIVE safe integer → the proof
 *    cannot be anchored, so it is not proof (a kill always bumps the
 *    counter, so a commit epoch is never 0);
 *  - any key beyond the exact two shapes → not an answer this control
 *    plane produces, and the extra key may be the very disclaimer that
 *    matters;
 *  - `killedAgent` naming a DIFFERENT agent → some other scope was killed;
 *  - `escalatedToGlobal` without `killed: true` → an escalation that did
 *    not actually engage the global switch is not an escalation;
 *  - BOTH `killedAgent` and `escalatedToGlobal` → the control plane does
 *    exactly one of these; a body claiming both is not one of its answers.
 *
 * Deliberately NOT required: `killed === false` on the scoped path. A
 * global kill engaged concurrently (a button press, a honeytoken) makes
 * `killed` true while our scoped record is still made correctly.
 */
export interface LimitKillConfirmation {
  /** the control plane's kill epoch AFTER this kill was committed */
  epoch: number;
}

export function parseLimitKillConfirmation(
  body: unknown,
  agentId: string,
): LimitKillConfirmation | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const b = body as Record<string, unknown>;
  // EXACT own-key schema. This is a proof boundary, so "the fields I need
  // are present" is not enough: an answer carrying anything else is not one
  // of the two shapes the control plane produces, and an unrecognised field
  // may be exactly the disclaimer that matters (degraded persistence is
  // signalled by an EXTRA key). Deployment consequence, same as elsewhere:
  // upgrade the control plane first — an older gateway reading a newer
  // response simply never confirms, which holds the latch rather than
  // releasing it.
  const keys = Object.keys(b).sort().join(",");
  const scoped = keys === "epoch,killed,killedAgent";
  const escalated = keys === "epoch,escalatedToGlobal,killed";
  if (!scoped && !escalated) return null;
  if (typeof b.killed !== "boolean") return null;
  // A successful kill always BUMPS the counter, so 0 is never a commit
  // epoch — accepting it would anchor the latch before any kill existed.
  if (typeof b.epoch !== "number" || !Number.isSafeInteger(b.epoch) || b.epoch < 1) return null;
  if (scoped && b.killedAgent !== agentId) return null;
  if (escalated && !(b.escalatedToGlobal === true && b.killed === true)) return null;
  return { epoch: b.epoch };
}

/** Boolean form, for the reporter's delivery gate. */
export function isLimitKillConfirmation(body: unknown, agentId: string): boolean {
  return parseLimitKillConfirmation(body, agentId) !== null;
}
