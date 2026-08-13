/**
 * What counts as PROOF that a limit's scoped kill actually landed.
 *
 * The limit tracker's latch lifecycle turns on this answer: a confirmed
 * latch may later release on the agent's absence from `/status` (the
 * owner's 2GO restore). So "confirmed" must mean the control plane really
 * recorded THIS agent's kill, durably — not merely that something answered
 * with a 2xx. Every rejection below is a case where a lie or an accident
 * could otherwise re-arm a budget with no owner ceremony:
 *
 *  - not an object → nothing was asserted at all;
 *  - `persistenceDegraded` / `unhealthy` present → the kill is in force in
 *    memory but may not survive a restart; a restart would then erase it,
 *    and the next answer's absence would look exactly like a restore;
 *  - `killedAgent` naming a DIFFERENT agent → some other scope was killed;
 *  - `escalatedToGlobal` without `killed: true` → an escalation that did
 *    not actually engage the global switch is not an escalation.
 *
 * Deliberately NOT required: `killed === false` on the scoped path. A
 * global kill engaged concurrently (a button press, a honeytoken) makes
 * `killed` true while our scoped record is still made correctly.
 */
export function isLimitKillConfirmation(body: unknown, agentId: string): boolean {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return false;
  const b = body as Record<string, unknown>;
  if (b.persistenceDegraded !== undefined || b.unhealthy !== undefined) return false;
  if (b.killedAgent !== undefined) return b.killedAgent === agentId;
  // the capacity fallback: the scoped kill escalated to the global one,
  // which must then actually be engaged
  return b.escalatedToGlobal === true && b.killed === true;
}
