/**
 * The ONE agentId contract of OwnerSwitch — the single source of truth for
 * what an agent identifier may look like, shared by every layer that touches
 * one: the MCP gateway's config (refuses to start with an invalid id), the
 * control plane's scoped-kill surfaces (`POST /kill {agentId}`, veto
 * registration, ceremonies), the kill-state file's strict loader, and the
 * gateway client's `/status` parser. One validator everywhere, so an agent
 * that can act is always an agent that can be scope-killed — an id the
 * gateway accepted but the kill endpoint refuses would be an agent with no
 * scoped stop.
 *
 * The shape is deliberately boring: 1–128 printable-ASCII characters, no
 * leading or trailing whitespace. Ids appear verbatim in the state file, the
 * unauthenticated /status body, audit surfaces and owner-facing UIs — no
 * control characters, no Unicode confusables.
 *
 * Three names are refused outright even though they fit the charset:
 * `__proto__`, `constructor` and `prototype`. Agent ids are used as object
 * keys in JavaScript consumers (the persisted state file, clients indexing
 * by id), where these names are prototype-pollution and shadowing footguns.
 * Refusing them at the contract level means no consumer needs to remember
 * to defend against them.
 */

export const MAX_AGENT_ID_CHARS = 128;

/**
 * Ceiling on simultaneously scope-killed agents. It exists because
 * scoped-kill entries persist in the kill-state file, which the loader
 * refuses over its byte cap: unbounded counts would let a kill flood write
 * a state file tomorrow's boot rejects. At this cap a scoped kill is NEVER
 * refused — it escalates to the global kill (see control-plane kill.ts):
 * out of room to stop one agent, stop them all.
 */
export const MAX_KILLED_AGENTS = 64;

const FORBIDDEN_AGENT_IDS = new Set(["__proto__", "constructor", "prototype"]);

/** 1–128 printable-ASCII chars, no edge whitespace, no prototype footguns. */
export function isValidAgentId(value: string): boolean {
  return (
    value.length >= 1 &&
    value.length <= MAX_AGENT_ID_CHARS &&
    /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/.test(value) &&
    !FORBIDDEN_AGENT_IDS.has(value)
  );
}
