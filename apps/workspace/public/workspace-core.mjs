/*
 * workspace-core.mjs — every decision the Workspace console makes, as pure
 * functions over wire data. No DOM, no fetch, no clock of its own: app.js is
 * glue around this module, and the vitest suite imports THIS file (the
 * deployed bytes), the apps/owner pattern.
 *
 * The one rule that shapes everything here: FAIL CLOSED. A reading the
 * console cannot positively prove healthy — unreachable, malformed, missing
 * a security-relevant field — renders as the safe state (treated as killed,
 * "cannot list", "not configured"), never as an optimistic default.
 */

/** The control plane's default veto window; used only to scale the countdown bar. */
export const DEFAULT_VETO_WINDOW_MS = 4 * 60_000;

/** Window/agent ids the console will render and echo into URLs. */
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

export function isSafeId(value) {
  return typeof value === "string" && SAFE_ID.test(value);
}

/* ------------------------------------------------------------------ */
/* kill state                                                          */
/* ------------------------------------------------------------------ */

/**
 * Classify the console API's /api/status reading into the one state the
 * whole page hangs off. Fail closed on every doubt:
 *  - not an object, reachable !== true, malformed status  → "unreachable"
 *  - epoch missing/invalid                                → "unreachable"
 *    (no silent default: a guessed epoch would make stale approvals look
 *    current — the same rule the gateway client follows)
 *  - killedAgents not an array of safe ids                → "unreachable"
 *    (a missing list is an untrustworthy answer, per GET /status's contract)
 *  - killed === true                                      → "killed"
 *  - killed === false, everything present                 → "armed"
 * "unreachable" and "killed" both carry treatAsKilled: true — the console
 * renders them with the same stopped visuals, differing only in wording.
 */
export function classifyKillState(reading) {
  const unreachable = (detail) => ({
    state: "unreachable",
    badge: "UNREACHABLE",
    treatAsKilled: true,
    epoch: null,
    scopedKills: [],
    warnings: [],
    detail: `${detail} — treated as killed (fail closed)`,
  });
  if (typeof reading !== "object" || reading === null) return unreachable("no status reading");
  if (reading.reachable !== true) {
    const err = typeof reading.error === "string" ? reading.error : "control plane unreachable";
    return unreachable(err);
  }
  const status = reading.status;
  if (typeof status !== "object" || status === null) return unreachable("malformed status");
  const { killed, epoch, killedAgents } = status;
  if (killed !== true && killed !== false) return unreachable("status carries no killed flag");
  if (typeof epoch !== "number" || !Number.isInteger(epoch) || epoch < 0) {
    return unreachable("status carries no usable epoch");
  }
  if (!Array.isArray(killedAgents) || !killedAgents.every((id) => isSafeId(id))) {
    return unreachable("status carries no usable killedAgents list");
  }
  const warnings = [];
  if (status.persistenceDegraded === true) {
    warnings.push("persistence degraded — a restart may not preserve this state");
  }
  if (typeof status.unhealthy === "string" && status.unhealthy !== "") {
    warnings.push(status.unhealthy);
  }
  if (killed === true) {
    const reason = typeof status.reason === "string" && status.reason !== "" ? status.reason : null;
    return {
      state: "killed",
      badge: "KILLED",
      treatAsKilled: true,
      epoch,
      scopedKills: killedAgents,
      warnings,
      detail: reason === null ? "kill switch engaged" : `kill switch engaged — ${reason}`,
    };
  }
  return {
    state: "armed",
    badge: "ARMED",
    treatAsKilled: false,
    epoch,
    scopedKills: killedAgents,
    warnings,
    detail:
      killedAgents.length === 0
        ? "fleet live"
        : `fleet live — ${killedAgents.length} agent${killedAgents.length === 1 ? "" : "s"} scope-killed`,
  };
}

/* ------------------------------------------------------------------ */
/* countdowns                                                          */
/* ------------------------------------------------------------------ */

/** "MM:SS" from a remaining-ms value; clamped at 0 and capped at 99:59. */
export function formatCountdown(msRemaining) {
  const total = Math.max(0, Math.floor((Number.isFinite(msRemaining) ? msRemaining : 0) / 1000));
  const capped = Math.min(total, 99 * 60 + 59);
  const mm = String(Math.floor(capped / 60)).padStart(2, "0");
  const ss = String(capped % 60).padStart(2, "0");
  return `${mm}:${ss}`;
}

/**
 * Countdown parts for one deadline: remaining ms (floored at 0), the MM:SS
 * label, and the 0..1 fraction of a full window still left (drives the bar).
 */
export function countdown(deadline, nowMs, windowMs = DEFAULT_VETO_WINDOW_MS) {
  const msRemaining = Math.max(0, deadline - nowMs);
  const span = windowMs > 0 ? windowMs : DEFAULT_VETO_WINDOW_MS;
  return {
    msRemaining,
    label: formatCountdown(msRemaining),
    fraction: Math.max(0, Math.min(1, msRemaining / span)),
  };
}

/** UTC wall-clock "HH:MM:SS" for journal rows (deterministic everywhere). */
export function formatClock(ms) {
  const value = Number.isFinite(ms) ? ms : 0;
  return new Date(Math.max(0, value)).toISOString().slice(11, 19);
}

/* ------------------------------------------------------------------ */
/* pending veto windows                                                */
/* ------------------------------------------------------------------ */

/** One pending-list entry, validated field by field; null refuses it. */
export function validatePendingWindow(entry) {
  if (typeof entry !== "object" || entry === null) return null;
  const { id, status, agentId, tool, deadline, delivered } = entry;
  if (!isSafeId(id)) return null;
  if (status !== "pending" && status !== "extended") return null;
  if (typeof agentId !== "string" || agentId === "" || agentId.length > 256) return null;
  if (typeof tool !== "string" || tool === "" || tool.length > 256) return null;
  if (typeof deadline !== "number" || !Number.isInteger(deadline) || deadline < 0) return null;
  if (delivered !== true && delivered !== false) return null;
  return { id, status, agentId, tool, deadline, delivered };
}

/**
 * The pending panel's model from the console API's /api/veto/pending reading.
 * kinds: "unconfigured" (no device credential on the console server),
 * "unreachable" (couldn't ask, or the answer didn't validate — fail closed:
 * never rendered as an empty happy list), "ok" (windows sorted by deadline,
 * each with its countdown; malformed entries counted in `dropped`, never
 * silently discarded).
 */
export function pendingModel(reading, nowMs) {
  if (typeof reading !== "object" || reading === null) {
    return { kind: "unreachable", windows: [], dropped: 0 };
  }
  if (reading.kind === "unconfigured") {
    return { kind: "unconfigured", windows: [], dropped: 0 };
  }
  if (reading.kind !== "ok" || !Array.isArray(reading.windows)) {
    return { kind: "unreachable", windows: [], dropped: 0 };
  }
  const valid = [];
  let dropped = 0;
  for (const entry of reading.windows) {
    const window = validatePendingWindow(entry);
    if (window === null) dropped += 1;
    else valid.push(window);
  }
  valid.sort((a, b) => a.deadline - b.deadline || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return {
    kind: "ok",
    dropped,
    windows: valid.map((window) => ({ ...window, ...countdown(window.deadline, nowMs) })),
  };
}

/**
 * What a veto RESPONSE may do to the button it was clicked on. "superseded"
 * when the view moved on (the response's window is no longer the button's
 * window — a stale response must never paint the current view); "stopped"
 * ONLY on the server's explicit ok + status:"vetoed"; anything else —
 * refusal, network error, missing body — is "retry". The same doctrine as
 * the owner app's vetoResultAction: a 4xx/5xx is NOT success.
 */
export function vetoResultAction(armedWindowId, currentWindowId, result) {
  if (armedWindowId !== currentWindowId) return "superseded";
  return result !== null &&
    typeof result === "object" &&
    result.ok === true &&
    typeof result.body === "object" &&
    result.body !== null &&
    result.body.status === "vetoed"
    ? "stopped"
    : "retry";
}

/**
 * Diff two pending id lists so the journal can narrate windows appearing and
 * closing. Order-preserving over `next` for appeared, over `prev` for gone.
 */
export function diffWindowIds(prevIds, nextIds) {
  const prev = new Set(prevIds);
  const next = new Set(nextIds);
  return {
    appeared: nextIds.filter((id) => !prev.has(id)),
    disappeared: prevIds.filter((id) => !next.has(id)),
  };
}

/**
 * The journal wording for a window that left the pending list, given the
 * open GET /veto/:id status read that followed. Unknown/failed reads stay
 * honest: the console reports it lost sight of the window, not an outcome
 * it never saw.
 */
export function closedWindowText(id, finalStatus) {
  const known = ["vetoed", "released", "held", "spent", "pending", "extended"];
  if (typeof finalStatus === "string" && known.includes(finalStatus)) {
    return `veto window ${id} closed — ${finalStatus}`;
  }
  return `veto window ${id} left the pending list — final status unknown`;
}

/** The tone a closed-window journal entry carries (drives row color only). */
export function closedWindowTone(finalStatus) {
  if (finalStatus === "vetoed" || finalStatus === "held") return "stop";
  if (finalStatus === "released") return "ok";
  return "warn";
}

/* ------------------------------------------------------------------ */
/* devices                                                             */
/* ------------------------------------------------------------------ */

/**
 * The devices panel's model from /api/devices. kinds: "unconfigured" (no
 * owner token on the console server), "unreachable", "refused" (upstream
 * said no — expired session, 501 not configured — surfaced with its status,
 * fail closed), "ok". A malformed device entry fails the whole reading
 * closed rather than rendering a half-true list.
 */
export function devicesModel(reading) {
  if (typeof reading !== "object" || reading === null) return { kind: "unreachable", devices: [] };
  if (reading.kind === "unconfigured") return { kind: "unconfigured", devices: [] };
  if (reading.kind === "refused") {
    const upstreamStatus =
      typeof reading.upstreamStatus === "number" && Number.isInteger(reading.upstreamStatus)
        ? reading.upstreamStatus
        : 0;
    const error = typeof reading.error === "string" ? reading.error : "refused";
    return { kind: "refused", upstreamStatus, error, devices: [] };
  }
  if (reading.kind !== "ok" || !Array.isArray(reading.devices)) {
    return { kind: "unreachable", devices: [] };
  }
  const devices = [];
  for (const entry of reading.devices) {
    if (typeof entry !== "object" || entry === null) return { kind: "unreachable", devices: [] };
    const { deviceId, name, enrolledAt, revokedAt, pushRegistered } = entry;
    if (!isSafeId(deviceId)) return { kind: "unreachable", devices: [] };
    if (typeof name !== "string" || name === "" || name.length > 256) {
      return { kind: "unreachable", devices: [] };
    }
    if (typeof enrolledAt !== "number" || !Number.isInteger(enrolledAt) || enrolledAt < 0) {
      return { kind: "unreachable", devices: [] };
    }
    const revoked = revokedAt !== undefined && revokedAt !== null;
    devices.push({
      deviceId,
      name,
      enrolledAt,
      enrolledOn: new Date(enrolledAt).toISOString().slice(0, 10),
      revoked,
      pushRegistered: pushRegistered === true,
    });
  }
  return { kind: "ok", devices };
}

/* ------------------------------------------------------------------ */
/* the console's own journal                                           */
/* ------------------------------------------------------------------ */

/**
 * A bounded, newest-first event journal of what THIS console observed and
 * did — labelled as such in the UI, because the control plane's
 * authoritative audit trail has no read endpoint yet. Consecutive pushes of
 * the same kind+text collapse into one row with a count, so a 2-second
 * poller in a long outage cannot scroll the history away.
 */
export function createJournal(limit = 250) {
  const capacity = Number.isInteger(limit) && limit > 0 ? limit : 250;
  const entries = []; // newest first
  let seq = 0;
  return {
    push(at, kind, text, tone = "info") {
      const latest = entries[0];
      if (latest !== undefined && latest.kind === kind && latest.text === text) {
        latest.count += 1;
        latest.at = at;
        return latest;
      }
      seq += 1;
      const entry = { seq, at, kind, text, tone, count: 1 };
      entries.unshift(entry);
      if (entries.length > capacity) entries.length = capacity;
      return entry;
    },
    entries() {
      return entries.slice();
    },
  };
}

/* ------------------------------------------------------------------ */
/* kill-state freshness and ordering (post-merge audit #2)             */
/* ------------------------------------------------------------------ */

/**
 * How long the last accepted status reading may stand before the console
 * refuses to keep showing it. Four poll periods: enough to ride out one
 * slow answer, short enough that a suspended tab or hung fetch cannot
 * leave yesterday's ARMED on screen.
 */
export const STATUS_FRESH_TTL_MS = 8_000;

export function isStatusStale(lastFreshAt, nowMs, ttlMs = STATUS_FRESH_TTL_MS) {
  return typeof lastFreshAt !== "number" || !(nowMs - lastFreshAt <= ttlMs);
}

/** The view a stale (expired-TTL) status renders as — treated as killed. */
export function staleKillView(prev) {
  return {
    state: "unreachable",
    badge: "UNREACHABLE",
    treatAsKilled: true,
    epoch: prev !== null && typeof prev === "object" && typeof prev.epoch === "number" ? prev.epoch : null,
    scopedKills: [],
    warnings: [],
    detail: "status reading is STALE — no fresh answer inside the freshness window; treated as killed (fail closed)",
  };
}

/**
 * The MONOTONIC reducer between the accepted view and a candidate: the kill
 * epoch never decreases on a real control plane (restarts reload it from
 * disk), so a candidate whose epoch regresses is a stale or forged answer —
 * refused as unreachable, never allowed to downgrade what the console
 * already accepted. Everything else passes through. (Response ORDERING is
 * additionally handled by the caller's serial polling + generation guard;
 * this reducer is the belt to that suspenders.)
 */
export function reduceKillView(prev, next) {
  if (
    prev !== null &&
    typeof prev === "object" &&
    typeof prev.epoch === "number" &&
    next !== null &&
    typeof next === "object" &&
    typeof next.epoch === "number" &&
    next.epoch < prev.epoch
  ) {
    return {
      state: "unreachable",
      badge: "UNREACHABLE",
      treatAsKilled: true,
      epoch: prev.epoch,
      scopedKills: [],
      warnings: [],
      detail: `status regressed to epoch ${next.epoch} behind accepted epoch ${prev.epoch} — stale or forged; treated as killed (fail closed)`,
    };
  }
  return next;
}

/* ------------------------------------------------------------------ */
/* kill confirmation (post-merge audit #4)                             */
/* ------------------------------------------------------------------ */

/**
 * What an /api/kill answer may be CALLED. "confirmed" needs the exact
 * shape — ok:true with killed:true and a usable epoch; a {} body, a
 * killed:false, or a malformed epoch is "unconfirmed" however the HTTP
 * status looked. A confirmed kill whose answer carries
 * persistenceDegraded is stated as exactly that: engaged now, but a
 * restart may not preserve it.
 */
export function killConfirmation(result) {
  const unconfirmed = (why) => ({ kind: "unconfirmed", text: `kill NOT confirmed — ${why} — check the control plane directly` });
  if (typeof result !== "object" || result === null) return unconfirmed("no answer");
  if (result.ok !== true) {
    const why =
      typeof result.error === "string"
        ? result.error
        : typeof result.body === "object" && result.body !== null && typeof result.body.error === "string"
          ? result.body.error
          : "the console server did not report success";
    return unconfirmed(why);
  }
  const body = result.body;
  if (typeof body !== "object" || body === null) return unconfirmed("the answer carried no body");
  if (body.killed !== true) return unconfirmed("the answer did not say killed:true");
  if (typeof body.epoch !== "number" || !Number.isInteger(body.epoch) || body.epoch < 0) {
    return unconfirmed("the answer carried no usable epoch");
  }
  if (body.persistenceDegraded === true) {
    return {
      kind: "confirmed-degraded",
      text: `kill engaged (epoch ${body.epoch}) — but persistence is DEGRADED: a restart may not preserve it`,
    };
  }
  return { kind: "confirmed", text: `kill engaged — control plane confirmed (epoch ${body.epoch})` };
}

/**
 * The journal entries a kill-state transition earns. Pure over (prev, next)
 * classifications; prev === null (first reading) journals the initial state.
 */
export function killStateTransitionEvents(prev, next) {
  if (next === null) return [];
  if (prev !== null && prev.state === next.state) return [];
  const tone = next.state === "armed" ? "ok" : next.state === "killed" ? "stop" : "warn";
  const from = prev === null ? "console started" : `was ${prev.badge}`;
  return [{ kind: `kill-state:${next.state}`, text: `kill state ${next.badge} (${from}) — ${next.detail}`, tone }];
}
