import { randomBytes, randomUUID } from "node:crypto";
import { statSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import type { ToolCall } from "@ownerswitchai/shared";
import {
  isLoopbackAddress,
  verifyDeviceSignature,
  verifyOwnerSession,
  type DeviceCredential,
  type OwnerSession,
} from "./auth.js";
import { KillStateFileStore } from "./kill-state.js";
import { KILL_SOURCES, KillSwitch, type KillSource } from "./kill.js";
import { RestoreCeremony } from "./twogo.js";
import { VetoWindow } from "./veto.js";

/**
 * HTTP layer of the control plane. One process, one KillSwitch, one map of
 * live veto windows — the gateway, the owner app and the physical button all
 * talk to the same state through this handler.
 *
 * Deliberately framework-free: Node's http module only, so the surface stays
 * small enough to audit in one sitting.
 *
 * Auth keeps the asymmetry of the switch itself:
 *  - POST /kill     — a device signature or owner session attributes the kill;
 *                     with neither, loopback callers may still kill (recorded
 *                     as an unauthenticated "api" kill). Stopping must never
 *                     fail because auth was misconfigured.
 *  - POST /alert    — a flagged event that does NOT change kill state (a
 *                     honeytoken FILE was touched). Same auth shape as /kill;
 *                     recorded in the audit log, never a lockdown.
 *  - POST /restore/ceremony     — owner session required; starts 2GO (GO 1/2)
 *                     while the system is killed. The ceremony binds to the
 *                     owner, the kill epoch in force, and its start time. An
 *                     owner holds at most ONE live ceremony per kill epoch,
 *                     and GO 1/2 is IDEMPOTENT: while one is pending, a
 *                     repeat call returns that same ceremony (200) with its
 *                     clocks untouched — a retry or second tab cannot
 *                     invalidate the id the owner holds, and a stolen
 *                     same-owner session cannot reset the cooldown.
 *                     There is deliberately NO cancel verb: a pending
 *                     ceremony ends only by TTL expiry, consumption, or a
 *                     new kill epoch. A cancel would hand the same bearer
 *                     token a repeatable way to destroy the owner's pending
 *                     ceremony — the exact lockout idempotency closes.
 *  - GET  /restore/ceremony/:id — owner session required; the ceremony's
 *                     state, cooldown remaining, and expiry.
 *  - POST /restore  — owner session required plus a live server-side ceremony
 *                     (GO 2/2): owned by this owner, past its cooldown, inside
 *                     its TTL, bound to the current kill epoch, consumed
 *                     atomically (single-spend holds for this one process and
 *                     event loop — where all ceremony state lives). No
 *                     exceptions, no loopback bypass, no shape-only path.
 *  - POST /veto     — device signature required; a gateway registers a window
 *                     for a call it is holding. Registration puts text in
 *                     front of the owner and grows server state, so unlike
 *                     /kill there is no loopback fallback: a gateway that
 *                     cannot register must fail its call closed, not get an
 *                     open door here.
 *  - POST /veto/:id — owner session required; the session names the vetoer.
 *  - GET  /status   — open; the gateway polls it. Body carries `killed` and
 *                     the kill `epoch` (a monotone count of every kill this
 *                     deployment has ever had) — the deliberate, documented
 *                     widening of what this open route leaks; see getStatus()
 *                     below and packages/mcp/THREAT-MODEL.md.
 */
export interface ControlPlaneOptions {
  now?: () => number;
  /** Shared secret the physical button / kill triggers sign requests with. */
  deviceSecret?: string;
  /**
   * Where the kill switch persists killed state, its reason and the kill
   * epoch across process restarts.
   *
   * In production (the default), this is REQUIRED and checked at boot: it
   * must be an explicit absolute path outside the working directory, in a
   * directory owned by the process user with no group/world write access.
   * Anything else refuses to start — whoever can write this directory holds
   * an administrative capability over kill state.
   *
   * With dev: true, it defaults to DEFAULT_KILL_STATE_FILE in the working
   * directory, and null runs a deliberately ephemeral control plane (unit
   * tests, throwaway demos): a restart then forgets the kill, so only opt
   * out where that is the point.
   */
  killStateFile?: string | null;
  /**
   * Development mode: skips the kill-state path safety checks (with a loud
   * one-line warning) and enables the conveniences above. Never set this for
   * a control plane that real agents depend on.
   */
  dev?: boolean;
}

/** Default kill-state location IN DEV MODE, resolved against the working directory. */
export const DEFAULT_KILL_STATE_FILE = "ownerswitch-kill-state.json";

/**
 * Production boot guard for the kill-state path. Every refusal says exactly
 * what is wrong and what the operator must do — a control plane that starts
 * with a tamperable state file is worse than one that refuses to start.
 */
function guardKillStatePath(file: string | null | undefined): string {
  const refuse = (what: string, fix: string): never => {
    const msg = `[ownerswitch] refusing to start: ${what}. ${fix} (Pass dev: true only for a development instance.)`;
    console.error(msg);
    throw new Error(msg);
  };
  if (file === undefined) {
    return refuse(
      "no killStateFile configured",
      "Set killStateFile to an explicit absolute path in a protected directory, e.g. /var/lib/ownerswitch/kill-state.json.",
    );
  }
  if (file === null) {
    return refuse(
      "killStateFile: null (ephemeral) is a development convenience",
      "An ephemeral control plane forgets kills on restart. Set an absolute killStateFile.",
    );
  }
  if (!isAbsolute(file)) {
    return refuse(
      `killStateFile "${file}" is a relative path`,
      "Set an explicit absolute path — a relative path silently points at a different store whenever the working directory changes.",
    );
  }
  const resolved = resolve(file);
  const rel = relative(process.cwd(), resolved);
  if (rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))) {
    return refuse(
      `killStateFile "${resolved}" resolves inside the working directory ${process.cwd()}`,
      "The working directory is not a protected location. Put the state file in a dedicated directory such as /var/lib/ownerswitch/.",
    );
  }
  const dir = dirname(resolved);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  let stats;
  try {
    stats = statSync(dir);
  } catch (err) {
    return refuse(
      `the kill-state directory ${dir} cannot be inspected (${err instanceof Error ? err.message : String(err)})`,
      `Create it first, owned by uid ${uid ?? "<process uid>"} with mode 0700: mkdir -p ${dir} && chmod 700 ${dir}.`,
    );
  }
  if (!stats.isDirectory()) {
    return refuse(`${dir} is not a directory`, "Point killStateFile at a file inside a real, protected directory.");
  }
  if ((stats.mode & 0o022) !== 0) {
    return refuse(
      `the kill-state directory ${dir} is group- or world-writable (mode ${(stats.mode & 0o777).toString(8)})`,
      `Anyone who can write this directory can tamper with kill state. Run: chmod 700 ${dir}.`,
    );
  }
  // POSIX-only check: without getuid (Windows) ownership cannot be compared.
  if (uid !== undefined && stats.uid !== uid) {
    return refuse(
      `the kill-state directory ${dir} is owned by uid ${stats.uid}, but the control plane runs as uid ${uid}`,
      `The directory must belong to the user that runs the control plane. Run: chown ${uid} ${dir}.`,
    );
  }
  return resolved;
}

export interface ControlPlane {
  /** Plug into http.createServer(handler). */
  handler: (req: IncomingMessage, res: ServerResponse) => void;
  killSwitch: KillSwitch;
  /** Live veto windows by id; the gateway registers, the API vetoes/reads. */
  vetoWindows: Map<string, VetoWindow>;
}

/**
 * Hard ceiling on ceremony RECORDS held in memory — a memory backstop, not a
 * rate limit and never the primary bound. Before it is consulted, every dead
 * record (TTL-expired, consumed, superseded kill epoch) is purged and each
 * owner is limited to one live ceremony per kill epoch, so the map's size is
 * the number of DISTINCT owners with a pending ceremony: normal use is 1–2.
 * The ceiling only stops a flood of hostile owner sessions from growing the
 * map without bound, which is why it sits far above any legitimate count.
 */
export const MAX_CEREMONY_RECORDS = 256;

/** Thrown when the request body is not valid JSON — maps to 400. */
class BadJsonError extends Error {}

async function readRawBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function parseJsonBody(raw: string): Record<string, unknown> {
  const trimmed = raw.trim();
  if (trimmed === "") return {}; // empty body is fine — stopping must never fail on a technicality
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new BadJsonError("body must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof BadJsonError) throw err;
    throw new BadJsonError("malformed JSON body");
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

/** 401s stay generic: an unauthenticated caller learns nothing about the domain. */
function sendUnauthorized(res: ServerResponse): void {
  sendJson(res, 401, { error: "unauthorized" });
}

function headerValue(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

/** All four x-device-* headers, or null when the request doesn't attempt device auth. */
function deviceCredentialFrom(req: IncomingMessage): DeviceCredential | null {
  const deviceId = headerValue(req, "x-device-id");
  const timestamp = headerValue(req, "x-device-timestamp");
  const nonce = headerValue(req, "x-device-nonce");
  const signature = headerValue(req, "x-device-signature");
  if (!deviceId || !timestamp || !nonce || !signature) return null;
  return { deviceId, timestamp: Number(timestamp), nonce, signature };
}

function bearerToken(req: IncomingMessage): string | null {
  // the auth-scheme is case-insensitive (RFC 9110 §11.1); the token is not
  const match = /^Bearer (.+)$/i.exec(headerValue(req, "authorization") ?? "");
  return match ? match[1] : null;
}

export function createControlPlane(opts: ControlPlaneOptions = {}): ControlPlane {
  const now = opts.now ?? Date.now;
  // Persisted kill state loads synchronously inside the KillSwitch
  // constructor — before this function returns a handler, so before any
  // request can be answered. A process restart resumes the kill state it
  // went down with (`kill -9` is not a restore), and a state file that
  // exists but cannot be read boots the plane killed. In production the
  // path is guarded first: a state file an attacker can write is not
  // persistence, so a bad location refuses to start.
  let killStateFile: string | undefined;
  if (opts.dev === true) {
    console.error(
      "[ownerswitch] DEV MODE: kill-state path safety checks are disabled — never point production agents at this control plane.",
    );
    killStateFile =
      opts.killStateFile === null
        ? undefined
        : (opts.killStateFile ?? resolve(process.cwd(), DEFAULT_KILL_STATE_FILE));
  } else {
    killStateFile = guardKillStatePath(opts.killStateFile);
  }
  const killSwitch = new KillSwitch(
    now,
    killStateFile === undefined ? {} : { store: new KillStateFileStore(killStateFile) },
  );
  const vetoWindows = new Map<string, VetoWindow>();
  const seenNonces = new Map<string, number>();
  // Live restore ceremonies, keyed by id. Deliberately process-local: losing
  // this map (a restart) can only make restores harder, never easier — an id
  // that is not in here restores nothing, whatever its body claims.
  const ceremonies = new Map<string, { ceremony: RestoreCeremony; epoch: number }>();

  function ownerSessionFrom(req: IncomingMessage): OwnerSession | null {
    const token = bearerToken(req);
    return token === null ? null : verifyOwnerSession(token, { now });
  }

  function hasValidDeviceSignature(req: IncomingMessage, rawBody: string): boolean {
    if (opts.deviceSecret === undefined) return false;
    const credential = deviceCredentialFrom(req);
    if (credential === null) return false;
    return verifyDeviceSignature(credential, rawBody, opts.deviceSecret, { now, seenNonces });
  }

  // Degraded durability is worth a field only when true: the in-memory state
  // in this response is in force either way, but a restart may not preserve
  // it. Absence of the fields means persistence is healthy (or deliberately
  // ephemeral). `unhealthy` is the harder condition: a failed persist whose
  // stale on-disk state could ALSO not be quarantined — a restart may boot
  // from that stale state, so the plane is not fit for service until an
  // owner repairs the store.
  const degradedFields = () => ({
    ...(killSwitch.persistenceDegraded ? { persistenceDegraded: true as const } : {}),
    ...(killSwitch.quarantineFailed
      ? {
          unhealthy:
            "stale kill state could not be quarantined — durable state is untrustworthy; owner intervention required",
        }
      : {}),
  });

  /**
   * `epoch` is included unconditionally, killed or not: a client needs the
   * CURRENT epoch to tell a stale approval from a fresh one, and that
   * question matters most exactly when killed is false (kill-then-restore
   * flips killed back to false; epoch is what keeps a pre-kill approval
   * dead). Disclosure note (also in packages/mcp/THREAT-MODEL.md): this
   * route is deliberately unauthenticated, so exposing epoch lets ANY
   * caller learn a monotone count of how many times this deployment has
   * ever been killed — not when, not why, not by whom (those still require
   * an owner session). That is a real, if small, widening of what an open
   * endpoint discloses. It is worth it because `killed` alone cannot do
   * this job: a client holding an approval (e.g. an executor's
   * ActionTicket, packages/executor/DESIGN.md §3) must be able to detect
   * that its approval predates a kill even after the system has since been
   * restored, and only a value that never resets can do that.
   */
  function getStatus(res: ServerResponse): void {
    if (!killSwitch.killed) {
      sendJson(res, 200, { killed: false, epoch: killSwitch.epoch, ...degradedFields() });
      return;
    }
    // lastKill is tracked directly — this route is polled by every gateway
    // and must not scan an ever-growing audit log.
    const lastKill = killSwitch.lastKill;
    sendJson(res, 200, {
      killed: true,
      reason: lastKill?.reason,
      at: lastKill?.at,
      epoch: killSwitch.epoch,
      ...degradedFields(),
    });
  }

  async function postKill(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // The raw body is read before parsing because the device HMAC covers the
    // exact bytes on the wire.
    const raw = await readRawBody(req);
    const authenticated = hasValidDeviceSignature(req, raw) || ownerSessionFrom(req) !== null;

    if (!authenticated && !isLoopbackAddress(req.socket.remoteAddress)) {
      sendUnauthorized(res);
      return;
    }

    const body = parseJsonBody(raw);
    const claimed = KILL_SOURCES.includes(body.source as KillSource)
      ? (body.source as KillSource)
      : "api";
    // An unverified source claim is not trusted: unauthenticated loopback
    // kills are recorded as plain "api" kills, flagged in the audit trail.
    const source = authenticated ? claimed : "api";
    const reason = typeof body.reason === "string" ? body.reason : undefined;
    killSwitch.engage(source, reason, { unauthenticated: !authenticated });
    // The kill is in force in memory no matter what; the response only claims
    // durability when the persist actually succeeded.
    sendJson(res, 200, { killed: true, ...degradedFields() });
  }

  async function postAlert(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Same auth shape as /kill — an alert is attributed the same way — but it
    // only records a flagged event; it never engages the switch, so it can
    // never be a one-touch denial of service.
    const raw = await readRawBody(req);
    const authenticated = hasValidDeviceSignature(req, raw) || ownerSessionFrom(req) !== null;

    if (!authenticated && !isLoopbackAddress(req.socket.remoteAddress)) {
      sendUnauthorized(res);
      return;
    }

    const body = parseJsonBody(raw);
    const claimed = KILL_SOURCES.includes(body.source as KillSource)
      ? (body.source as KillSource)
      : "api";
    const source = authenticated ? claimed : "api";
    const reason = typeof body.reason === "string" ? body.reason : undefined;
    killSwitch.alert(source, reason, { unauthenticated: !authenticated });
    sendJson(res, 200, { alerted: true, killed: killSwitch.killed });
  }

  async function postCeremonyStart(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // GO 1/2. Owner session required — no exceptions, no loopback bypass.
    const session = ownerSessionFrom(req);
    if (session === null) {
      sendUnauthorized(res);
      return;
    }
    parseJsonBody(await readRawBody(req)); // drain and validate; nothing else is trusted from the body
    if (!killSwitch.killed) {
      sendJson(res, 409, { error: "not killed — nothing to restore" });
      return;
    }
    // Dead records first, BEFORE any capacity decision: a ceremony that is
    // past its TTL, already consumed, or bound to a superseded kill epoch is
    // unspendable by every path in this file, so it must never hold a slot
    // against the one ceremony that matters. (An earlier version purged only
    // TTL expiry, which let corpses block new ceremonies for minutes — a
    // lockout of restore, the exact operation this system exists to protect.)
    for (const [staleId, record] of ceremonies) {
      const dead =
        now() >= record.ceremony.expiresAt ||
        record.ceremony.state === "completed" ||
        record.epoch !== killSwitch.epoch;
      if (dead) ceremonies.delete(staleId);
    }
    // One live ceremony per owner per kill epoch, and GO 1/2 is IDEMPOTENT:
    // while this owner already has a live ceremony (post-purge, so it is
    // current-epoch, unconsumed and unexpired), return THAT ceremony with
    // its clocks untouched. A double-click, a browser retry or a second tab
    // must not invalidate the id the owner is holding — and a stolen
    // same-owner session must not be able to reset the cooldown forever by
    // hammering this route. There is deliberately no way to abandon a
    // pending ceremony early: it ends by TTL expiry, consumption, or a new
    // kill epoch — any owner-session cancel verb would reopen the same
    // stolen-session lockout this idempotency closes.
    for (const [existingId, record] of ceremonies) {
      if (record.ceremony.ownerId === session.ownerId) {
        sendJson(res, 200, {
          id: existingId,
          state: record.ceremony.tick(),
          cooldownRemainingMs: record.ceremony.cooldownRemainingMs(),
          expiresAt: record.ceremony.expiresAt,
        });
        return;
      }
    }
    // Secondary backstop only — with the purge and the one-per-owner rule
    // above, size counts distinct owners, so reaching this ceiling means a
    // flood of hostile sessions, not normal use. Full fails closed: new
    // ceremonies are refused (an owner with a pending one still gets it back
    // via the idempotent path above), a live ceremony is never evicted to
    // make room, and fullness can only ever deny a restore path, never open
    // one.
    if (ceremonies.size >= MAX_CEREMONY_RECORDS) {
      sendJson(res, 409, { error: "ceremony rejected" });
      return;
    }
    // Unguessable capability id: 122 bits from the CSPRNG. Holding one id
    // (or watching them mint) must not help anyone name another.
    const id = `cer_${randomUUID()}`;
    const ceremony = new RestoreCeremony(id, session.ownerId, { now });
    ceremonies.set(id, { ceremony, epoch: killSwitch.epoch });
    sendJson(res, 201, {
      id,
      state: ceremony.tick(),
      cooldownRemainingMs: ceremony.cooldownRemainingMs(),
      expiresAt: ceremony.expiresAt,
    });
  }

  function getCeremony(req: IncomingMessage, res: ServerResponse, id: string): void {
    const session = ownerSessionFrom(req);
    if (session === null) {
      sendUnauthorized(res);
      return;
    }
    const record = ceremonies.get(id);
    // Another owner's ceremony reads as absent — existence is not revealed.
    if (record === undefined || record.ceremony.ownerId !== session.ownerId) {
      sendJson(res, 404, { error: `no ceremony "${id}"` });
      return;
    }
    const ticked = record.ceremony.tick();
    // "completed" only ever happens via /restore, so it reads as consumed; a
    // ceremony from a superseded kill epoch is dead and reads as expired.
    const state =
      ticked === "completed"
        ? "consumed"
        : record.epoch !== killSwitch.epoch
          ? "expired"
          : ticked;
    sendJson(res, 200, {
      state,
      cooldownRemainingMs: record.ceremony.cooldownRemainingMs(),
      expiresAt: record.ceremony.expiresAt,
    });
  }

  async function postRestore(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // GO 2/2. Owner session required — no exceptions, no loopback bypass.
    // Restoring is the expensive direction and stays that way.
    const session = ownerSessionFrom(req);
    if (session === null) {
      sendUnauthorized(res);
      return;
    }
    const body = parseJsonBody(await readRawBody(req));
    const ceremonyId = typeof body.ceremonyId === "string" ? body.ceremonyId : "";
    const record = ceremonies.get(ceremonyId);
    // Every rejection is the same generic 409 — a uniform response SHAPE, so
    // the body never says which check failed (wrong owner, wrong epoch,
    // timing, replay). It is NOT a constant-time or side-channel-free
    // guarantee: evaluation order, timing and transport metadata still
    // differ between causes.
    const rejected = () => sendJson(res, 409, { error: "restore rejected" });
    // A failed quarantine means stale kill state may survive on disk and a
    // restart may boot from it. Until an owner repairs the store, the plane
    // must not become ready: restores stay denied, because flipping the
    // in-memory switch is the only working stop left.
    if (killSwitch.quarantineFailed) return rejected();
    if (record === undefined) return rejected();
    if (record.ceremony.ownerId !== session.ownerId) return rejected();
    if (record.epoch !== killSwitch.epoch) return rejected();
    if (!killSwitch.killed) return rejected();
    try {
      // confirm() is the atomic consume: it only succeeds in "ready" (past
      // the cooldown, inside the TTL) and transitions to "completed" before
      // returning, so a concurrent second spend throws. Single-spend holds
      // for one process and one event loop — where all ceremony state lives.
      killSwitch.restore(record.ceremony.confirm());
    } catch {
      return rejected();
    }
    sendJson(res, 200, { killed: false });
  }

  async function postVeto(req: IncomingMessage, res: ServerResponse, id: string): Promise<void> {
    // A veto is a stop, but it names an owner — so it stays authenticated,
    // and the session (not the body) says who vetoed.
    const session = ownerSessionFrom(req);
    if (session === null) {
      sendUnauthorized(res);
      return;
    }
    const window = vetoWindows.get(id);
    if (!window) {
      sendJson(res, 404, { error: `no veto window "${id}"` });
      return;
    }
    parseJsonBody(await readRawBody(req)); // drain and validate; `by` comes from the session
    try {
      window.veto(session.ownerId);
      sendJson(res, 200, { status: window.state });
    } catch (err) {
      sendJson(res, 409, { error: err instanceof Error ? err.message : String(err) });
    }
  }

  /** The registered call, or null when the body doesn't describe one. */
  function toolCallFrom(value: unknown): ToolCall | null {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const { agentId, tool, args } = value as Record<string, unknown>;
    if (typeof agentId !== "string" || agentId === "") return null;
    if (typeof tool !== "string" || tool === "") return null;
    if (args !== undefined && (typeof args !== "object" || args === null || Array.isArray(args))) {
      return null;
    }
    return { agentId, tool, args: args as Record<string, unknown> | undefined };
  }

  async function postRegisterVeto(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Strictly device-authenticated: whoever registers decides what the owner
    // gets asked about. Unauthenticated callers must not reach the owner.
    const raw = await readRawBody(req);
    if (!hasValidDeviceSignature(req, raw)) {
      sendUnauthorized(res);
      return;
    }
    const call = toolCallFrom(parseJsonBody(raw).call);
    if (call === null) {
      sendJson(res, 400, { error: "call must be an object with string agentId and tool" });
      return;
    }
    const id = `veto_${randomBytes(6).toString("hex")}`;
    const window = new VetoWindow(call, { now });
    vetoWindows.set(id, window);
    sendJson(res, 201, { id, status: window.state });
  }

  function getVeto(res: ServerResponse, id: string): void {
    const window = vetoWindows.get(id);
    if (!window) {
      sendJson(res, 404, { error: `no veto window "${id}"` });
      return;
    }
    sendJson(res, 200, { status: window.tick() });
  }

  function handler(req: IncomingMessage, res: ServerResponse): void {
    void route(req, res).catch((err) => {
      // never crash the process: a broken request gets an error response instead
      if (res.writableEnded) return;
      if (err instanceof BadJsonError) sendJson(res, 400, { error: err.message });
      else sendJson(res, 500, { error: "internal error" });
    });
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? "GET";
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const vetoMatch = /^\/veto\/([^/]+)$/.exec(path);
    const ceremonyMatch = /^\/restore\/ceremony\/([^/]+)$/.exec(path);

    if (method === "GET" && path === "/status") return getStatus(res);
    if (method === "POST" && path === "/kill") return postKill(req, res);
    if (method === "POST" && path === "/alert") return postAlert(req, res);
    if (method === "POST" && path === "/restore/ceremony") return postCeremonyStart(req, res);
    if (method === "GET" && ceremonyMatch) {
      return getCeremony(req, res, decodeURIComponent(ceremonyMatch[1]));
    }
    if (method === "POST" && path === "/restore") return postRestore(req, res);
    if (method === "POST" && path === "/veto") return postRegisterVeto(req, res);
    if (vetoMatch) {
      const id = decodeURIComponent(vetoMatch[1]);
      if (method === "POST") return postVeto(req, res, id);
      if (method === "GET") return getVeto(res, id);
    }
    sendJson(res, 404, { error: "not found" });
  }

  return { handler, killSwitch, vetoWindows };
}
