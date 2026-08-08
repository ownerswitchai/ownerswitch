import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { ToolCall } from "@ownerswitchai/shared";
import {
  isLoopbackAddress,
  verifyDeviceSignature,
  verifyOwnerSession,
  type DeviceCredential,
  type OwnerSession,
} from "./auth.js";
import { KillSwitch, type KillSource } from "./kill.js";
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
 *  - POST /restore/ceremony     — owner session required; starts 2GO (GO 1/2)
 *                     while the system is killed. The ceremony binds to the
 *                     owner, the kill epoch in force, and its start time.
 *  - GET  /restore/ceremony/:id — owner session required; the ceremony's
 *                     state and how long until its cooldown ends.
 *  - POST /restore  — owner session required plus a live server-side ceremony
 *                     (GO 2/2): owned by this owner, past its cooldown, inside
 *                     its TTL, bound to the current kill epoch, consumed
 *                     atomically. No exceptions, no loopback bypass, no
 *                     shape-only path.
 *  - POST /veto     — device signature required; a gateway registers a window
 *                     for a call it is holding. Registration puts text in
 *                     front of the owner and grows server state, so unlike
 *                     /kill there is no loopback fallback: a gateway that
 *                     cannot register must fail its call closed, not get an
 *                     open door here.
 *  - POST /veto/:id — owner session required; the session names the vetoer.
 *  - GET  /status   — open; the gateway polls it and it leaks only kill state.
 */
export interface ControlPlaneOptions {
  now?: () => number;
  /** Shared secret the physical button / kill triggers sign requests with. */
  deviceSecret?: string;
}

export interface ControlPlane {
  /** Plug into http.createServer(handler). */
  handler: (req: IncomingMessage, res: ServerResponse) => void;
  killSwitch: KillSwitch;
  /** Live veto windows by id; the gateway registers, the API vetoes/reads. */
  vetoWindows: Map<string, VetoWindow>;
}

const KILL_SOURCES: readonly KillSource[] = ["button", "honeytoken", "app", "voice", "api"];

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
  const killSwitch = new KillSwitch(now);
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

  function getStatus(res: ServerResponse): void {
    if (!killSwitch.killed) {
      sendJson(res, 200, { killed: false });
      return;
    }
    const lastKill = [...killSwitch.auditLog()].reverse().find((e) => e.type === "kill");
    sendJson(res, 200, {
      killed: true,
      reason: lastKill?.event.reason,
      at: lastKill?.event.at,
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
    sendJson(res, 200, { killed: true });
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
    // Dead ceremonies (past their TTL, whatever their state) are unspendable;
    // sweep here to keep the map bounded in a long-lived process.
    for (const [staleId, record] of ceremonies) {
      if (now() >= record.ceremony.expiresAt) ceremonies.delete(staleId);
    }
    const id = `cer_${randomBytes(6).toString("hex")}`;
    const ceremony = new RestoreCeremony(id, session.ownerId, { now });
    ceremonies.set(id, { ceremony, epoch: killSwitch.epoch });
    sendJson(res, 201, {
      id,
      state: ceremony.tick(),
      cooldownRemainingMs: ceremony.cooldownRemainingMs(),
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
    sendJson(res, 200, { state, cooldownRemainingMs: record.ceremony.cooldownRemainingMs() });
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
    // Every rejection is the same generic 409: which check failed (wrong
    // owner, wrong epoch, timing, replay) is not information a caller
    // holding a stolen session gets to enumerate.
    const rejected = () => sendJson(res, 409, { error: "restore rejected" });
    if (record === undefined) return rejected();
    if (record.ceremony.ownerId !== session.ownerId) return rejected();
    if (record.epoch !== killSwitch.epoch) return rejected();
    if (!killSwitch.killed) return rejected();
    try {
      // confirm() is the atomic consume: it only succeeds in "ready" (past
      // the cooldown, inside the TTL) and transitions to "completed" before
      // returning, so a concurrent second spend of the same ceremony throws.
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
