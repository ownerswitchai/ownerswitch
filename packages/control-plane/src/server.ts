import type { IncomingMessage, ServerResponse } from "node:http";
import { KillSwitch, type KillSource } from "./kill.js";
import type { VetoWindow } from "./veto.js";

/**
 * HTTP layer of the control plane. One process, one KillSwitch, one map of
 * live veto windows — the gateway, the owner app and the physical button all
 * talk to the same state through this handler.
 *
 * Deliberately framework-free: Node's http module only, so the surface stays
 * small enough to audit in one sitting.
 */
export interface ControlPlaneOptions {
  now?: () => number;
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

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (raw === "") return {}; // empty body is fine — stopping must never fail on a technicality
  try {
    const parsed: unknown = JSON.parse(raw);
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

export function createControlPlane(opts: ControlPlaneOptions = {}): ControlPlane {
  const now = opts.now ?? Date.now;
  const killSwitch = new KillSwitch(now);
  const vetoWindows = new Map<string, VetoWindow>();

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
    // TODO(auth): verify the button HMAC here before trusting source "button".
    const body = await readJsonBody(req);
    const source = KILL_SOURCES.includes(body.source as KillSource)
      ? (body.source as KillSource)
      : "api";
    const reason = typeof body.reason === "string" ? body.reason : undefined;
    killSwitch.engage(source, reason);
    sendJson(res, 200, { killed: true });
  }

  async function postRestore(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // TODO(auth): verify the owner passkey session and that the 2GO ceremony
    // actually completed — for now we trust the authorization's shape only.
    const body = await readJsonBody(req);
    try {
      killSwitch.restore({
        ceremonyId: String(body.ceremonyId ?? ""),
        ownerId: String(body.ownerId ?? ""),
        completedAt: Number(body.completedAt ?? 0),
      });
      sendJson(res, 200, { killed: false });
    } catch (err) {
      sendJson(res, 409, { error: err instanceof Error ? err.message : String(err) });
    }
  }

  async function postVeto(req: IncomingMessage, res: ServerResponse, id: string): Promise<void> {
    // TODO(auth): verify the owner passkey session before accepting a veto.
    const window = vetoWindows.get(id);
    if (!window) {
      sendJson(res, 404, { error: `no veto window "${id}"` });
      return;
    }
    const body = await readJsonBody(req);
    const by = typeof body.by === "string" ? body.by : "unknown";
    try {
      window.veto(by);
      sendJson(res, 200, { status: window.state });
    } catch (err) {
      sendJson(res, 409, { error: err instanceof Error ? err.message : String(err) });
    }
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

    if (method === "GET" && path === "/status") return getStatus(res);
    if (method === "POST" && path === "/kill") return postKill(req, res);
    if (method === "POST" && path === "/restore") return postRestore(req, res);
    if (vetoMatch) {
      const id = decodeURIComponent(vetoMatch[1]);
      if (method === "POST") return postVeto(req, res, id);
      if (method === "GET") return getVeto(res, id);
    }
    sendJson(res, 404, { error: "not found" });
  }

  return { handler, killSwitch, vetoWindows };
}
