import { readFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { join, resolve, sep } from "node:path";
import type { ConsoleApi } from "./console-api.js";

/**
 * The console server: serves the static console (strict CSP, no inline
 * anything) and an ALLOW-LISTED /api surface over the upstream client.
 * Everything else is 404 — this is not a general proxy, and no request the
 * browser makes can reach an upstream path this file does not name.
 *
 * The console's own callers are unauthenticated (README, honest limits):
 * every verb exposed here is deny-only (veto, kill) or a read an enrolled
 * surface could make. Approve/restore/merge do not exist on this surface.
 */

export interface ConsoleServerOptions {
  api: ConsoleApi;
  /** directory holding index.html and friends (flat, no subdirectories) */
  publicDir: string;
}

export interface ListeningConsole {
  server: Server;
  port: number;
  close(): Promise<void>;
}

/** Window ids the proxy will echo into an upstream path. */
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** Flat filenames only — the character class has no "/", so traversal cannot parse. */
const SAFE_FILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

const STATIC_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
};

const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
  "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const MAX_REQUEST_BODY_BYTES = 4 * 1024;
const MAX_KILL_REASON_CHARS = 256;

function baseHeaders(contentType: string): Record<string, string> {
  return {
    "content-type": contentType,
    // a cached killed:false is a replayable lie — same stance as GET /status
    "cache-control": "no-store, max-age=0",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": CSP,
  };
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, baseHeaders("application/json; charset=utf-8"));
  res.end(JSON.stringify(body));
}

function readRawBody(req: IncomingMessage): Promise<string | null> {
  return new Promise((resolvePromise) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    const finish = (value: string | null) => {
      if (!done) {
        done = true;
        resolvePromise(value);
      }
    };
    req.on("data", (chunk: Buffer) => {
      if (done) return; // an oversized body streams on ignored — never buffered
      size += chunk.length;
      if (size > MAX_REQUEST_BODY_BYTES) {
        // refuse WITHOUT destroying the socket: the caller's 400 must still
        // reach the client (a killed connection reads as a network error,
        // not a refusal)
        finish(null);
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => finish(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => finish(null));
  });
}

export function createConsoleServer(opts: ConsoleServerOptions): {
  handler: (req: IncomingMessage, res: ServerResponse) => void;
  listen(port: number, bind: string): Promise<ListeningConsole>;
} {
  const publicRoot = resolve(opts.publicDir);

  async function serveStatic(req: IncomingMessage, res: ServerResponse, pathname: string): Promise<void> {
    if (req.method !== "GET" && req.method !== "HEAD") {
      sendJson(res, 405, { error: "method not allowed" });
      return;
    }
    const name = pathname === "/" ? "index.html" : pathname.slice(1);
    if (!SAFE_FILE.test(name)) {
      sendJson(res, 404, { error: "not found" });
      return;
    }
    const dot = name.lastIndexOf(".");
    const type = dot === -1 ? undefined : STATIC_TYPES[name.slice(dot)];
    if (type === undefined) {
      sendJson(res, 404, { error: "not found" });
      return;
    }
    const filePath = join(publicRoot, name);
    if (!filePath.startsWith(publicRoot + sep)) {
      // unreachable given SAFE_FILE — kept as the belt to that suspenders
      sendJson(res, 404, { error: "not found" });
      return;
    }
    try {
      const content = await readFile(filePath);
      res.writeHead(200, { ...baseHeaders(type), "content-length": String(content.length) });
      res.end(req.method === "HEAD" ? undefined : content);
    } catch {
      sendJson(res, 404, { error: "not found" });
    }
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", "http://console.invalid");
    const path = url.pathname;

    if (!path.startsWith("/api/")) {
      await serveStatic(req, res, path);
      return;
    }

    if (method === "GET" && path === "/api/status") {
      sendJson(res, 200, await opts.api.status());
      return;
    }
    if (method === "GET" && path === "/api/veto/pending") {
      sendJson(res, 200, await opts.api.pending());
      return;
    }
    if (method === "GET" && path === "/api/devices") {
      sendJson(res, 200, await opts.api.devices());
      return;
    }
    const windowMatch = /^\/api\/veto\/([^/]+)$/.exec(path);
    if (windowMatch !== null) {
      const id = windowMatch[1] as string;
      if (!SAFE_ID.test(id)) {
        sendJson(res, 400, { error: "window id must be 1-128 chars of [A-Za-z0-9_-]" });
        return;
      }
      if (method === "GET") {
        sendJson(res, 200, await opts.api.windowStatus(id));
        return;
      }
      if (method === "POST") {
        sendJson(res, 200, await opts.api.veto(id));
        return;
      }
      sendJson(res, 405, { error: "method not allowed" });
      return;
    }
    if (path === "/api/kill") {
      if (method !== "POST") {
        sendJson(res, 405, { error: "method not allowed" });
        return;
      }
      const raw = await readRawBody(req);
      if (raw === null) {
        sendJson(res, 400, { error: "request body unreadable or oversized" });
        return;
      }
      let reason = "workspace console e-stop";
      if (raw !== "") {
        let parsed: unknown;
        try {
          parsed = JSON.parse(raw);
        } catch {
          sendJson(res, 400, { error: "body must be JSON" });
          return;
        }
        const candidate = (parsed as { reason?: unknown }).reason;
        if (candidate !== undefined) {
          if (
            typeof candidate !== "string" ||
            candidate === "" ||
            candidate.length > MAX_KILL_REASON_CHARS ||
            /[\u0000-\u001f\u007f]/.test(candidate)
          ) {
            sendJson(res, 400, {
              error: `reason must be a non-empty single-line string of at most ${MAX_KILL_REASON_CHARS} chars`,
            });
            return;
          }
          reason = candidate;
        }
      }
      sendJson(res, 200, await opts.api.kill(reason));
      return;
    }
    sendJson(res, 404, { error: "not found" });
  }

  const handler = (req: IncomingMessage, res: ServerResponse): void => {
    void route(req, res).catch(() => {
      if (!res.headersSent) sendJson(res, 500, { error: "console server error" });
      else res.end();
    });
  };

  return {
    handler,
    listen(port: number, bind: string): Promise<ListeningConsole> {
      const server = createServer(handler);
      return new Promise((resolvePromise, reject) => {
        server.once("error", reject);
        server.listen(port, bind, () => {
          const addr = server.address();
          if (addr === null || typeof addr === "string") {
            reject(new Error("console server has no address"));
            return;
          }
          resolvePromise({
            server,
            port: addr.port,
            close: () =>
              new Promise<void>((resolveClose, rejectClose) => {
                server.close((err) => (err ? rejectClose(err) : resolveClose()));
              }),
          });
        });
      });
    },
  };
}
