import { createServer, type Server } from "node:http";

/**
 * Press sources — where physical presses come from.
 *
 * Two V0 sources behind one interface:
 *  - "keyboard": stdin in raw mode. Any USB kill button that enumerates as a
 *    keyboard (most cheap ones do) works with zero drivers.
 *  - "http": a tiny loopback POST /press endpoint, for testing the daemon
 *    without hardware.
 *
 * The daemon only ever sees `OnPress` — a registration function — so tests
 * and future sources (GPIO, BLE) plug in without touching the daemon.
 */

/** A single press listener. */
export type PressListener = () => void;

/** Detaches a listener registered via OnPress. */
export type Unsubscribe = () => void;

/**
 * The one seam between a source and the daemon: "call me on every press".
 * `createButtonDaemon` takes this as its `onPress` option.
 */
export type OnPress = (listener: PressListener) => Unsubscribe;

export interface PressSource {
  /** Register a listener; pass this as the daemon's `onPress`. */
  onPress: OnPress;
  /** Bring the input up (stdin raw mode / local HTTP listener). */
  start(): Promise<void>;
  /** Release it (restore stdin / close the server). */
  stop(): Promise<void>;
  /** One line for the CLI banner, e.g. `keyboard — key "space"`. */
  describe(): string;
}

function listenerSet() {
  const listeners = new Set<PressListener>();
  return {
    add(listener: PressListener): Unsubscribe {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    emit(): void {
      for (const listener of [...listeners]) listener();
    },
  };
}

/** What the keyboard source needs from stdin — a seam for tests. */
export interface KeyboardStdin {
  isTTY?: boolean;
  setRawMode?(mode: boolean): unknown;
  on(event: "data", handler: (chunk: Buffer | string) => void): unknown;
  off(event: "data", handler: (chunk: Buffer | string) => void): unknown;
  resume(): unknown;
  pause(): unknown;
}

export interface KeyboardSourceOptions {
  /** "space" (default), "enter", or any single character, e.g. "k". */
  key?: string;
  stdin?: KeyboardStdin;
  /** Raw mode swallows Ctrl+C; this restores it. Default: SIGINT to self. */
  onInterrupt?: () => void;
}

const NAMED_KEYS: Record<string, readonly string[]> = {
  space: [" "],
  enter: ["\r", "\n"],
};

const CTRL_C = "\u0003";

export function createKeyboardSource(opts: KeyboardSourceOptions = {}): PressSource {
  const stdin = opts.stdin ?? (process.stdin as KeyboardStdin);
  const keyName = opts.key ?? "space";
  const chars = NAMED_KEYS[keyName] ?? (keyName.length === 1 ? [keyName] : null);
  if (chars === null) {
    throw new Error(`unknown key "${keyName}" — use "space", "enter", or a single character`);
  }
  const onInterrupt = opts.onInterrupt ?? (() => process.kill(process.pid, "SIGINT"));
  const listeners = listenerSet();
  let dataHandler: ((chunk: Buffer | string) => void) | null = null;

  return {
    onPress: (listener) => listeners.add(listener),
    describe: () => `keyboard — key "${keyName}"`,
    async start() {
      if (dataHandler !== null) return;
      dataHandler = (chunk) => {
        const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
        for (const char of text) {
          if (char === CTRL_C) return onInterrupt();
          if (chars.includes(char)) listeners.emit();
        }
      };
      if (stdin.isTTY) stdin.setRawMode?.(true);
      stdin.on("data", dataHandler);
      stdin.resume();
    },
    async stop() {
      if (dataHandler === null) return;
      stdin.off("data", dataHandler);
      dataHandler = null;
      if (stdin.isTTY) stdin.setRawMode?.(false);
      stdin.pause();
    },
  };
}

export interface HttpSourceOptions {
  /** Default 5455 — "KILL" on a phone keypad. Pass 0 for an ephemeral port. */
  port?: number;
  /** Default 127.0.0.1 — the press endpoint is a local test aid, keep it local. */
  host?: string;
}

export interface HttpPressSource extends PressSource {
  /** The press URL, once start() has resolved. */
  url(): string;
}

export const DEFAULT_HTTP_PORT = 5455;

export function createHttpSource(opts: HttpSourceOptions = {}): HttpPressSource {
  const host = opts.host ?? "127.0.0.1";
  const listeners = listenerSet();
  let server: Server | null = null;
  let boundPort: number | null = null;

  const url = (): string => {
    if (boundPort === null) throw new Error("http press source not started");
    return `http://${host}:${boundPort}/press`;
  };

  return {
    onPress: (listener) => listeners.add(listener),
    describe: () => `http — POST ${url()}`,
    url,
    async start() {
      if (server !== null) return;
      const srv = createServer((req, res) => {
        const sendJson = (status: number, body: unknown): void => {
          res.writeHead(status, { "content-type": "application/json" });
          res.end(JSON.stringify(body));
        };
        const path = new URL(req.url ?? "/", "http://localhost").pathname;
        if (path !== "/press") return sendJson(404, { error: "not found" });
        if (req.method !== "POST") return sendJson(405, { error: "POST only" });
        req.resume(); // presses carry no payload; drain whatever was sent
        listeners.emit();
        sendJson(200, { pressed: true });
      });
      server = srv;
      await new Promise<void>((resolve, reject) => {
        srv.once("error", reject);
        srv.listen(opts.port ?? DEFAULT_HTTP_PORT, host, () => {
          const addr = srv.address();
          if (addr === null || typeof addr === "string") return reject(new Error("no address"));
          boundPort = addr.port;
          resolve();
        });
      });
    },
    async stop() {
      if (server === null) return;
      const srv = server;
      server = null;
      boundPort = null;
      await new Promise<void>((resolve) => srv.close(() => resolve()));
    },
  };
}
