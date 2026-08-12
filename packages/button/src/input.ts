import { createReadStream } from "node:fs";
import { createServer, type Server } from "node:http";

/**
 * Press sources — where physical presses come from.
 *
 * Three V0 sources behind one interface:
 *  - "keyboard": stdin in raw mode. Any USB kill button that enumerates as a
 *    keyboard (most cheap ones do) works with zero drivers.
 *  - "http": a tiny loopback POST /press endpoint, for testing the daemon
 *    without hardware.
 *  - "serial": a line-based USB serial device — an e-stop wired to a
 *    microcontroller that prints a trigger line ("KILL") on press.
 *
 * The daemon only ever sees `OnPress` — a registration function — so tests
 * and new sources (GPIO, BLE) plug in without touching the daemon.
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

/**
 * What the serial source needs from an opened device — a seam for tests.
 * `fs.ReadStream` satisfies it; so does a fake EventEmitter.
 */
export interface SerialPortStream {
  on(event: "data", handler: (chunk: Buffer | string) => void): unknown;
  once(event: "close", handler: () => void): unknown;
  once(event: "error", handler: (err: Error) => void): unknown;
  /** Release the device (closes the underlying descriptor). */
  destroy(): void;
}

/** Cancels a pending reconnect. */
type CancelReconnect = () => void;

export interface SerialSourceOptions {
  /** Device path, e.g. /dev/ttyACM0 (Linux) or /dev/cu.usbmodem1101 (macOS). */
  device: string;
  /**
   * The line that counts as a press, matched after trimming. Default "KILL" —
   * what the reference Pico e-stop firmware prints on the press edge. "READY"
   * and every other line are ignored.
   */
  trigger?: string;
  /**
   * The line that reports a hardware self-check failure — the dual-channel
   * firmware's NC/NO cross-check disagreeing (issue #40). Default "FAULT".
   * A fault is NEVER a press: it flows to `onFault` only, so a wiring
   * defect is reported to the owner instead of forging (or masking) a
   * kill. The firmware re-asserts it while the condition persists; the
   * reporter dedupes episodes.
   */
  faultLine?: string;
  /** Called once per received fault line (see `faultLine`). */
  onFault?: () => void;
  /**
   * Opens the device. Default: `fs.createReadStream`. The Pico's USB CDC data
   * channel is a character device you read like a file — USB CDC ignores baud,
   * so the firmware's lines arrive without termios. A seam for tests.
   */
  open?: (device: string) => SerialPortStream;
  /**
   * Re-open this many ms after the device errors or closes — a flaky USB cable
   * or a physical reconnect. Default 2000; 0 disables reconnect (open once,
   * then give up).
   */
  reconnectMs?: number;
  /** Schedules a reconnect and returns its canceller. Seam for tests; default setTimeout, unref'd. */
  schedule?: (fn: () => void, ms: number) => CancelReconnect;
  /**
   * Reports a device error / disconnect. Default: warn to stderr. A lost device
   * is reported, NOT treated as a press: a silent unplug must not forge a kill,
   * and a flaky cable must not kill on every hiccup. The firmware's own
   * fail-safe still prints a real "KILL" line while it has power.
   */
  onError?: (err: Error) => void;
}

/** The reference firmware prints this on the e-stop's press edge. */
export const DEFAULT_SERIAL_TRIGGER = "KILL";

/** The dual-channel firmware prints this while its NC/NO cross-check disagrees. */
export const DEFAULT_SERIAL_FAULT_LINE = "FAULT";

/**
 * Cap the unterminated-line buffer so a wedged device can't grow it without
 * bound. Counted in UTF-16 code units after decoding, not incoming bytes —
 * memory stays bounded either way (within a small constant factor).
 */
const SERIAL_BUFFER_CAP = 4096;

function defaultSerialOpen(device: string): SerialPortStream {
  return createReadStream(device);
}

function defaultSerialSchedule(fn: () => void, ms: number): CancelReconnect {
  const timer = setTimeout(fn, ms);
  // A reconnect timer must not, by itself, keep the process alive.
  (timer as { unref?: () => void }).unref?.();
  return () => clearTimeout(timer);
}

/**
 * A press source backed by a line-based USB serial device: the button is an
 * e-stop wired to a microcontroller that prints `trigger` (default "KILL") over
 * USB when pressed. Lines are buffered across chunks, so a trigger split across
 * two reads still counts as exactly one press. Survives a flaky cable by
 * re-opening the device (see `reconnectMs`).
 */
export function createSerialSource(opts: SerialSourceOptions): PressSource {
  const { device } = opts;
  // Trim to match the per-line trim below; refuse a trigger that could never
  // match (multiline) or would match a BLANK line (empty) — an empty trigger
  // would turn every keepalive newline into a press.
  const trigger = (opts.trigger ?? DEFAULT_SERIAL_TRIGGER).trim();
  if (trigger === "" || /[\r\n]/.test(trigger)) {
    throw new Error("serial trigger must be a non-empty single line");
  }
  const faultLine = (opts.faultLine ?? DEFAULT_SERIAL_FAULT_LINE).trim();
  if (faultLine === "" || /[\r\n]/.test(faultLine)) {
    throw new Error("serial fault line must be a non-empty single line");
  }
  // one line, one meaning: a config where a press and a fault are the same
  // bytes would let a wiring defect read as a kill (or vice versa)
  if (faultLine === trigger) {
    throw new Error(`serial fault line and trigger must differ (both "${trigger}")`);
  }
  const reconnectMs = opts.reconnectMs ?? 2_000;
  const openDevice = opts.open ?? defaultSerialOpen;
  const schedule = opts.schedule ?? defaultSerialSchedule;
  const onError =
    opts.onError ??
    ((err: Error) => console.error(`ownerswitch-button: serial ${device}: ${err.message}`));
  const listeners = listenerSet();

  let stream: SerialPortStream | null = null;
  let cancelReconnect: CancelReconnect | null = null;
  let running = false;
  let buffer = "";

  const feed = (chunk: Buffer | string): void => {
    buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    let nl: number;
    while ((nl = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (line === trigger) listeners.emit();
      else if (line === faultLine) opts.onFault?.();
    }
    // A device that never sends a newline must not grow the buffer forever.
    if (buffer.length > SERIAL_BUFFER_CAP) buffer = buffer.slice(-SERIAL_BUFFER_CAP);
  };

  const scheduleReconnect = (): void => {
    if (!running || reconnectMs <= 0) return;
    cancelReconnect?.();
    cancelReconnect = schedule(() => {
      cancelReconnect = null;
      connect();
    }, reconnectMs);
  };

  function connect(): void {
    if (!running) return;
    let opened: SerialPortStream;
    try {
      opened = openDevice(device);
    } catch (err) {
      onError(err instanceof Error ? err : new Error(String(err)));
      scheduleReconnect();
      return;
    }
    stream = opened;
    buffer = "";
    // Ignore late data from a stream we've since replaced or stopped.
    opened.on("data", (chunk) => {
      if (stream === opened) feed(chunk);
    });
    const gone = (err?: Error): void => {
      if (stream !== opened) return;
      stream = null;
      if (err !== undefined) onError(err);
      scheduleReconnect();
    };
    opened.once("error", (err) => gone(err));
    opened.once("close", () => gone());
  }

  return {
    onPress: (listener) => listeners.add(listener),
    describe: () => `serial — ${device} (trigger "${trigger}")`,
    async start() {
      if (running) return;
      running = true;
      connect();
    },
    async stop() {
      running = false;
      cancelReconnect?.();
      cancelReconnect = null;
      const open = stream;
      stream = null;
      buffer = "";
      open?.destroy();
    },
  };
}
