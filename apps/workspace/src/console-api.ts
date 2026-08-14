import { isIP } from "node:net";
import { deviceSignedHeaders } from "./device-sig.js";
import { validateDeviceId } from "./startup.js";

/**
 * The console server's upstream client: the ONLY code that talks to the
 * control plane, and the only place credentials exist. Every call carries a
 * bounded timeout (CONTRIBUTING.md: nothing waits forever on a remote call),
 * refuses redirects (a redirected control-plane response is never trusted —
 * the owner-runtime rule), and maps every failure — network, timeout,
 * non-JSON — into an explicit fail-closed reading instead of a thrown guess.
 *
 * DTO DOCTRINE (post-merge audit #5): nothing the upstream authored reaches
 * the browser unless it passed a per-field allowlist below. Error strings
 * are STABLE LOCAL CONSTANTS — never Error.message (a Node header validator
 * can echo the offending header value, bearer included), never an upstream
 * body's error text (an upstream can reflect the Authorization header). A
 * response that fails its shape is treated as unreachable/malformed, which
 * the console renders fail-closed.
 */

export interface UpstreamOptions {
  /** validated by sanitizeControlPlaneUrl; only its origin is ever used */
  controlPlaneUrl: string;
  /** fleet device-HMAC lane (veto/pending, veto, kill attribution) */
  deviceId?: string;
  deviceSecret?: string;
  /** owner session bearer (GET /devices) */
  ownerToken?: string;
  /** default 3000 ms */
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

export type StatusReading =
  | { reachable: true; status: unknown }
  | { reachable: false; error: string };

export type ListReading<Field extends string> =
  | { kind: "unconfigured"; missing: string }
  | { kind: "unreachable"; error: string }
  | { kind: "refused"; upstreamStatus: number; error: string }
  | ({ kind: "ok" } & Record<Field, unknown>);

export type ActionResult =
  | { ok: boolean; upstreamStatus: number; body: unknown }
  | { ok: false; unreachable: true; error: string };

export interface ConsoleApi {
  status(): Promise<StatusReading>;
  pending(): Promise<ListReading<"windows">>;
  devices(): Promise<ListReading<"devices">>;
  windowStatus(id: string): Promise<{ status: string | null }>;
  veto(id: string): Promise<ActionResult>;
  kill(reason: string): Promise<ActionResult>;
  /** which lanes this console can drive; names only, never values */
  lanes(): { device: boolean; ownerSession: boolean };
}

const DEFAULT_TIMEOUT_MS = 3000;

/** Reject upstream bodies over this size before parsing (a status read is tiny). */
const MAX_UPSTREAM_BODY_BYTES = 1024 * 1024;

const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

/**
 * Validate the control-plane URL ONCE, into the one shape the client will
 * ever dial (audit #6): no userinfo (a credential in a URL is a credential
 * in a log), no path/query/fragment (this is an origin, not an endpoint),
 * and plaintext http ONLY to a literal loopback host — the owner bearer and
 * the device MACs must not ride unencrypted to anything routable. The
 * returned origin is also the only form safe to print.
 */
export function sanitizeControlPlaneUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("control-plane URL is not a valid absolute URL");
  }
  if (url.username !== "" || url.password !== "") {
    throw new Error("control-plane URL must not carry userinfo");
  }
  if (url.search !== "" || url.hash !== "") {
    throw new Error("control-plane URL must not carry a query or fragment");
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new Error("control-plane URL must be an origin — no path");
  }
  // WHATWG keeps IPv6 hostnames bracketed ("[::1]") — unwrap before judging
  const host =
    url.hostname.startsWith("[") && url.hostname.endsWith("]")
      ? url.hostname.slice(1, -1)
      : url.hostname;
  // NUMERIC loopback only — "localhost" is a resolver name (hosts-file or
  // DNS decides what it means), and a bearer must never ride to whatever
  // that resolution happens to be today
  const loopback = host === "::1" || (isIP(host) === 4 && host.startsWith("127."));
  if (url.protocol === "http:") {
    if (!loopback) {
      throw new Error(
        "http control-plane URLs are allowed only to NUMERIC loopback (127.0.0.0/8 or [::1] — " +
          '"localhost" is a resolver name, use 127.0.0.1); use https anywhere else',
      );
    }
  } else if (url.protocol !== "https:") {
    throw new Error("control-plane URL must be http (loopback only) or https");
  }
  return url.origin;
}

function errorText(err: unknown): string {
  // stable local codes only — err.message is never forwarded (see header)
  if (err instanceof Error && err.name === "AbortError") return "control plane timed out";
  return "control plane request failed";
}

/**
 * a bounded, control-character-free string that carries NO configured
 * credential, or null. The taboo screen is the enforcement behind "the
 * secret never reaches the browser": an upstream that reflects the bearer
 * or the device secret inside an otherwise-allowlisted field (a device
 * name, a reason, a tool label) turns that reading malformed instead of
 * transiting the console.
 */
function safeString(value: unknown, maxChars: number, taboo: readonly string[]): string | null {
  if (typeof value !== "string" || value === "" || value.length > maxChars || CONTROL_CHARS.test(value)) {
    return null;
  }
  for (const secret of taboo) {
    if (value.includes(secret)) return null;
  }
  return value;
}

/** ms-since-epoch inside Date's actual range, as a safe integer, or null */
function safeEpochMs(value: unknown): number | null {
  return typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= 8_640_000_000_000_000
    ? value
    : null;
}

/**
 * The /status DTO. Required core (killed/epoch/killedAgents) mirrors the
 * gateway's own fail-closed reading; optional fields are re-emitted only in
 * allowlisted shapes, and the `unhealthy` free text is replaced by a local
 * constant with the same meaning.
 */
function shapeStatus(body: unknown, taboo: readonly string[]): Record<string, unknown> | null {
  if (typeof body !== "object" || body === null) return null;
  const b = body as Record<string, unknown>;
  if (b.killed !== true && b.killed !== false) return null;
  if (typeof b.epoch !== "number" || !Number.isSafeInteger(b.epoch) || b.epoch < 0) return null;
  if (!Array.isArray(b.killedAgents)) return null;
  const killedAgents: string[] = [];
  for (const entry of b.killedAgents) {
    const id = safeString(entry, 128, taboo);
    if (id === null) return null;
    killedAgents.push(id);
  }
  const reason = safeString(b.reason, 256, taboo);
  const at = safeEpochMs(b.at);
  return {
    killed: b.killed,
    epoch: b.epoch,
    killedAgents,
    ...(reason !== null ? { reason } : {}),
    ...(at !== null ? { at } : {}),
    ...(b.persistenceDegraded === true ? { persistenceDegraded: true } : {}),
    ...(b.unhealthy !== undefined
      ? { unhealthy: "durable kill state is untrustworthy — owner intervention required" }
      : {}),
  };
}

/** one /veto/pending entry, or null when any field fails its allowlist */
function shapeWindow(entry: unknown, taboo: readonly string[]): Record<string, unknown> | null {
  if (typeof entry !== "object" || entry === null) return null;
  const e = entry as Record<string, unknown>;
  const id = safeString(e.id, 128, taboo);
  if (id === null || !SAFE_ID.test(id)) return null;
  if (e.status !== "pending" && e.status !== "extended") return null;
  const agentId = safeString(e.agentId, 128, taboo);
  const tool = safeString(e.tool, 128, taboo);
  if (agentId === null || tool === null) return null;
  // a deadline outside Date's range would RangeError inside the browser's
  // renderer and freeze a stale panel — malformed here, fail closed there
  const deadline = safeEpochMs(e.deadline);
  if (deadline === null) return null;
  if (e.delivered !== true && e.delivered !== false) return null;
  return { id, status: e.status, agentId, tool, deadline, delivered: e.delivered };
}

/** one GET /devices entry (already-redacted upstream), re-allowlisted here */
function shapeDevice(entry: unknown, taboo: readonly string[]): Record<string, unknown> | null {
  if (typeof entry !== "object" || entry === null) return null;
  const e = entry as Record<string, unknown>;
  const deviceId = safeString(e.deviceId, 128, taboo);
  if (deviceId === null) return null;
  const name =
    e.name === ""
      ? ""
      : safeString(e.name, 128, taboo);
  if (name === null) return null;
  const enrolledAt = safeEpochMs(e.enrolledAt);
  if (enrolledAt === null) return null;
  const revokedAt = e.revokedAt === null ? null : safeEpochMs(e.revokedAt);
  if (e.revokedAt !== null && revokedAt === null) return null;
  if (e.pushRegistered !== true && e.pushRegistered !== false) return null;
  return {
    deviceId,
    name,
    enrolledAt,
    revokedAt,
    pushRegistered: e.pushRegistered,
  };
}

/**
 * Read a response INCREMENTALLY, aborting the moment the byte cap is
 * crossed — `res.text()` would buffer (and transparently decompress) the
 * whole thing first, which turns a gzip bomb into a heap exhaustion before
 * any length check runs.
 */
async function boundedText(res: Response, controller: AbortController): Promise<string> {
  const body = res.body;
  if (body === null) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_UPSTREAM_BODY_BYTES) {
      controller.abort();
      try {
        await reader.cancel();
      } catch {
        /* the abort already tore the stream down */
      }
      throw new Error("oversized control-plane response");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export function createConsoleApi(opts: UpstreamOptions): ConsoleApi {
  const base = sanitizeControlPlaneUrl(opts.controlPlaneUrl);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const now = opts.now ?? Date.now;
  // a bad device id must fail HERE, at the shared constructor boundary —
  // not inside the first signed call, where the signer's throw would read
  // as an outage and could block even the kill path (audit follow-up #4)
  if (opts.deviceId !== undefined && opts.deviceId !== "") validateDeviceId(opts.deviceId);
  const deviceConfigured =
    opts.deviceId !== undefined &&
    opts.deviceId !== "" &&
    opts.deviceSecret !== undefined &&
    opts.deviceSecret !== "";
  // the enforcement behind "no credential reaches the browser": any shaped
  // string CONTAINING a configured secret poisons its reading (see
  // safeString). Short values are skipped — a 1-char secret would taboo
  // half the alphabet, and real credentials are long.
  const taboo: string[] = [opts.deviceSecret, opts.ownerToken].filter(
    (s): s is string => typeof s === "string" && s.length >= 8,
  );

  /**
   * One upstream exchange → {upstreamStatus, body} or a thrown error the
   * callers map fail-closed. The body must parse as JSON: an unparseable
   * answer is a "no", never a shrug (CONTRIBUTING.md).
   */
  async function exchange(
    path: string,
    method: "GET" | "POST",
    rawBody: string | null,
    signed: boolean,
  ): Promise<{ upstreamStatus: number; body: unknown }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const headers: Record<string, string> = {
        "content-type": "application/json",
        "cache-control": "no-store",
      };
      if (signed && deviceConfigured) {
        Object.assign(
          headers,
          deviceSignedHeaders(opts.deviceId as string, opts.deviceSecret as string, rawBody ?? "", now()),
        );
      }
      const res = await fetchImpl(base + path, {
        method,
        headers,
        redirect: "error",
        signal: controller.signal,
        ...(method === "POST" ? { body: rawBody ?? "" } : {}),
      });
      const text = await boundedText(res, controller);
      return { upstreamStatus: res.status, body: JSON.parse(text === "" ? "{}" : text) };
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    lanes() {
      return {
        device: deviceConfigured,
        ownerSession: opts.ownerToken !== undefined && opts.ownerToken !== "",
      };
    },

    async status(): Promise<StatusReading> {
      try {
        const { upstreamStatus, body } = await exchange("/status", "GET", null, false);
        if (upstreamStatus !== 200) {
          return { reachable: false, error: `control plane answered HTTP ${upstreamStatus}` };
        }
        const shaped = shapeStatus(body, taboo);
        if (shaped === null) {
          return { reachable: false, error: "control plane answered a malformed status" };
        }
        return { reachable: true, status: shaped };
      } catch (err) {
        return { reachable: false, error: errorText(err) };
      }
    },

    async pending(): Promise<ListReading<"windows">> {
      if (!deviceConfigured) {
        return { kind: "unconfigured", missing: "OWNERSWITCH_DEVICE_SECRET" };
      }
      try {
        const { upstreamStatus, body } = await exchange("/veto/pending", "GET", null, true);
        if (upstreamStatus !== 200) {
          return { kind: "refused", upstreamStatus, error: "pending listing refused" };
        }
        const windows = (body as { windows?: unknown }).windows;
        if (!Array.isArray(windows)) {
          return { kind: "unreachable", error: "pending listing carried no windows array" };
        }
        const shaped: Array<Record<string, unknown>> = [];
        for (const entry of windows) {
          const window = shapeWindow(entry, taboo);
          // one malformed entry poisons the whole reading — hiding just that
          // entry would silently hide a window the owner might need to veto
          if (window === null) return { kind: "unreachable", error: "pending listing malformed" };
          shaped.push(window);
        }
        return { kind: "ok", windows: shaped };
      } catch (err) {
        return { kind: "unreachable", error: errorText(err) };
      }
    },

    async devices(): Promise<ListReading<"devices">> {
      if (opts.ownerToken === undefined || opts.ownerToken === "") {
        return { kind: "unconfigured", missing: "OWNERSWITCH_OWNER_TOKEN" };
      }
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetchImpl(`${base}/devices`, {
          method: "GET",
          headers: {
            "cache-control": "no-store",
            authorization: `Bearer ${opts.ownerToken}`,
          },
          redirect: "error",
          signal: controller.signal,
        });
        const text = await boundedText(res, controller);
        const body: unknown = JSON.parse(text === "" ? "{}" : text);
        if (res.status !== 200) {
          return { kind: "refused", upstreamStatus: res.status, error: "device listing refused" };
        }
        const devices = (body as { devices?: unknown }).devices;
        if (!Array.isArray(devices)) {
          return { kind: "unreachable", error: "device listing carried no devices array" };
        }
        const shaped: Array<Record<string, unknown>> = [];
        for (const entry of devices) {
          const device = shapeDevice(entry, taboo);
          if (device === null) return { kind: "unreachable", error: "device listing malformed" };
          shaped.push(device);
        }
        return { kind: "ok", devices: shaped };
      } catch (err) {
        return { kind: "unreachable", error: errorText(err) };
      } finally {
        clearTimeout(timer);
      }
    },

    async windowStatus(id: string): Promise<{ status: string | null }> {
      try {
        // the OPEN status read — anyone holding an id learns how the
        // question ended, nothing about its clock; that is exactly the
        // journal's need when a window leaves the pending list
        const { upstreamStatus, body } = await exchange(`/veto/${encodeURIComponent(id)}`, "GET", null, false);
        if (upstreamStatus !== 200) return { status: null };
        return { status: safeString((body as { status?: unknown }).status, 32, taboo) };
      } catch {
        return { status: null };
      }
    },

    async veto(id: string): Promise<ActionResult> {
      if (!deviceConfigured) {
        return { ok: false, unreachable: true, error: "no device credential configured (OWNERSWITCH_DEVICE_SECRET)" };
      }
      try {
        // empty body → the device-veto lane; deny-only, idempotent server-side
        const { upstreamStatus, body } = await exchange(`/veto/${encodeURIComponent(id)}`, "POST", "", true);
        const ok = upstreamStatus === 200;
        return {
          ok,
          upstreamStatus,
          body: ok
            ? { status: safeString((body as { status?: unknown }).status, 32, taboo) }
            : { error: "veto refused by the control plane" },
        };
      } catch (err) {
        return { ok: false, unreachable: true, error: errorText(err) };
      }
    },

    async kill(reason: string): Promise<ActionResult> {
      // The STOP direction must never be blocked by missing config: with a
      // device credential the kill is signed and attributed; without one it
      // is sent anyway and the control plane decides (its loopback lane
      // exists for exactly this). Cheap to stop is the doctrine.
      const body = JSON.stringify({ source: "api", reason });
      try {
        const { upstreamStatus, body: answer } = await exchange("/kill", "POST", body, true);
        const ok = upstreamStatus === 200;
        const a = (typeof answer === "object" && answer !== null ? answer : {}) as Record<string, unknown>;
        return {
          ok,
          upstreamStatus,
          body: ok
            ? {
                killed: a.killed === true || a.killed === false ? a.killed : null,
                epoch:
                  typeof a.epoch === "number" && Number.isSafeInteger(a.epoch) && a.epoch >= 0
                    ? a.epoch
                    : null,
                ...(a.persistenceDegraded === true ? { persistenceDegraded: true } : {}),
              }
            : { error: "kill refused by the control plane" },
        };
      } catch (err) {
        return { ok: false, unreachable: true, error: errorText(err) };
      }
    },
  };
}
