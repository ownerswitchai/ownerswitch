import { deviceSignedHeaders } from "./device-sig.js";

/**
 * The console server's upstream client: the ONLY code that talks to the
 * control plane, and the only place credentials exist. Every call carries a
 * bounded timeout (CONTRIBUTING.md: nothing waits forever on a remote call),
 * refuses redirects (a redirected control-plane response is never trusted —
 * the owner-runtime rule), and maps every failure — network, timeout,
 * non-JSON — into an explicit fail-closed reading instead of a thrown guess.
 */

export interface UpstreamOptions {
  /** e.g. http://127.0.0.1:4181 — trailing slash stripped */
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

function errorText(err: unknown): string {
  if (err instanceof Error && err.name === "AbortError") return "control plane timed out";
  return err instanceof Error ? err.message : "control plane request failed";
}

export function createConsoleApi(opts: UpstreamOptions): ConsoleApi {
  const base = opts.controlPlaneUrl.replace(/\/+$/, "");
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const now = opts.now ?? Date.now;
  const deviceConfigured =
    opts.deviceId !== undefined &&
    opts.deviceId !== "" &&
    opts.deviceSecret !== undefined &&
    opts.deviceSecret !== "";

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
      const text = await res.text();
      if (text.length > MAX_UPSTREAM_BODY_BYTES) throw new Error("oversized control-plane response");
      return { upstreamStatus: res.status, body: JSON.parse(text === "" ? "{}" : text) };
    } finally {
      clearTimeout(timer);
    }
  }

  function refusalError(body: unknown, fallback: string): string {
    return typeof body === "object" && body !== null && typeof (body as { error?: unknown }).error === "string"
      ? ((body as { error: string }).error)
      : fallback;
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
        return { reachable: true, status: body };
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
          return {
            kind: "refused",
            upstreamStatus,
            error: refusalError(body, "pending listing refused"),
          };
        }
        const windows = (body as { windows?: unknown }).windows;
        if (!Array.isArray(windows)) {
          return { kind: "unreachable", error: "pending listing carried no windows array" };
        }
        return { kind: "ok", windows };
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
        const text = await res.text();
        if (text.length > MAX_UPSTREAM_BODY_BYTES) throw new Error("oversized control-plane response");
        const body: unknown = JSON.parse(text === "" ? "{}" : text);
        if (res.status !== 200) {
          return {
            kind: "refused",
            upstreamStatus: res.status,
            error: refusalError(body, "device listing refused"),
          };
        }
        const devices = (body as { devices?: unknown }).devices;
        if (!Array.isArray(devices)) {
          return { kind: "unreachable", error: "device listing carried no devices array" };
        }
        return { kind: "ok", devices };
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
        const status = (body as { status?: unknown }).status;
        return { status: typeof status === "string" ? status : null };
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
        return { ok: upstreamStatus === 200, upstreamStatus, body };
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
        return { ok: upstreamStatus === 200, upstreamStatus, body: answer };
      } catch (err) {
        return { ok: false, unreachable: true, error: errorText(err) };
      }
    },
  };
}
