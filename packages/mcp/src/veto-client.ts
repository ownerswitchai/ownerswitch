import { randomBytes } from "node:crypto";
import {
  signDeviceRequest,
  type VetoPurpose,
  type VetoWireStatus,
} from "@ownerswitchai/control-plane";
import type { ToolCall } from "@ownerswitchai/shared";

/**
 * Client for the control plane's veto-window surface:
 *
 *   POST /veto      — register a window for a call the gateway is holding
 *                     (device-signed: registration puts text in front of the
 *                     owner, so it must be attributable)
 *   GET  /veto/:id  — read the window's current status (open endpoint)
 *
 * Fail-closed by construction, same stance as the gateway's /status client:
 * any doubt — network error, timeout, non-2xx, unparseable body — surfaces as
 * a VetoClientError, and the proxy turns that into a refused call. The one
 * non-error outcome besides success is a 404 on status(), reported as
 * "missing" so the caller can drop its stale record and re-register (the
 * control plane keeps windows in memory; a restart forgets them).
 */
export interface DeviceIdentity {
  /** provisioned device id; must not contain "." (HMAC payload delimiter) */
  id: string;
  /** shared secret matching the control plane's deviceSecret */
  secret: string;
}

export interface VetoClientOptions {
  baseUrl: string;
  device: DeviceIdentity;
  /** abort each control-plane call after this many ms; default 1500 */
  timeoutMs?: number;
  /** injectable for tests */
  fetchImpl?: typeof fetch;
  now?: () => number;
}

export interface VetoStatusResult {
  /**
   * The window's wire status; "spent" is a would-be release from a dead kill
   * epoch (the control plane's rule, see control-plane/src/veto.ts), and
   * "missing" is a 404 — drop the stale record and re-register.
   */
  status: VetoWireStatus | "missing";
  /**
   * On a "released" status, the control plane's single-use signed MergeGrant
   * for this exact call (present only when the control plane has a grant key
   * configured — the executing-broker deployment). Relayed verbatim to the
   * broker, which verifies it independently; the gateway cannot forge one.
   */
  grant?: unknown;
}

export interface VetoClient {
  /**
   * `purpose` is the canonical (connector, operation, policyVersion) the
   * gateway resolved for an executor-routed call — the control plane
   * records it on the window, signs it into any grant, and mints grants
   * ONLY for purposes it knows to be grant-eligible. Omit it for plain
   * forwarded tools; such windows release but never carry signed authority.
   */
  register(call: ToolCall, purpose?: VetoPurpose): Promise<{ id: string }>;
  status(id: string): Promise<VetoStatusResult>;
}

/** Carries the fail-closed detail for the refusal message. Never a secret. */
export class VetoClientError extends Error {
  constructor(
    message: string,
    readonly httpStatus?: number,
  ) {
    super(message);
    this.name = "VetoClientError";
  }
}

const UNREACHABLE = "control plane unreachable — fail closed";

const VETO_STATUSES: readonly VetoWireStatus[] = [
  "pending",
  "vetoed",
  "released",
  "extended",
  "held",
  "spent",
];

export function createVetoClient(options: VetoClientOptions): VetoClient {
  const { baseUrl, device, timeoutMs = 1500, fetchImpl = fetch, now = Date.now } = options;

  async function request(input: URL, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetchImpl(input, { ...init, signal: controller.signal });
    } catch {
      throw new VetoClientError(UNREACHABLE);
    } finally {
      clearTimeout(timer);
    }
  }

  async function register(call: ToolCall, purpose?: VetoPurpose): Promise<{ id: string }> {
    const body = JSON.stringify({ call, ...(purpose !== undefined ? { purpose } : {}) });
    const timestamp = now();
    const nonce = randomBytes(12).toString("hex");
    const res = await request(new URL("/veto", baseUrl), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-device-id": device.id,
        "x-device-timestamp": String(timestamp),
        "x-device-nonce": nonce,
        "x-device-signature": signDeviceRequest(
          { deviceId: device.id, timestamp, nonce },
          body,
          device.secret,
          { method: "POST", pathAndQuery: "/veto" },
        ),
      },
      body,
    });
    if (res.status === 401) {
      throw new VetoClientError(
        "control plane rejected this gateway's device credentials — " +
          "check device.id and device.secret in the OwnerSwitch config",
        401,
      );
    }
    if (!res.ok) {
      throw new VetoClientError(`control plane refused veto registration (HTTP ${res.status})`, res.status);
    }
    const parsed: unknown = await res.json().catch(() => null);
    const id = (parsed as { id?: unknown } | null)?.id;
    if (typeof id !== "string" || id === "") throw new VetoClientError(UNREACHABLE);
    return { id };
  }

  async function status(id: string): Promise<VetoStatusResult> {
    // cache: "no-store" plus explicit request headers: a cached "released"
    // is exactly as dangerous as a cached killed:false — it would resurrect
    // a spent release. The control plane also serves /veto/:id with
    // Cache-Control: no-store (server.ts sendJson) — both ends refuse
    // caching, matching the gateway's /status client (client.ts).
    const res = await request(new URL(`/veto/${encodeURIComponent(id)}`, baseUrl), {
      method: "GET",
      cache: "no-store",
      headers: { "cache-control": "no-store, no-cache", pragma: "no-cache" },
    });
    if (res.status === 404) return { status: "missing" };
    if (!res.ok) {
      throw new VetoClientError(`control plane refused veto status lookup (HTTP ${res.status})`, res.status);
    }
    const parsed: unknown = await res.json().catch(() => null);
    const status = (parsed as { status?: unknown } | null)?.status;
    if (!VETO_STATUSES.includes(status as VetoWireStatus)) throw new VetoClientError(UNREACHABLE);
    const grant = (parsed as { grant?: unknown } | null)?.grant;
    return { status: status as VetoWireStatus, ...(grant !== undefined ? { grant } : {}) };
  }

  return { register, status };
}
