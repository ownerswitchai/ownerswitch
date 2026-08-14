import { verifyDeviceSignature } from "@ownerswitchai/control-plane";
import { describe, expect, it } from "vitest";
import { createConsoleApi } from "./console-api.js";

interface Captured {
  url: string;
  init: RequestInit;
}

/** A fetch stub that records every exchange and answers from a script. */
function scripted(answer: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const captured: Captured[] = [];
  const fetchImpl = ((url: string | URL, init?: RequestInit) => {
    captured.push({ url: String(url), init: init ?? {} });
    return Promise.resolve(answer(String(url), init ?? {}));
  }) as typeof fetch;
  return { captured, fetchImpl };
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** A fetch that never answers and honours the abort signal — the timeout path. */
const hanging = ((_url: string | URL, init?: RequestInit) =>
  new Promise<Response>((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () =>
      reject(new DOMException("aborted", "AbortError")),
    );
  })) as typeof fetch;

const AT = 1_755_000_000_000;

describe("console-api /status", () => {
  it("reads a live plane and strips trailing slashes from the base url", async () => {
    const { captured, fetchImpl } = scripted(() =>
      json(200, { killed: false, epoch: 0, killedAgents: [] }),
    );
    const api = createConsoleApi({ controlPlaneUrl: "http://cp.invalid///", fetchImpl });
    const reading = await api.status();
    expect(reading).toEqual({
      reachable: true,
      status: { killed: false, epoch: 0, killedAgents: [] },
    });
    expect(captured[0]?.url).toBe("http://cp.invalid/status");
    expect(captured[0]?.init.redirect).toBe("error");
    expect((captured[0]?.init.headers as Record<string, string>)["cache-control"]).toBe("no-store");
  });

  it("maps a timeout to unreachable — nothing waits forever", async () => {
    const api = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      fetchImpl: hanging,
      timeoutMs: 20,
    });
    const reading = await api.status();
    expect(reading).toEqual({ reachable: false, error: "control plane timed out" });
  });

  it("maps network errors, non-200s and non-JSON to unreachable — unparseable is a no", async () => {
    const down = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      fetchImpl: (() => Promise.reject(new Error("ECONNREFUSED"))) as typeof fetch,
    });
    expect((await down.status()).reachable).toBe(false);

    const teapot = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      fetchImpl: scripted(() => json(503, { error: "nope" })).fetchImpl,
    });
    expect(await teapot.status()).toEqual({
      reachable: false,
      error: "control plane answered HTTP 503",
    });

    const garbled = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      fetchImpl: scripted(() => new Response("<html>proxy error</html>", { status: 200 })).fetchImpl,
    });
    expect((await garbled.status()).reachable).toBe(false);
  });

  it("refuses an oversized answer before parsing it", async () => {
    const huge = `"${"x".repeat(1024 * 1024 + 16)}"`;
    const api = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      fetchImpl: scripted(() => new Response(huge, { status: 200 })).fetchImpl,
    });
    expect((await api.status()).reachable).toBe(false);
  });
});

describe("console-api /veto/pending — the device-HMAC lane", () => {
  it("is unconfigured without a device secret, and says which env is missing", async () => {
    const api = createConsoleApi({ controlPlaneUrl: "http://cp.invalid" });
    expect(await api.pending()).toEqual({
      kind: "unconfigured",
      missing: "OWNERSWITCH_DEVICE_SECRET",
    });
  });

  it("signs the read with headers the real verifier accepts", async () => {
    const { captured, fetchImpl } = scripted(() => json(200, { windows: [] }));
    const api = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      deviceId: "workspace-console",
      deviceSecret: "fleet-secret",
      fetchImpl,
      now: () => AT,
    });
    const reading = await api.pending();
    expect(reading).toEqual({ kind: "ok", windows: [] });
    const headers = captured[0]?.init.headers as Record<string, string>;
    expect(
      verifyDeviceSignature(
        {
          deviceId: headers["x-device-id"] as string,
          timestamp: Number(headers["x-device-timestamp"]),
          nonce: headers["x-device-nonce"] as string,
          signature: headers["x-device-signature"] as string,
        },
        "",
        "fleet-secret",
        { now: () => AT, seenNonces: new Map() },
      ),
    ).toBe(true);
  });

  it("maps upstream refusals with their status and error, and a missing windows array to unreachable", async () => {
    const refused = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      deviceId: "c",
      deviceSecret: "wrong",
      fetchImpl: scripted(() => json(401, { error: "unauthorized" })).fetchImpl,
    });
    expect(await refused.pending()).toEqual({
      kind: "refused",
      upstreamStatus: 401,
      error: "unauthorized",
    });

    const hollow = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      deviceId: "c",
      deviceSecret: "s",
      fetchImpl: scripted(() => json(200, {})).fetchImpl,
    });
    expect((await hollow.pending()).kind).toBe("unreachable");
  });
});

describe("console-api /devices — the owner-session lane", () => {
  it("is unconfigured without a token", async () => {
    const api = createConsoleApi({ controlPlaneUrl: "http://cp.invalid" });
    expect(await api.devices()).toEqual({
      kind: "unconfigured",
      missing: "OWNERSWITCH_OWNER_TOKEN",
    });
  });

  it("sends the bearer and maps ok / refused readings", async () => {
    const { captured, fetchImpl } = scripted(() => json(200, { devices: [] }));
    const api = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      ownerToken: "tok-1",
      fetchImpl,
    });
    expect(await api.devices()).toEqual({ kind: "ok", devices: [] });
    const headers = captured[0]?.init.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer tok-1");
    expect(captured[0]?.init.redirect).toBe("error");

    const expired = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      ownerToken: "tok-2",
      fetchImpl: scripted(() => json(401, { error: "unauthorized" })).fetchImpl,
    });
    expect(await expired.devices()).toEqual({
      kind: "refused",
      upstreamStatus: 401,
      error: "unauthorized",
    });
  });
});

describe("console-api actions", () => {
  it("veto refuses to pretend without a device credential", async () => {
    const api = createConsoleApi({ controlPlaneUrl: "http://cp.invalid" });
    const result = await api.veto("veto_a");
    expect(result.ok).toBe(false);
    expect("unreachable" in result && result.unreachable).toBe(true);
  });

  it("veto POSTs an empty signed body to the window path and passes the answer through", async () => {
    const { captured, fetchImpl } = scripted(() => json(200, { status: "vetoed" }));
    const api = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      deviceId: "workspace-console",
      deviceSecret: "fleet-secret",
      fetchImpl,
      now: () => AT,
    });
    const result = await api.veto("veto_8c21");
    expect(result).toEqual({ ok: true, upstreamStatus: 200, body: { status: "vetoed" } });
    expect(captured[0]?.url).toBe("http://cp.invalid/veto/veto_8c21");
    expect(captured[0]?.init.method).toBe("POST");
    expect(captured[0]?.init.body).toBe("");
    const headers = captured[0]?.init.headers as Record<string, string>;
    expect(headers["x-device-id"]).toBe("workspace-console");
  });

  it("a refused veto keeps ok:false and the upstream body — never success by accident", async () => {
    const api = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      deviceId: "c",
      deviceSecret: "s",
      fetchImpl: scripted(() => json(409, { error: "too late to veto" })).fetchImpl,
    });
    expect(await api.veto("veto_x")).toEqual({
      ok: false,
      upstreamStatus: 409,
      body: { error: "too late to veto" },
    });
  });

  it("kill signs the exact body when a credential exists, and still sends without one", async () => {
    const signed = scripted(() => json(200, { killed: true, epoch: 1 }));
    const api = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      deviceId: "workspace-console",
      deviceSecret: "fleet-secret",
      fetchImpl: signed.fetchImpl,
      now: () => AT,
    });
    const result = await api.kill("workspace console e-stop");
    expect(result.ok).toBe(true);
    const body = signed.captured[0]?.init.body as string;
    expect(JSON.parse(body)).toEqual({ source: "api", reason: "workspace console e-stop" });
    const headers = signed.captured[0]?.init.headers as Record<string, string>;
    expect(
      verifyDeviceSignature(
        {
          deviceId: headers["x-device-id"] as string,
          timestamp: Number(headers["x-device-timestamp"]),
          nonce: headers["x-device-nonce"] as string,
          signature: headers["x-device-signature"] as string,
        },
        body,
        "fleet-secret",
        { now: () => AT, seenNonces: new Map() },
      ),
    ).toBe(true);

    const unsigned = scripted(() => json(200, { killed: true, epoch: 1 }));
    const bare = createConsoleApi({ controlPlaneUrl: "http://cp.invalid", fetchImpl: unsigned.fetchImpl });
    expect((await bare.kill("e-stop")).ok).toBe(true);
    const bareHeaders = unsigned.captured[0]?.init.headers as Record<string, string>;
    expect(bareHeaders["x-device-id"]).toBeUndefined();
  });

  it("windowStatus reads the open status and answers null on any doubt", async () => {
    const api = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      fetchImpl: scripted(() => json(200, { status: "vetoed" })).fetchImpl,
    });
    expect(await api.windowStatus("veto_a")).toEqual({ status: "vetoed" });

    const gone = createConsoleApi({
      controlPlaneUrl: "http://cp.invalid",
      fetchImpl: scripted(() => json(404, { error: "no veto window" })).fetchImpl,
    });
    expect(await gone.windowStatus("veto_a")).toEqual({ status: null });

    const down = createConsoleApi({ controlPlaneUrl: "http://cp.invalid", fetchImpl: hanging, timeoutMs: 20 });
    expect(await down.windowStatus("veto_a")).toEqual({ status: null });
  });

  it("lanes reports names-only configuration", () => {
    expect(createConsoleApi({ controlPlaneUrl: "http://cp.invalid" }).lanes()).toEqual({
      device: false,
      ownerSession: false,
    });
    expect(
      createConsoleApi({
        controlPlaneUrl: "http://cp.invalid",
        deviceId: "c",
        deviceSecret: "s",
        ownerToken: "t",
      }).lanes(),
    ).toEqual({ device: true, ownerSession: true });
  });
});
