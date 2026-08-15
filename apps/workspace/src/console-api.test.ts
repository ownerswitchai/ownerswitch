import { verifyDeviceSignature } from "@ownerswitchai/control-plane";
import { describe, expect, it } from "vitest";
import { createConsoleApi, sanitizeControlPlaneUrl } from "./console-api.js";

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

// the tests dial a stub, so any https origin is fine; http is reserved for
// literal loopback by sanitizeControlPlaneUrl and covered separately below
const CP = "https://cp.invalid";

describe("sanitizeControlPlaneUrl — the one URL parse (audit #6)", () => {
  it("accepts numeric-loopback http and any https, and returns the bare origin", () => {
    expect(sanitizeControlPlaneUrl("http://127.0.0.1:4181")).toBe("http://127.0.0.1:4181");
    expect(sanitizeControlPlaneUrl("http://[::1]:4181")).toBe("http://[::1]:4181");
    expect(sanitizeControlPlaneUrl("https://cp.example.com")).toBe("https://cp.example.com");
  });

  it("refuses plaintext http to anything that is not NUMERIC loopback — resolver names included", () => {
    for (const raw of [
      "http://cp.example.com",
      "http://192.168.1.20:4181",
      "http://localhost:4181", // a resolver name, not a literal
      "http://localhost.evil.example",
      "http://10.0.0.1",
    ]) {
      expect(() => sanitizeControlPlaneUrl(raw), raw).toThrow(/loopback/);
    }
    // not even a parseable IP literal — WHATWG refuses it before we can
    expect(() => sanitizeControlPlaneUrl("http://127.999.999.999:4181")).toThrow();
  });

  it("refuses userinfo, path, query and fragment — an origin, nothing more", () => {
    expect(() => sanitizeControlPlaneUrl("https://user:pw@cp.example.com")).toThrow(/userinfo/);
    expect(() => sanitizeControlPlaneUrl("https://cp.example.com/api")).toThrow(/path/);
    expect(() => sanitizeControlPlaneUrl("https://cp.example.com/?x=1")).toThrow(/query/);
    expect(() => sanitizeControlPlaneUrl("https://cp.example.com/#f")).toThrow(/query|fragment/);
    expect(() => sanitizeControlPlaneUrl("ftp://cp.example.com")).toThrow(/http/);
    expect(() => sanitizeControlPlaneUrl("not a url")).toThrow(/absolute URL/);
  });
});

describe("console-api /status", () => {
  it("reads a live plane through the sanitized origin", async () => {
    const { captured, fetchImpl } = scripted(() =>
      json(200, { killed: false, epoch: 0, killedAgents: [] }),
    );
    const api = createConsoleApi({ controlPlaneUrl: `${CP}/`, fetchImpl });
    const reading = await api.status();
    expect(reading).toEqual({
      reachable: true,
      status: { killed: false, epoch: 0, killedAgents: [] },
    });
    expect(captured[0]?.url).toBe(`${CP}/status`);
    expect(captured[0]?.init.redirect).toBe("error");
    expect((captured[0]?.init.headers as Record<string, string>)["cache-control"]).toBe("no-store");
  });

  it("maps a timeout to unreachable — nothing waits forever", async () => {
    const api = createConsoleApi({ controlPlaneUrl: CP, fetchImpl: hanging, timeoutMs: 20 });
    const reading = await api.status();
    expect(reading).toEqual({ reachable: false, error: "control plane timed out" });
  });

  it("maps network errors, non-200s and non-JSON to unreachable — unparseable is a no", async () => {
    const down = createConsoleApi({
      controlPlaneUrl: CP,
      fetchImpl: (() => Promise.reject(new Error("ECONNREFUSED"))) as typeof fetch,
    });
    expect((await down.status()).reachable).toBe(false);

    const teapot = createConsoleApi({
      controlPlaneUrl: CP,
      fetchImpl: scripted(() => json(503, { error: "nope" })).fetchImpl,
    });
    expect(await teapot.status()).toEqual({
      reachable: false,
      error: "control plane answered HTTP 503",
    });

    const garbled = createConsoleApi({
      controlPlaneUrl: CP,
      fetchImpl: scripted(() => new Response("<html>proxy error</html>", { status: 200 })).fetchImpl,
    });
    expect((await garbled.status()).reachable).toBe(false);
  });

  it("a 200 that fails the status DTO is unreachable — {} or a wrong type never renders ARMED", async () => {
    for (const body of [
      {},
      { killed: "false", epoch: 0, killedAgents: [] },
      { killed: false, epoch: -1, killedAgents: [] },
      { killed: false, epoch: 0 }, // no killedAgents list
      { killed: false, epoch: 0, killedAgents: [42] },
    ]) {
      const api = createConsoleApi({
        controlPlaneUrl: CP,
        fetchImpl: scripted(() => json(200, body)).fetchImpl,
      });
      const reading = await api.status();
      expect(reading.reachable, JSON.stringify(body)).toBe(false);
    }
  });

  it("re-emits only allowlisted fields and replaces upstream free text", async () => {
    const api = createConsoleApi({
      controlPlaneUrl: CP,
      fetchImpl: scripted(() =>
        json(200, {
          killed: true,
          epoch: 3,
          killedAgents: ["agent-1"],
          reason: "owner pressed stop",
          at: AT,
          persistenceDegraded: true,
          unhealthy: "internal detail with a /path/the/browser/should/not/see",
          surprise: { nested: "never forwarded" },
        }),
      ).fetchImpl,
    });
    const reading = await api.status();
    expect(reading).toEqual({
      reachable: true,
      status: {
        killed: true,
        epoch: 3,
        killedAgents: ["agent-1"],
        reason: "owner pressed stop",
        at: AT,
        persistenceDegraded: true,
        unhealthy: "durable kill state is untrustworthy — owner intervention required",
      },
    });
    expect(JSON.stringify(reading)).not.toContain("surprise");
    expect(JSON.stringify(reading)).not.toContain("/path/the/browser");
  });

  it("refuses an oversized answer before parsing it", async () => {
    const huge = `"${"x".repeat(1024 * 1024 + 16)}"`;
    const api = createConsoleApi({
      controlPlaneUrl: CP,
      fetchImpl: scripted(() => new Response(huge, { status: 200 })).fetchImpl,
    });
    expect((await api.status()).reachable).toBe(false);
  });

  it("the byte cap is STREAMED — an unbounded body is cut off mid-stream, not buffered whole", async () => {
    // a would-be 1 GiB answer delivered in 64 KiB chunks; the reader must
    // stop within a chunk or two of the 1 MiB cap instead of draining it
    const chunk = new TextEncoder().encode("x".repeat(64 * 1024));
    let pulls = 0;
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        if (pulls > 16_384) controller.close();
        else controller.enqueue(chunk);
      },
    });
    const api = createConsoleApi({
      controlPlaneUrl: CP,
      fetchImpl: (() => Promise.resolve(new Response(endless, { status: 200 }))) as typeof fetch,
    });
    expect((await api.status()).reachable).toBe(false);
    expect(pulls).toBeLessThan(32); // ~17 chunks reach 1 MiB; 16384 would mean it drained
  });

  it("an out-of-Date-range timestamp never reaches the browser's renderer", async () => {
    const okBase = { killed: true, epoch: 1, killedAgents: [] };
    const tooFar = createConsoleApi({
      controlPlaneUrl: CP,
      fetchImpl: scripted(() => json(200, { ...okBase, at: 1e17 })).fetchImpl,
    });
    const reading = await tooFar.status();
    // `at` fails its bound and is omitted; the reading itself stays usable
    expect(reading).toEqual({ reachable: true, status: okBase });

    const unsafeEpoch = createConsoleApi({
      controlPlaneUrl: CP,
      fetchImpl: scripted(() => json(200, { ...okBase, epoch: 2 ** 53 })).fetchImpl,
    });
    expect((await unsafeEpoch.status()).reachable).toBe(false);
  });
});

describe("console-api /veto/pending — the device-HMAC lane", () => {
  it("is unconfigured without a device secret, and says which env is missing", async () => {
    const api = createConsoleApi({ controlPlaneUrl: CP });
    expect(await api.pending()).toEqual({
      kind: "unconfigured",
      missing: "OWNERSWITCH_DEVICE_SECRET",
    });
  });

  it("signs the read with headers the real verifier accepts", async () => {
    const { captured, fetchImpl } = scripted(() => json(200, { windows: [] }));
    const api = createConsoleApi({
      controlPlaneUrl: CP,
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
        { method: "GET", pathAndQuery: "/veto/pending" },
        { now: () => AT, seenNonces: new Map() },
      ),
    ).toBe(true);
  });

  it("shapes each window through the allowlist and passes a clean listing", async () => {
    const api = createConsoleApi({
      controlPlaneUrl: CP,
      deviceId: "c",
      deviceSecret: "stub-secret",
      fetchImpl: scripted(() =>
        json(200, {
          windows: [
            {
              id: "veto_1",
              status: "pending",
              agentId: "agent-1",
              tool: "write_file",
              deadline: AT + 60_000,
              delivered: false,
              extra: "dropped",
            },
          ],
        }),
      ).fetchImpl,
    });
    const reading = await api.pending();
    expect(reading).toEqual({
      kind: "ok",
      windows: [
        {
          id: "veto_1",
          status: "pending",
          agentId: "agent-1",
          tool: "write_file",
          deadline: AT + 60_000,
          delivered: false,
        },
      ],
    });
  });

  it("one malformed entry fails the WHOLE listing closed — hiding a window would hide a veto", async () => {
    for (const entry of [
      { id: "veto_1", status: "released", agentId: "a", tool: "t", deadline: 1, delivered: false },
      { id: "../x", status: "pending", agentId: "a", tool: "t", deadline: 1, delivered: false },
      { id: "veto_1", status: "pending", agentId: "a\u0000b", tool: "t", deadline: 1, delivered: false },
      { id: "veto_1", status: "pending", agentId: "a", tool: "t", deadline: "soon", delivered: false },
    ]) {
      const api = createConsoleApi({
        controlPlaneUrl: CP,
        deviceId: "c",
        deviceSecret: "stub-secret",
        fetchImpl: scripted(() => json(200, { windows: [entry] })).fetchImpl,
      });
      expect((await api.pending()).kind, JSON.stringify(entry)).toBe("unreachable");
    }
  });

  it("maps refusals to a LOCAL constant with the status — upstream error text never passes", async () => {
    const refused = createConsoleApi({
      controlPlaneUrl: CP,
      deviceId: "c",
      deviceSecret: "wrong-secret",
      fetchImpl: scripted(() => json(401, { error: "unauthorized: Bearer tok-canary-123" })).fetchImpl,
    });
    const reading = await refused.pending();
    expect(reading).toEqual({ kind: "refused", upstreamStatus: 401, error: "pending listing refused" });
    expect(JSON.stringify(reading)).not.toContain("tok-canary-123");

    const hollow = createConsoleApi({
      controlPlaneUrl: CP,
      deviceId: "c",
      deviceSecret: "stub-secret",
      fetchImpl: scripted(() => json(200, {})).fetchImpl,
    });
    expect((await hollow.pending()).kind).toBe("unreachable");
  });
});

describe("console-api /devices — the owner-session lane", () => {
  it("is unconfigured without a token", async () => {
    const api = createConsoleApi({ controlPlaneUrl: CP });
    expect(await api.devices()).toEqual({
      kind: "unconfigured",
      missing: "OWNERSWITCH_OWNER_TOKEN",
    });
  });

  it("sends the bearer, shapes entries, and maps refusals to local constants", async () => {
    const { captured, fetchImpl } = scripted(() =>
      json(200, {
        devices: [
          {
            deviceId: "dev_1",
            name: "Owner's phone",
            enrolledAt: AT,
            revokedAt: null,
            pushRegistered: false,
            secretMaterial: "never-forwarded",
          },
        ],
      }),
    );
    const api = createConsoleApi({ controlPlaneUrl: CP, ownerToken: "tok-0000001", fetchImpl });
    const reading = await api.devices();
    expect(reading).toEqual({
      kind: "ok",
      devices: [
        { deviceId: "dev_1", name: "Owner's phone", enrolledAt: AT, revokedAt: null, pushRegistered: false },
      ],
    });
    expect(JSON.stringify(reading)).not.toContain("never-forwarded");
    const headers = captured[0]?.init.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer tok-0000001");
    expect(captured[0]?.init.redirect).toBe("error");

    const expired = createConsoleApi({
      controlPlaneUrl: CP,
      ownerToken: "tok-0000002",
      fetchImpl: scripted(() => json(401, { error: "unauthorized" })).fetchImpl,
    });
    expect(await expired.devices()).toEqual({
      kind: "refused",
      upstreamStatus: 401,
      error: "device listing refused",
    });

    const malformed = createConsoleApi({
      controlPlaneUrl: CP,
      ownerToken: "tok-0000003",
      fetchImpl: scripted(() => json(200, { devices: [{ deviceId: "d", name: 42 }] })).fetchImpl,
    });
    expect((await malformed.devices()).kind).toBe("unreachable");
  });
});

describe("console-api credential canaries — no secret in ANY reading (audit #5)", () => {
  const DEVICE_CANARY = "device-secret-canary-8f1";
  const TOKEN_CANARY = "owner-token-canary-3c9";

  it("an Error.message carrying a credential never reaches a reading", async () => {
    const api = createConsoleApi({
      controlPlaneUrl: CP,
      deviceId: "c",
      deviceSecret: DEVICE_CANARY,
      ownerToken: TOKEN_CANARY,
      fetchImpl: (() =>
        Promise.reject(
          new Error(`invalid header value: "Bearer ${TOKEN_CANARY}" hmac=${DEVICE_CANARY}`),
        )) as typeof fetch,
    });
    for (const reading of [
      await api.status(),
      await api.pending(),
      await api.devices(),
      await api.windowStatus("veto_x"),
      await api.veto("veto_x"),
      await api.kill("drill"),
    ]) {
      const text = JSON.stringify(reading);
      expect(text).not.toContain(TOKEN_CANARY);
      expect(text).not.toContain(DEVICE_CANARY);
    }
  });

  it("a credential reflected inside an ALLOWLISTED 200 field poisons that reading — fail closed", async () => {
    // window.tool echoes the bearer: the listing must go unreachable
    const pendingReflect = createConsoleApi({
      controlPlaneUrl: CP,
      deviceId: "c",
      deviceSecret: DEVICE_CANARY,
      fetchImpl: scripted(() =>
        json(200, {
          windows: [
            { id: "veto_1", status: "pending", agentId: "a", tool: `run ${DEVICE_CANARY}`, deadline: 1, delivered: false },
          ],
        }),
      ).fetchImpl,
    });
    const pendingReading = await pendingReflect.pending();
    expect(pendingReading.kind).toBe("unreachable");
    expect(JSON.stringify(pendingReading)).not.toContain(DEVICE_CANARY);

    // a device name echoing the owner token: same fate
    const devicesReflect = createConsoleApi({
      controlPlaneUrl: CP,
      ownerToken: TOKEN_CANARY,
      fetchImpl: scripted(() =>
        json(200, {
          devices: [
            { deviceId: "d1", name: `phone ${TOKEN_CANARY}`, enrolledAt: 1, revokedAt: null, pushRegistered: false },
          ],
        }),
      ).fetchImpl,
    });
    const devicesReading = await devicesReflect.devices();
    expect(devicesReading.kind).toBe("unreachable");
    expect(JSON.stringify(devicesReading)).not.toContain(TOKEN_CANARY);

    // a kill reason echoing the token: the optional field is dropped
    const statusReflect = createConsoleApi({
      controlPlaneUrl: CP,
      ownerToken: TOKEN_CANARY,
      fetchImpl: scripted(() =>
        json(200, { killed: true, epoch: 1, killedAgents: [], reason: `stop ${TOKEN_CANARY}` }),
      ).fetchImpl,
    });
    const statusReading = await statusReflect.status();
    expect(JSON.stringify(statusReading)).not.toContain(TOKEN_CANARY);
  });

  it("an upstream that reflects the Authorization header never reaches a reading", async () => {
    const reflect = scripted((_url, init) =>
      json(401, { error: `you sent: ${JSON.stringify(init.headers)}` }),
    );
    const api = createConsoleApi({
      controlPlaneUrl: CP,
      deviceId: "c",
      deviceSecret: DEVICE_CANARY,
      ownerToken: TOKEN_CANARY,
      fetchImpl: reflect.fetchImpl,
    });
    for (const reading of [
      await api.status(),
      await api.pending(),
      await api.devices(),
      await api.veto("veto_x"),
      await api.kill("drill"),
    ]) {
      const text = JSON.stringify(reading);
      expect(text).not.toContain(TOKEN_CANARY);
      expect(text).not.toContain(DEVICE_CANARY);
    }
  });
});

describe("console-api actions", () => {
  it("a bad device id fails at CONSTRUCTION, not inside the first signed call", () => {
    expect(() =>
      createConsoleApi({ controlPlaneUrl: CP, deviceId: "has.dot", deviceSecret: "stub-secret" }),
    ).toThrow(/OWNERSWITCH_DEVICE_ID/);
  });

  it("a credential too short to taboo-screen is refused at construction — it must not exist at all", () => {
    expect(() => createConsoleApi({ controlPlaneUrl: CP, deviceId: "c", deviceSecret: "s" })).toThrow(
      /OWNERSWITCH_DEVICE_SECRET.*8/,
    );
    expect(() => createConsoleApi({ controlPlaneUrl: CP, ownerToken: "tok-1" })).toThrow(
      /OWNERSWITCH_OWNER_TOKEN.*8/,
    );
  });

  it("veto refuses to pretend without a device credential", async () => {
    const api = createConsoleApi({ controlPlaneUrl: CP });
    const result = await api.veto("veto_a");
    expect(result.ok).toBe(false);
    expect("unreachable" in result && result.unreachable).toBe(true);
  });

  it("veto POSTs an empty signed body and re-emits only the shaped status", async () => {
    const { captured, fetchImpl } = scripted(() => json(200, { status: "vetoed", detail: "dropped" }));
    const api = createConsoleApi({
      controlPlaneUrl: CP,
      deviceId: "workspace-console",
      deviceSecret: "fleet-secret",
      fetchImpl,
      now: () => AT,
    });
    const result = await api.veto("veto_8c21");
    expect(result).toEqual({ ok: true, upstreamStatus: 200, body: { status: "vetoed" } });
    expect(captured[0]?.url).toBe(`${CP}/veto/veto_8c21`);
    expect(captured[0]?.init.method).toBe("POST");
    expect(captured[0]?.init.body).toBe("");
    const headers = captured[0]?.init.headers as Record<string, string>;
    expect(headers["x-device-id"]).toBe("workspace-console");
  });

  it("a refused veto keeps ok:false with a LOCAL error — never success, never upstream text", async () => {
    const api = createConsoleApi({
      controlPlaneUrl: CP,
      deviceId: "c",
      deviceSecret: "stub-secret",
      fetchImpl: scripted(() => json(409, { error: "too late to veto — window w9 details" })).fetchImpl,
    });
    expect(await api.veto("veto_x")).toEqual({
      ok: false,
      upstreamStatus: 409,
      body: { error: "veto refused by the control plane" },
    });
  });

  it("kill signs the exact body when a credential exists, and still sends without one", async () => {
    const signed = scripted(() => json(200, { killed: true, epoch: 1 }));
    const api = createConsoleApi({
      controlPlaneUrl: CP,
      deviceId: "workspace-console",
      deviceSecret: "fleet-secret",
      fetchImpl: signed.fetchImpl,
      now: () => AT,
    });
    const result = await api.kill("workspace console e-stop");
    expect(result).toEqual({ ok: true, upstreamStatus: 200, body: { killed: true, epoch: 1 } });
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
        { method: "POST", pathAndQuery: "/kill" },
        { now: () => AT, seenNonces: new Map() },
      ),
    ).toBe(true);

    const unsigned = scripted(() => json(200, { killed: true, epoch: 1 }));
    const bare = createConsoleApi({ controlPlaneUrl: CP, fetchImpl: unsigned.fetchImpl });
    expect((await bare.kill("e-stop")).ok).toBe(true);
    const bareHeaders = unsigned.captured[0]?.init.headers as Record<string, string>;
    expect(bareHeaders["x-device-id"]).toBeUndefined();
  });

  it("a kill answer outside the DTO is re-emitted as null fields, never invented", async () => {
    const api = createConsoleApi({
      controlPlaneUrl: CP,
      fetchImpl: scripted(() => json(200, { unexpected: "shape" })).fetchImpl,
    });
    expect(await api.kill("drill")).toEqual({
      ok: true,
      upstreamStatus: 200,
      body: { killed: null, epoch: null },
    });
  });

  it("windowStatus reads the open status and answers null on any doubt", async () => {
    const api = createConsoleApi({
      controlPlaneUrl: CP,
      fetchImpl: scripted(() => json(200, { status: "vetoed" })).fetchImpl,
    });
    expect(await api.windowStatus("veto_a")).toEqual({ status: "vetoed" });

    const gone = createConsoleApi({
      controlPlaneUrl: CP,
      fetchImpl: scripted(() => json(404, { error: "no veto window" })).fetchImpl,
    });
    expect(await gone.windowStatus("veto_a")).toEqual({ status: null });

    const down = createConsoleApi({ controlPlaneUrl: CP, fetchImpl: hanging, timeoutMs: 20 });
    expect(await down.windowStatus("veto_a")).toEqual({ status: null });
  });

  it("lanes reports names-only configuration", () => {
    expect(createConsoleApi({ controlPlaneUrl: CP }).lanes()).toEqual({
      device: false,
      ownerSession: false,
    });
    expect(
      createConsoleApi({
        controlPlaneUrl: CP,
        deviceId: "c",
        deviceSecret: "stub-secret",
        ownerToken: "tok-lanes-1",
      }).lanes(),
    ).toEqual({ device: true, ownerSession: true });
  });
});
