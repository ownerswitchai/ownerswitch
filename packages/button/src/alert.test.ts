import { describe, expect, it, vi } from "vitest";
import { verifyDeviceSignature } from "@ownerswitchai/control-plane";
import { createFaultReporter } from "./alert.js";

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const reporter = (fetchImpl: typeof fetch, nowRef: { t: number }, extra = {}) =>
  createFaultReporter({
    controlPlaneUrl: "http://cp.local",
    deviceId: "btn-1",
    secret: "device-secret",
    now: () => nowRef.t,
    fetchImpl,
    log: () => {},
    ...extra,
  });

describe("createFaultReporter", () => {
  it("reports one device-signed POST /alert per episode, however often the firmware re-asserts", async () => {
    const nowRef = { t: 1_000_000 };
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const doFetch = vi.fn(async (url: URL | string, init?: RequestInit) => {
      calls.push({ url: String(url), init: init! });
      return new Response(JSON.stringify({ alerted: true }), { status: 200 });
    });
    const r = reporter(doFetch as unknown as typeof fetch, nowRef);

    // firmware re-asserts every 5 s; one episode, one alert
    for (let i = 0; i < 5; i++) {
      r.faultSignal();
      nowRef.t += 5_000;
    }
    await flush();
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("http://cp.local/alert");
    const body = calls[0].init.body as string;
    expect(JSON.parse(body)).toMatchObject({ source: "button" });
    expect(JSON.parse(body).reason).toMatch(/cross-check/);

    // the signature verifies exactly like the control plane would verify it
    const headers = calls[0].init.headers as Record<string, string>;
    expect(
      verifyDeviceSignature(
        {
          deviceId: headers["x-device-id"],
          timestamp: Number(headers["x-device-timestamp"]),
          nonce: headers["x-device-nonce"],
          signature: headers["x-device-signature"],
        },
        body,
        "device-secret",
        { now: () => Number(headers["x-device-timestamp"]), seenNonces: new Map() },
      ),
    ).toBe(true);

    // silence past the episode gap, then a fresh fault -> a NEW alert
    nowRef.t += 31_000;
    r.faultSignal();
    await flush();
    expect(calls).toHaveLength(2);
  });

  it("retries a bounded number of times, then hands durability back to the firmware's re-assert", async () => {
    vi.useFakeTimers();
    try {
      const nowRef = { t: 0 };
      const doFetch = vi.fn(async () => new Response("", { status: 503 }));
      const r = reporter(doFetch as unknown as typeof fetch, nowRef);
      r.faultSignal();
      await vi.runAllTimersAsync();
      expect(doFetch).toHaveBeenCalledTimes(4); // 1 try + 3 retries, then stop
    } finally {
      vi.useRealTimers();
    }
  });

  it("has no kill verb: every request goes to /alert, never /kill", async () => {
    const nowRef = { t: 0 };
    const urls: string[] = [];
    const doFetch = vi.fn(async (url: URL | string) => {
      urls.push(String(url));
      return new Response("{}", { status: 200 });
    });
    const r = reporter(doFetch as unknown as typeof fetch, nowRef);
    r.faultSignal();
    await flush();
    expect(urls.every((u) => u.endsWith("/alert"))).toBe(true);
  });
});
