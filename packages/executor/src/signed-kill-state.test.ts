import { createHmac } from "node:crypto";
import { canonicalJson } from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
import { signedLiveKillStateFromControlPlane } from "./signed-kill-state.js";

const KEY = "kill-state-key-shared-cp-and-broker";
const NOW = 1_800_000_000_000;

/** A control plane that signs correctly, with overridable fields for attacks. */
function signingControlPlane(
  overrides: {
    killed?: boolean;
    epoch?: number;
    key?: string;
    ttlMs?: number;
    tamperNonce?: boolean;
    status?: number;
  } = {},
): typeof fetch {
  return async (input) => {
    const url = new URL(String(input));
    const nonce = url.searchParams.get("nonce") ?? "";
    const payload = {
      killed: overrides.killed ?? false,
      epoch: overrides.epoch ?? 3,
      nonce: overrides.tamperNonce === true ? `${nonce}-x` : nonce,
      expiresAt: NOW + (overrides.ttlMs ?? 5_000),
    };
    const sig = createHmac("sha256", overrides.key ?? KEY)
      .update(canonicalJson(payload))
      .digest("hex");
    return new Response(JSON.stringify({ ...payload, sig }), {
      status: overrides.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  };
}

const reader = (fetchImpl: typeof fetch, now = () => NOW) =>
  signedLiveKillStateFromControlPlane({
    baseUrl: "http://127.0.0.1:8787",
    killStateKey: KEY,
    fetchImpl,
    now,
  });

describe("signedLiveKillStateFromControlPlane", () => {
  it("accepts a correctly signed, fresh, nonce-matched envelope", async () => {
    expect(await reader(signingControlPlane({ killed: false, epoch: 7 }))()).toEqual({
      killed: false,
      epoch: 7,
    });
    expect(await reader(signingControlPlane({ killed: true, epoch: 9 }))()).toEqual({
      killed: true,
      epoch: 9,
    });
  });

  it("fails CLOSED against an impostor with the wrong key (the port-squatting attack)", async () => {
    // a hostile process bound the port and answers killed:false — but it
    // cannot sign, so the broker reads KILLED regardless
    expect(await reader(signingControlPlane({ killed: false, key: "attacker-key" }))()).toEqual({
      killed: true,
      epoch: -1,
    });
  });

  it("fails CLOSED on a replayed envelope (nonce does not match this request)", async () => {
    expect(await reader(signingControlPlane({ killed: false, tamperNonce: true }))()).toEqual({
      killed: true,
      epoch: -1,
    });
  });

  it("fails CLOSED on a stale (expired) envelope even if correctly signed", async () => {
    // signed for NOW+5s, but read the answer 10s later
    const late = () => NOW + 10_000;
    expect(await reader(signingControlPlane({ killed: false }), late)()).toEqual({
      killed: true,
      epoch: -1,
    });
  });

  it("fails CLOSED on non-200, unreachable, and unparseable answers", async () => {
    expect(await reader(signingControlPlane({ status: 501 }))()).toEqual({ killed: true, epoch: -1 });
    const throwing: typeof fetch = async () => {
      throw new Error("connection refused");
    };
    expect(await reader(throwing)()).toEqual({ killed: true, epoch: -1 });
    const garbage: typeof fetch = async () => new Response("not json", { status: 200 });
    expect(await reader(garbage)()).toEqual({ killed: true, epoch: -1 });
  });

  it("fails CLOSED on a missing or malformed epoch — no epoch-less 'go' slips through", async () => {
    const noEpoch: typeof fetch = async (input) => {
      const nonce = new URL(String(input)).searchParams.get("nonce") ?? "";
      const payload = { killed: false, nonce, expiresAt: NOW + 5_000 };
      const sig = createHmac("sha256", KEY).update(canonicalJson(payload)).digest("hex");
      return new Response(JSON.stringify({ ...payload, sig }), { status: 200 });
    };
    expect(await reader(noEpoch)()).toEqual({ killed: true, epoch: -1 });
  });

  it("refuses to build without a key", () => {
    expect(() =>
      signedLiveKillStateFromControlPlane({ baseUrl: "http://x", killStateKey: "" }),
    ).toThrowError(/kill-state key/);
  });
});
