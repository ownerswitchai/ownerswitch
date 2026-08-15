import { describe, expect, it } from "vitest";
import {
  createOwnerSession,
  isLoopbackAddress,
  signDeviceRequest,
  verifyDeviceSignature,
  verifyOwnerSession,
} from "./auth.js";

const SECRET = "button-secret";
const CTX = { method: "POST", pathAndQuery: "/kill" };

/** A valid credential for `body`, signed at `at` on a fresh clock. */
const signedAt = (at: number, body = '{"source":"button"}', nonce = "n-1", context = CTX) => ({
  credential: {
    deviceId: "btn-1",
    timestamp: at,
    nonce,
    signature: signDeviceRequest({ deviceId: "btn-1", timestamp: at, nonce }, body, SECRET, context),
  },
  body,
});

describe("verifyDeviceSignature (fleet-hmac v2)", () => {
  it("accepts a correctly signed request", () => {
    const { credential, body } = signedAt(100_000);
    const ok = verifyDeviceSignature(credential, body, SECRET, CTX, {
      now: () => 100_000,
      seenNonces: new Map(),
    });
    expect(ok).toBe(true);
  });

  it("rejects a tampered body", () => {
    const { credential } = signedAt(100_000);
    const ok = verifyDeviceSignature(credential, '{"source":"api"}', SECRET, CTX, {
      now: () => 100_000,
      seenNonces: new Map(),
    });
    expect(ok).toBe(false);
  });

  it("rejects a redirected METHOD or PATH — the v2 binding (PR #62 audit #7)", () => {
    const { credential, body } = signedAt(100_000);
    const opts = () => ({ now: () => 100_000, seenNonces: new Map<string, number>() });
    // the same captured MAC aimed at a different verb, endpoint, window id
    // or query — every redirection must fail on its FIRST use
    expect(verifyDeviceSignature(credential, body, SECRET, { ...CTX, method: "GET" }, opts())).toBe(false);
    expect(
      verifyDeviceSignature(credential, body, SECRET, { ...CTX, pathAndQuery: "/alert" }, opts()),
    ).toBe(false);
    expect(
      verifyDeviceSignature(credential, body, SECRET, { ...CTX, pathAndQuery: "/kill?x=1" }, opts()),
    ).toBe(false);
    // and a window-id swap on the veto route
    const veto = signedAt(100_000, "", "n-veto", { method: "POST", pathAndQuery: "/veto/w1" });
    expect(
      verifyDeviceSignature(
        veto.credential,
        veto.body,
        SECRET,
        { method: "POST", pathAndQuery: "/veto/w2" },
        opts(),
      ),
    ).toBe(false);
  });

  it("case-folds the method — 'post' and 'POST' sign the same transcript", () => {
    const { credential, body } = signedAt(100_000, undefined, "n-case", {
      method: "post",
      pathAndQuery: "/kill",
    });
    expect(
      verifyDeviceSignature(credential, body, SECRET, CTX, { now: () => 100_000, seenNonces: new Map() }),
    ).toBe(true);
  });

  it("a non-canonical request target verifies to false instead of throwing", () => {
    const { credential, body } = signedAt(100_000);
    for (const pathAndQuery of ["kill", "/kill#frag", "/kill space", ""]) {
      const ok = verifyDeviceSignature(credential, body, SECRET, { method: "POST", pathAndQuery }, {
        now: () => 100_000,
        seenNonces: new Map(),
      });
      expect(ok, pathAndQuery).toBe(false);
    }
  });

  it("rejects the wrong secret", () => {
    const { credential, body } = signedAt(100_000);
    const ok = verifyDeviceSignature(credential, body, "other-secret", CTX, {
      now: () => 100_000,
      seenNonces: new Map(),
    });
    expect(ok).toBe(false);
  });

  it("rejects garbage and wrong-length signatures without throwing", () => {
    const { credential, body } = signedAt(100_000);
    for (const signature of ["", "zz", "deadbeef", credential.signature.slice(0, -2)]) {
      const ok = verifyDeviceSignature({ ...credential, signature }, body, SECRET, CTX, {
        now: () => 100_000,
        seenNonces: new Map(),
      });
      expect(ok).toBe(false);
    }
  });

  it("rejects timestamps outside the 60 s window, in both directions", () => {
    const verify = (signedAtMs: number, nowMs: number) => {
      const { credential, body } = signedAt(signedAtMs);
      return verifyDeviceSignature(credential, body, SECRET, CTX, {
        now: () => nowMs,
        seenNonces: new Map(),
      });
    };
    expect(verify(100_000, 100_000 + 59_000)).toBe(true); // 59 s old — fine
    expect(verify(100_000, 100_000 + 60_001)).toBe(false); // too old
    expect(verify(100_000 + 60_001, 100_000)).toBe(false); // too far in the future
  });

  it("rejects a replayed nonce", () => {
    const seenNonces = new Map<string, number>();
    const { credential, body } = signedAt(100_000);
    const opts = { now: () => 100_000, seenNonces };
    expect(verifyDeviceSignature(credential, body, SECRET, CTX, opts)).toBe(true);
    expect(verifyDeviceSignature(credential, body, SECRET, CTX, opts)).toBe(false);
  });

  it("an invalid signature does not burn the nonce", () => {
    const seenNonces = new Map<string, number>();
    const { credential, body } = signedAt(100_000);
    const opts = { now: () => 100_000, seenNonces };
    expect(
      verifyDeviceSignature({ ...credential, signature: "deadbeef" }, body, SECRET, CTX, opts),
    ).toBe(false);
    expect(verifyDeviceSignature(credential, body, SECRET, CTX, opts)).toBe(true);
  });

  it("nonces are scoped per device", () => {
    const seenNonces = new Map<string, number>();
    const opts = { now: () => 100_000, seenNonces };
    const a = signedAt(100_000);
    expect(verifyDeviceSignature(a.credential, a.body, SECRET, CTX, opts)).toBe(true);

    const fields = { deviceId: "btn-2", timestamp: 100_000, nonce: "n-1" };
    const b = { ...fields, signature: signDeviceRequest(fields, a.body, SECRET, CTX) };
    expect(verifyDeviceSignature(b, a.body, SECRET, CTX, opts)).toBe(true);
  });

  it("signDeviceRequest keeps the dot-free field grammar and integer timestamps", () => {
    const fields = { deviceId: "btn-1", timestamp: 100_000, nonce: "n-1" };
    expect(() => signDeviceRequest({ ...fields, deviceId: "btn.1" }, "{}", SECRET, CTX)).toThrow(/"\."/);
    expect(() => signDeviceRequest({ ...fields, nonce: "5.x" }, "{}", SECRET, CTX)).toThrow(/"\."/);
    expect(() => signDeviceRequest({ ...fields, timestamp: 0.5 }, "{}", SECRET, CTX)).toThrow(/integer/);
    expect(() =>
      signDeviceRequest(fields, "{}", SECRET, { method: "POST", pathAndQuery: "no-slash" }),
    ).toThrow(/canonical/);
  });

  it("prunes nonce entries once they fall outside the replay window", () => {
    const seenNonces = new Map<string, number>();
    let t = 100_000;
    const opts = { now: () => t, seenNonces };

    const a = signedAt(t);
    expect(verifyDeviceSignature(a.credential, a.body, SECRET, CTX, opts)).toBe(true);
    expect(seenNonces.has("btn-1:n-1")).toBe(true);

    t += 61_000; // n-1's timestamp can no longer verify — its entry is dead weight
    const b = signedAt(t, undefined, "n-2");
    expect(verifyDeviceSignature(b.credential, b.body, SECRET, CTX, opts)).toBe(true);
    expect(seenNonces.has("btn-1:n-1")).toBe(false); // swept
    expect(seenNonces.has("btn-1:n-2")).toBe(true);
  });
});

describe("owner sessions", () => {
  it("a created session verifies and names its owner", () => {
    const session = createOwnerSession("adam", { now: () => 0 });
    expect(verifyOwnerSession(session.token, { now: () => 0 })?.ownerId).toBe("adam");
  });

  it("tokens are opaque, unique, and unknown ones verify to null", () => {
    const a = createOwnerSession("adam");
    const b = createOwnerSession("adam");
    expect(a.token).not.toBe(b.token);
    expect(verifyOwnerSession("not-a-token")).toBeNull();
  });

  it("sessions expire after 15 minutes", () => {
    const session = createOwnerSession("adam", { now: () => 0 });
    expect(verifyOwnerSession(session.token, { now: () => 15 * 60_000 - 1 })).not.toBeNull();
    expect(verifyOwnerSession(session.token, { now: () => 15 * 60_000 })).toBeNull();
    // and stays expired even if asked again at an earlier time
    expect(verifyOwnerSession(session.token, { now: () => 0 })).toBeNull();
  });
});

describe("isLoopbackAddress", () => {
  it.each(["127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1"])("%s is loopback", (addr) => {
    expect(isLoopbackAddress(addr)).toBe(true);
  });

  it.each([undefined, "", "192.168.1.10", "10.0.0.1", "203.0.113.7", "::ffff:10.0.0.1", "fe80::1"])(
    "%s is not",
    (addr) => {
      expect(isLoopbackAddress(addr)).toBe(false);
    },
  );
});
