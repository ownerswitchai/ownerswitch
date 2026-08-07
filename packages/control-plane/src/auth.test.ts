import { describe, expect, it } from "vitest";
import {
  createOwnerSession,
  isLoopbackAddress,
  signDeviceRequest,
  verifyDeviceSignature,
  verifyOwnerSession,
} from "./auth.js";

const SECRET = "button-secret";

/** A valid credential for `body`, signed at `at` on a fresh clock. */
const signedAt = (at: number, body = '{"source":"button"}', nonce = "n-1") => ({
  credential: {
    deviceId: "btn-1",
    timestamp: at,
    nonce,
    signature: signDeviceRequest({ deviceId: "btn-1", timestamp: at, nonce }, body, SECRET),
  },
  body,
});

describe("verifyDeviceSignature", () => {
  it("accepts a correctly signed request", () => {
    const { credential, body } = signedAt(100_000);
    const ok = verifyDeviceSignature(credential, body, SECRET, {
      now: () => 100_000,
      seenNonces: new Set(),
    });
    expect(ok).toBe(true);
  });

  it("rejects a tampered body", () => {
    const { credential } = signedAt(100_000);
    const ok = verifyDeviceSignature(credential, '{"source":"api"}', SECRET, {
      now: () => 100_000,
      seenNonces: new Set(),
    });
    expect(ok).toBe(false);
  });

  it("rejects the wrong secret", () => {
    const { credential, body } = signedAt(100_000);
    const ok = verifyDeviceSignature(credential, body, "other-secret", {
      now: () => 100_000,
      seenNonces: new Set(),
    });
    expect(ok).toBe(false);
  });

  it("rejects garbage and wrong-length signatures without throwing", () => {
    const { credential, body } = signedAt(100_000);
    for (const signature of ["", "zz", "deadbeef", credential.signature.slice(0, -2)]) {
      const ok = verifyDeviceSignature({ ...credential, signature }, body, SECRET, {
        now: () => 100_000,
        seenNonces: new Set(),
      });
      expect(ok).toBe(false);
    }
  });

  it("rejects timestamps outside the 60 s window, in both directions", () => {
    const verify = (signedAtMs: number, nowMs: number) => {
      const { credential, body } = signedAt(signedAtMs);
      return verifyDeviceSignature(credential, body, SECRET, {
        now: () => nowMs,
        seenNonces: new Set(),
      });
    };
    expect(verify(100_000, 100_000 + 59_000)).toBe(true); // 59 s old — fine
    expect(verify(100_000, 100_000 + 60_001)).toBe(false); // too old
    expect(verify(100_000 + 60_001, 100_000)).toBe(false); // too far in the future
  });

  it("rejects a replayed nonce", () => {
    const seenNonces = new Set<string>();
    const { credential, body } = signedAt(100_000);
    const opts = { now: () => 100_000, seenNonces };
    expect(verifyDeviceSignature(credential, body, SECRET, opts)).toBe(true);
    expect(verifyDeviceSignature(credential, body, SECRET, opts)).toBe(false);
  });

  it("an invalid signature does not burn the nonce", () => {
    const seenNonces = new Set<string>();
    const { credential, body } = signedAt(100_000);
    const opts = { now: () => 100_000, seenNonces };
    expect(verifyDeviceSignature({ ...credential, signature: "deadbeef" }, body, SECRET, opts)).toBe(
      false,
    );
    expect(verifyDeviceSignature(credential, body, SECRET, opts)).toBe(true);
  });

  it("nonces are scoped per device", () => {
    const seenNonces = new Set<string>();
    const opts = { now: () => 100_000, seenNonces };
    const a = signedAt(100_000);
    expect(verifyDeviceSignature(a.credential, a.body, SECRET, opts)).toBe(true);

    const fields = { deviceId: "btn-2", timestamp: 100_000, nonce: "n-1" };
    const b = { ...fields, signature: signDeviceRequest(fields, a.body, SECRET) };
    expect(verifyDeviceSignature(b, a.body, SECRET, opts)).toBe(true);
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
