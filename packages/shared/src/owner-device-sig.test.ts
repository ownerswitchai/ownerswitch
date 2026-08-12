import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  assertCanonicalPathAndQuery,
  OWNER_DEVICE_SIG_LABEL,
  ownerDeviceSigPreimage,
} from "./owner-device-sig.js";

const emptyBodyHash = () => new Uint8Array(createHash("sha256").update("").digest());
const sha256Hex = (bytes: Uint8Array) => createHash("sha256").update(Buffer.from(bytes)).digest("hex");

describe("owner-device signature preimage — the one source of truth", () => {
  it("pins the exact bytes for a fixed input (drift guard vs apps/owner)", () => {
    // This SAME vector is produced by apps/owner/src/device-sig.ts's
    // deviceSigPreimage — verified equal at build. If either side changes the
    // encoding, this hash changes and the signer/verifier silently disagree,
    // so it is pinned here.
    const preimage = ownerDeviceSigPreimage({
      deviceId: "owner-phone",
      method: "post", // lower-cased on purpose: signed UPPER
      pathAndQuery: "/veto/veto_abc/seen",
      bodyHash: emptyBodyHash(),
      timestamp: 1_000_000,
      nonce: "n-1",
    });
    expect(sha256Hex(preimage)).toBe(
      "437c98d569bf7e6f4923820337e74a26d2b72cd9bfeaa6c62418df6318a035cd",
    );
  });

  it("method is case-folded: get and GET sign identically", () => {
    const fields = {
      deviceId: "d",
      pathAndQuery: "/veto/w1",
      bodyHash: emptyBodyHash(),
      timestamp: 1,
      nonce: "n",
    };
    expect(ownerDeviceSigPreimage({ ...fields, method: "get" })).toEqual(
      ownerDeviceSigPreimage({ ...fields, method: "GET" }),
    );
  });

  it("is injective across fields — a body change or a path change moves the bytes", () => {
    const base = {
      deviceId: "d",
      method: "POST",
      pathAndQuery: "/veto/w1/seen",
      bodyHash: emptyBodyHash(),
      timestamp: 1,
      nonce: "n",
    };
    const a = sha256Hex(ownerDeviceSigPreimage(base));
    const bodyChanged = sha256Hex(
      ownerDeviceSigPreimage({ ...base, bodyHash: new Uint8Array(createHash("sha256").update("x").digest()) }),
    );
    const pathChanged = sha256Hex(ownerDeviceSigPreimage({ ...base, pathAndQuery: "/veto/w2/seen" }));
    expect(new Set([a, bodyChanged, pathChanged]).size).toBe(3);
    expect(OWNER_DEVICE_SIG_LABEL).toBe("ownerswitch/device-sig/v1");
  });

  it("refuses a non-32-byte body hash and an unsafe timestamp", () => {
    const base = { deviceId: "d", method: "POST", pathAndQuery: "/x", timestamp: 1, nonce: "n" };
    expect(() => ownerDeviceSigPreimage({ ...base, bodyHash: new Uint8Array(31) })).toThrow(/32-byte/);
    expect(() =>
      ownerDeviceSigPreimage({ ...base, bodyHash: emptyBodyHash(), timestamp: 1.5 }),
    ).toThrow(/safe integer/);
  });

  it("assertCanonicalPathAndQuery rejects non-serialized targets", () => {
    expect(() => assertCanonicalPathAndQuery("veto/w1")).toThrow(/origin-form/); // no leading /
    expect(() => assertCanonicalPathAndQuery("/x?q=é")).toThrow(/printable ASCII/); // raw unicode
    expect(() => assertCanonicalPathAndQuery("/x?q=%c3%a9")).toThrow(/uppercase-hex/); // lowercase hex
    expect(() => assertCanonicalPathAndQuery("/x#frag")).toThrow(/fragment/);
    expect(() => assertCanonicalPathAndQuery("//host/x")).toThrow(); // protocol-relative smuggling
    // a properly-serialized target with an uppercase escape is accepted
    expect(() => assertCanonicalPathAndQuery("/veto/veto_abc/seen?q=%C3%A9")).not.toThrow();
  });
});
