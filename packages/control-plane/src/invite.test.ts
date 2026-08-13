import { createHash, generateKeyPairSync, sign as ecSign } from "node:crypto";
import { ownerEnrollPopPreimage } from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
import { InviteStore } from "./invite.js";
import { enrolledOwnerDeviceFromSpki, verifyEnrollProofOfPossession } from "./owner-device.js";

const clock = (start = 1_000) => {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
};

const commit = (secret: string) => createHash("sha256").update(secret, "utf8").digest("base64url");

const record = (inviteId: string, secret: string, kind: "bootstrap" | "device" = "bootstrap") => ({
  inviteId,
  tokenHash: commit(secret),
  ownerId: "owner-adam",
  deviceName: "Adam's phone",
  challenge: Buffer.from("ch".repeat(16)).toString("base64url"),
  origin:
    kind === "bootstrap"
      ? ({ kind: "bootstrap" } as const)
      : ({ kind: "device", deviceId: "phone-1", deviceGeneration: 1 } as const),
});

describe("InviteStore — hash commitment, single use, TTL", () => {
  it("stores only the COMMITMENT and spends exactly once on the correct preimage", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const minted = store.register(record("inv-1", "the-secret"));
    // the record carries the hash, never the secret
    expect(JSON.stringify(minted)).not.toContain("the-secret");

    const spent = store.consume("inv-1", "the-secret");
    expect(spent.ok).toBe(true);
    // burned: the same preimage opens nothing twice
    expect(store.consume("inv-1", "the-secret").ok).toBe(false);
  });

  it("a FAILED attempt does not burn the invite (a typo must not cost the owner their invite)", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", "correct-secret"));
    expect(store.consume("inv-1", "wrong-secret").ok).toBe(false);
    expect(store.consume("inv-1", "").ok).toBe(false);
    // still alive for the real preimage
    expect(store.consume("inv-1", "correct-secret").ok).toBe(true);
  });

  it("expires by TTL, sweeps, and enforces the live-invite cap", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now, ttlMs: 60_000, maxInvites: 2 });
    store.register(record("inv-1", "s1"));
    store.register(record("inv-2", "s2"));
    expect(() => store.register(record("inv-3", "s3"))).toThrow(/too many/);
    c.advance(60_001);
    expect(store.consume("inv-1", "s1").ok).toBe(false); // expired
    store.register(record("inv-3", "s3")); // the sweep freed the cap
    expect(store.size).toBe(1);
  });

  it("refuses malformed commitments and duplicate ids at mint", () => {
    const store = new InviteStore();
    expect(() => store.register({ ...record("inv-1", "s"), tokenHash: "not-a-hash" })).toThrow(/43/);
    store.register(record("inv-2", "s"));
    expect(() => store.register(record("inv-2", "other"))).toThrow(/already exists/);
  });

  it("a successful bootstrap enrolment invalidates sibling BOOTSTRAP invites, not device-minted ones", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("boot-1", "s1", "bootstrap"));
    store.register(record("boot-2", "s2", "bootstrap"));
    store.register(record("dev-1", "s3", "device"));
    expect(store.invalidateBootstrapSiblings()).toBe(2);
    expect(store.consume("boot-2", "s2").ok).toBe(false); // a drawer secret enrolls no second root
    expect(store.consume("dev-1", "s3").ok).toBe(true); // device-minted flow untouched
  });
});

describe("verifyEnrollProofOfPossession — the ceremony transcript", () => {
  const kp = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const device = enrolledOwnerDeviceFromSpki(
    "phone-new",
    kp.publicKey.export({ format: "pem", type: "spki" }).toString(),
  );
  const credentialId = Buffer.from("credential-id-bytes-0001").toString("base64url");
  const fields = { inviteId: "inv-1", ownerId: "owner-adam", credentialId };

  const signPop = (over: Partial<typeof fields> = {}) => {
    const f = { ...fields, ...over };
    const preimage = ownerEnrollPopPreimage({
      inviteId: f.inviteId,
      ownerId: f.ownerId,
      credentialId: new Uint8Array(Buffer.from(f.credentialId, "base64url")),
      spki: new Uint8Array(device.publicKey.export({ type: "spki", format: "der" })),
    });
    return ecSign("sha256", preimage, { key: kp.privateKey, dsaEncoding: "ieee-p1363" }).toString(
      "base64url",
    );
  };

  it("accepts the key's own signature over the exact ceremony transcript", () => {
    expect(verifyEnrollProofOfPossession({ ...fields, device, proof: signPop() })).toBe(true);
  });

  it("binds every field: another invite, owner, or credential cannot reuse the proof", () => {
    const proof = signPop();
    expect(verifyEnrollProofOfPossession({ ...fields, inviteId: "inv-2", device, proof })).toBe(false);
    expect(verifyEnrollProofOfPossession({ ...fields, ownerId: "owner-eve", device, proof })).toBe(false);
    expect(
      verifyEnrollProofOfPossession({
        ...fields,
        credentialId: Buffer.from("other-credential").toString("base64url"),
        device,
        proof,
      }),
    ).toBe(false);
  });

  it("a DIFFERENT key's signature never proves possession of this one", () => {
    const other = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const preimage = ownerEnrollPopPreimage({
      inviteId: fields.inviteId,
      ownerId: fields.ownerId,
      credentialId: new Uint8Array(Buffer.from(credentialId, "base64url")),
      spki: new Uint8Array(device.publicKey.export({ type: "spki", format: "der" })),
    });
    const forged = ecSign("sha256", preimage, { key: other.privateKey, dsaEncoding: "ieee-p1363" });
    expect(
      verifyEnrollProofOfPossession({ ...fields, device, proof: forged.toString("base64url") }),
    ).toBe(false);
  });

  it("refuses a DER-encoded signature (raw r||s only) and empty fields", () => {
    const preimage = ownerEnrollPopPreimage({
      inviteId: fields.inviteId,
      ownerId: fields.ownerId,
      credentialId: new Uint8Array(Buffer.from(credentialId, "base64url")),
      spki: new Uint8Array(device.publicKey.export({ type: "spki", format: "der" })),
    });
    const der = ecSign("sha256", preimage, kp.privateKey).toString("base64url"); // default DER
    expect(verifyEnrollProofOfPossession({ ...fields, device, proof: der })).toBe(false);
    expect(verifyEnrollProofOfPossession({ ...fields, inviteId: "", device, proof: signPop() })).toBe(
      false,
    );
  });
});
