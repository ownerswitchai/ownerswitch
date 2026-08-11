import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  sha256Hex,
  signMergeGrant,
  verifyMergeGrant,
  type MergeGrant,
} from "./merge-grant.js";

const KEY = "grant-key-shared-by-control-plane-and-broker";
const NOW = 1_800_000_000_000;

function grant(overrides: Partial<MergeGrant> = {}): MergeGrant {
  const canonicalArgs = canonicalJson({
    owner: "o",
    repo: "r",
    pullNumber: 7,
    expectedHeadSha: "a".repeat(40),
  });
  return {
    v: 2,
    jti: "jti-1",
    agentId: "agent-1",
    tool: "github.merge_pr",
    connector: "github",
    operation: "merge_pull_request",
    policyVersion: "sha256:abc",
    canonicalArgs,
    callHash: sha256Hex(canonicalArgs),
    killEpoch: 3,
    expiresAt: NOW + 120_000,
    ...overrides,
  };
}

describe("canonicalJson", () => {
  it("is order-independent and drops undefined", () => {
    expect(canonicalJson({ b: 1, a: 2, c: undefined })).toBe(canonicalJson({ a: 2, b: 1 }));
    expect(canonicalJson({ z: { y: 1, x: 2 } })).toBe('{"z":{"x":2,"y":1}}');
  });
});

describe("signMergeGrant / verifyMergeGrant", () => {
  it("round-trips a valid grant", () => {
    const signed = signMergeGrant(grant(), KEY);
    const result = verifyMergeGrant(signed, KEY, { now: () => NOW });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.grant.jti).toBe("jti-1");
  });

  it("rejects a tampered field — the signature covers every field", () => {
    const signed = signMergeGrant(grant(), KEY);
    // an attacker swaps the args (e.g. a different PR) but keeps the sig
    const tampered = { ...signed, canonicalArgs: canonicalJson({ owner: "evil" }) };
    const result = verifyMergeGrant(tampered, KEY, { now: () => NOW });
    expect(result).toMatchObject({ ok: false });
  });

  it("rejects a grant signed with a different key — the gateway cannot forge one", () => {
    const signed = signMergeGrant(grant(), "some-other-key");
    expect(verifyMergeGrant(signed, KEY, { now: () => NOW })).toMatchObject({ ok: false });
  });

  it("rejects an expired grant", () => {
    const signed = signMergeGrant(grant({ expiresAt: NOW - 1 }), KEY);
    expect(verifyMergeGrant(signed, KEY, { now: () => NOW })).toMatchObject({
      ok: false,
      reason: expect.stringContaining("expired"),
    });
  });

  it("rejects a grant whose callHash does not match its canonicalArgs", () => {
    const signed = signMergeGrant(grant({ callHash: sha256Hex("something else") }), KEY);
    expect(verifyMergeGrant(signed, KEY, { now: () => NOW })).toMatchObject({ ok: false });
  });

  it("rejects malformed and missing input without throwing", () => {
    for (const bad of [null, 42, {}, { v: 2 }, { ...signMergeGrant(grant(), KEY), sig: "" }]) {
      expect(verifyMergeGrant(bad, KEY, { now: () => NOW }).ok).toBe(false);
    }
  });

  it("rejects the retired v1 format — a purpose-less grant no longer verifies", () => {
    const { connector: _c, operation: _o, policyVersion: _p, ...v1 } = grant();
    const signed = signMergeGrant(grant(), KEY);
    expect(verifyMergeGrant({ ...v1, v: 1, sig: signed.sig }, KEY, { now: () => NOW })).toMatchObject({
      ok: false,
      reason: expect.stringContaining("version"),
    });
  });

  it("rejects a grant with an empty connector or operation — purpose is mandatory", () => {
    for (const overrides of [{ connector: "" }, { operation: "" }]) {
      const signed = signMergeGrant(grant(overrides as Partial<MergeGrant>), KEY);
      expect(verifyMergeGrant(signed, KEY, { now: () => NOW }).ok).toBe(false);
    }
  });

  it("covers the purpose fields with the signature — tampering the connector breaks it", () => {
    const signed = signMergeGrant(grant(), KEY);
    for (const tampered of [
      { ...signed, connector: "slack" },
      { ...signed, operation: "post_message" },
      { ...signed, policyVersion: "sha256:other" },
    ]) {
      expect(verifyMergeGrant(tampered, KEY, { now: () => NOW })).toMatchObject({
        ok: false,
        reason: expect.stringContaining("signature"),
      });
    }
  });

  it("an empty key never verifies — a broker without a grant key trusts nothing", () => {
    const signed = signMergeGrant(grant(), KEY);
    expect(verifyMergeGrant(signed, "", { now: () => NOW })).toMatchObject({ ok: false });
    expect(() => signMergeGrant(grant(), "")).toThrowError(/grant key/);
  });
});
