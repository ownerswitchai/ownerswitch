import { describe, expect, it } from "vitest";
import { generateHoneytoken } from "./generate.js";
import {
  HoneytokenRegistry,
  loadRegistry,
  requireCanaryKey,
  requireDeploymentId,
} from "./registry.js";

const CANARY_KEY = "canary-key-9f3a7c2e1b8d4056aa771122";
const OTHER_KEY = "canary-key-different-0011223344556677";
const DEPLOY = "deploy-prod";

const registryOf = (deployment = DEPLOY, key = CANARY_KEY) => {
  const r = new HoneytokenRegistry(key, deployment);
  r.add(generateHoneytoken({ kind: "aws", label: "a" }));
  r.add(generateHoneytoken({ kind: "generic", label: "b" }));
  return r;
};

describe("requireCanaryKey — fix #2, no weak or defaulted keys", () => {
  it("accepts a strong, dedicated key", () => {
    expect(() => requireCanaryKey(CANARY_KEY, DEPLOY)).not.toThrow();
  });

  it("rejects absent, empty, or non-string keys — no silent fallback", () => {
    expect(() => requireCanaryKey(undefined)).toThrow(/dedicated per-deployment canary key is required/);
    expect(() => requireCanaryKey("")).toThrow(/required/);
    expect(() => requireCanaryKey(12345 as unknown as string)).toThrow(/required/);
  });

  it("rejects short keys", () => {
    expect(() => requireCanaryKey("too-short-key")).toThrow(/too short/);
  });

  it("rejects obviously-sample / weak values, not just empty strings", () => {
    for (const weak of [
      "changeme",
      "device-secret",
      "your-secret-here",
      "canary",
      "0123456789abcdef",
      "xxxxxxxxxxxxxxxxxxxxxxxxxx", // repeated single char, long enough otherwise
    ]) {
      expect(() => requireCanaryKey(weak, DEPLOY), weak).toThrow();
    }
  });

  it("rejects a key equal to the deployment id — they are separate secrets", () => {
    const same = "shared-value-used-for-both-1234567";
    expect(() => requireCanaryKey(same, same)).toThrow(/must not equal the deployment id/);
  });

  it("requireDeploymentId rejects short or empty ids", () => {
    expect(() => requireDeploymentId("")).toThrow();
    expect(() => requireDeploymentId("ab")).toThrow();
    expect(() => requireDeploymentId("prod-1")).not.toThrow();
  });
});

describe("HoneytokenRegistry", () => {
  it("the constructor validates the key and id up front", () => {
    expect(() => new HoneytokenRegistry("weak", DEPLOY)).toThrow();
    expect(() => new HoneytokenRegistry(CANARY_KEY, "")).toThrow();
  });

  it("match finds registered values, deduped by canary id and ordered by position", () => {
    const r = new HoneytokenRegistry(CANARY_KEY, DEPLOY);
    const aws = generateHoneytoken({ kind: "aws" });
    const openai = generateHoneytoken({ kind: "openai" });
    r.add(aws);
    r.add(openai);

    const text = `first ${openai.value} then ${aws.value} then ${openai.value} again`;
    const matches = r.match(text);
    expect(matches.map((m) => m.canaryId)).toEqual([openai.canaryId, aws.canaryId]);
    expect(matches.map((m) => m.kind)).toEqual(["openai", "aws"]);
  });

  it("does not match unregistered values — real credentials never trip", () => {
    const r = registryOf();
    for (const foreign of [
      "AKIAIOSFODNN7EXAMPLE",
      "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
      "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH",
      "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    ]) {
      expect(r.match(foreign)).toEqual([]);
    }
  });

  it("canaryIds lists every registered token", () => {
    const r = registryOf();
    expect(r.canaryIds()).toHaveLength(2);
  });
});

describe("serialize / loadRegistry — fix #1/#2 tamper + deployment binding", () => {
  it("round-trips, and the loaded registry matches the same tokens", () => {
    const r = registryOf();
    const token = generateHoneytoken({ kind: "stripe" });
    r.add(token);

    const loaded = loadRegistry(r.serialize(), { canaryKey: CANARY_KEY, deploymentId: DEPLOY });
    expect(loaded.deploymentId).toBe(DEPLOY);
    expect(loaded.size).toBe(3);
    expect(loaded.match(`k=${token.value}`)[0]?.canaryId).toBe(token.canaryId);
  });

  it("rejects a registry whose MAC does not verify (tampered entries)", () => {
    const r = registryOf();
    const serialized = r.serialize();
    // Splice in an attacker-chosen value without re-MACing.
    const tampered = serialized.replace(
      '"entries": [',
      '"entries": [\n    { "canaryId": "EVIL00000000", "kind": "generic", "value": "AKIAIOSFODNN7EXAMPLE" },',
    );
    expect(() => loadRegistry(tampered, { canaryKey: CANARY_KEY, deploymentId: DEPLOY })).toThrow(
      /MAC does not verify/,
    );
  });

  it("rejects the right registry under the wrong canary key", () => {
    const serialized = registryOf().serialize();
    expect(() => loadRegistry(serialized, { canaryKey: OTHER_KEY, deploymentId: DEPLOY })).toThrow(
      /MAC does not verify/,
    );
  });

  it("rejects a registry minted for a different deployment", () => {
    const serialized = registryOf("deploy-a").serialize();
    expect(() =>
      loadRegistry(serialized, { canaryKey: CANARY_KEY, deploymentId: "deploy-b" }),
    ).toThrow(/is for deployment "deploy-a", not "deploy-b"/);
  });

  it("one deployment's registry never matches another deployment's tokens", () => {
    // Two deployments, each with its own tokens. Cross-loading is impossible
    // (MAC + deployment binding), and even the raw values differ, so a token
    // planted for A is inert at B.
    const a = registryOf("deploy-a");
    const aToken = generateHoneytoken({ kind: "generic" });
    a.add(aToken);
    const b = new HoneytokenRegistry(OTHER_KEY, "deploy-b");
    expect(b.match(aToken.value)).toEqual([]);
  });

  it("rejects malformed JSON, wrong version, and missing MAC loudly", () => {
    const id = { canaryKey: CANARY_KEY, deploymentId: DEPLOY };
    expect(() => loadRegistry("not json", id)).toThrow(/not valid JSON/);
    expect(() => loadRegistry(JSON.stringify({ version: 99, deploymentId: DEPLOY, entries: [], mac: "x" }), id)).toThrow(
      /unsupported honeytoken registry version/,
    );
    expect(() => loadRegistry(JSON.stringify({ version: 1, deploymentId: DEPLOY, entries: [] }), id)).toThrow(
      /missing its integrity MAC/,
    );
  });
});
