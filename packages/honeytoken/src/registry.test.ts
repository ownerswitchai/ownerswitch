import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateHoneytoken } from "./generate.js";
import {
  HoneytokenRegistry,
  loadRegistry,
  MAX_REGISTRY_ENTRIES,
  MAX_REGISTRY_FILE_BYTES,
  readRegistryFile,
  requireCanaryKey,
  requireDeploymentId,
  writeRegistryFile,
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

describe("MAX_REGISTRY_ENTRIES — a locally replaced huge registry is rejected before it does any real work", () => {
  const id = { canaryKey: CANARY_KEY, deploymentId: DEPLOY };

  it("rejects an oversized entries array cheaply, before shape-validating a single element", () => {
    // Every element is `null` — not RegistryEntry-shaped at all. If the count
    // check ran AFTER shape validation this would fail with a DIFFERENT
    // message ("entries are malformed"); getting the entry-limit message
    // proves the cheap length check runs first.
    const entries = new Array<null>(MAX_REGISTRY_ENTRIES + 1).fill(null);
    const payload = JSON.stringify({ version: 1, deploymentId: DEPLOY, entries, mac: "irrelevant" });
    expect(() => loadRegistry(payload, id)).toThrow(
      new RegExp(`${MAX_REGISTRY_ENTRIES + 1} entries, over the ${MAX_REGISTRY_ENTRIES}-entry limit`),
    );
  });

  it("accepts exactly MAX_REGISTRY_ENTRIES (the cap is a ceiling, not an off-by-one)", () => {
    const registry = new HoneytokenRegistry(CANARY_KEY, DEPLOY);
    for (let i = 0; i < MAX_REGISTRY_ENTRIES; i += 1) {
      registry.add({
        kind: "generic",
        canaryId: String(i).padStart(12, "A"),
        core: `CANARYFAKE${i}`,
        value: `FAKEVALUE${i}`,
      });
    }
    const loaded = loadRegistry(registry.serialize(), id);
    expect(loaded.size).toBe(MAX_REGISTRY_ENTRIES);
  });
});

describe("readRegistryFile / writeRegistryFile — symlink-safe, size-capped, mode 0600", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "oswt-registry-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("round-trips: what writeRegistryFile writes, readRegistryFile reads back exactly", () => {
    const registry = registryOf();
    const path = join(dir, "registry.json");
    writeRegistryFile(path, registry.serialize());
    expect(readRegistryFile(path)).toBe(registry.serialize());
  });

  it("writes at mode 0600 — nobody else's to read", () => {
    const path = join(dir, "registry.json");
    writeRegistryFile(path, "{}");
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("creates parent directories as needed", () => {
    const path = join(dir, "nested", "deeper", "registry.json");
    writeRegistryFile(path, "{}");
    expect(readFileSync(path, "utf8")).toBe("{}");
  });

  it("leaves no stray temp file behind after a successful write", () => {
    writeRegistryFile(join(dir, "registry.json"), "{}");
    expect(readdirSync(dir)).toEqual(["registry.json"]);
  });

  it("overwrites an existing file atomically", () => {
    const path = join(dir, "registry.json");
    writeRegistryFile(path, "{\"v\":1}");
    writeRegistryFile(path, "{\"v\":2}");
    expect(readFileSync(path, "utf8")).toBe('{"v":2}');
  });

  it("read refuses to follow a symlink at the target path", () => {
    const real = join(dir, "elsewhere.json");
    writeFileSync(real, "top secret, not a registry");
    const link = join(dir, "registry.json");
    symlinkSync(real, link);
    expect(() => readRegistryFile(link)).toThrow(/symlink/);
  });

  it("read rejects a file over MAX_REGISTRY_FILE_BYTES before parsing it", () => {
    const path = join(dir, "huge.json");
    writeFileSync(path, "x".repeat(MAX_REGISTRY_FILE_BYTES + 1));
    expect(() => readRegistryFile(path)).toThrow(
      new RegExp(`over the ${MAX_REGISTRY_FILE_BYTES}-byte honeytoken registry limit`),
    );
  });

  it("read accepts a file exactly at the byte cap", () => {
    const path = join(dir, "at-cap.json");
    writeFileSync(path, "x".repeat(MAX_REGISTRY_FILE_BYTES));
    expect(readRegistryFile(path)).toHaveLength(MAX_REGISTRY_FILE_BYTES);
  });

  it("write replaces a symlink at the destination rather than writing through it", () => {
    const decoyTarget = join(dir, "decoy-target.json");
    writeFileSync(decoyTarget, "untouched original content");
    const link = join(dir, "registry.json");
    symlinkSync(decoyTarget, link);

    writeRegistryFile(link, '{"fresh":true}');

    // the symlink's ORIGINAL target must be untouched — the write must not
    // have gone "through" the link to clobber whatever it pointed at
    expect(readFileSync(decoyTarget, "utf8")).toBe("untouched original content");
    // `link` is now a plain regular file holding the new content
    expect(readFileSync(link, "utf8")).toBe('{"fresh":true}');
  });

  it("read on a missing file fails with a clear error, not a crash", () => {
    expect(() => readRegistryFile(join(dir, "does-not-exist.json"))).toThrow();
  });
});
