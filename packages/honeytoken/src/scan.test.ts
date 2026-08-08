import { describe, expect, it } from "vitest";
import { generateHoneytoken } from "./generate.js";
import { HoneytokenRegistry } from "./registry.js";
import { scanForHoneytokens } from "./scan.js";

const CANARY_KEY = "canary-key-scan-test-0011223344556677";
const DEPLOY = "deploy-scan";

const registryWith = (...tokens: ReturnType<typeof generateHoneytoken>[]) => {
  const r = new HoneytokenRegistry(CANARY_KEY, DEPLOY);
  for (const t of tokens) r.add(t);
  return r;
};

describe("scanForHoneytokens", () => {
  it("a planted decoy value inside tool-call arguments trips the scanner", () => {
    const token = generateHoneytoken({ kind: "stripe" });
    const registry = registryWith(token);
    const args = JSON.stringify({
      tool: "stripe.create_payout",
      args: { api_key: token.value, amount_cents: 125_000 },
    });

    const matches = scanForHoneytokens(args, registry);
    expect(matches).toHaveLength(1);
    expect(matches[0].canaryId).toBe(token.canaryId);
    expect(matches[0].kind).toBe("stripe");
    expect(matches[0].value).toBe(token.value);
  });

  it("real credential-shaped strings that were never planted do NOT trip", () => {
    const registry = registryWith(generateHoneytoken({ kind: "aws" }));
    for (const foreign of [
      "AKIAIOSFODNN7EXAMPLE",
      "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
      "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH",
      "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
      "the CANARY project ships CANARYTOKENS as a feature",
    ]) {
      expect(scanForHoneytokens(foreign, registry)).toEqual([]);
    }
  });

  it("a decoy from another deployment's registry does not trip this one", () => {
    const mine = registryWith(generateHoneytoken({ kind: "generic" }));
    const theirs = generateHoneytoken({ kind: "generic" }); // never added to `mine`
    expect(scanForHoneytokens(theirs.value, mine)).toEqual([]);
  });

  it("clean text scans clean", () => {
    const registry = registryWith(generateHoneytoken({ kind: "aws" }));
    expect(scanForHoneytokens("", registry)).toEqual([]);
    expect(
      scanForHoneytokens(JSON.stringify({ path: "/tmp/notes.md", content: "hello" }), registry),
    ).toEqual([]);
  });
});
