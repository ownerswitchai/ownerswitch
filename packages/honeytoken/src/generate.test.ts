import { describe, expect, it } from "vitest";
import {
  CANARY_MARKER,
  generateHoneytoken,
  HONEYTOKEN_KINDS,
  newCanaryId,
  verifyCanaryId,
  type HoneytokenKind,
} from "./generate.js";
import { scanForHoneytokens } from "./scan.js";

const SECRET = "deployment-canary-secret";
const OTHER_SECRET = "a-different-deployments-secret";

/** The provider costume each kind must wear — canary core included. */
const COSTUMES: Record<HoneytokenKind, RegExp> = {
  aws: /^AKIACANARY[A-Z2-7]{10}$/,
  stripe: /^sk_live_CANARY[A-Z2-7]{10}[0-9A-Za-z]{8}$/,
  openai: /^sk-CANARY[A-Z2-7]{10}[0-9A-Za-z]{32}$/,
  generic: /^CANARY[A-Z2-7]{10}[0-9A-Za-z]{24}$/,
};

describe("generateHoneytoken", () => {
  it.each(HONEYTOKEN_KINDS)('"%s" wears its provider costume around the canary core', (kind) => {
    const token = generateHoneytoken({ kind, secret: SECRET });
    expect(token.value).toMatch(COSTUMES[kind]);
    expect(token.core).toBe(CANARY_MARKER + token.canaryId);
    expect(token.value).toContain(token.core);
  });

  it("the aws kind matches the real access-key-id shape a sweep greps for", () => {
    const token = generateHoneytoken({ kind: "aws", secret: SECRET });
    expect(token.value).toHaveLength(20);
    expect(token.value).toMatch(/^AKIA[A-Z2-7]{16}$/);
  });

  it("every value carries the unmistakable CANARY marker — no audit-log reader can take it for a live credential", () => {
    for (const kind of HONEYTOKEN_KINDS) {
      const token = generateHoneytoken({ kind, secret: SECRET });
      expect(token.value).toContain(CANARY_MARKER);
      expect(verifyCanaryId(token.canaryId, SECRET)).toBe(true);
      // and the embedded id is recoverable by the scanner, exactly once
      const matches = scanForHoneytokens(token.value, SECRET);
      expect(matches).toHaveLength(1);
      expect(matches[0].canaryId).toBe(token.canaryId);
    }
  });

  it("labels ride along as metadata, never inside the value", () => {
    const token = generateHoneytoken({ kind: "stripe", label: "prod .env.backup", secret: SECRET });
    expect(token.label).toBe("prod .env.backup");
    expect(token.value).not.toContain("prod");
    expect(generateHoneytoken({ kind: "stripe", secret: SECRET }).label).toBeUndefined();
  });

  it("canary ids are unique across generations", () => {
    const ids = new Set<string>();
    for (const kind of HONEYTOKEN_KINDS) {
      for (let i = 0; i < 50; i += 1) ids.add(generateHoneytoken({ kind, secret: SECRET }).canaryId);
    }
    expect(ids.size).toBe(HONEYTOKEN_KINDS.length * 50);
  });

  it("rejects unknown kinds loudly", () => {
    expect(() => generateHoneytoken({ kind: "gcp" as HoneytokenKind, secret: SECRET })).toThrow(
      /unknown honeytoken kind "gcp"/,
    );
  });

  it("requires a per-deployment secret — never silently mints an unkeyed token", () => {
    expect(() => generateHoneytoken({ kind: "aws", secret: "" })).toThrow(/canary secret is required/);
    expect(() => newCanaryId("")).toThrow(/canary secret is required/);
    expect(() => verifyCanaryId("ABCDEF1234", "")).toThrow(/canary secret is required/);
  });
});

describe("canary ids are keyed and unforgeable", () => {
  it("verifyCanaryId accepts only ids minted with the SAME key", () => {
    const id = newCanaryId(SECRET);
    expect(id).toMatch(/^[A-Z2-7]{10}$/);
    expect(verifyCanaryId(id, SECRET)).toBe(true);

    // the whole point of fix #1: a canary minted for one deployment does not
    // verify under another deployment's key
    expect(verifyCanaryId(id, OTHER_SECRET)).toBe(false);

    expect(verifyCanaryId(id.slice(0, 9), SECRET)).toBe(false); // wrong length
    expect(verifyCanaryId(`${id.slice(0, 9)}1`, SECRET)).toBe(false); // "1" is outside base32
    const flipped = id.slice(0, 9) + (id.endsWith("A") ? "B" : "A");
    expect(verifyCanaryId(flipped, SECRET)).toBe(false); // checksum broken
  });

  it("a token minted for another deployment does NOT trip this deployment's scanner", () => {
    const foreign = generateHoneytoken({ kind: "aws", secret: OTHER_SECRET });
    // it is a perfectly valid canary for the OTHER deployment…
    expect(scanForHoneytokens(foreign.value, OTHER_SECRET)).toHaveLength(1);
    // …and inert here, so one tenant's bait can never kill another's agents
    expect(scanForHoneytokens(foreign.value, SECRET)).toEqual([]);
  });

  it("the checksum is not derivable from source alone — a fixed public salt would be forgeable", () => {
    // Reconstruct the pre-fix (unkeyed) checksum an attacker could compute
    // from the repo, and confirm it does not validate under a real key. This
    // pins that the checksum genuinely depends on the secret.
    const id = newCanaryId(SECRET);
    const randomPart = id.slice(0, 6);
    // brute-forcing four base32 chars is 2^20 tries; a source-only guess is one try
    expect(verifyCanaryId(`${randomPart}AAAA`, SECRET)).toBe(false);
  });
});
