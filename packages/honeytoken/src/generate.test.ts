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

/** The provider costume each kind must wear — canary core included. */
const COSTUMES: Record<HoneytokenKind, RegExp> = {
  aws: /^AKIACANARY[A-Z2-7]{10}$/,
  stripe: /^sk_live_CANARY[A-Z2-7]{10}[0-9A-Za-z]{8}$/,
  openai: /^sk-CANARY[A-Z2-7]{10}[0-9A-Za-z]{32}$/,
  generic: /^CANARY[A-Z2-7]{10}[0-9A-Za-z]{24}$/,
};

describe("generateHoneytoken", () => {
  it.each(HONEYTOKEN_KINDS)('"%s" wears its provider costume around the canary core', (kind) => {
    const token = generateHoneytoken({ kind });
    expect(token.value).toMatch(COSTUMES[kind]);
    expect(token.core).toBe(CANARY_MARKER + token.canaryId);
    expect(token.value).toContain(token.core);
  });

  it("the aws kind matches the real access-key-id shape a sweep greps for", () => {
    const token = generateHoneytoken({ kind: "aws" });
    expect(token.value).toHaveLength(20);
    expect(token.value).toMatch(/^AKIA[A-Z2-7]{16}$/);
  });

  it("every value carries the unmistakable CANARY marker — no audit-log reader can take it for a live credential", () => {
    for (const kind of HONEYTOKEN_KINDS) {
      const token = generateHoneytoken({ kind });
      expect(token.value).toContain(CANARY_MARKER);
      expect(verifyCanaryId(token.canaryId)).toBe(true);
      // and the embedded id is recoverable by the scanner, exactly once
      const matches = scanForHoneytokens(token.value);
      expect(matches).toHaveLength(1);
      expect(matches[0].canaryId).toBe(token.canaryId);
    }
  });

  it("labels ride along as metadata, never inside the value", () => {
    const token = generateHoneytoken({ kind: "stripe", label: "prod .env.backup" });
    expect(token.label).toBe("prod .env.backup");
    expect(token.value).not.toContain("prod");
    expect(generateHoneytoken({ kind: "stripe" }).label).toBeUndefined();
  });

  it("canary ids are unique across generations", () => {
    const ids = new Set<string>();
    for (const kind of HONEYTOKEN_KINDS) {
      for (let i = 0; i < 50; i += 1) ids.add(generateHoneytoken({ kind }).canaryId);
    }
    expect(ids.size).toBe(HONEYTOKEN_KINDS.length * 50);
  });

  it("rejects unknown kinds loudly", () => {
    expect(() => generateHoneytoken({ kind: "gcp" as HoneytokenKind })).toThrow(
      /unknown honeytoken kind "gcp"/,
    );
  });
});

describe("canary ids", () => {
  it("verifyCanaryId accepts only minted ids — length, alphabet and checksum all hold", () => {
    const id = newCanaryId();
    expect(id).toMatch(/^[A-Z2-7]{10}$/);
    expect(verifyCanaryId(id)).toBe(true);

    expect(verifyCanaryId(id.slice(0, 9))).toBe(false); // wrong length
    expect(verifyCanaryId(`${id.slice(0, 9)}1`)).toBe(false); // "1" is outside base32
    const flipped = id.slice(0, 9) + (id.endsWith("A") ? "B" : "A");
    expect(verifyCanaryId(flipped)).toBe(false); // checksum broken
  });
});
