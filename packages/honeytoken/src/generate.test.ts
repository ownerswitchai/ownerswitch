import { describe, expect, it } from "vitest";
import {
  CANARY_ID_LENGTH,
  CANARY_MARKER,
  generateHoneytoken,
  HONEYTOKEN_KINDS,
  type HoneytokenKind,
} from "./generate.js";

/** The provider costume each kind must wear, with its full body length. */
const COSTUMES: Record<HoneytokenKind, RegExp> = {
  aws: /^AKIACANARY[A-Z2-7]{10}$/, // 20 chars, 50-bit body
  stripe: /^sk_live_CANARY[A-Z2-7]{18}$/, // 32 chars, 90-bit body
  openai: /^sk-CANARY[A-Z2-7]{42}$/, // 51 chars, 210-bit body
  generic: /^CANARY[A-Z2-7]{34}$/, // 40 chars, 170-bit body
};

describe("generateHoneytoken", () => {
  it.each(HONEYTOKEN_KINDS)('"%s" wears its provider costume around the canary core', (kind) => {
    const token = generateHoneytoken({ kind });
    expect(token.value).toMatch(COSTUMES[kind]);
    expect(token.core).toMatch(/^CANARY[A-Z2-7]+$/);
    expect(token.value).toContain(token.core);
  });

  it("the aws kind matches the real access-key-id shape a sweep greps for", () => {
    const token = generateHoneytoken({ kind: "aws" });
    expect(token.value).toHaveLength(20);
    expect(token.value).toMatch(/^AKIA[A-Z2-7]{16}$/);
  });

  it("every value carries the unmistakable CANARY marker — no audit-log reader can take it for a live credential", () => {
    for (const kind of HONEYTOKEN_KINDS) {
      expect(generateHoneytoken({ kind }).value).toContain(CANARY_MARKER);
    }
  });

  it("the canary id is a stable, preimage-resistant label derived from the value", () => {
    const token = generateHoneytoken({ kind: "openai" });
    expect(token.canaryId).toMatch(new RegExp(`^[A-Z2-7]{${CANARY_ID_LENGTH}}$`));
    // deterministic from the value, and never contains the secret body
    expect(token.value).not.toContain(token.canaryId);
  });

  it("bodies carry real entropy: the random portion differs every time", () => {
    const bodies = new Set<string>();
    for (const kind of HONEYTOKEN_KINDS) {
      for (let i = 0; i < 100; i += 1) {
        const t = generateHoneytoken({ kind });
        bodies.add(t.core.slice(CANARY_MARKER.length));
      }
    }
    expect(bodies.size).toBe(HONEYTOKEN_KINDS.length * 100);
  });

  it("labels ride along as metadata, never inside the value", () => {
    const token = generateHoneytoken({ kind: "stripe", label: "prod .env.backup" });
    expect(token.label).toBe("prod .env.backup");
    expect(token.value).not.toContain("prod");
    expect(generateHoneytoken({ kind: "stripe" }).label).toBeUndefined();
  });

  it("rejects unknown kinds loudly", () => {
    expect(() => generateHoneytoken({ kind: "gcp" as HoneytokenKind })).toThrow(
      /unknown honeytoken kind "gcp"/,
    );
  });
});
