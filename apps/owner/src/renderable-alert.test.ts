import { describe, expect, it } from "vitest";
import {
  assertRenderableAlert,
  canonicalRenderableAlert,
  renderContentHash,
  validateRenderableAlert,
} from "./renderable-alert.js";
import type { RenderableAlertV1 } from "./types.js";

const ok: RenderableAlertV1 = {
  v: 1,
  agentId: "agent-7",
  tool: "github.merge",
  summary: "Merge PR #7 into main",
};

// Control and bidi characters are built from numeric code points, never
// written as literal bytes: a raw control byte in source is invisible and
// easy to corrupt (the same reasoning as the numeric comparisons in
// secret.ts). NUL, TAB, LF, CR, C0-end, DEL, NEL (C1), C1-end:
const C0_C1_CONTROLS = [0x00, 0x09, 0x0a, 0x0d, 0x1f, 0x7f, 0x85, 0x9f].map((cp) =>
  String.fromCodePoint(cp),
);
// LRE RLE PDF LRO RLO LRI RLI FSI PDI:
const BIDI_CONTROLS = [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069].map(
  (cp) => String.fromCodePoint(cp),
);
// What a hand-maintained list of the nine would miss — the rest of
// Bidi_Control (ALM, LRM, RLM) and other invisibles (SOFT HYPHEN, ZWSP):
const INVISIBLE_EXTRAS = [0x061c, 0x200e, 0x200f, 0x00ad, 0x200b].map((cp) =>
  String.fromCodePoint(cp),
);
const RLO = String.fromCodePoint(0x202e);
const EMOJI = String.fromCodePoint(0x1f600); // 1 code point, 2 UTF-16 units

describe("validateRenderableAlert", () => {
  it("accepts a conforming alert", () => {
    expect(validateRenderableAlert(ok)).toBeNull();
  });

  it("enforces per-field code-point limits (inclusive)", () => {
    expect(validateRenderableAlert({ ...ok, agentId: "a".repeat(64) })).toBeNull();
    expect(validateRenderableAlert({ ...ok, agentId: "a".repeat(65) })).toEqual({
      field: "agentId",
      reason: "too-long",
    });
    expect(validateRenderableAlert({ ...ok, tool: "t".repeat(65) })).toEqual({
      field: "tool",
      reason: "too-long",
    });
    expect(validateRenderableAlert({ ...ok, summary: "s".repeat(200) })).toBeNull();
    expect(validateRenderableAlert({ ...ok, summary: "s".repeat(201) })).toEqual({
      field: "summary",
      reason: "too-long",
    });
  });

  it("counts astral code points as one each, not UTF-16 units", () => {
    // 64 emoji = 64 code points (128 UTF-16 units) — within the agentId limit
    expect(validateRenderableAlert({ ...ok, agentId: EMOJI.repeat(64) })).toBeNull();
    expect(validateRenderableAlert({ ...ok, agentId: EMOJI.repeat(65) })).toEqual({
      field: "agentId",
      reason: "too-long",
    });
  });

  it("rejects C0/C1 controls, CR/LF/TAB included", () => {
    for (const bad of C0_C1_CONTROLS) {
      expect(validateRenderableAlert({ ...ok, summary: `hi${bad}there` })).toEqual({
        field: "summary",
        reason: "forbidden-character",
      });
    }
  });

  it("rejects explicit bidi embedding/override/isolate controls (UTR #36)", () => {
    for (const bad of BIDI_CONTROLS) {
      expect(validateRenderableAlert({ ...ok, tool: `x${bad}y` })).toEqual({
        field: "tool",
        reason: "forbidden-character",
      });
    }
  });

  it("rejects the FULL Bidi_Control and Default_Ignorable classes, not just the nine embedding controls", () => {
    // U+061C ALM, U+200E LRM, U+200F RLM, U+00AD SOFT HYPHEN, U+200B ZWSP
    for (const bad of INVISIBLE_EXTRAS) {
      expect(validateRenderableAlert({ ...ok, summary: `pay${bad}ee` })).toEqual({
        field: "summary",
        reason: "forbidden-character",
      });
    }
  });

  it("allows legitimate RTL letters — isolated at display, not stripped", () => {
    // Hebrew "shalom" — letters, not controls; the client bidi-isolates them
    const shalom = String.fromCodePoint(0x05e9, 0x05dc, 0x05d5, 0x05dd);
    expect(validateRenderableAlert({ ...ok, summary: `${shalom} world` })).toBeNull();
  });

  it("validates the runtime V1 envelope, not just the text fields", () => {
    // unsupported version: a function that hashes V1 must never hash v2
    expect(validateRenderableAlert({ ...ok, v: 2 })).toEqual({
      field: "v",
      reason: "unsupported-version",
    });
    // non-string and missing fields
    expect(validateRenderableAlert({ ...ok, tool: 42 })).toEqual({
      field: "tool",
      reason: "not-a-string",
    });
    const missing: Record<string, unknown> = { ...ok };
    delete missing.summary;
    expect(validateRenderableAlert(missing)).toEqual({
      field: "summary",
      reason: "not-a-string",
    });
    // unexpected properties are refused at the mint boundary
    expect(validateRenderableAlert({ ...ok, extra: "x" })).toEqual({
      field: "envelope",
      reason: "unexpected-property",
    });
    // non-objects are refused outright
    for (const bad of [null, undefined, "alert", 7, [ok]]) {
      expect(validateRenderableAlert(bad)).toEqual({ field: "envelope", reason: "malformed" });
    }
  });
});

describe("assertRenderableAlert", () => {
  it("throws on the first violation, naming the field and reason", () => {
    expect(() => assertRenderableAlert({ ...ok, summary: "x".repeat(201) })).toThrow(
      /summary: too-long/,
    );
    expect(() => assertRenderableAlert({ ...ok, tool: `a${RLO}b` })).toThrow(
      /tool: forbidden-character/,
    );
    expect(() => assertRenderableAlert(ok)).not.toThrow();
  });
});

describe("canonicalRenderableAlert + renderContentHash", () => {
  it("canonicalizes with lexicographically sorted keys and no whitespace", () => {
    expect(canonicalRenderableAlert(ok)).toBe(
      '{"agentId":"agent-7","summary":"Merge PR #7 into main","tool":"github.merge","v":1}',
    );
  });

  it("is independent of input key order", () => {
    const reordered: RenderableAlertV1 = {
      summary: ok.summary,
      v: 1,
      tool: ok.tool,
      agentId: ok.agentId,
    };
    expect(canonicalRenderableAlert(reordered)).toBe(canonicalRenderableAlert(ok));
  });

  it("hashes the canonical envelope (base64url, no padding) — one rendering per revision", async () => {
    const hash = await renderContentHash(ok);
    expect(hash).not.toMatch(/[+/=]/);
    // a different summary is a different hash -> necessarily a different revision
    expect(await renderContentHash({ ...ok, summary: "Merge PR #8 into main" })).not.toBe(hash);
    // identical content -> identical hash
    expect(await renderContentHash({ ...ok })).toBe(hash);
  });

  it("refuses to hash a non-conforming alert or a non-V1 envelope", async () => {
    await expect(renderContentHash({ ...ok, summary: "x".repeat(201) })).rejects.toThrow(
      /too-long/,
    );
    await expect(renderContentHash({ ...ok, v: 2 })).rejects.toThrow(/unsupported-version/);
    await expect(renderContentHash({ ...ok, extra: 1 })).rejects.toThrow(/unexpected-property/);
  });
});
