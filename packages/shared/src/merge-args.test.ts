import { describe, expect, it } from "vitest";
import { canonicalJson } from "./merge-grant.js";
import { buildRenderableApproval, isSafeToDisplay, parseMergePrArgs } from "./merge-args.js";

const SHA = "a".repeat(40);
const VALID = { owner: "o", repo: "r", pullNumber: 7, expectedHeadSha: SHA, expectedBaseRef: "main" };

describe("parseMergePrArgs — the CLOSED canonical merge schema", () => {
  it("parses the exact allowed shape, with and without mergeMethod", () => {
    expect(parseMergePrArgs(canonicalJson(VALID))).toEqual(VALID);
    expect(parseMergePrArgs(canonicalJson({ ...VALID, mergeMethod: "squash" }))).toEqual({
      ...VALID,
      mergeMethod: "squash",
    });
  });

  it("REFUSES unknown keys — extra fields are never silently ignored", () => {
    for (const extra of [{ dryRun: true }, { base: "main" }, { sha: SHA }]) {
      expect(() => parseMergePrArgs(canonicalJson({ ...VALID, ...extra }))).toThrowError(
        /unknown argument/,
      );
    }
  });

  it("refuses a missing or malformed expectedBaseRef — the destination pin is mandatory too", () => {
    const { expectedBaseRef: _base, ...withoutBase } = VALID;
    expect(() => parseMergePrArgs(canonicalJson(withoutBase))).toThrowError(/expectedBaseRef/);
    for (const bad of ["", "a".repeat(301), "evil\u0000ref"]) {
      expect(() =>
        parseMergePrArgs(canonicalJson({ ...VALID, expectedBaseRef: bad })),
      ).toThrowError(/expectedBaseRef/);
    }
  });

  it("refuses a missing or malformed expectedHeadSha — the pin is mandatory", () => {
    const { expectedHeadSha: _sha, ...withoutSha } = VALID;
    expect(() => parseMergePrArgs(canonicalJson(withoutSha))).toThrowError(/expectedHeadSha/);
    expect(() =>
      parseMergePrArgs(canonicalJson({ ...VALID, expectedHeadSha: "abc123" })),
    ).toThrowError(/expectedHeadSha/);
  });

  it("refuses an unknown mergeMethod and malformed scalar fields", () => {
    expect(() => parseMergePrArgs(canonicalJson({ ...VALID, mergeMethod: "fast-forward" }))).toThrowError(
      /mergeMethod/,
    );
    expect(() => parseMergePrArgs(canonicalJson({ ...VALID, pullNumber: 0 }))).toThrowError(
      /pullNumber/,
    );
    expect(() => parseMergePrArgs(canonicalJson({ ...VALID, owner: "" }))).toThrowError(/owner/);
  });

  it("refuses non-object and non-JSON input", () => {
    expect(() => parseMergePrArgs("not json")).toThrowError(/not valid JSON/);
    expect(() => parseMergePrArgs("[1,2]")).toThrowError(/JSON object/);
    expect(() => parseMergePrArgs("null")).toThrowError(/JSON object/);
  });
});

describe("isSafeToDisplay + buildRenderableApproval — the owner-display contract", () => {
  const RTL_OVERRIDE = "‮"; // U+202E, reorders the visible identifier
  it("accepts ordinary identifiers and rejects bidi/format/control/non-NFC", () => {
    expect(isSafeToDisplay("main")).toBe(true);
    expect(isSafeToDisplay("release-1.2")).toBe(true);
    expect(isSafeToDisplay(`ma${RTL_OVERRIDE}in`)).toBe(false);
    // property-based rejection catches what an enumerated range missed:
    // ARABIC LETTER MARK, SOFT HYPHEN, MONGOLIAN VOWEL SEPARATOR, interlinear
    // annotation anchors, plus the classics (ZWSP, BOM, separators, isolate)
    for (const cp of [0x061c, 0x00ad, 0x180e, 0xfff9, 0xfffb, 0x200b, 0xfeff, 0x2028, 0x2029, 0x2066, 0x2060, 0x7f, 0x85]) {
      expect(isSafeToDisplay(`x${String.fromCodePoint(cp)}y`)).toBe(false);
    }
    // an ASTRAL default-ignorable (a TAG character, U+E0041) is rejected too
    expect(isSafeToDisplay(`x${String.fromCodePoint(0xe0041)}y`)).toBe(false);
    // a decomposed form (NFD "e"+combining acute) is not NFC-idempotent
    expect(isSafeToDisplay("café")).toBe(false);
  });

  it("expectedBaseRef refuses a bidi-override branch name", () => {
    expect(() =>
      parseMergePrArgs(canonicalJson({ ...VALID, expectedBaseRef: `ma${RTL_OVERRIDE}in` })),
    ).toThrowError(/expectedBaseRef/);
  });

  it("builds a typed per-field renderable, and refuses to render an unsafe field", () => {
    const r = buildRenderableApproval(
      parseMergePrArgs(canonicalJson({ ...VALID, mergeMethod: "squash" })),
    );
    expect(r).toEqual({
      v: 1,
      action: "github.merge_pull_request",
      owner: "o",
      repo: "r",
      pullNumber: 7,
      expectedHeadSha: SHA,
      expectedBaseRef: "main",
      mergeMethod: "squash",
    });
    expect(() => buildRenderableApproval({ ...VALID, repo: `ev${RTL_OVERRIDE}il` })).toThrowError(
      /not safe to display/,
    );
  });
});
