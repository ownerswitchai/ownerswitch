import { describe, expect, it } from "vitest";
import { canonicalJson } from "./merge-grant.js";
import { parseMergePrArgs } from "./merge-args.js";

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
