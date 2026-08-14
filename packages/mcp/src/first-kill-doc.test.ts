import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The Beta 1 measurement watched macOS Terminal repeatedly mangle
 * multi-line backslash pastes of the walkthrough's commands — an export
 * line and a curl merged into each other mid-paste, twice. Every command a
 * human is told to paste is therefore ONE line, and this test keeps a
 * future reflow of the document from quietly undoing that.
 */
describe("FIRST-KILL.md paste safety", () => {
  it("no code fence contains a backslash line continuation", () => {
    const doc = readFileSync(resolve(__dirname, "..", "..", "..", "FIRST-KILL.md"), "utf8");
    const offenders: string[] = [];
    let inFence = false;
    doc.split("\n").forEach((line, i) => {
      if (line.startsWith("```")) {
        inFence = !inFence;
        return;
      }
      if (inFence && line.trimEnd().endsWith("\\")) {
        offenders.push(`FIRST-KILL.md:${i + 1}: ${line.trim()}`);
      }
    });
    expect(offenders).toEqual([]);
  });
});
