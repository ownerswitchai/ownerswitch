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
  const doc = readFileSync(resolve(__dirname, "..", "..", "..", "FIRST-KILL.md"), "utf8");

  it("no code fence contains a backslash line continuation", () => {
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

  it("no bash fence contains a # anywhere — zsh runs pasted comments as commands", () => {
    // A default macOS zsh has no INTERACTIVE_COMMENTS: a pasted line
    // starting with "#" errors, and a TRAILING comment on an assignment
    // makes the assignment a command-scoped prefix — the variable ends up
    // unset. Fences are commands only; narration lives in prose.
    const offenders: string[] = [];
    let inBashFence = false;
    doc.split("\n").forEach((line, i) => {
      if (line.startsWith("```")) {
        inBashFence = !inBashFence && line.trimEnd() === "```bash";
        return;
      }
      if (inBashFence && line.includes("#")) {
        offenders.push(`FIRST-KILL.md:${i + 1}: ${line.trim()}`);
      }
    });
    expect(offenders).toEqual([]);
  });
});
