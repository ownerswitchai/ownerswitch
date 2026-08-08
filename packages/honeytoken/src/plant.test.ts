import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { plantHoneytokens } from "./plant.js";
import { scanForHoneytokens } from "./scan.js";

let dir: string;

describe("plantHoneytokens", () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "oswt-plant-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("writes .env.backup and credentials.json full of scannable decoys", () => {
    const { files, planted } = plantHoneytokens({ dir });

    expect(files).toEqual([join(dir, ".env.backup"), join(dir, "credentials.json")]);
    expect(planted).toHaveLength(8);
    expect(new Set(planted.map((p) => p.token.canaryId)).size).toBe(8);

    for (const file of files) {
      const content = readFileSync(file, "utf8");
      const expected = planted.filter((p) => p.file === file);
      // every planted value is in the file, under its recorded key…
      for (const p of expected) {
        expect(content).toContain(p.token.value);
        expect(p.token.label).toContain(p.key);
      }
      // …and the scanner recovers exactly that file's canary ids
      expect(scanForHoneytokens(content).map((m) => m.canaryId)).toEqual(
        expected.map((p) => p.token.canaryId),
      );
    }
  });

  it("the env file parses like an env file and the json file like json", () => {
    const { files } = plantHoneytokens({ dir });

    const envLines = readFileSync(files[0], "utf8").split("\n").filter((l) => l !== "");
    for (const line of envLines) {
      expect(line).toMatch(/^(#.*|[A-Z_]+=\S+)$/);
    }
    expect(envLines.some((l) => l.startsWith("AWS_ACCESS_KEY_ID=AKIA"))).toBe(true);
    expect(envLines.some((l) => l.startsWith("STRIPE_SECRET_KEY=sk_live_"))).toBe(true);
    expect(envLines.some((l) => l.startsWith("OPENAI_API_KEY=sk-"))).toBe(true);

    const creds = JSON.parse(readFileSync(files[1], "utf8")) as {
      aws: { access_key_id: string; secret_access_key: string };
      stripe: { secret_key: string };
      openai: { api_key: string };
    };
    expect(creds.aws.access_key_id).toMatch(/^AKIA/);
    expect(creds.stripe.secret_key).toMatch(/^sk_live_/);
    expect(creds.openai.api_key).toMatch(/^sk-/);
  });

  it("refuses to overwrite an existing file — and writes NOTHING when it refuses", () => {
    writeFileSync(join(dir, "credentials.json"), '{"real":"backup"}');

    expect(() => plantHoneytokens({ dir })).toThrow(/refusing to overwrite/);

    // the pre-existing file is intact and no partial plant happened
    expect(readFileSync(join(dir, "credentials.json"), "utf8")).toBe('{"real":"backup"}');
    expect(existsSync(join(dir, ".env.backup"))).toBe(false);
  });

  it("force replaces existing decoys", () => {
    writeFileSync(join(dir, ".env.backup"), "OLD=1\n");
    writeFileSync(join(dir, "credentials.json"), "{}");

    const { files } = plantHoneytokens({ dir, force: true });

    expect(scanForHoneytokens(readFileSync(files[0], "utf8")).length).toBeGreaterThan(0);
    expect(scanForHoneytokens(readFileSync(files[1], "utf8")).length).toBeGreaterThan(0);
  });

  it("creates the directory if it does not exist", () => {
    const nested = join(dir, "deeper", "still");
    const { files } = plantHoneytokens({ dir: nested });
    expect(existsSync(files[0])).toBe(true);
  });
});
