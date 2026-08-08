import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { plantHoneytokens } from "./plant.js";

const CANARY_KEY = "canary-key-plant-test-0011223344556677";
const DEPLOY = "deploy-plant";

let dir: string;
const plant = (opts: { force?: boolean } = {}) =>
  plantHoneytokens({ dir, canaryKey: CANARY_KEY, deploymentId: DEPLOY, ...opts });

describe("plantHoneytokens", () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "oswt-plant-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("writes .env.backup and credentials.json and a matching registry", () => {
    const { files, planted, registry } = plant();

    expect(files).toEqual([join(dir, ".env.backup"), join(dir, "credentials.json")]);
    expect(planted).toHaveLength(8);
    expect(new Set(planted.map((p) => p.token.canaryId)).size).toBe(8);
    expect(registry.size).toBe(8);

    for (const file of files) {
      const content = readFileSync(file, "utf8");
      const expected = planted.filter((p) => p.file === file);
      for (const p of expected) {
        expect(content).toContain(p.token.value);
        expect(p.token.label).toContain(p.key);
      }
      // the registry recovers exactly that file's canary ids from its content
      expect(registry.match(content).map((m) => m.canaryId)).toEqual(
        expected.map((p) => p.token.canaryId),
      );
    }
  });

  it("the env file parses like an env file and the json file like json", () => {
    const { files } = plant();

    const envLines = readFileSync(files[0], "utf8").split("\n").filter((l) => l !== "");
    for (const line of envLines) expect(line).toMatch(/^(#.*|[A-Z_]+=\S+)$/);
    expect(envLines.some((l) => l.startsWith("AWS_ACCESS_KEY_ID=AKIA"))).toBe(true);
    expect(envLines.some((l) => l.startsWith("STRIPE_SECRET_KEY=sk_live_"))).toBe(true);

    const creds = JSON.parse(readFileSync(files[1], "utf8")) as {
      aws: { access_key_id: string };
      openai: { api_key: string };
    };
    expect(creds.aws.access_key_id).toMatch(/^AKIA/);
    expect(creds.openai.api_key).toMatch(/^sk-/);
  });

  it("a weak canary key is rejected before any bait is written", () => {
    expect(() => plantHoneytokens({ dir, canaryKey: "changeme", deploymentId: DEPLOY })).toThrow();
    expect(existsSync(join(dir, ".env.backup"))).toBe(false);
  });

  it("refuses to overwrite an existing file — and writes NOTHING when it refuses", () => {
    writeFileSync(join(dir, "credentials.json"), '{"real":"backup"}');
    expect(() => plant()).toThrow(/refusing to overwrite/);
    expect(readFileSync(join(dir, "credentials.json"), "utf8")).toBe('{"real":"backup"}');
    expect(existsSync(join(dir, ".env.backup"))).toBe(false);
  });

  it("force replaces existing decoys", () => {
    writeFileSync(join(dir, ".env.backup"), "OLD=1\n");
    writeFileSync(join(dir, "credentials.json"), "{}");
    const { registry, files } = plant({ force: true });
    expect(registry.match(readFileSync(files[0], "utf8")).length).toBeGreaterThan(0);
  });

  it("creates the directory if it does not exist", () => {
    dir = join(dir, "deeper", "still");
    const { files } = plant();
    expect(existsSync(files[0])).toBe(true);
  });
});
