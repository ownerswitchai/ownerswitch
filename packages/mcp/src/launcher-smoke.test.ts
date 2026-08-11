import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

/**
 * SMOKE TEST — the two production launchers must run under PLAIN Node from
 * their built `dist/` artifacts. The package `main`/`exports` point at
 * `dist/index.js` for the default condition, so `node dist/<launcher>.js`
 * resolves the workspace packages to built JS, not TypeScript source. This
 * test proves that resolution end to end: each launcher is spawned with an
 * empty environment and must exit with a CONFIG error (a missing required
 * variable) — NOT a module-resolution error (ERR_MODULE_NOT_FOUND /
 * "Cannot find package" / an attempt to import a .ts file). Without the
 * packaging fix, plain Node would try to load `src/index.ts` and die on the
 * TypeScript syntax.
 */

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const controlPlane = resolve(repoRoot, "packages/mcp/dist/control-plane.js");
const broker = resolve(repoRoot, "packages/executor/dist/merge-broker-cli.js");

describe("production launchers run under plain node from dist", () => {
  beforeAll(() => {
    // In CI the pipeline builds before testing; locally, build on demand so
    // the smoke test is self-contained. Building is idempotent and skipped
    // when the artifacts already exist.
    if (!existsSync(controlPlane) || !existsSync(broker)) {
      execFileSync("pnpm", ["-r", "build"], { cwd: repoRoot, stdio: "ignore" });
    }
  }, 300_000);

  const runsToConfigError = (scriptPath: string): void => {
    expect(existsSync(scriptPath)).toBe(true);
    // spawn with a DELIBERATELY empty env (only PATH so node is findable):
    // resolution must succeed far enough to reach the config check
    const res = spawnSync(process.execPath, [scriptPath], {
      env: { PATH: process.env.PATH ?? "" },
      encoding: "utf8",
      timeout: 20_000,
    });
    const output = `${res.stdout ?? ""}${res.stderr ?? ""}`;
    // it must NOT be a module-resolution failure
    expect(output).not.toMatch(/ERR_MODULE_NOT_FOUND|Cannot find package|Unknown file extension|\.ts['"]?$/m);
    // it MUST have loaded and reached the config validation
    expect(output).toMatch(/is required/);
    expect(res.status).not.toBe(0);
  };

  it("control-plane.js loads its workspace deps and fails on missing config", () => {
    runsToConfigError(controlPlane);
  });

  it("merge-broker-cli.js loads its workspace deps and fails on missing config", () => {
    runsToConfigError(broker);
  });
});
