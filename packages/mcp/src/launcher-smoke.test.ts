import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

/**
 * SMOKE TEST — the production launchers must run under PLAIN Node from their
 * built `dist/` artifacts. The package `main`/`exports` point at `dist/*.js`
 * for the default condition, so `node dist/<launcher>.js` resolves the
 * workspace packages (@ownerswitchai/gateway, /executor, /control-plane,
 * /honeytoken, /shared) to built JS, not TypeScript source. This test proves
 * that resolution end to end for ALL THREE installed entrypoints: each is
 * spawned with an empty environment and must reach its CONFIG check — NOT die
 * on a module-resolution error (ERR_MODULE_NOT_FOUND / "Cannot find package" /
 * an attempt to import a .ts file). The gateway CLI in particular imports
 * @ownerswitchai/gateway and @ownerswitchai/executor by BARE name, so it
 * exercises those package-main paths the broker/CP launchers do not.
 */

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");

/** Each installed entrypoint, and the config-error shape it reaches with an empty env. */
const LAUNCHERS = [
  { name: "control-plane.js", path: resolve(repoRoot, "packages/mcp/dist/control-plane.js"), reachedConfig: /is required/ },
  { name: "merge-broker-cli.js", path: resolve(repoRoot, "packages/executor/dist/merge-broker-cli.js"), reachedConfig: /is required/ },
  { name: "cli.js (gateway)", path: resolve(repoRoot, "packages/mcp/dist/cli.js"), reachedConfig: /config error|is missing|no config/ },
] as const;

const NOT_RESOLUTION_ERROR = /ERR_MODULE_NOT_FOUND|Cannot find package|Unknown file extension|\.ts['"]?$/m;

describe("production launchers run under plain node from dist", () => {
  beforeAll(() => {
    // In CI the pipeline builds before testing; locally, build on demand so
    // the smoke test is self-contained. Building is idempotent and skipped
    // when the artifacts already exist.
    if (LAUNCHERS.some((l) => !existsSync(l.path))) {
      execFileSync("pnpm", ["-r", "build"], { cwd: repoRoot, stdio: "ignore" });
    }
  }, 300_000);

  const runWithEnv = (scriptPath: string, env: Record<string, string>) =>
    spawnSync(process.execPath, [scriptPath], { env, encoding: "utf8", timeout: 20_000 });

  for (const launcher of LAUNCHERS) {
    it(`${launcher.name} loads its workspace deps and fails on missing config`, () => {
      expect(existsSync(launcher.path)).toBe(true);
      // DELIBERATELY empty env (only PATH so node is findable): resolution must
      // succeed far enough to reach the config check.
      const res = runWithEnv(launcher.path, { PATH: process.env.PATH ?? "" });
      const output = `${res.stdout ?? ""}${res.stderr ?? ""}`;
      expect(output).not.toMatch(NOT_RESOLUTION_ERROR);
      expect(output).toMatch(launcher.reachedConfig);
      expect(res.status).not.toBe(0);
    });
  }

  // R10-3: the secret-holding services refuse to start if a Node PRELOAD
  // vector is present, so a service unit that left NODE_OPTIONS/NODE_PATH set
  // fails LOUDLY rather than running injected code in-process with the keys.
  for (const name of ["NODE_OPTIONS", "NODE_PATH"] as const) {
    it(`control-plane and broker refuse to start when ${name} is set`, () => {
      const value = name === "NODE_OPTIONS" ? "--max-old-space-size=256" : "/tmp";
      for (const path of [LAUNCHERS[0].path, LAUNCHERS[1].path]) {
        const res = runWithEnv(path, { PATH: process.env.PATH ?? "", [name]: value });
        const output = `${res.stdout ?? ""}${res.stderr ?? ""}`;
        expect(output).toMatch(new RegExp(`${name}[\\s\\S]*refusing to start`));
        expect(res.status).not.toBe(0);
      }
    });
  }
});
