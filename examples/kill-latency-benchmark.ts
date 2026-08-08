/**
 * Benchmark: kill-to-deny latency.
 *
 * Measures exactly what the landing page's speed claim refers to — the
 * elapsed time from POST /kill returning to the gateway's NEXT
 * evaluateRemote() call denying a call that was allowed a moment before.
 * See apps/web/index.html.
 *
 * There is no polling loop or cache to account for: packages/mcp/src/proxy.ts
 * calls evaluateRemote() fresh, per tool call, with a live GET /status lookup
 * every time (see engine.ts / client.ts) — so this number is the gateway's
 * actual per-call control-plane round trip, not an artifact of some poll
 * interval a caller chose. Each iteration spins up a real control plane
 * (createControlPlane, not the ephemeral dev:true mode) with kill state
 * persisted to a real file, so the fsync'd write that POST /kill waits on
 * before responding is included, exactly as it would be in production.
 *
 * Run with: pnpm bench:kill-latency
 */
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControlPlane } from "../packages/control-plane/src/index.js";
import { createControlPlaneClient, evaluateRemote } from "../packages/gateway/src/index.js";
import type { Policy, ToolCall } from "../packages/shared/src/index.js";

const ITERATIONS = 300;

const policy: Policy = {
  rules: [{ id: "reads", tool: "search.*", decision: "allow", description: "reads are safe" }],
  defaultDecision: "deny",
};
const call: ToolCall = { agentId: "bench-agent", tool: "search.web", args: { q: "ownerswitch" } };

async function startServer(): Promise<{ baseUrl: string; close: () => void; dir: string }> {
  const dir = mkdtempSync(join(tmpdir(), "ownerswitch-bench-"));
  // Not dev:true, not an ephemeral store: a real, guarded, fsync'd
  // killStateFile — the same durability path a production control plane
  // pays for on every kill.
  const controlPlane = createControlPlane({ killStateFile: join(dir, "kill-state.json") });
  const server = createServer(controlPlane.handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no address");
  return { baseUrl: `http://127.0.0.1:${addr.port}`, close: () => server.close(), dir };
}

/** One full cycle: fresh control plane, allow -> kill -> deny. Returns the ms between them. */
async function measureOnce(): Promise<number> {
  const { baseUrl, close, dir } = await startServer();
  try {
    const client = createControlPlaneClient({ baseUrl });

    const before = await evaluateRemote(call, policy, client);
    if (before.decision !== "allow") {
      throw new Error(`setup broken: expected allow before kill, got "${before.decision}"`);
    }

    const res = await fetch(`${baseUrl}/kill`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ source: "api", reason: "kill-latency-benchmark" }),
    });
    if (!res.ok) throw new Error(`POST /kill failed: HTTP ${res.status}`);
    await res.text(); // fully drain the response before starting the clock
    const killReturned = performance.now(); // <-- "POST /kill returning"

    const verdict = await evaluateRemote(call, policy, client); // <-- the gateway's NEXT evaluateRemote()
    const denyObserved = performance.now();
    if (verdict.decision !== "deny") {
      throw new Error(`expected deny after kill, got "${verdict.decision}"`);
    }

    return denyObserved - killReturned;
  } finally {
    close();
    rmSync(dir, { recursive: true, force: true });
  }
}

function percentile(sortedAsc: number[], p: number): number {
  const idx = Math.min(sortedAsc.length - 1, Math.floor((p / 100) * sortedAsc.length));
  return sortedAsc[idx];
}

async function main(): Promise<void> {
  const samples: number[] = [];
  for (let i = 0; i < ITERATIONS; i++) {
    samples.push(await measureOnce());
  }
  samples.sort((a, b) => a - b);
  const mean = samples.reduce((a, b) => a + b, 0) / samples.length;

  console.log(`kill-to-deny latency: POST /kill returning -> next evaluateRemote() denying`);
  console.log(`${ITERATIONS} runs, localhost, fresh control plane + fsync'd kill-state file per run\n`);
  console.log(`  mean: ${mean.toFixed(3)}ms`);
  console.log(`  p50:  ${percentile(samples, 50).toFixed(3)}ms`);
  console.log(`  p95:  ${percentile(samples, 95).toFixed(3)}ms`);
  console.log(`  p99:  ${percentile(samples, 99).toFixed(3)}ms`);
  console.log(`  max:  ${percentile(samples, 100).toFixed(3)}ms`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
