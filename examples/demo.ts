/**
 * End-to-end demo: gateway → control plane over HTTP.
 *
 * Starts the control-plane server on an ephemeral port, evaluates three tool
 * calls through evaluateRemote (live /status lookup on every call), then
 * engages the kill switch via POST /kill and shows that even the previously
 * allowed read now comes back deny.
 *
 * Run with: pnpm demo
 */
import { createServer } from "node:http";
import { createControlPlane } from "../packages/control-plane/src/index.js";
import { createControlPlaneClient, evaluateRemote } from "../packages/gateway/src/index.js";
import type { Policy, ToolCall, Verdict } from "../packages/shared/src/index.js";

const policy: Policy = {
  rules: [
    { id: "reads", tool: "search.*", decision: "allow", description: "reads are safe" },
    { id: "merges", tool: "github.merge_pr", decision: "veto", description: "owner can veto merges" },
    { id: "money", tool: "stripe.*", decision: "approve", description: "money moves need the owner" },
  ],
  defaultDecision: "approve",
};

const calls: ToolCall[] = [
  { agentId: "demo-agent", tool: "search.web", args: { q: "ownerswitch" } },
  { agentId: "demo-agent", tool: "github.merge_pr", args: { repo: "ownerswitchai/app", pr: 42 } },
  { agentId: "demo-agent", tool: "stripe.payout", args: { amountUsd: 25_000 } },
];

function startServer(): Promise<{ baseUrl: string; close: () => void }> {
  // Dev + ephemeral on purpose: the demo must reset fully on every run. A
  // real deployment omits dev and must configure a protected killStateFile.
  const controlPlane = createControlPlane({ dev: true, killStateFile: null });
  const server = createServer(controlPlane.handler);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") throw new Error("no address");
      resolve({ baseUrl: `http://127.0.0.1:${addr.port}`, close: () => server.close() });
    });
  });
}

const show = (call: ToolCall, verdict: Verdict) =>
  console.log(`  ${call.tool.padEnd(18)} -> ${verdict.decision.padEnd(7)} (${verdict.reason})`);

async function main(): Promise<void> {
  const { baseUrl, close } = await startServer();
  console.log(`control plane listening at ${baseUrl}\n`);

  const client = createControlPlaneClient({ baseUrl });

  console.log("before kill:");
  for (const call of calls) {
    show(call, await evaluateRemote(call, policy, client));
  }

  console.log("\nPOST /kill — the owner hits the red button");
  await fetch(`${baseUrl}/kill`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ source: "button", reason: "owner pressed the red button" }),
  });

  console.log("\nafter kill (same allowed read):");
  show(calls[0], await evaluateRemote(calls[0], policy, client));

  close();
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
