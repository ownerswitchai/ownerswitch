/**
 * The DEMO AGENT for the First Kill tutorial — a real MCP client that
 * spawns the OwnerSwitch gateway (which spawns the demo tools server), then
 * tries a scripted set of tool calls and prints, honestly, what the gateway
 * answered. No AI, no API key, no external MCP client install: this is the
 * smallest thing that behaves like an agent on the wire, so you can watch
 * OwnerSwitch allow, hold, deny, and kill it.
 *
 * Run from packages/mcp (terminal 2, with the dev control plane up in
 * terminal 1):
 *   npx tsx examples/first-kill-agent.ts
 *   npx tsx examples/first-kill-agent.ts --config /path/to/your.config.json
 */
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const here = resolve(fileURLToPath(import.meta.url), "..");
let config = resolve(here, "first-kill.config.json");
const flag = process.argv.indexOf("--config");
if (flag !== -1) {
  const value = process.argv[flag + 1];
  if (value === undefined) {
    console.error("--config needs a file path");
    process.exit(1);
  }
  config = resolve(value);
}

// the agent speaks to the GATEWAY; the gateway spawns the demo tools server
const transport = new StdioClientTransport({
  command: "npx",
  args: ["tsx", resolve(here, "..", "src", "cli.ts"), "--config", config],
  cwd: resolve(here, ".."),
  stderr: "inherit", // the gateway's startup line prints straight through
});
const client = new Client({ name: "first-kill-demo-agent", version: "0.0.1" });

try {
  await client.connect(transport);
} catch (err) {
  console.error("could not connect to the gateway:", err instanceof Error ? err.message : err);
  console.error("→ is the dev control plane running? (terminal 1: pnpm --filter @ownerswitchai/mcp dev:control-plane)");
  console.error("→ run the preflight: npx tsx src/cli.ts doctor --config " + config);
  process.exit(1);
}

const tools = await client.listTools();
console.log(`connected through the gateway — upstream offers: ${tools.tools.map((t) => t.name).join(", ")}\n`);

/** try one call; print the verdict the way an agent would experience it */
async function attempt(tool: string, args: Record<string, unknown>): Promise<void> {
  const label = `${tool}(${JSON.stringify(args)})`;
  try {
    const result = await client.callTool({ name: tool, arguments: args });
    const text = (result.content as Array<{ type: string; text?: string }> | undefined)
      ?.filter((c) => c.type === "text")
      .map((c) => c.text)
      .join(" ");
    console.log(`  RAN     ${label}\n          -> ${text ?? "(no text)"}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const kind = /-32052/.test(message)
      ? "HELD    " // veto window open — the owner has minutes to stop it
      : /-32053/.test(message)
        ? "VETOED  "
        : /-32050/.test(message)
          ? "DENIED  "
          : /-32051/.test(message)
            ? "NEEDS-OK"
            : /-32054/.test(message)
              ? "KILLED  "
              : "ERROR   ";
    console.log(`  ${kind}${label}\n          -> ${message.split("\n")[0]}`);
  }
}

console.log("the demo agent tries its day's work:\n");
await attempt("list_files", {});
await attempt("read_file", { name: "welcome.txt" });
await attempt("write_file", { name: "hello.txt", content: "hi from the demo agent" });
await attempt("move_file", { from: "welcome.txt", to: "renamed.txt" });

console.log(
  "\nwhat you just saw: reads/lists RAN (allow), write_file was HELD or VETOED\n" +
    "(the owner decides), move_file was DENIED by policy — or, after the kill,\n" +
    "EVERYTHING came back KILLED. The gateway told the agent exactly why, every time.",
);

await client.close();
// the npx→tsx chain under the gateway can outlive the closed transport (the
// same indirection the README warns about) — a demo must not leave orphans
process.exit(0);
