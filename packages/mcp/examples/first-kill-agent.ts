/**
 * The DEMO AGENT for the First Kill tutorial — a real MCP client that
 * spawns the OwnerSwitch gateway (which spawns the demo tools server), then
 * tries a scripted set of tool calls and prints, honestly, what the gateway
 * answered. No AI, no API key, no external MCP client install: this is the
 * smallest thing that behaves like an agent on the wire, so you can watch
 * OwnerSwitch allow, hold, veto, deny, and kill it.
 *
 * The session is ONE gateway connection end to end — that matters: a held
 * call's veto window lives in this gateway process, so the HELD → owner
 * veto → VETOED transition is only observable on the SAME connection. After
 * the held write the agent prints the window id and waits for you to veto
 * (Enter to continue); then it retries the exact same call and shows the
 * verdict. Non-interactive runs (no TTY, or --no-wait) skip the pause.
 *
 * Run from packages/mcp (terminal 2, with the dev control plane up in
 * terminal 1):
 *   npx tsx examples/first-kill-agent.ts
 *   npx tsx examples/first-kill-agent.ts --config /path/to/your.config.json
 */
import { createInterface } from "node:readline/promises";
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
const interactive = process.stdin.isTTY === true && !process.argv.includes("--no-wait");

// The gateway is spawned as ONE node process (node --import tsx), not
// through a package-runner chain: the README documents how npx/pnpm
// indirection leaves orphaned descendants when a client tears the
// connection down — a demo must be able to PROVE its child exited.
const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["--import", "tsx", resolve(here, "..", "src", "cli.ts"), "--config", config],
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

type Outcome = { kind: string; message: string };

/** try one call; return + print the verdict the way an agent experiences it */
async function attempt(tool: string, args: Record<string, unknown>): Promise<Outcome> {
  const label = `${tool}(${JSON.stringify(args)})`;
  try {
    const result = await client.callTool({ name: tool, arguments: args });
    const text = (result.content as Array<{ type: string; text?: string }> | undefined)
      ?.filter((c) => c.type === "text")
      .map((c) => c.text)
      .join(" ");
    console.log(`  RAN     ${label}\n          -> ${text ?? "(no text)"}`);
    return { kind: "RAN", message: text ?? "" };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const kind = /-32052/.test(message)
      ? "HELD"
      : /-32053/.test(message)
        ? "VETOED"
        : /-32050/.test(message)
          ? "DENIED"
          : /-32051/.test(message)
            ? "NEEDS-OK"
            : /-32054/.test(message)
              ? "KILLED"
              : "ERROR";
    console.log(`  ${kind.padEnd(8)}${label}\n          -> ${message.split("\n")[0]}`);
    return { kind, message };
  }
}

console.log("the demo agent tries its day's work:\n");
await attempt("list_files", {});
await attempt("read_file", { name: "welcome.txt" });
const write = await attempt("write_file", { name: "hello.txt", content: "hi from the demo agent" });
await attempt("move_file", { from: "welcome.txt", to: "renamed.txt" });

// THE OWNER'S TURN — on the same live session, because the veto window
// belongs to THIS gateway process: veto it now, and the retry below shows
// the held call staying blocked.
let retry: Outcome | null = null;
if (write.kind === "HELD") {
  const windowId = /veto window \(id "([^"]+)"\)/.exec(write.message)?.[1];
  if (windowId !== undefined && interactive) {
    console.log(
      `\nthe write is HELD in veto window "${windowId}". Be the owner — in another terminal:\n\n` +
        `  curl -fsS -X POST http://127.0.0.1:4600/veto/${windowId} \\\n` +
        `    -H "Authorization: Bearer $OWNERSWITCH_OWNER_TOKEN" \\\n` +
        `    -H 'content-type: application/json' -d '{"decision":"veto"}'\n`,
    );
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    await rl.question("press Enter after the veto (or Enter to just retry): ");
    rl.close();
    console.log("\nthe agent retries the exact same write:\n");
    retry = await attempt("write_file", { name: "hello.txt", content: "hi from the demo agent" });
  } else if (windowId !== undefined) {
    console.log(
      `\n(non-interactive run: veto window "${windowId}" is open — veto it and retry on the same\n` +
        "session to see VETOED; the interactive run walks this step)",
    );
  }
}

// the closing summary tells the truth about THIS run, not the ideal one
const writeStory =
  retry?.kind === "VETOED"
    ? "write_file was HELD and — once you vetoed — stayed VETOED on retry"
    : retry?.kind === "HELD"
      ? "write_file was HELD, and without a veto the retry is STILL HELD (the window is yours to decide)"
      : retry?.kind === "RAN"
        ? "write_file was HELD and, released, RAN on retry"
        : write.kind === "KILLED"
          ? "every call was KILLED"
          : "write_file was HELD (veto it and retry on a live session to see VETOED)";
console.log(
  `\nwhat you just saw: reads/lists RAN (allow), ${writeStory}, move_file was DENIED\n` +
    "by policy; after a kill, EVERYTHING comes back KILLED. The gateway told the agent\n" +
    "exactly why, every time.",
);

// PROVEN shutdown, not a blind exit: close the session, then verify the
// gateway child actually exited (it has no package-runner chain to orphan).
const pid = transport.pid;
await client.close();
if (pid !== null) {
  const gone = () => {
    try {
      process.kill(pid, 0);
      return false;
    } catch {
      return true;
    }
  };
  const deadline = Date.now() + 3_000;
  while (!gone() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 50));
  }
  if (!gone()) {
    console.error(`gateway child ${pid} survived close() — killing it (this would be a bug, tell us)`);
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* raced its exit */
    }
    process.exitCode = 1;
  }
}
process.stdin.unref?.();
