import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createControlPlane, createOwnerSession } from "@ownerswitchai/control-plane";
import { afterEach, describe, expect, it } from "vitest";

/**
 * The First Kill tutorial's LIFECYCLE regression, the review's exact cut:
 * the HELD → owner veto → VETOED transition exists only on the SAME gateway
 * connection (the callKey → window binding is gateway-process state; a
 * fresh gateway registers a fresh window). So: ONE real gateway child, one
 * MCP client session — hold, veto over the control plane's real HTTP,
 * retry the identical call on the same session, see VETOED, and prove the
 * upstream never wrote. Then prove the child actually exits on close.
 */
const PKG = resolve(__dirname, "..");

const dirs: string[] = [];
const servers: Server[] = [];
afterEach(() => {
  while (servers.length > 0) servers.pop()?.close();
  while (dirs.length > 0) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

const quiet = <T>(build: () => T): T => {
  const original = console.error;
  console.error = () => {};
  try {
    return build();
  } finally {
    console.error = original;
  }
};

describe("first-kill lifecycle E2E — one gateway session end to end", () => {
  it("HELD -> owner veto -> the SAME session's identical retry is VETOED, and the upstream wrote nothing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-first-kill-"));
    dirs.push(dir);
    const sandbox = join(dir, "sandbox");

    // a real control plane on a real socket
    const cp = quiet(() =>
      createControlPlane({
        dev: true,
        killStateFile: null,
        deviceSecret: "e2e-device-secret",
        acceptSessionOnlyApprovalRisk: true,
      }),
    );
    const server = createServer(cp.handler);
    servers.push(server);
    const base = await new Promise<string>((resolvePort) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        if (addr === null || typeof addr === "string") throw new Error("no address");
        resolvePort(`http://127.0.0.1:${addr.port}`);
      });
    });

    // the tutorial's config shape, pointed at this control plane and a
    // per-test sandbox (argv — the gateway strips OWNERSWITCH_* env)
    const configPath = join(dir, "config.json");
    writeFileSync(
      configPath,
      JSON.stringify({
        controlPlaneUrl: base,
        device: { id: "mcp-gateway", secret: "e2e-device-secret" },
        upstream: {
          command: process.execPath,
          args: ["--import", "tsx", "examples/demo-tools-server.ts", sandbox],
        },
        policy: {
          rules: [
            { id: "writes", tool: "write_file", decision: "veto", description: "the owner can veto writes" },
            { id: "reads", tool: "read_*", decision: "allow", description: "reads are safe" },
            { id: "lists", tool: "list_*", decision: "allow", description: "listing is safe" },
            { id: "moves", tool: "move_file", decision: "allow", description: "allowed here to exercise the wrapper" },
          ],
          defaultDecision: "approve",
        },
      }),
      { mode: 0o600 },
    );

    // ONE gateway child (no package-runner chain), ONE client session
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ["--import", "tsx", resolve(PKG, "src", "cli.ts"), "--config", configPath],
      cwd: PKG,
      stderr: "ignore",
    });
    const client = new Client({ name: "first-kill-e2e", version: "0.0.1" });
    await client.connect(transport);
    const pid = transport.pid;
    expect(pid).not.toBeNull();

    const write = () =>
      client.callTool({ name: "write_file", arguments: { name: "hello.txt", content: "hi" } });

    // 1. the write is HELD, naming its window
    const held = await write().then(
      () => null,
      (err: Error) => err.message,
    );
    expect(held).toMatch(/-32052/);
    const windowId = /veto window \(id "([^"]+)"\)/.exec(held ?? "")?.[1];
    expect(windowId).toBeDefined();

    // 2. the owner vetoes it over the control plane's REAL HTTP surface —
    //    the tutorial's exact curl, -fsS semantics included (a non-2xx fails)
    const session = createOwnerSession("owner-e2e");
    const veto = await fetch(`${base}/veto/${windowId}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${session.token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ decision: "veto" }),
    });
    expect(veto.status).toBe(200);
    expect(((await veto.json()) as { status: string }).status).toBe("vetoed");

    // 3. the SAME session retries the IDENTICAL call: VETOED, not a new hold
    const retried = await write().then(
      () => null,
      (err: Error) => err.message,
    );
    expect(retried).toMatch(/-32053/);
    expect(retried).toMatch(/vetoed/i);

    // 4. the upstream executed NOTHING: zero writes reached the sandbox
    expect(existsSync(join(sandbox, "hello.txt"))).toBe(false);

    // 4b. list and move run through the gateway VIA THE SANDBOX WRAPPERS —
    //     the boundary-checked paths, not direct readdir/rename
    const listed = await client.callTool({ name: "list_files", arguments: {} });
    const listedText = (listed.content as Array<{ type: string; text?: string }>)
      .filter((c) => c.type === "text")
      .map((c) => c.text)
      .join(" ");
    expect(listedText).toContain("welcome.txt");
    await client.callTool({ name: "move_file", arguments: { from: "welcome.txt", to: "renamed.txt" } });
    expect(existsSync(join(sandbox, "renamed.txt"))).toBe(true);
    expect(existsSync(join(sandbox, "welcome.txt"))).toBe(false);

    // 5. proven shutdown: the gateway child is GONE after close()
    await client.close();
    const goneBy = Date.now() + 5_000;
    let gone = false;
    while (!gone && Date.now() < goneBy) {
      try {
        process.kill(pid as number, 0);
        await new Promise((r) => setTimeout(r, 50));
      } catch {
        gone = true;
      }
    }
    expect(gone).toBe(true);
  }, 30_000);
});
