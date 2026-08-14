/**
 * DEMO upstream for the First Kill tutorial — a tiny, real stdio MCP server
 * with four file tools over ONE sandbox directory. It exists so the
 * quickstart has an upstream with ZERO network dependency: the documented
 * `npx -y @modelcontextprotocol/server-filesystem` alternative downloads a
 * package on first run, which on a fresh machine can blow straight through
 * the gateway's (and doctor's) MCP-handshake timeout.
 *
 * The sandbox rules live in demo-sandbox.ts (imported below, and covered by
 * regression tests): real-directory 0700 root, single-basename names,
 * O_NOFOLLOW opens — a planted symlink refuses instead of reaching outside
 * the directory. This keeps the demo honest about staying in its sandbox;
 * the OwnerSwitch enforcement boundary is still the gateway in front.
 *
 * Run by the gateway (see examples/first-kill.config.json), or by hand:
 *   npx tsx examples/demo-tools-server.ts
 */
import { readdirSync, renameSync } from "node:fs";
import { resolve } from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import {
  ensureSandboxRoot,
  readSandboxFile,
  seedSandboxFile,
  validateName,
  writeSandboxFile,
} from "../src/demo-sandbox.js";

// sandbox dir: argv wins (the gateway strips OWNERSWITCH_* from the
// upstream's env on purpose, so an env override would never arrive through
// it), then env for direct runs, then the tutorial default
const DEMO_DIR = ensureSandboxRoot(
  process.argv[2] ?? process.env.OWNERSWITCH_DEMO_DIR ?? "/tmp/ownerswitch-demo",
);
// seed one file so the demo agent's first read has something real to read
seedSandboxFile(DEMO_DIR, "welcome.txt", "OwnerSwitch demo sandbox — feel free to delete.\n");

const asText = (text: string) => ({ content: [{ type: "text" as const, text }] });

const server = new Server(
  { name: "ownerswitch-demo-tools", version: "0.0.1" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "list_files",
      description: `List the files in the demo directory (${DEMO_DIR}).`,
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
    },
    {
      name: "read_file",
      description: "Read a file from the demo directory.",
      inputSchema: {
        type: "object",
        properties: { name: { type: "string", description: "file name" } },
        required: ["name"],
        additionalProperties: false,
      },
    },
    {
      name: "write_file",
      description: "Write a file in the demo directory.",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string", description: "file name" },
          content: { type: "string", description: "file content" },
        },
        required: ["name", "content"],
        additionalProperties: false,
      },
    },
    {
      name: "move_file",
      description: "Rename a file inside the demo directory.",
      inputSchema: {
        type: "object",
        properties: {
          from: { type: "string", description: "current name" },
          to: { type: "string", description: "new name" },
        },
        required: ["from", "to"],
        additionalProperties: false,
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, string>;
  switch (req.params.name) {
    case "list_files": {
      const names = readdirSync(DEMO_DIR);
      return asText(names.length === 0 ? "(empty)" : names.join("\n"));
    }
    case "read_file":
      return asText(readSandboxFile(DEMO_DIR, args.name));
    case "write_file": {
      const bytes = writeSandboxFile(DEMO_DIR, args.name, args.content);
      return asText(`wrote ${args.name} (${bytes} bytes)`);
    }
    case "move_file": {
      // rename moves the directory ENTRY (a planted symlink moves as a
      // link, its target untouched); both names pass the basename rule
      renameSync(resolve(DEMO_DIR, validateName(args.from)), resolve(DEMO_DIR, validateName(args.to)));
      return asText(`moved ${args.from} -> ${args.to}`);
    }
    default:
      throw new Error(`unknown tool "${req.params.name}"`);
  }
});

await server.connect(new StdioServerTransport());
