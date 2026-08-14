/**
 * DEMO upstream for the First Kill tutorial — a tiny, real stdio MCP server
 * with four file tools over ONE sandbox directory. It exists so the
 * quickstart has an upstream with ZERO network dependency: the documented
 * `npx -y @modelcontextprotocol/server-filesystem` alternative downloads a
 * package on first run, which on a fresh machine can blow straight through
 * the gateway's (and doctor's) MCP-handshake timeout.
 *
 * This is a DEMO: the sandbox containment below keeps the demo agent inside
 * its directory, but nothing here is part of the OwnerSwitch enforcement
 * boundary — the gateway in front of it is the product.
 *
 * Run by the gateway (see examples/first-kill.config.json), or by hand:
 *   npx tsx examples/demo-tools-server.ts
 */
import { mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { resolve, sep } from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const DEMO_DIR = resolve(process.env.OWNERSWITCH_DEMO_DIR ?? "/tmp/ownerswitch-demo");
mkdirSync(DEMO_DIR, { recursive: true });
// seed one file so the demo agent's first read has something real to read
try {
  writeFileSync(resolve(DEMO_DIR, "welcome.txt"), "OwnerSwitch demo sandbox — feel free to delete.\n", {
    flag: "wx",
  });
} catch {
  /* already seeded */
}

/** every path stays inside the sandbox — a demo should not write your $HOME */
function inSandbox(name: string): string {
  const full = resolve(DEMO_DIR, name);
  if (full !== DEMO_DIR && !full.startsWith(DEMO_DIR + sep)) {
    throw new Error(`path escapes the demo sandbox: ${name}`);
  }
  return full;
}

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
      return asText(readFileSync(inSandbox(args.name), "utf8"));
    case "write_file": {
      writeFileSync(inSandbox(args.name), args.content, "utf8");
      return asText(`wrote ${args.name} (${Buffer.byteLength(args.content, "utf8")} bytes)`);
    }
    case "move_file": {
      renameSync(inSandbox(args.from), inSandbox(args.to));
      return asText(`moved ${args.from} -> ${args.to}`);
    }
    default:
      throw new Error(`unknown tool "${req.params.name}"`);
  }
});

await server.connect(new StdioServerTransport());
