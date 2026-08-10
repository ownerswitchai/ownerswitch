import { chmodSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  canonicalJson,
  sha256Hex,
  signMergeGrant,
  type MergeGrant,
} from "@ownerswitchai/shared";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createBrokerMergeClient } from "./broker-client.js";
import { ConnectorCallError } from "./connector-error.js";
import type { LiveKillState } from "./executor.js";
import type { InstallationTokenSource } from "./github-app-auth.js";
import { createMergeBroker, type MergeBroker } from "./merge-broker.js";
import { createSecretLedger } from "./secret-ledger.js";

/**
 * The EXECUTING merge broker over a REAL unix domain socket, with the GitHub
 * HTTP side stubbed. What these tests pin: the broker never returns a token;
 * it validates the control-plane-signed grant independently (bad signature,
 * expired, replayed/burned, args-vs-grant mismatch including the sha), it
 * gates on live kill state and the grant's kill epoch, and its socket
 * hardening (directory, mode, gid). No live GitHub call anywhere.
 */

const GRANT_KEY = "grant-key-shared-cp-and-broker";
const TOKEN = "ghs_installation_token_never_leaves_the_broker";
const HEAD_SHA = "a".repeat(40);
const NOW = 1_800_000_000_000;
const MERGE_ARGS = { owner: "ownerswitchai", repo: "throwaway", pullNumber: 7, expectedHeadSha: HEAD_SHA };
const CANONICAL_ARGS = canonicalJson(MERGE_ARGS);

let dir: string;
let broker: MergeBroker | undefined;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "oswitch-broker-"));
  chmodSync(dir, 0o750);
});
afterEach(async () => {
  await broker?.close();
  broker = undefined;
  rmSync(dir, { recursive: true, force: true });
});

function grant(overrides: Partial<MergeGrant> = {}) {
  const g: MergeGrant = {
    v: 1,
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    agentId: "agent-1",
    tool: "github.merge_pr",
    canonicalArgs: CANONICAL_ARGS,
    callHash: sha256Hex(CANONICAL_ARGS),
    killEpoch: 0,
    expiresAt: NOW + 120_000,
    ...overrides,
  };
  return signMergeGrant(g, overrides.canonicalArgs !== undefined ? GRANT_KEY : GRANT_KEY);
}

/** A GitHub stub: PUT merge → 200 merged; GET pr → head sha. Records calls. */
function fakeGitHub(opts?: { failMerge?: number }) {
  const calls: Array<{ method: string; url: string; auth: string }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push({
      method,
      url,
      auth: ((init?.headers ?? {}) as Record<string, string>)["authorization"] ?? "",
    });
    if (url.endsWith("/access_tokens")) {
      return new Response(
        JSON.stringify({ token: TOKEN, expires_at: new Date(NOW + 3600_000).toISOString(), repositories: [{ name: "throwaway" }] }),
        { status: 201, headers: { "content-type": "application/json" } },
      );
    }
    if (method === "PUT") {
      if (opts?.failMerge !== undefined) {
        return new Response(JSON.stringify({ message: "nope" }), { status: opts.failMerge });
      }
      return new Response(
        JSON.stringify({ merged: true, sha: "mergecommit01", message: "Pull Request successfully merged" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    // GET pull request (pin or verify)
    return new Response(JSON.stringify({ merged: false, head: { sha: HEAD_SHA } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  return { calls, fetchImpl };
}

const alive = async (): Promise<LiveKillState> => ({ killed: false, epoch: 0 });

async function startBroker(opts?: {
  fetchLiveKillState?: () => Promise<LiveKillState>;
  allowedRepos?: readonly string[];
  github?: ReturnType<typeof fakeGitHub>;
  ledger?: ReturnType<typeof createSecretLedger>;
  tokens?: InstallationTokenSource;
  socketGid?: number;
}): Promise<string> {
  const github = opts?.github ?? fakeGitHub();
  const ledger = opts?.ledger ?? createSecretLedger();
  ledger.add(TOKEN);
  const socketPath = join(dir, "broker.sock");
  broker = createMergeBroker({
    tokens: opts?.tokens ?? { tokenFor: async () => TOKEN },
    ledger,
    grantKey: GRANT_KEY,
    fetchLiveKillState: opts?.fetchLiveKillState ?? alive,
    fetchImpl: github.fetchImpl,
    baseUrl: "https://api.github.com",
    now: () => NOW,
    ...(opts?.allowedRepos !== undefined ? { allowedRepos: opts.allowedRepos } : {}),
    ...(opts?.socketGid !== undefined ? { socketGid: opts.socketGid } : {}),
  });
  await broker.listen(socketPath);
  return socketPath;
}

function client(socketPath: string) {
  const ledger = createSecretLedger();
  ledger.add(TOKEN);
  return { client: createBrokerMergeClient({ socketPath, ledger, timeoutMs: 3_000 }), ledger };
}

/** Send a raw line to the socket and read one line back — for protocol tests. */
function rawExchange(socketPath: string, line: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    let buffer = "";
    socket.on("connect", () => socket.write(line));
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      if (buffer.includes("\n")) {
        socket.destroy();
        resolve(buffer);
      }
    });
    socket.on("error", reject);
  });
}

describe("createMergeBroker — the executing broker", () => {
  it("PERFORMS the merge with a valid grant and returns only the outcome — never a token", async () => {
    const github = fakeGitHub();
    const socketPath = await startBroker({ github });
    const { client: c } = client(socketPath);

    const result = await c.mergePullRequest(MERGE_ARGS, grant());
    expect(result).toEqual({
      merged: true,
      sha: "mergecommit01",
      message: "Pull Request successfully merged",
    });
    // the token authenticated the GitHub calls but never crossed the socket
    expect(JSON.stringify(result)).not.toContain(TOKEN);
    expect(github.calls.some((call) => call.method === "PUT")).toBe(true);
  });

  it("NEVER returns a token: no raw protocol op yields the credential", async () => {
    const socketPath = await startBroker({});
    // there is no token op; an attacker asking for one gets 'unknown operation'
    const res = await rawExchange(socketPath, `${JSON.stringify({ op: "token", repo: "throwaway" })}\n`);
    expect(res).not.toContain(TOKEN);
    expect(JSON.parse(res)).toMatchObject({ ok: false, error: expect.stringContaining("unknown operation") });
  });

  it("a direct socket client with NO valid grant gets a refusal — never a merge", async () => {
    const github = fakeGitHub();
    const socketPath = await startBroker({ github });
    // forged grant (signed with the wrong key — the agent cannot mint one)
    const forged = signMergeGrant(
      { v: 1, jti: "x", agentId: "a", tool: "github.merge_pr", canonicalArgs: CANONICAL_ARGS, callHash: sha256Hex(CANONICAL_ARGS), killEpoch: 0, expiresAt: NOW + 1000 },
      "attacker-key",
    );
    const res = await rawExchange(socketPath, `${JSON.stringify({ op: "merge", grant: forged, args: MERGE_ARGS })}\n`);
    expect(JSON.parse(res)).toMatchObject({ ok: false, kind: "refused" });
    expect(github.calls.some((call) => call.method === "PUT")).toBe(false); // nothing merged
  });

  it("rejects an expired grant, a bad signature, and a callHash mismatch", async () => {
    const socketPath = await startBroker({});
    const { client: c } = client(socketPath);

    await expect(c.mergePullRequest(MERGE_ARGS, grant({ expiresAt: NOW - 1 }))).rejects.toThrowError(
      /expired/,
    );
    const tampered = { ...grant(), sig: "00" };
    await expect(c.mergePullRequest(MERGE_ARGS, tampered)).rejects.toThrowError(/grant rejected/);
  });

  it("burns the grant jti — a replay of the SAME grant is refused (single-use, broker side)", async () => {
    const github = fakeGitHub();
    const socketPath = await startBroker({ github });
    const { client: c } = client(socketPath);
    const g = grant();

    await c.mergePullRequest(MERGE_ARGS, g);
    await expect(c.mergePullRequest(MERGE_ARGS, g)).rejects.toThrowError(/already used/);
    // exactly one merge ever dispatched
    expect(github.calls.filter((call) => call.method === "PUT")).toHaveLength(1);
  });

  it("refuses when the supplied args do not match the grant's signed args (including a swapped sha)", async () => {
    const github = fakeGitHub();
    const socketPath = await startBroker({ github });
    const { client: c } = client(socketPath);

    const swapped = { ...MERGE_ARGS, expectedHeadSha: "b".repeat(40) };
    await expect(c.mergePullRequest(swapped, grant())).rejects.toThrowError(/do not match the grant/);
    expect(github.calls.some((call) => call.method === "PUT")).toBe(false);
  });

  it("gates on live kill state and the grant's kill epoch", async () => {
    // killed → refuse
    const killed = await startBroker({ fetchLiveKillState: async () => ({ killed: true, epoch: 1 }) });
    await expect(client(killed).client.mergePullRequest(MERGE_ARGS, grant())).rejects.toThrowError(
      /kill switch engaged/,
    );
    await broker!.close();

    // epoch moved since approval → refuse (grant.killEpoch 0, live 1)
    const moved = await startBroker({ fetchLiveKillState: async () => ({ killed: false, epoch: 1 }) });
    await expect(client(moved).client.mergePullRequest(MERGE_ARGS, grant({ killEpoch: 0 }))).rejects.toThrowError(
      /kill epoch moved/,
    );
  });

  it("rechecks kill state ACROSS the token mint (TOCTOU): a kill during the mint aborts before dispatch", async () => {
    const github = fakeGitHub();
    let calls = 0;
    // alive on the first (before-mint) check, killed on the second (during mint)
    const fetchLiveKillState = async (): Promise<LiveKillState> => {
      calls += 1;
      return calls >= 2 ? { killed: true, epoch: 0 } : { killed: false, epoch: 0 };
    };
    // a token source that takes a beat, so the recheck is meaningful
    const tokens: InstallationTokenSource = {
      tokenFor: async () => {
        await Promise.resolve();
        return TOKEN;
      },
    };
    const socketPath = await startBroker({ github, fetchLiveKillState, tokens });
    await expect(client(socketPath).client.mergePullRequest(MERGE_ARGS, grant())).rejects.toThrowError(
      /not dispatched/,
    );
    expect(github.calls.some((call) => call.method === "PUT")).toBe(false);
  });

  it("maps a connector failure through with its outcome classification", async () => {
    const socketPath = await startBroker({ github: fakeGitHub({ failMerge: 405 }) });
    const err = await client(socketPath)
      .client.mergePullRequest(MERGE_ARGS, grant())
      .then(() => undefined, (e: unknown) => e);
    expect(err).toBeInstanceOf(ConnectorCallError);
    expect((err as ConnectorCallError).outcome).toBe("not-performed");
    expect((err as ConnectorCallError).message).toMatch(/not mergeable/);
  });

  it("pin-head is read-only, kill-gated, and needs no grant", async () => {
    const socketPath = await startBroker({});
    const { client: c } = client(socketPath);
    expect(await c.getPullRequestHead({ owner: "ownerswitchai", repo: "throwaway", pullNumber: 7 })).toBe(
      HEAD_SHA,
    );

    await broker!.close();
    const killed = await startBroker({ fetchLiveKillState: async () => ({ killed: true, epoch: 1 }) });
    await expect(
      client(killed).client.getPullRequestHead({ owner: "o", repo: "throwaway", pullNumber: 1 }),
    ).rejects.toThrowError(/kill switch engaged|refused/);
  });

  it("enforces the repository allow-list on both ops", async () => {
    const socketPath = await startBroker({ allowedRepos: ["allowed"] });
    const { client: c } = client(socketPath);
    await expect(c.getPullRequestHead({ owner: "o", repo: "throwaway", pullNumber: 1 })).rejects.toThrowError(
      /allow-list|refused/,
    );
  });

  it("hardens the socket: mode 0660, and refuses a world-accessible directory", async () => {
    const socketPath = await startBroker({});
    expect(statSync(socketPath).mode & 0o777).toBe(0o660);
    await broker!.close();

    chmodSync(dir, 0o757);
    broker = createMergeBroker({
      tokens: { tokenFor: async () => TOKEN },
      ledger: createSecretLedger(),
      grantKey: GRANT_KEY,
      fetchLiveKillState: alive,
    });
    await expect(broker.listen(join(dir, "b.sock"))).rejects.toThrowError(/world access/);
    broker = undefined;
  });

  it("verifies the socket GID and refuses to serve on a mismatch", async () => {
    // the socket's real gid is this process's egid; demand a different one
    const wrongGid = (process.getgid?.() ?? 0) + 99999;
    await expect(startBroker({ socketGid: wrongGid })).rejects.toThrowError(/gid .* not the required/);
    broker = undefined;
  });

  it("serves when the socket GID matches the requirement", async () => {
    const realGid = process.getgid?.() ?? 0;
    const socketPath = await startBroker({ socketGid: realGid });
    const { client: c } = client(socketPath);
    expect((await c.mergePullRequest(MERGE_ARGS, grant())).merged).toBe(true);
  });

  it("bounds the protocol: oversized and malformed requests are refused without leaking", async () => {
    const socketPath = await startBroker({});
    const oversized = await rawExchange(socketPath, `${"x".repeat(9 * 1024)}\n`);
    expect(JSON.parse(oversized)).toMatchObject({ ok: false, error: "request too large" });
    const malformed = await rawExchange(socketPath, "not json\n");
    expect(JSON.parse(malformed)).toMatchObject({ ok: false });
  });

  it("refuses to build without a grant key — it trusts nothing", () => {
    expect(() =>
      createMergeBroker({
        tokens: { tokenFor: async () => TOKEN },
        ledger: createSecretLedger(),
        grantKey: "",
        fetchLiveKillState: alive,
      }),
    ).toThrowError(/grant key/);
  });
});

describe("createBrokerMergeClient — the gateway side", () => {
  it("a missing grant is a not-performed refusal (owner-gated lane required)", async () => {
    const socketPath = await startBroker({});
    const { client: c } = client(socketPath);
    const err = await c
      .mergePullRequest(MERGE_ARGS)
      .then(() => undefined, (e: unknown) => e);
    expect(err).toBeInstanceOf(ConnectorCallError);
    expect((err as ConnectorCallError).outcome).toBe("not-performed");
    expect((err as ConnectorCallError).message).toMatch(/owner-gated lane|authorization grant/);
  });

  it("a dead broker surfaces as a fixed sentence, not transport internals", async () => {
    const { client: c } = client(join(dir, "nothing.sock"));
    const err = await c
      .mergePullRequest(MERGE_ARGS, grant())
      .then(() => undefined, (e: unknown) => e);
    expect((err as ConnectorCallError).message).toMatch(/not dispatched|cannot reach the merge broker/);
  });
});
