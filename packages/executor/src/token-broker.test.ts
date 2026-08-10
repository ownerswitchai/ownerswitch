import { chmodSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createBrokerTokenSource } from "./broker-client.js";
import type { LiveKillState } from "./executor.js";
import type { InstallationTokenSource } from "./github-app-auth.js";
import { createSecretLedger } from "./secret-ledger.js";
import { createTokenBroker, type TokenBroker } from "./token-broker.js";

/**
 * The credential broker, tested over a REAL unix domain socket — the same
 * transport a deployment uses — with the GitHub side stubbed. What these
 * tests pin: the kernel-enforceable parts of peer verification (directory
 * hardening refusals, socket mode), the kill gate in front of every mint,
 * the allow-list, protocol bounds, and that no secret the broker holds
 * rides an error line to a client.
 */

const TOKEN = "ghs_broker_minted_token_123456";

let dir: string;
let broker: TokenBroker | undefined;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "oswitch-broker-"));
  chmodSync(dir, 0o750);
});
afterEach(async () => {
  await broker?.close();
  broker = undefined;
  rmSync(dir, { recursive: true, force: true });
});

function tokens(behavior?: () => Promise<string>): InstallationTokenSource {
  return { tokenFor: behavior ?? (async () => TOKEN) };
}

const alive = async (): Promise<LiveKillState> => ({ killed: false, epoch: 0 });
const killed = async (): Promise<LiveKillState> => ({ killed: true, epoch: 1 });

async function startBroker(opts?: {
  tokens?: InstallationTokenSource;
  fetchLiveKillState?: () => Promise<LiveKillState>;
  allowedRepos?: readonly string[];
  ledger?: ReturnType<typeof createSecretLedger>;
}): Promise<string> {
  const socketPath = join(dir, "broker.sock");
  broker = createTokenBroker({
    tokens: opts?.tokens ?? tokens(),
    ledger: opts?.ledger ?? createSecretLedger(),
    fetchLiveKillState: opts?.fetchLiveKillState ?? alive,
    ...(opts?.allowedRepos !== undefined ? { allowedRepos: opts.allowedRepos } : {}),
  });
  await broker.listen(socketPath);
  return socketPath;
}

function client(socketPath: string) {
  const ledger = createSecretLedger();
  return { source: createBrokerTokenSource({ socketPath, ledger, timeoutMs: 2_000 }), ledger };
}

describe("createTokenBroker", () => {
  it("serves a scoped token over the socket; the gateway side registers it with its ledger", async () => {
    const socketPath = await startBroker();
    const { source, ledger } = client(socketPath);
    const token = await source.tokenFor("ownerswitch");
    expect(token).toBe(TOKEN);
    // the received token is redactable on the gateway side from the moment it exists
    expect(ledger.redact(`error echoing ${TOKEN}`)).toBe("error echoing [REDACTED]");
  });

  it("hardens the socket: file mode 0660 after listen", async () => {
    const socketPath = await startBroker();
    expect(statSync(socketPath).mode & 0o777).toBe(0o660);
  });

  it("refuses to listen in a directory with world access — the directory IS the peer allow-list", async () => {
    chmodSync(dir, 0o757);
    broker = createTokenBroker({
      tokens: tokens(),
      ledger: createSecretLedger(),
      fetchLiveKillState: alive,
    });
    await expect(broker.listen(join(dir, "broker.sock"))).rejects.toThrowError(
      /world access .*chmod 0750/,
    );
    broker = undefined;
  });

  it("refuses to replace a non-socket file at the socket path", async () => {
    const socketPath = join(dir, "broker.sock");
    writeFileSync(socketPath, "not a socket");
    broker = createTokenBroker({
      tokens: tokens(),
      ledger: createSecretLedger(),
      fetchLiveKillState: alive,
    });
    await expect(broker.listen(socketPath)).rejects.toThrowError(/not a socket/);
    broker = undefined;
  });

  it("checks LIVE kill state before every answer: engaged kill refuses, and a throwing check fails closed", async () => {
    const engaged = await startBroker({ fetchLiveKillState: killed });
    await expect(client(engaged).source.tokenFor("repo")).rejects.toThrowError(
      /kill switch engaged/,
    );
    await broker!.close();

    const broken = await startBroker({
      fetchLiveKillState: async () => {
        throw new Error("control plane gone");
      },
    });
    await expect(client(broken).source.tokenFor("repo")).rejects.toThrowError(
      /kill switch engaged \(or control plane unreachable\)/,
    );
  });

  it("enforces the repository allow-list", async () => {
    const socketPath = await startBroker({ allowedRepos: ["allowed-repo"] });
    const { source } = client(socketPath);
    await expect(source.tokenFor("other-repo")).rejects.toThrowError(/not in the broker's allow-list/);
    expect(await source.tokenFor("allowed-repo")).toBe(TOKEN);
  });

  it("bounds and validates the protocol: oversized and malformed requests are refused", async () => {
    const socketPath = await startBroker();
    const { connect } = await import("node:net");

    const exchange = (payload: string): Promise<string> =>
      new Promise((resolve, reject) => {
        const socket = connect(socketPath);
        let buffer = "";
        socket.on("connect", () => socket.write(payload));
        socket.on("data", (chunk) => {
          buffer += chunk.toString("utf8");
          if (buffer.includes("\n")) {
            socket.destroy();
            resolve(buffer);
          }
        });
        socket.on("error", reject);
      });

    const oversized = await exchange(`${"x".repeat(5 * 1024)}\n`);
    expect(JSON.parse(oversized)).toMatchObject({ ok: false, error: "request too large" });

    const malformed = await exchange("not json\n");
    expect(JSON.parse(malformed)).toMatchObject({ ok: false });

    const wrongOp = await exchange(`${JSON.stringify({ op: "key", repo: "r" })}\n`);
    expect(JSON.parse(wrongOp)).toMatchObject({ ok: false, error: expect.stringContaining("unknown operation") });
  });

  it("never puts a broker-held secret on the wire in an error — the ledger scrubs refusals", async () => {
    const brokerLedger = createSecretLedger();
    const pem = "-----BEGIN RSA PRIVATE KEY-----SECRETSECRET-----END-----";
    brokerLedger.add(pem);
    const socketPath = await startBroker({
      ledger: brokerLedger,
      tokens: tokens(async () => {
        throw new Error(`mint blew up while holding ${pem}`);
      }),
    });
    const failure = await client(socketPath)
      .source.tokenFor("repo")
      .then(
        () => "",
        (err: unknown) => (err instanceof Error ? err.message : String(err)),
      );
    expect(failure).toContain("[REDACTED]");
    expect(failure).not.toContain("SECRETSECRET");
  });
});

describe("createBrokerTokenSource", () => {
  it("a dead broker surfaces as a fixed sentence naming the socket, not transport internals", async () => {
    const { source } = client(join(dir, "nothing-listens-here.sock"));
    await expect(source.tokenFor("repo")).rejects.toThrowError(/cannot reach the token broker/);
  });

  it("validates the repo name before ever dialing", async () => {
    const { source } = client(join(dir, "unused.sock"));
    await expect(source.tokenFor("..")).rejects.toThrowError(/repository name/);
  });
});
