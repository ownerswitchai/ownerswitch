import { connect } from "node:net";
import type { InstallationTokenSource } from "./github-app-auth.js";
import { assertSafeRepoName } from "./github-http.js";
import type { SecretLedger } from "./secret-ledger.js";

/**
 * The gateway's side of the token broker socket (token-broker.ts): an
 * InstallationTokenSource whose tokenFor() asks the broker instead of
 * minting locally — so the gateway process NEVER holds the App private
 * key. It holds only the minted tokens it must present to GitHub
 * (≤ 1 h, one repository), each registered with the ledger on receipt.
 *
 * No caching here: the broker caches per repository and re-checks kill
 * state per request; a gateway-side cache would only widen the window in
 * which a killed deployment keeps presenting a pre-kill token it already
 * had in hand.
 *
 * No-leak rule: failures surface as fixed sentences or the broker's own
 * error string — which the broker already redacted — re-redacted with this
 * process's ledger and bounded. Transport error text is never forwarded.
 */

const MAX_RESPONSE_BYTES = 64 * 1024;

export interface BrokerTokenSourceOptions {
  socketPath: string;
  ledger: SecretLedger;
  timeoutMs?: number;
}

export function createBrokerTokenSource(options: BrokerTokenSourceOptions): InstallationTokenSource {
  const { socketPath, ledger, timeoutMs = 20_000 } = options;

  return {
    async tokenFor(repo: string): Promise<string> {
      assertSafeRepoName(repo);
      return new Promise<string>((resolve, reject) => {
        let settled = false;
        let buffer = "";
        const socket = connect(socketPath);
        const fail = (message: string): void => {
          if (settled) return;
          settled = true;
          socket.destroy();
          reject(new Error(message));
        };
        const timer = setTimeout(
          () => fail(`the token broker did not answer within ${timeoutMs}ms`),
          timeoutMs,
        );
        socket.on("error", () => {
          clearTimeout(timer);
          // fixed sentence: a socket error's own text is not forwarded
          fail(`cannot reach the token broker at "${socketPath}" — is it running?`);
        });
        socket.on("connect", () => {
          socket.write(`${JSON.stringify({ op: "token", repo })}\n`);
        });
        socket.on("data", (chunk) => {
          if (settled) return;
          buffer += chunk.toString("utf8");
          if (buffer.length > MAX_RESPONSE_BYTES) {
            clearTimeout(timer);
            fail("the token broker's response exceeded the size bound");
            return;
          }
          const newline = buffer.indexOf("\n");
          if (newline === -1) return;
          clearTimeout(timer);
          let parsed: unknown;
          try {
            parsed = JSON.parse(buffer.slice(0, newline));
          } catch {
            fail("the token broker's response was not JSON");
            return;
          }
          const res = (parsed ?? {}) as { ok?: unknown; token?: unknown; error?: unknown };
          if (res.ok === true && typeof res.token === "string" && res.token !== "") {
            settled = true;
            socket.destroy();
            // redactable before anything else can observe it
            ledger.add(res.token);
            resolve(res.token);
            return;
          }
          const reason =
            typeof res.error === "string" && res.error !== ""
              ? ledger.redact(res.error).slice(0, 300)
              : "no reason given";
          fail(`the token broker refused to mint: ${reason}`);
        });
        socket.on("close", () => {
          clearTimeout(timer);
          fail("the token broker closed the connection without answering");
        });
      });
    },
  };
}
