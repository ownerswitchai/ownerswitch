import { connect } from "node:net";
import { ConnectorCallError } from "./connector-error.js";
import type { GitHubMergeClient, MergePrArgs } from "./github.js";
import { assertSafeRepoName } from "./github-http.js";
import type { SecretLedger } from "./secret-ledger.js";

/**
 * The gateway's side of the executing merge broker (merge-broker.ts): a
 * GitHubMergeClient whose calls are performed by the broker, over its UNIX
 * socket, so the gateway process holds NO GitHub credential and NO grant key.
 *
 * `getPullRequestHead` → {op:"pin-head"} (the review-time pin, read-only).
 * `mergePullRequest(args, grant)` → {op:"merge", grant, args}; the grant is
 * the control-plane-signed evidence the broker verifies independently. The
 * broker returns only the OUTCOME — never a token — which this client maps
 * back onto the GitHubMergeClient contract (a merge result, or a
 * ConnectorCallError carrying the broker's not-performed/unknown
 * classification).
 *
 * No-leak: the broker already redacted its error strings; this client
 * re-redacts with its own ledger and bounds them, and transport failures
 * surface as fixed sentences — a socket error's own text is never forwarded.
 */

const MAX_RESPONSE_BYTES = 64 * 1024;

export interface BrokerMergeClientOptions {
  socketPath: string;
  ledger: SecretLedger;
  timeoutMs?: number;
}

interface BrokerResponse {
  ok?: unknown;
  kind?: unknown;
  outcome?: unknown;
  error?: unknown;
  headSha?: unknown;
  merged?: unknown;
  sha?: unknown;
  message?: unknown;
}

export function createBrokerMergeClient(options: BrokerMergeClientOptions): GitHubMergeClient {
  const { socketPath, ledger, timeoutMs = 45_000 } = options;

  function exchange(request: unknown): Promise<BrokerResponse> {
    return new Promise<BrokerResponse>((resolve, reject) => {
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
        () => fail(`the merge broker did not answer within ${timeoutMs}ms`),
        timeoutMs,
      );
      socket.on("error", () => {
        clearTimeout(timer);
        // fixed sentence: a socket error's own text is not forwarded
        fail(`cannot reach the merge broker at "${socketPath}" — is it running?`);
      });
      socket.on("connect", () => socket.write(`${JSON.stringify(request)}\n`));
      socket.on("data", (chunk) => {
        if (settled) return;
        buffer += chunk.toString("utf8");
        if (buffer.length > MAX_RESPONSE_BYTES) {
          clearTimeout(timer);
          fail("the merge broker's response exceeded the size bound");
          return;
        }
        const newline = buffer.indexOf("\n");
        if (newline === -1) return;
        clearTimeout(timer);
        settled = true;
        socket.destroy();
        try {
          resolve((JSON.parse(buffer.slice(0, newline)) ?? {}) as BrokerResponse);
        } catch {
          reject(new Error("the merge broker's response was not JSON"));
        }
      });
      socket.on("close", () => {
        clearTimeout(timer);
        fail("the merge broker closed the connection without answering");
      });
    });
  }

  const redactedError = (res: BrokerResponse, fallback: string): string => {
    const raw = typeof res.error === "string" && res.error !== "" ? res.error : fallback;
    return ledger.redact(raw).slice(0, 400);
  };

  return {
    async mergePullRequest(args: MergePrArgs, grant?: unknown) {
      assertSafeRepoName(args.repo);
      if (grant === undefined) {
        // the broker path is owner-gated: no grant means no owner approval
        throw new ConnectorCallError(
          "the merge was not dispatched — no owner authorization grant (a broker-routed merge " +
            "requires an owner-gated lane; the merge was not attempted)",
          "not-performed",
        );
      }
      let res: BrokerResponse;
      try {
        res = await exchange({ op: "merge", grant, args });
      } catch (err) {
        // could not reach the broker at all — nothing was dispatched
        throw new ConnectorCallError(
          `the merge was not dispatched: ${err instanceof Error ? err.message : "broker unreachable"}`,
          "not-performed",
        );
      }
      if (res.ok === true && res.merged !== undefined) {
        return {
          merged: res.merged === true,
          sha: typeof res.sha === "string" ? ledger.redact(res.sha) : "",
          message: typeof res.message === "string" ? ledger.redact(res.message).slice(0, 400) : "",
        };
      }
      if (res.kind === "connector") {
        const outcome = res.outcome === "unknown" ? "unknown" : "not-performed";
        throw new ConnectorCallError(redactedError(res, "the merge failed at the broker"), outcome);
      }
      // a refusal (bad/expired/replayed grant, kill engaged, args mismatch):
      // nothing merged, definitively not performed
      throw new ConnectorCallError(
        redactedError(res, "the merge broker refused the request"),
        "not-performed",
      );
    },

    async getPullRequestHead(args) {
      assertSafeRepoName(args.repo);
      const res = await exchange({ op: "pin-head", args });
      if (res.ok === true && typeof res.headSha === "string" && res.headSha !== "") {
        return ledger.redact(res.headSha);
      }
      throw new Error(redactedError(res, "the merge broker refused the head-pin read"));
    },
  };
}
