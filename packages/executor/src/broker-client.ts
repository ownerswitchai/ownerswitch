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
 * OUTCOME HONESTY is the load-bearing property of that mapping. Once the
 * merge request has been WRITTEN to the broker's socket, this client cannot
 * distinguish "the broker refused before dispatch" from "the broker is
 * mid-PUT and my socket died" — so every post-send transport failure
 * (timeout, connection loss, unparseable or unrecognizable response) maps
 * to outcome UNKNOWN, never "not-performed": a false "did not run" invites
 * a retry that merges twice on one approval. Only failures that provably
 * precede transmission — the socket never connected, the broker refused
 * with kind:"refused" (its refusals all precede dispatch) — are
 * "not-performed". The broker records the true outcome by jti
 * ({op:"outcome"}) for resolving the in-doubt cases.
 *
 * No-leak: the broker already redacted its error strings; this client
 * re-redacts with its own ledger and bounds them, and transport failures
 * surface as fixed sentences — a socket error's own text is never forwarded.
 */

const MAX_RESPONSE_BYTES = 64 * 1024;

/**
 * Must exceed the broker's own requestTimeoutMs (default 120s) with slack:
 * the broker's phase-aware answer ("unknown, still in flight") is strictly
 * more useful than this client's own timeout, so this client should always
 * lose that race.
 */
const DEFAULT_TIMEOUT_MS = 130_000;

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
  baseRef?: unknown;
  merged?: unknown;
  sha?: unknown;
  message?: unknown;
}

/** A transport failure, tagged with whether the request had been sent —
 * the fact the outcome mapping pivots on. */
class BrokerTransportError extends Error {
  constructor(
    message: string,
    readonly sent: boolean,
  ) {
    super(message);
    this.name = "BrokerTransportError";
  }
}

export function createBrokerMergeClient(options: BrokerMergeClientOptions): GitHubMergeClient {
  const { socketPath, ledger, timeoutMs = DEFAULT_TIMEOUT_MS } = options;

  function exchange(request: unknown): Promise<BrokerResponse> {
    return new Promise<BrokerResponse>((resolve, reject) => {
      let settled = false;
      let sent = false;
      let buffer = "";
      const socket = connect(socketPath);
      const fail = (message: string): void => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(new BrokerTransportError(message, sent));
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
      socket.on("connect", () => {
        // conservatively "sent" from the moment transmission is attempted:
        // a write that buffered locally and died may still have arrived
        sent = true;
        socket.write(`${JSON.stringify(request)}\n`);
      });
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
          reject(new BrokerTransportError("the merge broker's response was not JSON", sent));
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
      const checkYourself =
        `Check ${args.owner}/${args.repo}#${args.pullNumber} directly (or query the broker's ` +
        `{op:"outcome"} surface) before re-approving — a re-approved merge could run twice.`;
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
        const sent = err instanceof BrokerTransportError && err.sent;
        const detail = err instanceof Error ? err.message : "broker transport failed";
        if (!sent) {
          // the request never left this process — nothing was dispatched
          throw new ConnectorCallError(`the merge was not dispatched: ${detail}`, "not-performed");
        }
        // the request reached (or may have reached) the broker and no
        // answer came back — the broker may be mid-merge RIGHT NOW
        throw new ConnectorCallError(
          `the merge request was sent to the broker but no answer arrived (${detail}) — the ` +
            `broker may still be performing it, so the outcome is UNKNOWN. ${checkYourself}`,
          "unknown",
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
        // a malformed classification fails toward uncertainty, never toward
        // "did not run"
        const outcome = res.outcome === "not-performed" ? "not-performed" : "unknown";
        throw new ConnectorCallError(redactedError(res, "the merge failed at the broker"), outcome);
      }
      if (res.kind === "refused") {
        // a refusal (bad/expired/replayed grant, wrong purpose, kill
        // engaged, args mismatch): every broker refusal precedes dispatch —
        // nothing merged, definitively not performed
        throw new ConnectorCallError(
          redactedError(res, "the merge broker refused the request"),
          "not-performed",
        );
      }
      // an answer this client does not recognize proves nothing about what
      // the broker did — after a sent request that is UNKNOWN, not a refusal
      throw new ConnectorCallError(
        `the merge broker's answer was unrecognizable ` +
          `(${redactedError(res, "no detail")}) — the outcome is UNKNOWN. ${checkYourself}`,
        "unknown",
      );
    },

    async getPullRequestHead(args) {
      assertSafeRepoName(args.repo);
      // read-only: transport failures are plain errors for the proxy's
      // fail-closed pinning step — no dispatch ambiguity to classify
      let res: BrokerResponse;
      try {
        res = await exchange({ op: "pin-head", args });
      } catch (err) {
        throw new Error(err instanceof Error ? err.message : "the merge broker was unreachable");
      }
      if (
        res.ok === true &&
        typeof res.headSha === "string" &&
        res.headSha !== "" &&
        typeof res.baseRef === "string" &&
        res.baseRef !== ""
      ) {
        return { headSha: ledger.redact(res.headSha), baseRef: ledger.redact(res.baseRef) };
      }
      throw new Error(redactedError(res, "the merge broker refused the head-pin read"));
    },
  };
}
