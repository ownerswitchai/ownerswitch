import { ConnectorCallError } from "./connector-error.js";
import type { GitHubMergeClient, MergePrArgs } from "./github.js";
import type { InstallationTokenSource } from "./github-app-auth.js";
import {
  assertSafeOwner,
  assertSafePullNumber,
  assertSafeRepoName,
  boundedRequest,
  fixedTransportMessage,
  GITHUB_API_BASE_URL,
  GITHUB_API_VERSION,
  githubErrorMessage,
  USER_AGENT,
  type BoundedResponse,
} from "./github-http.js";
import type { SecretLedger } from "./secret-ledger.js";

/**
 * The live GitHub connector: PUT /repos/{owner}/{repo}/pulls/{n}/merge with
 * an installation token minted for exactly that repository. This is the
 * module DESIGN.md §6 describes — read that section for the credential
 * model and the ambiguity analysis; what follows is the contract in brief.
 *
 * No-leak, structurally: no code path here logs, and no thrown error is
 * built from anything but (a) fixed prose, (b) HTTP status codes, (c) the
 * ticket's own args, and (d) GitHub's bounded JSON `message` — redacted
 * then truncated. Transport failures surface as one of two FIXED sentences
 * (fixedTransportMessage), never the transport error's own text: exact
 * full-secret replacement cannot redact a token FRAGMENT, so the channel is
 * removed rather than filtered. Response bodies are capped while streaming;
 * every request refuses redirects (an authenticated request following a
 * redirect hands its token to whoever controls the Location).
 *
 * `sha` is MANDATORY: every merge sends the head SHA the owner's approval
 * was pinned to (server-derived at review time — see the proxy's pinning
 * step and getPullRequestHead below). A branch that moved after review
 * draws HTTP 409 instead of merging commits nobody reviewed. That is the
 * point, not an error to engineer away.
 *
 * Ambiguity, per the API documentation (not assumption): GitHub offers no
 * idempotency key for merges. Merges ARE verifiable after the fact
 * (`merged` / `merge_commit_sha` on GET /pulls/{n}), and a dispatch whose
 * outcome is ambiguous — the request died on the wire, timed out, drew a
 * 5xx, an unrecognized status, or a 200 that did not confirm the merge —
 * is followed by ONE verification read. What that read proves is stated
 * precisely: "merged" is a fact about the PULL REQUEST's state, not about
 * WHICH request merged it; "not merged" is only a snapshot, since a
 * request that died on the wire can still complete after the read.
 *
 * Failure classification is a WHITELIST: only the statuses GitHub
 * documents for the merge endpoint (plus 401 auth and 429 rate limiting)
 * are treated as definitive rejections — "not-performed". Anything
 * unrecognized — including an intermediary-generated 408 — takes the
 * verification path and ends UNKNOWN at worst, never a false "did NOT
 * run".
 */

/** The statuses GitHub documents as merge rejections — nothing else is
 * trusted to mean "the merge did not happen". */
const DOCUMENTED_REJECTION_STATUSES: ReadonlySet<number> = new Set([
  401, 403, 404, 405, 409, 422, 429,
]);

/** Merge/PR JSON responses are modest; cap far above them. */
const MAX_BODY_BYTES = 4 * 1024 * 1024;

export interface GitHubMergeClientOptions {
  tokens: InstallationTokenSource;
  /** the same ledger the token source registers every credential with */
  ledger: SecretLedger;
  baseUrl?: string;
  /** injectable for tests; nothing in the test suite may reach GitHub */
  fetchImpl?: typeof fetch;
  /** per HTTP call; merges can be slow on large repos */
  timeoutMs?: number;
  /**
   * Invoked AFTER the installation token is acquired and immediately BEFORE
   * the merge PUT is dispatched. The executing broker uses it to re-check
   * live kill state across the token mint (which can take seconds) — a kill
   * or epoch change landing during the mint throws here, and because nothing
   * has been sent yet the outcome is definitively not-performed. It runs only
   * on the merge path, never on the read-only head pin.
   */
  beforeDispatch?: () => Promise<void>;
}

export function createGitHubMergeClient(options: GitHubMergeClientOptions): GitHubMergeClient {
  const {
    tokens,
    ledger,
    baseUrl = GITHUB_API_BASE_URL,
    fetchImpl = fetch,
    timeoutMs = 30_000,
    beforeDispatch,
  } = options;

  const notPerformed = (message: string): ConnectorCallError =>
    new ConnectorCallError(ledger.redact(message), "not-performed");
  const unknownOutcome = (message: string): ConnectorCallError =>
    new ConnectorCallError(ledger.redact(message), "unknown");

  const headers = (token: string): Record<string, string> => ({
    authorization: `Bearer ${token}`,
    accept: "application/vnd.github+json",
    "x-github-api-version": GITHUB_API_VERSION,
    "user-agent": USER_AGENT,
  });

  function prPath(args: Pick<MergePrArgs, "owner" | "repo" | "pullNumber">): string {
    assertSafeOwner(args.owner);
    assertSafeRepoName(args.repo);
    assertSafePullNumber(args.pullNumber);
    return (
      `${baseUrl}/repos/${encodeURIComponent(args.owner)}/${encodeURIComponent(args.repo)}` +
      `/pulls/${args.pullNumber}`
    );
  }

  /** GET the PR with a scoped token; shared by the head pin and the
   * verification read. Throws plain Errors with fixed/bounded text. */
  async function fetchPullRequest(
    prUrl: string,
    token: string,
  ): Promise<{ merged: boolean; mergeCommitSha: string | undefined; headSha: string | undefined }> {
    let res: BoundedResponse;
    try {
      res = await boundedRequest(
        fetchImpl,
        prUrl,
        { headers: headers(token) },
        timeoutMs,
        MAX_BODY_BYTES,
      );
    } catch (err) {
      throw new Error(`the pull request read failed: ${fixedTransportMessage(err)}`);
    }
    if (res.status !== 200) {
      throw new Error(`the pull request read answered HTTP ${res.status}`);
    }
    if (res.bodyText === null) {
      throw new Error("the pull request read exceeded the response size bound");
    }
    let body: unknown;
    try {
      body = JSON.parse(res.bodyText);
    } catch {
      throw new Error("the pull request read returned an unreadable body");
    }
    const { merged, merge_commit_sha, head } = (body ?? {}) as {
      merged?: unknown;
      merge_commit_sha?: unknown;
      head?: unknown;
    };
    const headSha = (head as { sha?: unknown } | null | undefined)?.sha;
    return {
      merged: merged === true,
      mergeCommitSha: typeof merge_commit_sha === "string" ? merge_commit_sha : undefined,
      headSha: typeof headSha === "string" ? headSha : undefined,
    };
  }

  /**
   * The one verification read after an ambiguous dispatch. Wording is
   * deliberate and everywhere the result travels: the read proves the pull
   * request IS merged — it cannot prove THIS dispatch performed the merge.
   */
  async function verifyAfterAmbiguousDispatch(
    args: MergePrArgs,
    prUrl: string,
    token: string,
    cause: string,
  ): Promise<{ merged: boolean; sha: string; message: string }> {
    const checkYourself =
      `Check ${args.owner}/${args.repo}#${args.pullNumber} directly before re-approving — ` +
      `a re-approved merge could run the action twice.`;
    let pr;
    try {
      pr = await fetchPullRequest(prUrl, token);
    } catch (err) {
      throw unknownOutcome(
        `${cause}; the post-dispatch verification read also failed ` +
          `(${err instanceof Error ? err.message : "unreadable"}), so the outcome is UNKNOWN. ` +
          checkYourself,
      );
    }
    if (pr.merged) {
      return {
        merged: true,
        sha: pr.mergeCommitSha !== undefined ? ledger.redact(pr.mergeCommitSha) : "",
        message: ledger.redact(
          `the pull request is merged — ${cause}, and a post-dispatch verification read ` +
            `confirms the pull request's MERGED STATE. Note precisely what that proves: the PR ` +
            `is merged; whether THIS dispatch performed the merge cannot be determined.`,
        ),
      };
    }
    throw unknownOutcome(
      `${cause}; a post-dispatch verification read shows the pull request NOT merged as of ` +
        `that read — but a request that died on the wire can still complete after it, so this ` +
        `is a snapshot, not proof. ${checkYourself}`,
    );
  }

  function rejectionDetail(res: BoundedResponse, args: MergePrArgs): string {
    const message = githubErrorMessage(res.bodyText, (text) => ledger.redact(text));
    const quoted = message === "" ? "" : `: ${message}`;
    const suffix = " The merge was NOT performed by this request.";
    const rateLimited =
      res.headers.get("x-ratelimit-remaining") === "0" || res.headers.get("retry-after") !== null;
    if ((res.status === 403 || res.status === 429) && rateLimited) {
      return `GitHub rate-limited the executor's credential (HTTP ${res.status})${quoted}.${suffix}`;
    }
    switch (res.status) {
      case 401:
        return `GitHub rejected the executor's credential (HTTP 401)${quoted}.${suffix}`;
      case 403:
        return (
          `GitHub forbade the merge (HTTP 403)${quoted} — the installation token has ` +
          `contents:write on ${args.owner}/${args.repo}, so look for repository rules or ` +
          `organization policy.${suffix}`
        );
      case 404:
        return (
          `GitHub answered 404 for ${args.owner}/${args.repo}#${args.pullNumber} — the pull ` +
          `request does not exist, or the App's installation cannot see that repository ` +
          `(GitHub serves 404, not 403, for resources a credential cannot see).${suffix}`
        );
      case 405:
        return (
          `GitHub reports the pull request is not mergeable (HTTP 405)${quoted} — draft, ` +
          `failing required checks, branch protection, or already merged.${suffix}`
        );
      case 409:
        return (
          `the head of ${args.owner}/${args.repo}#${args.pullNumber} no longer matches the ` +
          `approved expectedHeadSha (HTTP 409)${quoted} — the branch moved after the owner's ` +
          `approval, and merging it now would merge commits the owner never saw. Re-approve ` +
          `against the new head.${suffix}`
        );
      case 422:
        return `GitHub refused the merge request as invalid (HTTP 422)${quoted}.${suffix}`;
      case 429:
        return `GitHub rate-limited the executor's credential (HTTP 429)${quoted}.${suffix}`;
      default:
        return `GitHub refused the merge (HTTP ${res.status})${quoted}.${suffix}`;
    }
  }

  return {
    // The live client authenticates directly (same-process mode); the grant
    // is the executing broker's concern, so it is accepted and ignored here.
    async mergePullRequest(args: MergePrArgs, _grant?: unknown) {
      void _grant;
      // Failures before the PUT goes out — a name that can't form a URL, no
      // installation token — happen strictly BEFORE dispatch: nothing has
      // been sent, so the outcome is definitively not-performed.
      let prUrl: string;
      try {
        prUrl = prPath(args);
      } catch (err) {
        throw notPerformed(
          `the merge was not dispatched: ${err instanceof Error ? err.message : "invalid arguments"}`,
        );
      }
      if (typeof args.expectedHeadSha !== "string" || args.expectedHeadSha === "") {
        // defense in depth — parseMergePrArgs already requires it
        throw notPerformed(
          "the merge was not dispatched: expectedHeadSha is mandatory — every merge is pinned " +
            "to the head the owner approved",
        );
      }
      let token: string;
      try {
        token = await tokens.tokenFor(args.repo);
      } catch (err) {
        throw notPerformed(
          `the merge was not dispatched — no installation token: ` +
            `${err instanceof Error ? err.message : "token minting failed"}`,
        );
      }

      // TOCTOU close: the token mint may have taken seconds. Re-check live
      // kill state across it before anything is sent. A throw here is a
      // definitively-not-performed refusal — nothing has crossed to GitHub.
      if (beforeDispatch !== undefined) {
        try {
          await beforeDispatch();
        } catch (err) {
          throw notPerformed(
            `the merge was not dispatched — ` +
              `${err instanceof Error ? err.message : "pre-dispatch check refused"}`,
          );
        }
      }

      let res: BoundedResponse;
      try {
        res = await boundedRequest(
          fetchImpl,
          `${prUrl}/merge`,
          {
            method: "PUT",
            headers: { ...headers(token), "content-type": "application/json" },
            body: JSON.stringify({
              ...(args.mergeMethod !== undefined ? { merge_method: args.mergeMethod } : {}),
              sha: args.expectedHeadSha,
            }),
          },
          timeoutMs,
          MAX_BODY_BYTES,
        );
      } catch (err) {
        // dispatched but died on the wire — GitHub may have performed it.
        // Fixed sentence only: transport error text is never forwarded.
        return verifyAfterAmbiguousDispatch(
          args,
          prUrl,
          token,
          `the merge request failed on the wire (${fixedTransportMessage(err)})`,
        );
      }

      if (res.status === 200) {
        let body: unknown;
        try {
          body = res.bodyText === null ? undefined : JSON.parse(res.bodyText);
        } catch {
          body = undefined;
        }
        const { sha, merged, message } = (body ?? {}) as {
          sha?: unknown;
          merged?: unknown;
          message?: unknown;
        };
        if (merged !== true) {
          // a 200 that does not confirm the merge is malformed, not success
          return verifyAfterAmbiguousDispatch(
            args,
            prUrl,
            token,
            "GitHub answered HTTP 200 without confirming the merge",
          );
        }
        return {
          merged: true,
          sha: typeof sha === "string" ? ledger.redact(sha) : "",
          // redact THEN truncate — same load-bearing order as
          // githubErrorMessage: cutting first could leave an unrecognizable
          // fragment of an echoed credential
          message: typeof message === "string" ? ledger.redact(message).slice(0, 300) : "",
        };
      }
      if (DOCUMENTED_REJECTION_STATUSES.has(res.status)) {
        // received and refused by GitHub itself: definitively not merged
        throw notPerformed(rejectionDetail(res, args));
      }
      // Everything else — 5xx, an intermediary's 408, any status the merge
      // endpoint does not document — is NOT trusted to mean "did not run".
      return verifyAfterAmbiguousDispatch(
        args,
        prUrl,
        token,
        `GitHub answered an unrecognized HTTP ${res.status}`,
      );
    },

    async getPullRequestHead(args) {
      // read-only, nothing dispatched — failures are plain errors for the
      // proxy's fail-closed pinning step
      const prUrl = prPath(args);
      const token = await tokens.tokenFor(args.repo);
      const pr = await fetchPullRequest(prUrl, token);
      if (pr.merged) {
        throw new Error(
          `${args.owner}/${args.repo}#${args.pullNumber} is already merged — nothing to pin`,
        );
      }
      if (pr.headSha === undefined || !/^([0-9a-f]{40}|[0-9a-f]{64})$/i.test(pr.headSha)) {
        throw new Error("GitHub's pull request response carried no usable head sha");
      }
      return ledger.redact(pr.headSha);
    },
  };
}
