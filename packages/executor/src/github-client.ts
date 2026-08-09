import { ConnectorCallError } from "./connector-error.js";
import type { GitHubMergeClient, MergePrArgs } from "./github.js";
import type { InstallationTokenSource } from "./github-app-auth.js";
import {
  assertUrlSafeName,
  boundedFetch,
  errorText,
  GITHUB_API_BASE_URL,
  GITHUB_API_VERSION,
  readGitHubErrorMessage,
  USER_AGENT,
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
 * ticket's own args, and (d) GitHub's bounded JSON `message` — with every
 * message passed through the SecretLedger's redaction before the Error is
 * constructed, because GitHub's own auth errors quote credentials back.
 * The token exists only in a local variable and the request header; the
 * executor's scrub (github.ts) remains the second line of defence.
 *
 * Ambiguity, per the API documentation (not assumption): GitHub offers no
 * idempotency key for merges. It offers two adjacent things, and this
 * client uses both:
 *
 *   - `sha` — "SHA that pull request head must match to allow merge"
 *     (HTTP 409 on mismatch). When the ticket carries `expectedHeadSha`,
 *     the merge binds to the exact head the owner approved: a branch that
 *     moved after approval refuses instead of merging unreviewed commits.
 *   - Merges are VERIFIABLE after the fact: `merged` /`merge_commit_sha`
 *     on GET /repos/{owner}/{repo}/pulls/{n} (and the dedicated 204/404
 *     merged-check endpoint) give ground truth on whether the merge
 *     happened. A dispatch whose outcome is ambiguous — the request died
 *     on the wire, timed out, or drew a 5xx — is followed by one
 *     verification read: "merged" is conclusive (merges don't un-happen);
 *     "not merged" is only a snapshot, since a timed-out request can still
 *     land after the read, and the error says exactly that.
 *
 * Every 4xx is a rejection: GitHub received the request and refused it, so
 * the merge definitively did not happen — reported as
 * ConnectorCallError("not-performed"), which the proxy relays to the agent
 * as "did NOT run" instead of the blanket "may or may not have completed".
 */

export interface GitHubMergeClientOptions {
  tokens: InstallationTokenSource;
  /** the same ledger the token source registers every credential with */
  ledger: SecretLedger;
  baseUrl?: string;
  /** injectable for tests; nothing in the test suite may reach GitHub */
  fetchImpl?: typeof fetch;
  /** per HTTP call; merges can be slow on large repos */
  timeoutMs?: number;
}

export function createGitHubMergeClient(options: GitHubMergeClientOptions): GitHubMergeClient {
  const {
    tokens,
    ledger,
    baseUrl = GITHUB_API_BASE_URL,
    fetchImpl = fetch,
    timeoutMs = 30_000,
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

  function prPath(args: MergePrArgs): string {
    assertUrlSafeName(args.owner, "owner");
    assertUrlSafeName(args.repo, "repository name");
    return `${baseUrl}/repos/${args.owner}/${args.repo}/pulls/${args.pullNumber}`;
  }

  /**
   * The one verification read after an ambiguous dispatch. GET the PR and
   * trust only `merged: true` — that is conclusive, and `merge_commit_sha`
   * is the merge commit once merged. Anything else stays honestly unknown.
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
    let res: Response;
    try {
      res = await boundedFetch(fetchImpl, prUrl, { headers: headers(token) }, timeoutMs);
    } catch (err) {
      throw unknownOutcome(
        `${cause}; the post-dispatch verification read also failed (${errorText(err)}), so the ` +
          `outcome is UNKNOWN. ${checkYourself}`,
      );
    }
    if (!res.ok) {
      throw unknownOutcome(
        `${cause}; the post-dispatch verification read answered HTTP ${res.status}, so the ` +
          `outcome is UNKNOWN. ${checkYourself}`,
      );
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw unknownOutcome(
        `${cause}; the post-dispatch verification read returned an unreadable body, so the ` +
          `outcome is UNKNOWN. ${checkYourself}`,
      );
    }
    const { merged, merge_commit_sha } = (body ?? {}) as {
      merged?: unknown;
      merge_commit_sha?: unknown;
    };
    if (merged === true) {
      return {
        merged: true,
        sha: typeof merge_commit_sha === "string" ? ledger.redact(merge_commit_sha) : "",
        message: ledger.redact(
          `merged — ${cause}, but a post-dispatch verification read confirms the pull request ` +
            `is merged`,
        ),
      };
    }
    throw unknownOutcome(
      `${cause}; a post-dispatch verification read shows the pull request NOT merged as of ` +
        `that read — but a request that died on the wire can still complete after it, so this ` +
        `is a snapshot, not proof. ${checkYourself}`,
    );
  }

  async function rejectionDetail(res: Response, args: MergePrArgs): Promise<string> {
    const message = await readGitHubErrorMessage(res, (text) => ledger.redact(text));
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
      default:
        return `GitHub refused the merge (HTTP ${res.status})${quoted}.${suffix}`;
    }
  }

  return {
    async mergePullRequest(args: MergePrArgs) {
      // Failures before the PUT goes out — a name that can't form a URL, no
      // installation token — happen strictly BEFORE dispatch: nothing has
      // been sent, so the outcome is definitively not-performed.
      let prUrl: string;
      try {
        prUrl = prPath(args);
      } catch (err) {
        throw notPerformed(`the merge was not dispatched: ${errorText(err)}`);
      }
      let token: string;
      try {
        token = await tokens.tokenFor(args.repo);
      } catch (err) {
        throw notPerformed(
          `the merge was not dispatched — no installation token: ${errorText(err)}`,
        );
      }

      let res: Response;
      try {
        res = await boundedFetch(
          fetchImpl,
          `${prUrl}/merge`,
          {
            method: "PUT",
            headers: { ...headers(token), "content-type": "application/json" },
            body: JSON.stringify({
              ...(args.mergeMethod !== undefined ? { merge_method: args.mergeMethod } : {}),
              ...(args.expectedHeadSha !== undefined ? { sha: args.expectedHeadSha } : {}),
            }),
          },
          timeoutMs,
        );
      } catch (err) {
        // dispatched but died on the wire — GitHub may have performed it
        return verifyAfterAmbiguousDispatch(
          args,
          prUrl,
          token,
          `the merge request failed on the wire (${errorText(err)})`,
        );
      }

      if (res.status === 200) {
        let body: unknown;
        try {
          body = await res.json();
        } catch {
          return verifyAfterAmbiguousDispatch(
            args,
            prUrl,
            token,
            "GitHub answered HTTP 200 with an unreadable body",
          );
        }
        const { sha, merged, message } = (body ?? {}) as {
          sha?: unknown;
          merged?: unknown;
          message?: unknown;
        };
        return {
          merged: merged === true,
          sha: typeof sha === "string" ? ledger.redact(sha) : "",
          // redact THEN truncate — same load-bearing order as
          // readGitHubErrorMessage: cutting first could leave an
          // unrecognizable fragment of an echoed credential
          message: typeof message === "string" ? ledger.redact(message).slice(0, 300) : "",
        };
      }
      if (res.status >= 500) {
        // a gateway error can land after the backend applied the merge
        return verifyAfterAmbiguousDispatch(args, prUrl, token, `GitHub answered HTTP ${res.status}`);
      }
      // every remaining status is a rejection: received, refused, not merged
      throw notPerformed(await rejectionDetail(res, args));
    },
  };
}
