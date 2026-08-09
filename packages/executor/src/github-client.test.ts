import { describe, expect, it } from "vitest";
import { ConnectorCallError } from "./connector-error.js";
import { createGitHubMergeClient } from "./github-client.js";
import type { InstallationTokenSource } from "./github-app-auth.js";
import { createSecretLedger } from "./secret-ledger.js";

/**
 * The live connector, tested against scripted responses only — nothing in
 * this file (or anywhere in the suite) performs a live merge; the one live
 * run is the documented manual procedure in MANUAL-VERIFICATION.md.
 *
 * The two claims under test, per the task the module exists for:
 *  1. no code path ever puts the credential into a result, an error, or a
 *     rejection — including a GitHub error that echoes the token back;
 *  2. every failure is classified honestly: 4xx = definitively
 *     not-performed; wire death / 5xx = verify after the fact, and only
 *     claim what the verification read can actually prove.
 */

const TOKEN = "ghs_installation_token_0123456789abcdef";
const ARGS = { owner: "ownerswitchai", repo: "throwaway", pullNumber: 7 };

interface Recorded {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

function scripted(script: Array<(req: Recorded) => Response | never>) {
  const requests: Recorded[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const req: Recorded = {
      url: String(input),
      method: init?.method ?? "GET",
      headers: Object.fromEntries(
        Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [
          k.toLowerCase(),
          v,
        ]),
      ),
      body: init?.body !== undefined ? JSON.parse(String(init.body)) : undefined,
    };
    requests.push(req);
    const next = script.shift();
    if (next === undefined) throw new Error("scripted: no response left for " + req.url);
    return next(req);
  };
  return { requests, fetchImpl };
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

const wireDeath = (): never => {
  throw new TypeError("fetch failed: socket hang up");
};

function client(script: Array<(req: Recorded) => Response | never>) {
  const github = scripted(script);
  const ledger = createSecretLedger();
  ledger.add(TOKEN);
  const tokens: InstallationTokenSource = { tokenFor: async () => TOKEN };
  const merge = createGitHubMergeClient({ tokens, ledger, fetchImpl: github.fetchImpl });
  return { github, merge };
}

async function failureOf(promise: Promise<unknown>): Promise<ConnectorCallError> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(ConnectorCallError);
    return err as ConnectorCallError;
  }
  throw new Error("expected the merge to fail");
}

describe("createGitHubMergeClient", () => {
  it("merges: authenticated PUT with method and sha guard, result carries data and never the token", async () => {
    const { github, merge } = client([
      () => json({ sha: "abc123", merged: true, message: "Pull Request successfully merged" }),
    ]);

    const outcome = await merge.mergePullRequest({
      ...ARGS,
      mergeMethod: "squash",
      expectedHeadSha: "a".repeat(40),
    });

    expect(outcome).toEqual({
      merged: true,
      sha: "abc123",
      message: "Pull Request successfully merged",
    });
    expect(github.requests).toHaveLength(1);
    const req = github.requests[0]!;
    expect(req.method).toBe("PUT");
    expect(req.url).toBe("https://api.github.com/repos/ownerswitchai/throwaway/pulls/7/merge");
    expect(req.headers["authorization"]).toBe(`Bearer ${TOKEN}`);
    expect(req.headers["x-github-api-version"]).toBe("2022-11-28");
    // the sha guard: "SHA that pull request head must match to allow merge"
    expect(req.body).toEqual({ merge_method: "squash", sha: "a".repeat(40) });
    expect(JSON.stringify(outcome)).not.toContain(TOKEN);
  });

  it("omits merge_method and sha when the ticket does not pin them", async () => {
    const { github, merge } = client([() => json({ sha: "s", merged: true, message: "" })]);
    await merge.mergePullRequest(ARGS);
    expect(github.requests[0]!.body).toEqual({});
  });

  it("404: definitively not performed, and the message explains GitHub's 404-for-invisible convention", async () => {
    const { merge } = client([() => json({ message: "Not Found" }, 404)]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/404/);
    expect(err.message).toMatch(/cannot see/);
    expect(err.message).toMatch(/NOT performed/);
  });

  it("403: definitively not performed", async () => {
    const { merge } = client([() => json({ message: "Forbidden" }, 403)]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/HTTP 403/);
    expect(err.message).toMatch(/NOT performed/);
  });

  it("rate limiting (403 with exhausted quota, and 429) is named as such", async () => {
    const limited = client([
      () => json({ message: "API rate limit exceeded" }, 403, { "x-ratelimit-remaining": "0" }),
    ]);
    const err = await failureOf(limited.merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/rate-limited/);

    const secondary = client([
      () => json({ message: "You have exceeded a secondary rate limit" }, 429, {
        "retry-after": "60",
      }),
    ]);
    const err2 = await failureOf(secondary.merge.mergePullRequest(ARGS));
    expect(err2.outcome).toBe("not-performed");
    expect(err2.message).toMatch(/rate-limited/);
  });

  it("405 (not mergeable): definitively not performed, causes named", async () => {
    const { merge } = client([() => json({ message: "Pull Request is not mergeable" }, 405)]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/not mergeable/);
    expect(err.message).toMatch(/draft, failing required checks, branch protection, or already merged/);
  });

  it("409 (head changed): definitively not performed — the approval no longer matches the branch", async () => {
    const { merge } = client([() => json({ message: "Head branch was modified" }, 409)]);
    const err = await failureOf(
      merge.mergePullRequest({ ...ARGS, expectedHeadSha: "b".repeat(40) }),
    );
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/409/);
    expect(err.message).toMatch(/commits the owner never saw/);
  });

  it("401 and 422: definitively not performed", async () => {
    const unauthorized = client([() => json({ message: "Bad credentials" }, 401)]);
    const err401 = await failureOf(unauthorized.merge.mergePullRequest(ARGS));
    expect(err401.outcome).toBe("not-performed");
    expect(err401.message).toMatch(/rejected the executor's credential/);

    const invalid = client([() => json({ message: "Validation Failed" }, 422)]);
    const err422 = await failureOf(invalid.merge.mergePullRequest(ARGS));
    expect(err422.outcome).toBe("not-performed");
    expect(err422.message).toMatch(/HTTP 422/);
  });

  it("a GitHub error that echoes the token back is redacted before it can ride anywhere", async () => {
    const { merge } = client([
      () => json({ message: `Bad credentials: token ${TOKEN} is not valid` }, 401),
    ]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.message).toContain("[REDACTED]");
    expect(err.message).not.toContain(TOKEN);
  });

  it("a transport error whose text contains the token is redacted too", async () => {
    const { merge } = client([
      () => {
        // undici-style failures can serialize request details; simulate the
        // worst case — the credential inside the thrown error's text — and
        // one verification failure after it
        throw new TypeError(`fetch failed: header authorization: Bearer ${TOKEN}`);
      },
      wireDeath,
    ]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.message).toContain("[REDACTED]");
    expect(err.message).not.toContain(TOKEN);
  });

  it("wire death, then verification finds the PR merged: returns success, marked as verified", async () => {
    const { github, merge } = client([
      wireDeath,
      () => json({ merged: true, merge_commit_sha: "deadbeef" }),
    ]);
    const outcome = await merge.mergePullRequest(ARGS);
    expect(outcome.merged).toBe(true);
    expect(outcome.sha).toBe("deadbeef");
    expect(outcome.message).toMatch(/verification read confirms/);
    // the verification read is the PR GET, with the same scoped token
    expect(github.requests[1]!.method).toBe("GET");
    expect(github.requests[1]!.url).toBe(
      "https://api.github.com/repos/ownerswitchai/throwaway/pulls/7",
    );
  });

  it("wire death, verification says not merged: outcome UNKNOWN, message says a snapshot is not proof", async () => {
    const { merge } = client([wireDeath, () => json({ merged: false, merge_commit_sha: null })]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("unknown");
    expect(err.message).toMatch(/NOT merged as of that read/);
    expect(err.message).toMatch(/snapshot, not proof/);
    expect(err.message).toMatch(/Check ownerswitchai\/throwaway#7 directly/);
  });

  it("wire death, verification also dead: outcome UNKNOWN with explicit operator instructions", async () => {
    const { merge } = client([wireDeath, wireDeath]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("unknown");
    expect(err.message).toMatch(/UNKNOWN/);
    expect(err.message).toMatch(/before re-approving/);
  });

  it("a 5xx answer is ambiguous — verified the same way as wire death", async () => {
    const { merge } = client([
      () => json({ message: "Server Error" }, 502),
      () => json({ merged: true, merge_commit_sha: "cafe01" }),
    ]);
    const outcome = await merge.mergePullRequest(ARGS);
    expect(outcome.merged).toBe(true);
    expect(outcome.sha).toBe("cafe01");
  });

  it("no installation token: definitively not dispatched", async () => {
    const github = scripted([]);
    const ledger = createSecretLedger();
    const merge = createGitHubMergeClient({
      tokens: {
        tokenFor: async () => {
          throw new Error("GitHub rejected the App JWT (HTTP 401)");
        },
      },
      ledger,
      fetchImpl: github.fetchImpl,
    });
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/not dispatched/);
    expect(github.requests).toHaveLength(0);
  });

  it("refuses owner/repo values that could smuggle path segments into the URL — before any dispatch", async () => {
    const { merge, github } = client([]);
    const err = await failureOf(merge.mergePullRequest({ ...ARGS, owner: "a/../b" }));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/not dispatched/);
    expect(err.message).toMatch(/owner/);
    expect(github.requests).toHaveLength(0);
  });
});
