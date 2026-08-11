import { describe, expect, it } from "vitest";
import { ConnectorCallError } from "./connector-error.js";
import { createGitHubMergeClient } from "./github-client.js";
import type { InstallationTokenSource } from "./github-app-auth.js";
import type { MergePrArgs } from "./github.js";
import { createSecretLedger } from "./secret-ledger.js";

/**
 * The live connector, tested against scripted responses only — nothing in
 * this file (or anywhere in the suite) performs a live merge; the one live
 * run is the documented manual procedure in MANUAL-VERIFICATION.md.
 *
 * The claims under test:
 *  1. no code path ever puts the credential into a result, an error, or a
 *     rejection — including a GitHub error echoing the token back and a
 *     transport error carrying a token FRAGMENT (transport text is never
 *     forwarded at all: fixed sentences only);
 *  2. failure classification is a whitelist: only GitHub's documented
 *     rejection statuses count as "did NOT run"; everything else — 5xx,
 *     an intermediary 408, a 200 that doesn't confirm the merge — takes
 *     the verification path and ends UNKNOWN at worst;
 *  3. the verification read is worded for what it proves: the PR's merged
 *     STATE, never that this dispatch performed the merge;
 *  4. `sha` is mandatory on every merge, and every request refuses
 *     redirects.
 */

const TOKEN = "ghs_installation_token_0123456789abcdef";
const HEAD_SHA = "a".repeat(40);
const ARGS: MergePrArgs = {
  owner: "ownerswitchai",
  repo: "throwaway",
  pullNumber: 7,
  expectedHeadSha: HEAD_SHA,
  expectedBaseRef: "main",
};

interface Recorded {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  redirect: RequestRedirect | undefined;
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
      redirect: init?.redirect,
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

/** The pre-dispatch base-check GET (every merge now starts with one). */
const baseOk = () => json({ merged: false, head: { sha: HEAD_SHA }, base: { ref: "main" } });

function client(script: Array<(req: Recorded) => Response | never>, timeoutMs?: number) {
  const github = scripted(script);
  const ledger = createSecretLedger();
  ledger.add(TOKEN);
  const tokens: InstallationTokenSource = { tokenFor: async () => TOKEN };
  const merge = createGitHubMergeClient({
    tokens,
    ledger,
    fetchImpl: github.fetchImpl,
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
  });
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

describe("createGitHubMergeClient — mergePullRequest", () => {
  it("merges: authenticated PUT always carrying the pinned sha, refusing redirects; result carries data, never the token", async () => {
    const { github, merge } = client([
      baseOk,
      () => json({ sha: "abc123", merged: true, message: "Pull Request successfully merged" }),
    ]);

    const outcome = await merge.mergePullRequest({ ...ARGS, mergeMethod: "squash" });

    expect(outcome).toEqual({
      merged: true,
      sha: "abc123",
      message: "Pull Request successfully merged",
      attribution: "this-dispatch",
    });
    // request 0 is the pre-dispatch base check; request 1 is the PUT
    expect(github.requests).toHaveLength(2);
    expect(github.requests[0]!.method).toBe("GET");
    const req = github.requests[1]!;
    expect(req.method).toBe("PUT");
    expect(req.url).toBe("https://api.github.com/repos/ownerswitchai/throwaway/pulls/7/merge");
    expect(req.headers["authorization"]).toBe(`Bearer ${TOKEN}`);
    expect(req.headers["x-github-api-version"]).toBe("2022-11-28");
    // the sha guard is MANDATORY: "SHA that pull request head must match"
    expect(req.body).toEqual({ merge_method: "squash", sha: HEAD_SHA });
    // an authenticated request must never follow a redirect
    expect(req.redirect).toBe("error");
    expect(JSON.stringify(outcome)).not.toContain(TOKEN);
  });

  it("omits merge_method when unset — but sha is always sent", async () => {
    const { github, merge } = client([baseOk, () => json({ sha: "s", merged: true, message: "" })]);
    await merge.mergePullRequest(ARGS);
    expect(github.requests[1]!.body).toEqual({ sha: HEAD_SHA });
  });

  it("refuses to dispatch without expectedHeadSha — defense in depth under the parser", async () => {
    const { github, merge } = client([]);
    const err = await failureOf(
      merge.mergePullRequest({ ...ARGS, expectedHeadSha: "" } as MergePrArgs),
    );
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/expectedHeadSha is mandatory/);
    expect(github.requests).toHaveLength(0);
  });

  it("404: definitively not performed, and the message explains GitHub's 404-for-invisible convention", async () => {
    const { merge } = client([baseOk, () => json({ message: "Not Found" }, 404)]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/404/);
    expect(err.message).toMatch(/cannot see/);
    expect(err.message).toMatch(/NOT performed/);
  });

  it("403 and 401 and 422: documented rejections, definitively not performed", async () => {
    for (const [status, pattern] of [
      [403, /forbade the merge/],
      [401, /rejected the executor's credential/],
      [422, /HTTP 422/],
    ] as const) {
      const { merge } = client([baseOk, () => json({ message: "nope" }, status)]);
      const err = await failureOf(merge.mergePullRequest(ARGS));
      expect(err.outcome).toBe("not-performed");
      expect(err.message).toMatch(pattern);
      expect(err.message).toMatch(/NOT performed/);
    }
  });

  it("rate limiting (403 with exhausted quota, and 429) is named as such", async () => {
    const limited = client([
      baseOk,
      () => json({ message: "API rate limit exceeded" }, 403, { "x-ratelimit-remaining": "0" }),
    ]);
    const err = await failureOf(limited.merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/rate-limited/);

    const secondary = client([
      baseOk,
      () => json({ message: "You have exceeded a secondary rate limit" }, 429, {
        "retry-after": "60",
      }),
    ]);
    const err2 = await failureOf(secondary.merge.mergePullRequest(ARGS));
    expect(err2.outcome).toBe("not-performed");
    expect(err2.message).toMatch(/rate-limited/);
  });

  it("405 (not mergeable): definitively not performed, causes named", async () => {
    const { merge } = client([baseOk, () => json({ message: "Pull Request is not mergeable" }, 405)]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/not mergeable/);
    expect(err.message).toMatch(/draft, failing required checks, branch protection, or already merged/);
  });

  it("409 (head changed): definitively not performed — the approval no longer matches the branch", async () => {
    const { merge } = client([baseOk, () => json({ message: "Head branch was modified" }, 409)]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/409/);
    expect(err.message).toMatch(/commits the owner never saw/);
  });

  it("an UNRECOGNIZED 4xx — an intermediary's 408 — is never trusted as 'did not run': verification path", async () => {
    const verified = client([
      baseOk,
      () => json({ message: "Request Timeout" }, 408),
      () => json({ merged: true, merge_commit_sha: "deadbeef" }),
    ]);
    const outcome = await verified.merge.mergePullRequest(ARGS);
    expect(outcome.merged).toBe(true);
    expect(outcome.sha).toBe("deadbeef");
    expect(outcome.message).toMatch(/unrecognized HTTP 408/);

    const unverified = client([
      baseOk,
      () => json({ message: "Request Timeout" }, 408),
      () => json({ merged: false }),
    ]);
    const err = await failureOf(unverified.merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("unknown");
  });

  it("a 200 that does not confirm the merge is malformed, never success — verification decides", async () => {
    const { merge } = client([
      baseOk,
      () => json({ merged: false, message: "odd" }),
      () => json({ merged: false }),
    ]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("unknown");
    expect(err.message).toMatch(/HTTP 200 without confirming the merge/);
  });

  it("a GitHub error that echoes the token back is redacted before it can ride anywhere", async () => {
    const { merge } = client([
      baseOk,
      () => json({ message: `Bad credentials: token ${TOKEN} is not valid` }, 401),
    ]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.message).toContain("[REDACTED]");
    expect(err.message).not.toContain(TOKEN);
  });

  it("transport error text is NEVER forwarded — a token FRAGMENT in it cannot leak because the channel does not exist", async () => {
    const fragment = TOKEN.slice(0, 20); // a fragment defeats exact-match redaction
    const { merge } = client([
      baseOk,
      () => {
        throw new TypeError(`fetch failed: header authorization: Bearer ${fragment}…`);
      },
      () => {
        throw new TypeError(`verification also failed near ${fragment}`);
      },
    ]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("unknown");
    expect(err.message).toMatch(/a network-level failure occurred/);
    expect(err.message).not.toContain(fragment);
    expect(err.message).not.toContain("fetch failed");
  });

  it("a timeout surfaces as the fixed timeout sentence, not the abort error's text", async () => {
    let calls = 0;
    const hang: typeof fetch = (_input, init) => {
      calls += 1;
      if (calls === 1) {
        // the pre-dispatch base check answers; the PUT (and the
        // verification read) hang until aborted
        return Promise.resolve(
          json({ merged: false, head: { sha: HEAD_SHA }, base: { ref: "main" } }),
        );
      }
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(Object.assign(new Error("secret-ish abort internals"), { name: "AbortError" })),
        );
      });
    };
    const ledger = createSecretLedger();
    ledger.add(TOKEN);
    const merge = createGitHubMergeClient({
      tokens: { tokenFor: async () => TOKEN },
      ledger,
      fetchImpl: hang,
      timeoutMs: 25,
    });
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("unknown");
    expect(err.message).toMatch(/the request timed out/);
    expect(err.message).not.toContain("secret-ish");
  });

  it("wire death, then verification finds the PR merged: success worded for what the read PROVES", async () => {
    const { github, merge } = client([
      baseOk,
      wireDeath,
      () => json({ merged: true, merge_commit_sha: "deadbeef" }),
    ]);
    const outcome = await merge.mergePullRequest(ARGS);
    expect(outcome.merged).toBe(true);
    expect(outcome.sha).toBe("deadbeef");
    // the read proves the PR's merged STATE — not that THIS dispatch did it
    expect(outcome.message).toMatch(/MERGED STATE/);
    expect(outcome.message).toMatch(/whether THIS dispatch performed the merge cannot be determined/);
    expect(github.requests[2]!.method).toBe("GET");
    expect(github.requests[2]!.url).toBe(
      "https://api.github.com/repos/ownerswitchai/throwaway/pulls/7",
    );
    expect(github.requests[2]!.redirect).toBe("error");
  });

  it("wire death, verification says not merged: outcome UNKNOWN, a snapshot is not proof", async () => {
    const { merge } = client([baseOk, wireDeath, () => json({ merged: false, merge_commit_sha: null })]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("unknown");
    expect(err.message).toMatch(/NOT merged as of that read/);
    expect(err.message).toMatch(/snapshot, not proof/);
    expect(err.message).toMatch(/Check ownerswitchai\/throwaway#7 directly/);
  });

  it("wire death, verification also dead: outcome UNKNOWN with explicit operator instructions", async () => {
    const { merge } = client([baseOk, wireDeath, wireDeath]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("unknown");
    expect(err.message).toMatch(/UNKNOWN/);
    expect(err.message).toMatch(/before re-approving/);
  });

  it("a 5xx answer is ambiguous — verified the same way as wire death", async () => {
    const { merge } = client([
      baseOk,
      () => json({ message: "Server Error" }, 502),
      () => json({ merged: true, merge_commit_sha: "cafe01" }),
    ]);
    const outcome = await merge.mergePullRequest(ARGS);
    expect(outcome.merged).toBe(true);
    expect(outcome.sha).toBe("cafe01");
    // machine-readable caveat: merged STATE observed, not this dispatch
    expect(outcome.attribution).toBe("merged-state-only");
  });

  it("an oversized error body is dropped by the stream cap, never quoted", async () => {
    const huge = JSON.stringify({ message: `big ${"x".repeat(5 * 1024 * 1024)}` });
    const { merge } = client([baseOk, () => new Response(huge, { status: 403 })]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/HTTP 403/);
    expect(err.message.length).toBeLessThan(500);
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

  it("refuses dot segments and unsafe names in owner/repo — before any dispatch", async () => {
    for (const bad of [
      { ...ARGS, repo: ".." },
      { ...ARGS, repo: "." },
      { ...ARGS, owner: "a/../b" },
      { ...ARGS, owner: "a".repeat(40) },
      { ...ARGS, repo: "r".repeat(101) },
      { ...ARGS, pullNumber: 2 ** 53 },
    ]) {
      const { merge, github } = client([]);
      const err = await failureOf(merge.mergePullRequest(bad));
      expect(err.outcome).toBe("not-performed");
      expect(err.message).toMatch(/not dispatched/);
      expect(github.requests).toHaveLength(0);
    }
  });
});

describe("createGitHubMergeClient — getPullRequestHead (the review-time pin)", () => {
  it("returns the PR's current head sha AND base ref — the full pinned merge target", async () => {
    const { github, merge } = client([
      () => json({ merged: false, head: { sha: HEAD_SHA }, base: { ref: "main" } }),
    ]);
    expect(await merge.getPullRequestHead(ARGS)).toEqual({ headSha: HEAD_SHA, baseRef: "main" });
    expect(github.requests[0]!.method).toBe("GET");
    expect(github.requests[0]!.url).toBe(
      "https://api.github.com/repos/ownerswitchai/throwaway/pulls/7",
    );
  });

  it("refuses to pin an already-merged PR", async () => {
    const { merge } = client([() => json({ merged: true, head: { sha: HEAD_SHA } })]);
    await expect(merge.getPullRequestHead(ARGS)).rejects.toThrowError(/already merged/);
  });

  it("refuses a head that is not a full commit id", async () => {
    const { merge } = client([() => json({ merged: false, head: { sha: "abc123" }, base: { ref: "main" } })]);
    await expect(merge.getPullRequestHead(ARGS)).rejects.toThrowError(/no usable head sha/);
  });

  it("refuses a PR response with no usable base ref — the destination must be pinnable", async () => {
    const { merge } = client([() => json({ merged: false, head: { sha: HEAD_SHA } })]);
    await expect(merge.getPullRequestHead(ARGS)).rejects.toThrowError(/no usable base ref/);
  });
});

describe("createGitHubMergeClient — the pre-dispatch BASE check", () => {
  it("a PR retargeted after approval is refused before the PUT — zero merges", async () => {
    const { github, merge } = client([
      () => json({ merged: false, head: { sha: HEAD_SHA }, base: { ref: "release-1.0" } }),
    ]);
    const err = await failureOf(merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/retargeted after approval/);
    expect(err.message).toMatch(/"release-1.0"/);
    expect(github.requests.filter((r) => r.method === "PUT")).toHaveLength(0);
  });

  it("a base the check cannot read or verify is refused — never dispatched on a guess", async () => {
    const noBase = client([() => json({ merged: false, head: { sha: HEAD_SHA } })]);
    const err = await failureOf(noBase.merge.mergePullRequest(ARGS));
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toMatch(/no usable base ref/);

    const dead = client([wireDeath]);
    const err2 = await failureOf(dead.merge.mergePullRequest(ARGS));
    expect(err2.outcome).toBe("not-performed");
    expect(err2.message).toMatch(/base check could not read/);
    expect(dead.github.requests.filter((r) => r.method === "PUT")).toHaveLength(0);
  });
});
