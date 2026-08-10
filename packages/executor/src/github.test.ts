import { describe, expect, it } from "vitest";
import { ConnectorCallError } from "./connector-error.js";
import { GitHubMergePrExecutor, parseMergePrArgs, type GitHubMergeClient } from "./github.js";
import { createSecretLedger } from "./secret-ledger.js";
import type { ActionTicket } from "./ticket.js";

const SHA = "c".repeat(40);

const TICKET: ActionTicket = {
  agentId: "a1",
  sourceTool: "github.merge_pr",
  decision: "allow",
  ruleId: "merge",
  connector: "github",
  operation: "merge_pull_request",
  canonicalArgs: `{"expectedHeadSha":"${SHA}","owner":"ownerswitchai","pullNumber":7,"repo":"ownerswitch"}`,
  resourceId: "github:pr:ownerswitchai/ownerswitch#7",
  policyVersion: "sha256:test",
  killEpoch: 0,
  expiresAt: 2_000,
  nonce: "n-1",
  singleUse: true,
};

/** Client stub factory — getPullRequestHead never reached in these tests. */
function stubClient(merge: GitHubMergeClient["mergePullRequest"]): GitHubMergeClient {
  return {
    mergePullRequest: merge,
    getPullRequestHead: async () => SHA,
  };
}

describe("parseMergePrArgs", () => {
  it("accepts a full 40-hex and a full 64-hex expectedHeadSha", () => {
    const sha1 = "a".repeat(40);
    const sha256 = "b".repeat(64);
    expect(
      parseMergePrArgs(`{"owner":"o","repo":"r","pullNumber":1,"expectedHeadSha":"${sha1}"}`)
        .expectedHeadSha,
    ).toBe(sha1);
    expect(
      parseMergePrArgs(`{"owner":"o","repo":"r","pullNumber":1,"expectedHeadSha":"${sha256}"}`)
        .expectedHeadSha,
    ).toBe(sha256);
  });

  it("REQUIRES expectedHeadSha — a ticket without a pinned head does not parse", () => {
    expect(() => parseMergePrArgs('{"owner":"o","repo":"r","pullNumber":1}')).toThrowError(
      /requires expectedHeadSha/,
    );
  });

  it("refuses an abbreviated or malformed expectedHeadSha — an approval must bind to exactly one head", () => {
    for (const bad of ['"abc123"', `"${"g".repeat(40)}"`, "7", "true"]) {
      expect(() =>
        parseMergePrArgs(`{"owner":"o","repo":"r","pullNumber":1,"expectedHeadSha":${bad}}`),
      ).toThrowError(/expectedHeadSha/);
    }
  });

  it("requires a SAFE positive integer pullNumber", () => {
    expect(() =>
      parseMergePrArgs(
        `{"owner":"o","repo":"r","pullNumber":9007199254740993,"expectedHeadSha":"${SHA}"}`,
      ),
    ).toThrowError(/safe positive integer/);
  });
});

describe("GitHubMergePrExecutor with the SecretLedger's redaction", () => {
  it("scrubs ledger secrets from a client error — and keeps the outcome classification intact", async () => {
    const ledger = createSecretLedger();
    const token = "ghs_rotating_token_only_the_ledger_knows";
    ledger.add(token);
    const backend = new GitHubMergePrExecutor(
      stubClient(async () => {
        throw new ConnectorCallError(
          `GitHub refused the merge (HTTP 401): Bad credentials: ${token}. The merge was NOT performed by this request.`,
          "not-performed",
        );
      }),
      undefined,
      (text) => ledger.redact(text),
    );

    let caught: unknown;
    try {
      await backend.execute(TICKET);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ConnectorCallError);
    const err = caught as ConnectorCallError;
    expect(err.outcome).toBe("not-performed");
    expect(err.message).toContain("[REDACTED]");
    expect(err.message).not.toContain(token);
  });

  it("scrubs ledger secrets from result fields too — the second line of defence covers data, not just errors", async () => {
    const ledger = createSecretLedger();
    const token = "ghs_token_echoed_into_a_result";
    ledger.add(token);
    const backend = new GitHubMergePrExecutor(
      stubClient(async () => ({
        merged: true,
        sha: "abc",
        message: `merged (audit: ${token})`,
      })),
      undefined,
      (text) => ledger.redact(text),
    );
    const result = await backend.execute(TICKET);
    expect(JSON.stringify(result)).not.toContain(token);
    expect(result.detail.message).toContain("[REDACTED]");
  });

  it("without a client, refuses as not-configured and definitively not performed", async () => {
    const backend = new GitHubMergePrExecutor();
    let caught: unknown;
    try {
      await backend.execute(TICKET);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ConnectorCallError);
    expect((caught as ConnectorCallError).outcome).toBe("not-performed");
    expect((caught as ConnectorCallError).message).toMatch(/not configured/);
  });
});
