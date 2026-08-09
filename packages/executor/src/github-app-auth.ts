import { createSign, type KeyObject } from "node:crypto";
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
 * GitHub App authentication for the executor — the credential model
 * DESIGN.md §5 calls for once OwnerSwitch itself holds the prize: NOT a
 * personal access token (a PAT is a standing, broadly-scoped credential
 * that lives exactly as long as nobody rotates it), but a GitHub App whose
 * private key mints short-lived installation tokens scoped, per mint, to
 * exactly one repository and exactly the permissions the one operation
 * needs.
 *
 * The flow, per GitHub's documentation (verified against the REST API
 * description and the App JWT docs, 2026-08):
 *
 *   1. The App's RSA private key signs a JWT — RS256 required, `iat` set
 *      60 s in the past for clock drift, `exp` at most 10 minutes out,
 *      `iss` the App id.
 *   2. The JWT calls POST /app/installations/{installation_id}/access_tokens
 *      with an explicit `repositories: [repo]` and
 *      `permissions: { contents: "write", pull_requests: "read" }` body —
 *      an installation token is scoped DOWN at mint time, and a token this
 *      module mints can merge PRs in one named repository and read PR state
 *      there, nothing else. (The merge endpoint itself requires
 *      `contents: write`; `pull_requests: read` exists solely for the
 *      post-ambiguity verification read — see github-client.ts.)
 *   3. Installation tokens expire one hour after minting (GitHub's
 *      lifetime, not configurable). They are cached per repository and
 *      re-minted when within EXPIRY_MARGIN_MS of expiry, so a token is
 *      never knowingly presented near its deadline.
 *
 * No-leak rule, structural: the private key, every JWT, and every
 * installation token are registered with the SecretLedger the moment they
 * exist; no code path in this module logs, throws, or returns anything but
 * (a) the token to the caller that must present it, and (b) error messages
 * assembled from status codes and GitHub's bounded `message` field, passed
 * through the ledger's redaction.
 */

export interface GitHubAppConfig {
  /** the App id (or client id) — the JWT's `iss` claim; not a secret */
  appId: string;
  /** the numeric installation id of the App on the target account */
  installationId: string;
  /** the App's RSA private key, parsed (loadGitHubAppPrivateKey) */
  privateKey: KeyObject;
}

/**
 * The full permission set an installation token needs for
 * merge_pull_request: `contents: write` performs the merge (the documented
 * requirement of PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge);
 * `pull_requests: read` lets the client verify an ambiguous dispatch after
 * the fact via GET /repos/{owner}/{repo}/pulls/{pull_number}. Nothing else.
 */
export const INSTALLATION_TOKEN_PERMISSIONS: Readonly<Record<string, string>> = Object.freeze({
  contents: "write",
  pull_requests: "read",
});

/** JWTs live 9 minutes — inside GitHub's 10-minute cap with skew to spare. */
const JWT_LIFETIME_SECONDS = 9 * 60;
/** `iat` is backdated 60 s, as GitHub's own docs recommend for clock drift. */
const JWT_BACKDATE_SECONDS = 60;

/** Re-mint when a cached token is within this margin of its expiry. */
export const EXPIRY_MARGIN_MS = 5 * 60 * 1000;

export interface InstallationTokenSource {
  /**
   * A live installation token scoped to exactly `repo` (name only — the
   * owner side is fixed by the installation) and
   * INSTALLATION_TOKEN_PERMISSIONS. Cached until near expiry.
   */
  tokenFor(repo: string): Promise<string>;
}

export interface InstallationTokenSourceOptions {
  app: GitHubAppConfig;
  /** every secret this source ever holds is registered here */
  ledger: SecretLedger;
  baseUrl?: string;
  /** injectable for tests; nothing in the test suite may reach GitHub */
  fetchImpl?: typeof fetch;
  now?: () => number;
  timeoutMs?: number;
}

export function createInstallationTokenSource(
  options: InstallationTokenSourceOptions,
): InstallationTokenSource {
  const {
    app,
    ledger,
    baseUrl = GITHUB_API_BASE_URL,
    fetchImpl = fetch,
    now = Date.now,
    timeoutMs = 10_000,
  } = options;

  const cache = new Map<string, { token: string; expiresAtMs: number }>();
  const pending = new Map<string, Promise<string>>();

  function appJwt(): string {
    const iat = Math.floor(now() / 1000) - JWT_BACKDATE_SECONDS;
    const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
    const payload = b64url(
      JSON.stringify({ iat, exp: iat + JWT_BACKDATE_SECONDS + JWT_LIFETIME_SECONDS, iss: app.appId }),
    );
    const signature = createSign("RSA-SHA256")
      .update(`${header}.${payload}`)
      .sign(app.privateKey)
      .toString("base64url");
    const jwt = `${header}.${payload}.${signature}`;
    // the JWT is itself a credential (it mints tokens for 9 more minutes)
    ledger.add(jwt);
    return jwt;
  }

  async function mint(repo: string): Promise<string> {
    assertUrlSafeName(app.installationId, "installation id");
    const url = `${baseUrl}/app/installations/${app.installationId}/access_tokens`;
    let res: Response;
    try {
      res = await boundedFetch(
        fetchImpl,
        url,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${appJwt()}`,
            accept: "application/vnd.github+json",
            "content-type": "application/json",
            "x-github-api-version": GITHUB_API_VERSION,
            "user-agent": USER_AGENT,
          },
          body: JSON.stringify({
            repositories: [repo],
            permissions: INSTALLATION_TOKEN_PERMISSIONS,
          }),
        },
        timeoutMs,
      );
    } catch (err) {
      throw redacted(`cannot reach GitHub to mint an installation token: ${errorText(err)}`);
    }
    if (res.status !== 201) {
      throw redacted(await mintRefusalDetail(res, repo));
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw redacted("GitHub's installation-token response was not JSON");
    }
    const { token, expires_at } = (body ?? {}) as { token?: unknown; expires_at?: unknown };
    if (typeof token !== "string" || token === "") {
      throw redacted("GitHub's installation-token response carried no token");
    }
    // FIRST thing that happens to a token that exists: it becomes redactable
    ledger.add(token);
    // An unparseable expires_at is cached as already-expired: the token is
    // used once and re-minted next time. Guessing a lifetime would risk
    // presenting a token past its real expiry; minting more often only
    // costs an extra HTTPS call.
    const expiresAtMs = typeof expires_at === "string" ? Date.parse(expires_at) : Number.NaN;
    cache.set(repo, { token, expiresAtMs: Number.isNaN(expiresAtMs) ? 0 : expiresAtMs });
    return token;
  }

  async function mintRefusalDetail(res: Response, repo: string): Promise<string> {
    const message = await readGitHubErrorMessage(res, (text) => ledger.redact(text));
    const quoted = message === "" ? "" : `: ${message}`;
    switch (res.status) {
      case 401:
        return (
          `GitHub rejected the App JWT (HTTP 401)${quoted} — check that the App id and the ` +
          `private key belong to the same App, and that this host's clock is accurate`
        );
      case 404:
        return (
          `GitHub reports no installation "${app.installationId}" for this App (HTTP 404)${quoted} — ` +
          `is the App installed, and is the numeric installation id right?`
        );
      case 422:
        return (
          `GitHub refused the requested token scope (HTTP 422)${quoted} — is the App's ` +
          `installation granted access to "${repo}" with contents:write and pull_requests:read?`
        );
      default:
        return `minting an installation token failed (HTTP ${res.status})${quoted}`;
    }
  }

  function redacted(message: string): Error {
    return new Error(ledger.redact(message));
  }

  return {
    async tokenFor(repo: string): Promise<string> {
      assertUrlSafeName(repo, "repository name");
      const cached = cache.get(repo);
      if (cached !== undefined && now() < cached.expiresAtMs - EXPIRY_MARGIN_MS) {
        return cached.token;
      }
      const inFlight = pending.get(repo);
      if (inFlight !== undefined) return inFlight;
      const minting = mint(repo).finally(() => pending.delete(repo));
      pending.set(repo, minting);
      return minting;
    },
  };
}

function b64url(text: string): string {
  return Buffer.from(text, "utf8").toString("base64url");
}
