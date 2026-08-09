import { createVerify, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createInstallationTokenSource,
  EXPIRY_MARGIN_MS,
  INSTALLATION_TOKEN_PERMISSIONS,
} from "./github-app-auth.js";
import { createSecretLedger } from "./secret-ledger.js";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const APP = { appId: "12345", installationId: "42", privateKey };
const NOW = 1_750_000_000_000;
const HOUR = 60 * 60 * 1000;

interface Recorded {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

/** A scripted GitHub: records every request, answers from a queue. */
function fakeGitHub(script: Array<(req: Recorded) => Response>) {
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
    if (next === undefined) throw new Error("fakeGitHub: no scripted response left");
    return next(req);
  };
  return { requests, fetchImpl };
}

const json = (body: unknown, status = 201) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const tokenResponse = (token: string, expiresAtMs: number) => () =>
  json({ token, expires_at: new Date(expiresAtMs).toISOString() });

function source(
  script: Array<(req: Recorded) => Response>,
  opts?: { now?: () => number; ledger?: ReturnType<typeof createSecretLedger> },
) {
  const github = fakeGitHub(script);
  const ledger = opts?.ledger ?? createSecretLedger();
  const tokens = createInstallationTokenSource({
    app: APP,
    ledger,
    fetchImpl: github.fetchImpl,
    now: opts?.now ?? (() => NOW),
  });
  return { github, ledger, tokens };
}

describe("createInstallationTokenSource", () => {
  it("mints a token scoped to exactly one repository and the merge permissions, with a valid RS256 App JWT", async () => {
    const { github, tokens } = source([tokenResponse("ghs_minted_token_1", NOW + HOUR)]);

    const token = await tokens.tokenFor("ownerswitch");

    expect(token).toBe("ghs_minted_token_1");
    expect(github.requests).toHaveLength(1);
    const req = github.requests[0]!;
    expect(req.method).toBe("POST");
    expect(req.url).toBe("https://api.github.com/app/installations/42/access_tokens");
    // scoped DOWN at mint time: one named repository, two permissions,
    // nothing else — this is the whole blast radius of a stolen token
    expect(req.body).toEqual({
      repositories: ["ownerswitch"],
      permissions: { contents: "write", pull_requests: "read" },
    });
    expect(INSTALLATION_TOKEN_PERMISSIONS).toEqual({ contents: "write", pull_requests: "read" });

    // the App JWT: RS256-signed by our key, iat backdated 60s, exp ≤ 10min out
    const jwt = req.headers["authorization"]!.replace(/^Bearer /, "");
    const [header, payload, signature] = jwt.split(".") as [string, string, string];
    expect(JSON.parse(Buffer.from(header, "base64url").toString())).toEqual({
      alg: "RS256",
      typ: "JWT",
    });
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
    expect(claims.iss).toBe("12345");
    expect(claims.iat).toBe(Math.floor(NOW / 1000) - 60);
    expect(claims.exp).toBeGreaterThan(Math.floor(NOW / 1000));
    expect(claims.exp - Math.floor(NOW / 1000)).toBeLessThanOrEqual(600);
    const verified = createVerify("RSA-SHA256")
      .update(`${header}.${payload}`)
      .verify(publicKey, Buffer.from(signature, "base64url"));
    expect(verified).toBe(true);
  });

  it("caches per repository until near expiry, then re-mints", async () => {
    let now = NOW;
    const { github, tokens } = source(
      [
        tokenResponse("ghs_first", NOW + HOUR),
        tokenResponse("ghs_second", NOW + 2 * HOUR),
      ],
      { now: () => now },
    );

    expect(await tokens.tokenFor("repo")).toBe("ghs_first");
    expect(await tokens.tokenFor("repo")).toBe("ghs_first"); // cached
    expect(github.requests).toHaveLength(1);

    // inside the safety margin of expiry: the cached token is not presented
    now = NOW + HOUR - EXPIRY_MARGIN_MS + 1;
    expect(await tokens.tokenFor("repo")).toBe("ghs_second");
    expect(github.requests).toHaveLength(2);
  });

  it("tokens are per-repository: a second repo gets its own scoped mint", async () => {
    const { github, tokens } = source([
      tokenResponse("ghs_for_a", NOW + HOUR),
      tokenResponse("ghs_for_b", NOW + HOUR),
    ]);
    expect(await tokens.tokenFor("repo-a")).toBe("ghs_for_a");
    expect(await tokens.tokenFor("repo-b")).toBe("ghs_for_b");
    expect(github.requests.map((r) => (r.body as { repositories: string[] }).repositories)).toEqual(
      [["repo-a"], ["repo-b"]],
    );
  });

  it("concurrent requests for one repo share a single mint", async () => {
    const { github, tokens } = source([tokenResponse("ghs_once", NOW + HOUR)]);
    const [a, b] = await Promise.all([tokens.tokenFor("repo"), tokens.tokenFor("repo")]);
    expect(a).toBe("ghs_once");
    expect(b).toBe("ghs_once");
    expect(github.requests).toHaveLength(1);
  });

  it("an unparseable expires_at is cached as already-expired: used once, re-minted next time", async () => {
    const { github, tokens } = source([
      () => json({ token: "ghs_odd", expires_at: "not-a-date" }),
      tokenResponse("ghs_fresh", NOW + HOUR),
    ]);
    expect(await tokens.tokenFor("repo")).toBe("ghs_odd");
    expect(await tokens.tokenFor("repo")).toBe("ghs_fresh");
    expect(github.requests).toHaveLength(2);
  });

  it("a mint refusal that echoes the App JWT back reaches the caller redacted", async () => {
    const { tokens } = source([
      (req) => {
        const jwt = req.headers["authorization"]!.replace(/^Bearer /, "");
        return json({ message: `Bad credentials: ${jwt} rejected` }, 401);
      },
    ]);
    let message = "";
    try {
      await tokens.tokenFor("repo");
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    expect(message).toMatch(/HTTP 401/);
    expect(message).toContain("[REDACTED]");
    expect(message).not.toMatch(/eyJ/); // no base64url JWT fragment survives
  });

  it("names the installation on a 404 and the scope on a 422", async () => {
    const notFound = source([() => json({ message: "Not Found" }, 404)]);
    await expect(notFound.tokens.tokenFor("repo")).rejects.toThrowError(/installation "42"/);

    const badScope = source([() => json({ message: "not granted" }, 422)]);
    await expect(badScope.tokens.tokenFor("repo")).rejects.toThrowError(
      /contents:write and pull_requests:read/,
    );
  });

  it("a response with no token fails loudly, and the network path never leaks the key", async () => {
    const { tokens } = source([() => json({ expires_at: "2030-01-01T00:00:00Z" })]);
    await expect(tokens.tokenFor("repo")).rejects.toThrowError(/carried no token/);

    const dead = createInstallationTokenSource({
      app: APP,
      ledger: createSecretLedger(),
      fetchImpl: async () => {
        throw new Error("getaddrinfo ENOTFOUND api.github.com");
      },
    });
    await expect(dead.tokenFor("repo")).rejects.toThrowError(/cannot reach GitHub/);
  });

  it("refuses a repository name that could smuggle a path into the URL", async () => {
    const { tokens, github } = source([]);
    await expect(tokens.tokenFor("../../orgs/evil")).rejects.toThrowError(/repository name/);
    expect(github.requests).toHaveLength(0);
  });
});
