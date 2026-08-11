/**
 * Shared plumbing for the modules that talk to GitHub (github-app-auth.ts,
 * github-client.ts). Everything here follows the connector's no-leak rule
 * by construction: no logging, no error carrying a request, a header, raw
 * response bytes, or a transport error's own text — the ONLY thing lifted
 * out of a response is its JSON `message` string, redacted then bounded,
 * and the ONLY thing said about a transport failure is one of two fixed
 * sentences.
 */

export const GITHUB_API_BASE_URL = "https://api.github.com";

/** GitHub requires a User-Agent; undici sends none by default. */
export const USER_AGENT = "ownerswitch-executor";

export const GITHUB_API_VERSION = "2022-11-28";

/**
 * Transport failures map to FIXED messages — never `err.message`. Exact
 * full-secret replacement cannot redact a token FRAGMENT, and a transport
 * stack is free to serialize half a header into its error text; a fixed
 * sentence removes the channel entirely instead of trying to filter it.
 */
export function fixedTransportMessage(err: unknown): string {
  const name = err instanceof Error ? err.name : "";
  return name === "AbortError" || name === "TimeoutError"
    ? "the request timed out"
    : "a network-level failure occurred";
}

export interface BoundedResponse {
  status: number;
  headers: Headers;
  /** body text, or null when the stream exceeded maxBodyBytes */
  bodyText: string | null;
}

/**
 * One HTTP exchange with every bound the callers rely on:
 *  - a single timeout covering the connection AND the body read (a timer
 *    cleared when the headers arrive would leave the body free to hang
 *    forever);
 *  - the body is capped WHILE STREAMING — a hostile or broken peer cannot
 *    make this process buffer an unbounded body just to truncate it later;
 *  - `redirect: "error"` unconditionally: an authenticated request must
 *    never follow a redirect (a redirected Authorization header is a
 *    credential handed to whoever controls the Location).
 *
 * Throws only for transport-level failures (connect, abort, mid-body
 * death); the caller receives status + headers + bounded body for
 * everything else and does its own status mapping.
 */
export async function boundedRequest(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
  maxBodyBytes: number,
): Promise<BoundedResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { ...init, redirect: "error", signal: controller.signal });
    const bodyText = await readBoundedBody(res, maxBodyBytes);
    return { status: res.status, headers: res.headers, bodyText };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Reads a Response body accumulating at most maxBytes; past the cap the
 * stream is cancelled and null returned. Exposed for tests.
 */
export async function readBoundedBody(res: Response, maxBytes: number): Promise<string | null> {
  const body = res.body;
  if (body === null) return "";
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * GitHub name validation, strict enough that a validated value can appear
 * in a URL path without escaping surprises: bounded length, a conservative
 * character set, and NO dot segments — "." and ".." are path traversal, not
 * names. (Owners cannot contain dots at all; repository names can, but
 * never consist of them.) Values are still encodeURIComponent-ed at the
 * call sites — two independent layers.
 */
export function assertSafeOwner(value: string): void {
  if (value.length < 1 || value.length > 39 || !/^[A-Za-z0-9-]+$/.test(value)) {
    throw new Error("owner is not a valid GitHub owner name");
  }
}

export function assertSafeRepoName(value: string): void {
  if (
    value.length < 1 ||
    value.length > 100 ||
    value === "." ||
    value === ".." ||
    !/^[A-Za-z0-9_.-]+$/.test(value)
  ) {
    throw new Error("repository name is not a valid GitHub repository name");
  }
}

export function assertSafeInstallationId(value: string): void {
  if (!/^\d{1,20}$/.test(value)) {
    throw new Error("installation id must be a numeric id");
  }
}

export function assertSafePullNumber(value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error("pullNumber must be a safe positive integer");
  }
}

const MAX_ERROR_MESSAGE_CHARS = 300;

/**
 * The one field of an error response worth relaying: its JSON `message`,
 * redacted THEN bounded. Anything else about the body — including a body
 * that fails to parse, or was cut by the stream cap (null) — is dropped,
 * never quoted.
 *
 * The order is load-bearing: GitHub's own auth errors quote credentials
 * back, and truncating first would cut a long credential mid-way — leaving
 * a fragment the redactor's exact-match pass can no longer recognize. (A
 * unit test caught precisely that with an echoed App JWT.) So the full
 * message is redacted while every secret is still intact, and only the
 * redacted text is truncated.
 */
export function githubErrorMessage(
  bodyText: string | null,
  redact: (text: string) => string,
): string {
  if (bodyText === null || bodyText === "") return "";
  try {
    const parsed: unknown = JSON.parse(bodyText);
    if (typeof parsed !== "object" || parsed === null) return "";
    const { message } = parsed as { message?: unknown };
    return typeof message === "string" ? redact(message).slice(0, MAX_ERROR_MESSAGE_CHARS) : "";
  } catch {
    return "";
  }
}

export function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
