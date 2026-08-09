/**
 * Shared plumbing for the two modules that talk to GitHub
 * (github-app-auth.ts, github-client.ts). Everything here follows the
 * connector's no-leak rule by construction: no logging, no error carrying a
 * request, a header, or a raw response body — the ONLY thing lifted out of
 * a response is its JSON `message` string, bounded, for the caller to
 * redact.
 */

export const GITHUB_API_BASE_URL = "https://api.github.com";

/** GitHub requires a User-Agent; undici sends none by default. */
export const USER_AGENT = "ownerswitch-executor";

export const GITHUB_API_VERSION = "2022-11-28";

/** Every outbound request gets a bounded timeout (CONTRIBUTING.md). */
export async function boundedFetch(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** Refuse to build a URL from a value that could smuggle path segments. */
export function assertUrlSafeName(value: string, what: string): void {
  if (!/^[A-Za-z0-9_.-]+$/.test(value)) {
    throw new Error(`${what} contains characters that cannot appear in a GitHub name`);
  }
}

const MAX_ERROR_BODY_BYTES = 64 * 1024;
const MAX_ERROR_MESSAGE_CHARS = 300;

/**
 * The one field of an error response worth relaying: its JSON `message`,
 * redacted THEN bounded. Anything else about the body — including a body
 * that fails to parse — is dropped, never quoted.
 *
 * The order is load-bearing: GitHub's own auth errors quote credentials
 * back, and truncating first would cut a long credential mid-way — leaving
 * a fragment the redactor's exact-match pass can no longer recognize. (A
 * unit test caught precisely that with an echoed App JWT.) So the full
 * message is redacted while every secret is still intact, and only the
 * redacted text is truncated.
 */
export async function readGitHubErrorMessage(
  res: Response,
  redact: (text: string) => string,
): Promise<string> {
  try {
    const text = await res.text();
    if (text.length > MAX_ERROR_BODY_BYTES) return "";
    const parsed: unknown = JSON.parse(text);
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
