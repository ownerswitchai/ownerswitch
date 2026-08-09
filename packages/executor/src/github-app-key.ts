import { createPrivateKey, type KeyObject } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

/**
 * Loads the GitHub App's private key — the standing credential of the whole
 * executor deployment — under the same placement rule as the kill-state
 * file: an explicit absolute path OUTSIDE the agent's workspace, because a
 * key the agent can read makes every other boundary in this package
 * decorative. The checks here enforce what is checkable from this process;
 * the placement rule itself is a deployment requirement
 * (packages/mcp/THREAT-MODEL.md).
 *
 * Hardened I/O per CONTRIBUTING.md: refuse symlinks (O_NOFOLLOW), refuse
 * non-regular files, cap size before reading into memory, refuse a key
 * readable by group/other, refuse a key owned by another user. Error
 * messages name the path and the fix — never the file's contents.
 */

/** A real App key is ~1.7 KiB of PEM; anything near this cap is not one. */
export const MAX_PRIVATE_KEY_FILE_BYTES = 64 * 1024;

const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;

export interface LoadPrivateKeyOptions {
  /**
   * The agent-reachable directory the key must NOT live under — callers
   * pass the gateway's working directory. Same rule as the kill-state
   * file: "not in the agent's workspace" is enforced where it can be.
   */
  workspaceDir: string;
  /** injectable for tests; defaults to process.getuid where available */
  getuid?: () => number;
}

export interface LoadedPrivateKey {
  /** the PEM bytes, for the secret ledger — redacted from everything emitted */
  pem: string;
  /** the parsed key, ready for RS256 signing */
  key: KeyObject;
}

export function loadGitHubAppPrivateKey(
  path: string,
  options: LoadPrivateKeyOptions,
): LoadedPrivateKey {
  if (!isAbsolute(path)) {
    throw new Error(
      `GitHub App private key path must be absolute, got "${path}" — a relative path silently ` +
        `addresses a different file per working directory`,
    );
  }
  const workspace = resolve(options.workspaceDir);
  const rel = relative(workspace, resolve(path));
  if (rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))) {
    throw new Error(
      `GitHub App private key "${path}" is inside the workspace "${workspace}" — the key must ` +
        `live where the agent's side cannot read it, like the kill-state file (move it outside ` +
        `the workspace, e.g. /etc/ownerswitch/github-app.pem)`,
    );
  }

  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | O_NOFOLLOW);
  } catch (err) {
    if (errCode(err) === "ELOOP") {
      throw new Error(`GitHub App private key "${path}" is a symlink — refusing to follow it`);
    }
    throw new Error(`cannot open GitHub App private key "${path}": ${message(err)}`);
  }
  let pem: string;
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) {
      throw new Error(`GitHub App private key "${path}" is not a regular file`);
    }
    if (stat.size > MAX_PRIVATE_KEY_FILE_BYTES) {
      throw new Error(
        `GitHub App private key "${path}" is ${stat.size} bytes, over the ` +
          `${MAX_PRIVATE_KEY_FILE_BYTES}-byte limit — that is not a private key file`,
      );
    }
    if ((stat.mode & 0o077) !== 0) {
      throw new Error(
        `GitHub App private key "${path}" is readable by group/other (mode ` +
          `${(stat.mode & 0o777).toString(8)}) — chmod 600 it; a key other users can read is ` +
          `a standing merge capability for everyone on the host`,
      );
    }
    const getuid = options.getuid ?? process.getuid;
    if (getuid !== undefined && stat.uid !== getuid.call(process)) {
      throw new Error(
        `GitHub App private key "${path}" is owned by uid ${stat.uid}, not this process's uid ` +
          `${getuid.call(process)} — the executor must own its own credential`,
      );
    }
    const buffer = Buffer.alloc(Math.min(Number(stat.size), MAX_PRIVATE_KEY_FILE_BYTES));
    let total = 0;
    while (total < buffer.length) {
      const bytesRead = readSync(fd, buffer, total, buffer.length - total, null);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    pem = buffer.toString("utf8", 0, total);
  } finally {
    closeSync(fd);
  }

  let key: KeyObject;
  try {
    key = createPrivateKey(pem);
  } catch {
    // deliberately not forwarding the parse error: parser messages can quote
    // input, and this input is the credential
    throw new Error(
      `GitHub App private key "${path}" does not parse as a private key — expected the PEM ` +
        `(.pem) file downloaded from the App's settings page`,
    );
  }
  if (key.asymmetricKeyType !== "rsa") {
    throw new Error(
      `GitHub App private key "${path}" is ${key.asymmetricKeyType ?? "an unknown key type"}, ` +
        `not RSA — GitHub App JWTs must be signed RS256 (docs: generating a JWT for a GitHub App)`,
    );
  }
  return { pem, key };
}

function errCode(err: unknown): string | undefined {
  return typeof err === "object" && err !== null && "code" in err
    ? String((err as { code: unknown }).code)
    : undefined;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
