import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadGitHubAppPrivateKey, MAX_PRIVATE_KEY_FILE_BYTES } from "./github-app-key.js";

/**
 * The key loader enforces what is checkable of the placement rule: the App's
 * private key is the deployment's standing credential, and a key the agent
 * (or any other user on the host) can read defeats every boundary above it.
 */

const RSA_PEM = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
  type: "pkcs8",
  format: "pem",
}) as string;

let dir: string;
/** a second dir standing in for the agent's workspace */
let workspace: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "oswitch-key-"));
  workspace = mkdtempSync(join(tmpdir(), "oswitch-ws-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(workspace, { recursive: true, force: true });
});

function writeKey(name: string, content: string, mode = 0o600): string {
  const path = join(dir, name);
  writeFileSync(path, content, { mode });
  chmodSync(path, mode); // umask-proof
  return path;
}

describe("loadGitHubAppPrivateKey", () => {
  it("loads a 0600 RSA key and returns both the PEM (for the ledger) and the parsed key", () => {
    const path = writeKey("app.pem", RSA_PEM);
    const loaded = loadGitHubAppPrivateKey(path, { workspaceDir: workspace });
    expect(loaded.pem).toBe(RSA_PEM);
    expect(loaded.key.asymmetricKeyType).toBe("rsa");
  });

  it("refuses a relative path — it silently addresses a different file per cwd", () => {
    expect(() => loadGitHubAppPrivateKey("app.pem", { workspaceDir: workspace })).toThrowError(
      /must be absolute/,
    );
  });

  it("refuses a key inside the workspace — the agent's side must not be able to read it", () => {
    const inside = join(workspace, "app.pem");
    writeFileSync(inside, RSA_PEM, { mode: 0o600 });
    expect(() => loadGitHubAppPrivateKey(inside, { workspaceDir: workspace })).toThrowError(
      /inside the workspace/,
    );
  });

  it("refuses to follow a symlink at the key path", () => {
    const real = writeKey("real.pem", RSA_PEM);
    const link = join(dir, "link.pem");
    symlinkSync(real, link);
    expect(() => loadGitHubAppPrivateKey(link, { workspaceDir: workspace })).toThrowError(
      /symlink/,
    );
  });

  it("refuses a key readable by group or other", () => {
    const path = writeKey("app.pem", RSA_PEM, 0o644);
    expect(() => loadGitHubAppPrivateKey(path, { workspaceDir: workspace })).toThrowError(
      /readable by group\/other.*chmod 600/s,
    );
  });

  it("refuses a key owned by another user", () => {
    const path = writeKey("app.pem", RSA_PEM);
    expect(() =>
      loadGitHubAppPrivateKey(path, {
        workspaceDir: workspace,
        getuid: () => (process.getuid?.() ?? 0) + 1,
      }),
    ).toThrowError(/owned by uid/);
  });

  it("refuses a file over the size cap before reading it into memory", () => {
    const path = writeKey("huge.pem", "x".repeat(MAX_PRIVATE_KEY_FILE_BYTES + 1));
    expect(() => loadGitHubAppPrivateKey(path, { workspaceDir: workspace })).toThrowError(
      /over the .*limit/,
    );
  });

  it("refuses garbage without quoting the file's contents in the error", () => {
    const secretish = "not-a-key-but-still-must-not-leak-abc123";
    const path = writeKey("bad.pem", secretish);
    let message = "";
    try {
      loadGitHubAppPrivateKey(path, { workspaceDir: workspace });
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    expect(message).toMatch(/does not parse as a private key/);
    expect(message).not.toContain(secretish);
  });

  it("refuses a non-RSA key — GitHub App JWTs must be RS256", () => {
    const ed25519 = generateKeyPairSync("ed25519").privateKey.export({
      type: "pkcs8",
      format: "pem",
    }) as string;
    const path = writeKey("ed.pem", ed25519);
    expect(() => loadGitHubAppPrivateKey(path, { workspaceDir: workspace })).toThrowError(
      /not RSA/,
    );
  });
});
