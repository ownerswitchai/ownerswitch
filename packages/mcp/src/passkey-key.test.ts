import { generateKeyPairSync } from "node:crypto";
import { chmodSync, chownSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadOwnerPasskeyPublicKey } from "./passkey-key.js";

/**
 * The owner passkey PUBLIC key is the authorization ROOT for merge approval:
 * whoever can rewrite it enrolls their own authenticator and self-approves a
 * merge. It is not a secret, so READ is unrestricted — but PATH and WRITE are
 * held as strictly as the App private key. These tests pass
 * unsafeAllowUntrustedAncestryForTests where they are not exercising the
 * ancestry walk itself, because the tmp root (/tmp is 1777) fails the walk by
 * design.
 */

function p256Spki(): string {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({
    type: "spki",
    format: "pem",
  }) as string;
}

const SPKI = p256Spki();

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "oswitch-pk-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function writeKey(name: string, content: string, mode = 0o644): string {
  const path = join(dir, name);
  writeFileSync(path, content, { mode });
  chmodSync(path, mode); // umask-proof
  return path;
}

const skipAncestry = { unsafeAllowUntrustedAncestryForTests: true } as const;

describe("loadOwnerPasskeyPublicKey", () => {
  it("loads a 0644 P-256 SPKI key and returns the PEM plus the parsed key", () => {
    const path = writeKey("passkey.pem", SPKI);
    const loaded = loadOwnerPasskeyPublicKey(path, skipAncestry);
    expect(loaded.pem.trim()).toBe(SPKI.trim());
    expect(loaded.key.asymmetricKeyType).toBe("ec");
  });

  it("refuses a relative path — it silently addresses a different file per cwd", () => {
    expect(() => loadOwnerPasskeyPublicKey("passkey.pem", skipAncestry)).toThrowError(
      /must be absolute/,
    );
  });

  it("refuses to follow a symlink at the key path", () => {
    const real = writeKey("real.pem", SPKI);
    const link = join(dir, "link.pem");
    symlinkSync(real, link);
    expect(() => loadOwnerPasskeyPublicKey(link, skipAncestry)).toThrowError(/symlink/);
  });

  it("refuses a group- or world-WRITABLE key — a writer can enroll their own passkey", () => {
    const path = writeKey("passkey.pem", SPKI, 0o646); // world-writable
    expect(() => loadOwnerPasskeyPublicKey(path, skipAncestry)).toThrowError(
      /group- or world-writable/,
    );
  });

  it("PERMITS a world-READABLE key — the public key is not a secret", () => {
    const path = writeKey("passkey.pem", SPKI, 0o644);
    expect(() => loadOwnerPasskeyPublicKey(path, skipAncestry)).not.toThrow();
  });

  it("refuses a key owned by an untrusted uid (not root, not this process)", () => {
    const path = writeKey("passkey.pem", SPKI);
    const uid = process.getuid?.() ?? 0;
    if (uid === 0) {
      // running as root (CI): root is always trusted, so injecting getuid
      // cannot make a root-owned file look untrusted — actually chown it to
      // an unrelated uid (only root can, which is exactly when we're here).
      chownSync(path, 2, 2);
      expect(() => loadOwnerPasskeyPublicKey(path, skipAncestry)).toThrowError(/owned by uid/);
    } else {
      // running as a normal user: the file is ours (nonzero uid). Pretend our
      // uid differs so the real owner is neither root nor "us".
      expect(() =>
        loadOwnerPasskeyPublicKey(path, { ...skipAncestry, getuid: () => uid + 1 }),
      ).toThrowError(/owned by uid/);
    }
  });

  it("refuses a file over the SPKI size cap before reading it", () => {
    const path = writeKey("huge.pem", "x".repeat(16 * 1024 + 1));
    expect(() => loadOwnerPasskeyPublicKey(path, skipAncestry)).toThrowError(/too large/);
  });

  it("refuses garbage that does not parse as a public key", () => {
    const path = writeKey("bad.pem", "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n");
    expect(() => loadOwnerPasskeyPublicKey(path, skipAncestry)).toThrowError(
      /does not parse as a public key/,
    );
  });

  it("refuses a non-EC key — WebAuthn ES256 requires P-256", () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({
      type: "spki",
      format: "pem",
    }) as string;
    const path = writeKey("rsa.pem", rsa);
    expect(() => loadOwnerPasskeyPublicKey(path, skipAncestry)).toThrowError(/not an EC key/);
  });

  it("refuses an EC key on the WRONG curve — only prime256v1 is accepted", () => {
    const p384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey.export({
      type: "spki",
      format: "pem",
    }) as string;
    const path = writeKey("p384.pem", p384);
    expect(() => loadOwnerPasskeyPublicKey(path, skipAncestry)).toThrowError(/not prime256v1/);
  });

  it("with the ancestry walk ENABLED, refuses a key under a world-writable ancestor (/tmp)", () => {
    // no skip flag: the tmp root (1777) is world-writable, so the walk trips
    const path = writeKey("passkey.pem", SPKI);
    expect(() => loadOwnerPasskeyPublicKey(path)).toThrowError(
      /ancestor .* is group- or world-writable/,
    );
  });
});
