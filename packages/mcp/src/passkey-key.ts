import { createPublicKey, type KeyObject } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

/**
 * Loads the owner approval passkey's PUBLIC key with INTEGRITY hardening.
 *
 * The public key is an authorization ROOT: whoever can replace the file
 * enrolls their own authenticator, mints a session, and approves a merge.
 * It is not a secret (it is public by nature), so we do NOT restrict READ —
 * but we treat WRITE and PATH exactly as strictly as the App private key:
 * an absolute path whose real ancestry is trusted, opened O_NOFOLLOW so the
 * leaf is never a symlink, a regular file, size-capped, owned by root or
 * this process, and NOT writable by group or other. Then it must be EXACTLY
 * one SPKI `PUBLIC KEY` block on the P-256 (prime256v1) curve — a private
 * PEM is refused (see parseSpkiP256PublicKey), because this world-readable
 * file must never carry signing authority.
 *
 * The ancestry walk runs on the POST-realpath parent (matching the burn
 * store): an intermediate symlink cannot present a trusted-looking lexical
 * path while the real file sits under an attacker-writable directory.
 *
 * Provision it as root-owned, agent-unwritable configuration (see
 * MANUAL-VERIFICATION.md), the same class as the App PEM.
 */

const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
/** an SPKI P-256 public key PEM is ~180 bytes; anything near this is not one */
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;

export interface LoadPasskeyKeyOptions {
  getuid?: () => number;
  /**
   * Test-only: skip the trusted-ancestry walk. The public tmp roots that
   * unit tests must use (/tmp is 1777, world-writable) fail the walk by
   * design, exactly as they should in production — so tests that are not
   * exercising the ancestry check set this to place the key under tmp. Never
   * set in production; the same escape hatch the burn store uses.
   */
  unsafeAllowUntrustedAncestryForTests?: boolean;
}

export function loadOwnerPasskeyPublicKey(
  path: string,
  options: LoadPasskeyKeyOptions = {},
): { pem: string; key: KeyObject } {
  if (!isAbsolute(path)) {
    throw new Error(
      `owner passkey public key path must be absolute, got "${path}" — a relative path silently ` +
        `addresses a different file per working directory`,
    );
  }
  const getuid = options.getuid ?? process.getuid;
  const ourUid = getuid === undefined ? 0 : getuid.call(process);

  // Canonicalize the PARENT (not the leaf — the leaf must stay un-followed so
  // O_NOFOLLOW can reject a symlinked key), so intermediate symlinks are
  // resolved before we judge the ancestry. The leaf is re-attached to the
  // real parent; O_NOFOLLOW below still guarantees it is not itself a link.
  const lexical = resolve(path);
  let realParent: string;
  try {
    realParent = realpathSync(dirname(lexical));
  } catch (err) {
    throw new Error(
      `owner passkey public key parent directory "${dirname(lexical)}" is unreadable: ` +
        `${err instanceof Error ? err.message : "failed"}`,
    );
  }
  const realPath = join(realParent, basename(lexical));

  // Trusted ancestry: no ancestor may be owned by an untrusted uid or be
  // group/world-writable, or that writer could swap the key underneath us.
  if (options.unsafeAllowUntrustedAncestryForTests !== true) {
    assertTrustedAncestry(realParent, ourUid);
  }

  let fd: number;
  try {
    fd = openSync(realPath, constants.O_RDONLY | O_NOFOLLOW);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ELOOP") {
      throw new Error(`owner passkey public key "${realPath}" is a symlink — refusing to follow it`);
    }
    throw new Error(
      `cannot open owner passkey public key "${realPath}": ${err instanceof Error ? err.message : "failed"}`,
    );
  }
  let pem: string;
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new Error(`owner passkey public key "${realPath}" is not a regular file`);
    if (stat.size > MAX_PUBLIC_KEY_BYTES) {
      throw new Error(`owner passkey public key "${realPath}" is too large to be an SPKI key`);
    }
    if (stat.uid !== 0 && stat.uid !== ourUid) {
      throw new Error(
        `owner passkey public key "${realPath}" is owned by uid ${stat.uid}, not root or this ` +
          `process's uid ${ourUid} — an untrusted owner could replace the enrolled authenticator`,
      );
    }
    if ((stat.mode & 0o022) !== 0) {
      throw new Error(
        `owner passkey public key "${realPath}" is group- or world-writable (mode ` +
          `${(stat.mode & 0o777).toString(8)}) — anyone who can rewrite it can enroll their own ` +
          `passkey; chmod it 0644 root-owned`,
      );
    }
    const buffer = Buffer.alloc(Number(stat.size));
    let total = 0;
    while (total < buffer.length) {
      const read = readSync(fd, buffer, total, buffer.length - total, null);
      if (read === 0) break;
      total += read;
    }
    pem = buffer.toString("utf8", 0, total);
  } finally {
    closeSync(fd);
  }

  return parseSpkiP256PublicKey(pem, realPath);
}

/**
 * Parse STRICTLY as a P-256 SPKI *public* key and return a CANONICAL
 * re-export — never the caller's bytes.
 *
 * The critical hole this closes: `createPublicKey(pem)` will happily DERIVE a
 * public key from a PKCS#8 or SEC1 *private* PEM (verified: both parse, curve
 * prime256v1, and the private PEM even verifies its own assertions). Since
 * this file is treated as public and provisioned 0644 — READABLE by the
 * agent's uid — accepting a private key would hand the agent full assertion
 * authority (it could sign login, approval, AND restore assertions itself).
 * So we refuse anything that is not EXACTLY one SPKI `PUBLIC KEY` block:
 *  - any `PRIVATE KEY` armor is rejected outright (the reproduced attack);
 *  - exactly one PEM block, no second block, no leading/trailing content;
 *  - the body is parsed as DER with an explicit {type:"spki"}, so a private
 *    DER smuggled under a public header fails the ASN.1 shape too;
 *  - the returned `pem` is re-exported canonical SPKI, so downstream never
 *    sees attacker-influenced bytes.
 */
export function parseSpkiP256PublicKey(pem: string, path: string): { pem: string; key: KeyObject } {
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(pem)) {
    throw new Error(
      `owner passkey public key "${path}" is a PRIVATE key — provide ONLY the SPKI public key. A ` +
        `private key here (the file is world-readable config) would let the agent sign assertions itself`,
    );
  }
  if ((pem.match(/-----BEGIN /g) ?? []).length !== 1) {
    throw new Error(
      `owner passkey public key "${path}" must be exactly one PEM block — multiple blocks or trailing ` +
        `content are refused`,
    );
  }
  const match = /^-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\s]+?)-----END PUBLIC KEY-----\s*$/.exec(
    pem.trim(),
  );
  if (match === null) {
    throw new Error(
      `owner passkey public key "${path}" is not a single SPKI "PUBLIC KEY" PEM block (the enrolled ` +
        `authenticator's P-256 public key, \`openssl pkey -pubout\` form)`,
    );
  }
  let key: KeyObject;
  try {
    const der = Buffer.from(match[1].replace(/\s+/g, ""), "base64");
    // Explicit SPKI DER parse — NOT createPublicKey(pem), which would derive
    // a public key from a private PEM. A private DER fails the SPKI shape.
    key = createPublicKey({ key: der, format: "der", type: "spki" });
  } catch {
    throw new Error(`owner passkey public key "${path}" does not parse as an SPKI public key`);
  }
  if (key.asymmetricKeyType !== "ec") {
    throw new Error(`owner passkey public key "${path}" is not an EC key — WebAuthn ES256 needs P-256`);
  }
  const curve = (key.asymmetricKeyDetails as { namedCurve?: string } | undefined)?.namedCurve;
  if (curve !== "prime256v1") {
    throw new Error(
      `owner passkey public key "${path}" is EC curve "${curve ?? "unknown"}", not prime256v1 (P-256)`,
    );
  }
  // Return CANONICAL SPKI, re-exported from the parsed key — downstream binds
  // to bytes this loader produced, not the on-disk input.
  return { pem: key.export({ type: "spki", format: "pem" }).toString(), key };
}

/**
 * Walk from the key's real parent up to the filesystem root; refuse if any
 * ancestor is owned by an untrusted uid or is group/world-writable. Called
 * with a realpath'd directory, so the ancestry judged is the real one.
 */
function assertTrustedAncestry(realParent: string, ourUid: number): void {
  let current = realParent;
  for (;;) {
    let stat;
    try {
      stat = statDir(current);
    } catch {
      throw new Error(`owner passkey public key ancestor "${current}" is unreadable`);
    }
    if (stat.uid !== 0 && stat.uid !== ourUid) {
      throw new Error(
        `owner passkey public key ancestor "${current}" is owned by uid ${stat.uid} (not root or ` +
          `this uid) — an untrusted owner of any ancestor could substitute the key`,
      );
    }
    if ((stat.mode & 0o022) !== 0) {
      throw new Error(
        `owner passkey public key ancestor "${current}" is group- or world-writable — place the ` +
          `key under a 0755-or-tighter root-owned path`,
      );
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

function statDir(p: string): { uid: number; mode: number } {
  const fd = openSync(p, constants.O_RDONLY);
  try {
    const s = fstatSync(fd);
    return { uid: s.uid, mode: s.mode };
  } finally {
    closeSync(fd);
  }
}
