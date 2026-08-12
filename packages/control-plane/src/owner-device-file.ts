import { closeSync, constants, fstatSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { enrolledOwnerDeviceFromSpki } from "./owner-device.js";

/**
 * Load the owner-app device keys file — `{deviceId: SPKI PEM}` — with the
 * same INTEGRITY hardening the enrolled passkey gets (mcp/src/passkey-key.ts),
 * because this file is an authorization ROOT: whoever can rewrite it enrolls
 * their own device key, forges the delivery ack, redirects push enrollment,
 * and thereby releases veto-lane calls. It is public material (only public
 * keys), so we do NOT restrict read — but WRITE and PATH are treated exactly
 * as strictly as a private key: an absolute path whose real ancestry is
 * trusted, opened O_NOFOLLOW so the leaf is never a symlink, a regular file,
 * size-capped, owned by root or this process, and NOT group/world-writable.
 * Each value is then parsed by enrolledOwnerDeviceFromSpki, which refuses a
 * private key and canonicalizes the public bytes.
 *
 * Returns a `{deviceId: canonical SPKI PEM}` record for the `ownerDeviceKeys`
 * option. Provision the file as root-owned, agent-unwritable configuration.
 */

const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const MAX_KEYS_FILE_BYTES = 256 * 1024;

export interface LoadOwnerDeviceKeysOptions {
  getuid?: () => number;
  /** test-only: skip the trusted-ancestry walk (public tmp roots fail it by design) */
  unsafeAllowUntrustedAncestryForTests?: boolean;
}

export function loadOwnerDeviceKeysFile(
  path: string,
  options: LoadOwnerDeviceKeysOptions = {},
): Record<string, string> {
  if (!isAbsolute(path)) {
    throw new Error(`OWNERSWITCH_OWNER_DEVICE_KEYS_FILE must be an absolute path, got "${path}"`);
  }
  const getuid = options.getuid ?? process.getuid;
  const ourUid = getuid === undefined ? 0 : getuid.call(process);

  const lexical = resolve(path);
  let realParent: string;
  try {
    realParent = realpathSync(dirname(lexical));
  } catch (err) {
    throw new Error(
      `owner device keys file parent "${dirname(lexical)}" is unreadable: ${err instanceof Error ? err.message : "failed"}`,
    );
  }
  const realPath = join(realParent, basename(lexical));
  if (options.unsafeAllowUntrustedAncestryForTests !== true) {
    assertTrustedAncestry(realParent, ourUid);
  }

  let fd: number;
  try {
    fd = openSync(realPath, constants.O_RDONLY | O_NOFOLLOW);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ELOOP") {
      throw new Error(`owner device keys file "${realPath}" is a symlink — refusing to follow it`);
    }
    throw new Error(`cannot open owner device keys file "${realPath}": ${err instanceof Error ? err.message : "failed"}`);
  }
  let text: string;
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new Error(`owner device keys file "${realPath}" is not a regular file`);
    if (stat.size > MAX_KEYS_FILE_BYTES) throw new Error(`owner device keys file "${realPath}" is too large`);
    if (stat.uid !== 0 && stat.uid !== ourUid) {
      throw new Error(
        `owner device keys file "${realPath}" is owned by uid ${stat.uid}, not root or this process's ` +
          `uid ${ourUid} — an untrusted owner could enroll their own device key`,
      );
    }
    if ((stat.mode & 0o022) !== 0) {
      throw new Error(
        `owner device keys file "${realPath}" is group- or world-writable (mode ` +
          `${(stat.mode & 0o777).toString(8)}) — anyone who can rewrite it can forge the delivery ack; chmod 0644`,
      );
    }
    const buffer = Buffer.alloc(Number(stat.size));
    let total = 0;
    while (total < buffer.length) {
      const read = readSync(fd, buffer, total, buffer.length - total, null);
      if (read === 0) break;
      total += read;
    }
    text = buffer.toString("utf8", 0, total);
  } finally {
    closeSync(fd);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`owner device keys file "${realPath}" is not valid JSON: ${err instanceof Error ? err.message : "failed"}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`owner device keys file "${realPath}" must be a JSON object of deviceId → SPKI PEM`);
  }
  const out: Record<string, string> = {};
  for (const [deviceId, spki] of Object.entries(parsed as Record<string, unknown>)) {
    if (deviceId === "" || deviceId.includes(":")) {
      throw new Error(`owner device id ${JSON.stringify(deviceId)} is invalid (non-empty, no ":")`);
    }
    if (typeof spki !== "string" || spki === "") {
      throw new Error(`owner device "${deviceId}" has no SPKI public key string`);
    }
    // parse (rejects private keys, enforces P-256) and store the CANONICAL PEM
    out[deviceId] = enrolledOwnerDeviceFromSpki(deviceId, spki).publicKey.export({ type: "spki", format: "pem" }).toString();
  }
  return out;
}

function assertTrustedAncestry(realParent: string, ourUid: number): void {
  let current = realParent;
  for (;;) {
    let stat;
    try {
      stat = statSync(current);
    } catch {
      throw new Error(`owner device keys ancestor "${current}" is unreadable`);
    }
    if (stat.uid !== 0 && stat.uid !== ourUid) {
      throw new Error(`owner device keys ancestor "${current}" is owned by uid ${stat.uid} (not root or this uid)`);
    }
    if ((stat.mode & 0o022) !== 0) {
      throw new Error(`owner device keys ancestor "${current}" is group- or world-writable`);
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
}
