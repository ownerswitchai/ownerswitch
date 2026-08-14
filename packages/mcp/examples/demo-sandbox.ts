/**
 * The demo tool server's SANDBOX rules, in one importable module so the
 * regression tests can drive them directly (importing the server itself
 * would connect a stdio transport as a side effect).
 *
 * This is a demo, but a demo that an onboarding user runs against their
 * real filesystem — so it must not be a lie: a lexical prefix check that
 * then follows symlinks reads and writes OUTSIDE the directory it claims
 * to contain (a planted `welcome.txt -> ~/.ssh/id_ed25519` symlink would
 * be read out by the auto-allowed read_file). The rules:
 *
 *  - the sandbox ROOT must be a real directory, not a symlink (lstat),
 *    and is created 0700 when absent;
 *  - file names are a SINGLE BASENAME from a conservative charset — no
 *    separators, no "..", no dotfiles — so no name can even express a
 *    path outside the root;
 *  - every read and write opens with O_NOFOLLOW: a symlink planted AT the
 *    file name refuses instead of following to its target. (move_file
 *    renames the link itself, never its target, and both names pass the
 *    same basename rule.)
 *  - the seed swallows EEXIST only — any other failure surfaces.
 */
import {
  closeSync,
  constants,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeSync,
} from "node:fs";
import { resolve } from "node:path";

const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;

/** single conservative basename: letters/digits/._- , no leading dot */
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function validateName(name: string): string {
  if (typeof name !== "string" || !NAME_RE.test(name)) {
    throw new Error(
      `invalid file name "${String(name)}" — the demo sandbox accepts a single plain file name ` +
        "(letters, digits, dot, dash, underscore; no paths, no leading dot)",
    );
  }
  return name;
}

/** ensure the sandbox root exists, is OWNER-ONLY, and is not a symlink */
export function ensureSandboxRoot(dir: string): string {
  const root = resolve(dir);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const stat = lstatSync(root);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`demo sandbox root "${root}" must be a real directory (not a symlink)`);
  }
  return root;
}

/** read a sandbox file WITHOUT following a symlink planted at its name */
export function readSandboxFile(root: string, name: string): string {
  const fd = openSync(resolve(root, validateName(name)), constants.O_RDONLY | O_NOFOLLOW);
  try {
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}

/** write a sandbox file WITHOUT following a symlink planted at its name */
export function writeSandboxFile(root: string, name: string, content: string): number {
  const data = Buffer.from(content, "utf8");
  const fd = openSync(
    resolve(root, validateName(name)),
    constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | O_NOFOLLOW,
    0o600,
  );
  try {
    let written = 0;
    while (written < data.length) {
      written += writeSync(fd, data, written, data.length - written);
    }
    return data.length;
  } finally {
    closeSync(fd);
  }
}

/** seed a file if absent — EEXIST is the only swallowed failure */
export function seedSandboxFile(root: string, name: string, content: string): void {
  let fd: number;
  try {
    fd = openSync(
      resolve(root, validateName(name)),
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW,
      0o600,
    );
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") return; // already seeded (or a
    // planted entry occupies the name — either way, never overwrite through it)
    throw err;
  }
  try {
    const data = Buffer.from(content, "utf8");
    let written = 0;
    while (written < data.length) {
      written += writeSync(fd, data, written, data.length - written);
    }
  } finally {
    closeSync(fd);
  }
}
