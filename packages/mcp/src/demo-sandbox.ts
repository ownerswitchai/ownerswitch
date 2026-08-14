/**
 * The demo tool server's SANDBOX rules, in one importable module so the
 * regression tests can drive them directly (importing the server itself
 * would connect a stdio transport as a side effect).
 *
 * This is a demo, but a demo that an onboarding user runs against their
 * real filesystem — so its containment claim must actually hold, including
 * against a PRE-SEEDED sandbox on a shared machine. The rules, and the
 * attack each one answers:
 *
 *  - O_NOFOLLOW is REQUIRED: a platform that does not provide it refuses
 *    at startup instead of silently degrading to the symlink-following
 *    behaviour the flag exists to prevent;
 *  - the sandbox ROOT is canonicalized (realpath) once, then verified —
 *    and RE-verified before every operation: a real directory (never a
 *    symlink), owned by THIS uid, mode with NO group/world bits
 *    ((mode & 0o077) === 0). A pre-existing 0755/0777 root (an earlier
 *    demo's, or an attacker's) refuses with the exact chmod to run;
 *  - the root's PARENT (canonical) must be a directory owned by this uid
 *    or root, and — when world-writable — sticky (the /tmp model, where
 *    others cannot rename or unlink an entry they do not own). A
 *    world-writable non-sticky parent is a swappable namespace and
 *    refuses;
 *  - file names are a SINGLE BASENAME from a conservative charset — no
 *    separators, no "..", no dotfiles — so no name can even express a
 *    path outside the root;
 *  - every open is O_NOFOLLOW (a planted symlink refuses), and every
 *    opened fd is fstat-VERIFIED before any byte moves: a REGULAR file,
 *    nlink === 1 (a planted HARD LINK to a file outside the sandbox has
 *    nlink >= 2 and refuses — O_NOFOLLOW alone cannot see it), owned by
 *    this uid. Reads open O_NONBLOCK so a planted FIFO cannot hang the
 *    open before the type check refuses it;
 *  - writes open WITHOUT O_TRUNC and truncate only AFTER the fd checks
 *    pass — otherwise the truncation would destroy a hard-link target
 *    before the check could refuse it;
 *  - the seed swallows EEXIST only — and on EEXIST it lstat-checks WHAT
 *    occupies the name: a planted symlink/hardlink/FIFO there is reported
 *    loudly (with the path to remove), never silently left in place for a
 *    later read to trip over.
 *
 * Honest residue: without openat()-style fd-relative calls (which node's
 * fs API does not expose) there is a check-to-open window on the root
 * path itself; the parent-trust rule above is what keeps that window
 * unexploitable (an attacker who cannot swap the root's directory entry
 * cannot win the race). This is a demo sandbox, not the OwnerSwitch
 * enforcement boundary — the gateway in front of it is the product.
 */
import {
  closeSync,
  constants,
  fstatSync,
  ftruncateSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  writeSync,
  type Stats,
} from "node:fs";
import { dirname, join, resolve, sep } from "node:path";

/**
 * O_NOFOLLOW is the promise — a platform without it refuses, never
 * degrades. The flag is an EXPLICIT parameter (no default) so an
 * undefined value can never silently fall back to anything.
 */
export function requireNoFollow(flag: number | undefined): number {
  if (flag === undefined || flag === 0) {
    throw new Error(
      "this platform does not provide O_NOFOLLOW — the demo sandbox cannot keep its " +
        "no-symlink promise here, refusing to run",
    );
  }
  return flag;
}

const ourUid = (): number => (typeof process.getuid === "function" ? process.getuid() : 0);

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

/** the root's own boundary: real dir, ours, owner-only — else the exact fix */
function assertRootBoundary(root: string): void {
  const stat = lstatSync(root);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`demo sandbox root "${root}" must be a real directory (not a symlink)`);
  }
  if (stat.uid !== ourUid()) {
    throw new Error(
      `demo sandbox root "${root}" is owned by uid ${stat.uid}, not this user — ` +
        "remove it or point the demo at a directory you own",
    );
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(
      `demo sandbox root "${root}" has mode ${(stat.mode & 0o777).toString(8)} — it must be ` +
        `owner-only. Run: chmod 700 ${root} (or remove it and re-run to recreate it 0700)`,
    );
  }
}

/**
 * The parent-trust rule, applied to a NAMED parent directory: it must be
 * ours (or root's), and must grant NO group or world write — either bit
 * lets another party rename or replace the root entry between a check and
 * an open — unless the sticky bit restores the only-the-owner-renames
 * property (the /tmp model).
 */
function assertTrustedParentDir(parent: string): void {
  const ps = lstatSync(parent);
  const trusted =
    ps.isDirectory() &&
    (ps.uid === ourUid() || ps.uid === 0) &&
    ((ps.mode & 0o022) === 0 || (ps.mode & 0o1000) !== 0);
  if (!trusted) {
    throw new Error(
      `demo sandbox parent "${parent}" is not a trusted directory (foreign-owned, or group-/` +
        "world-writable without the sticky bit) — its entries can be swapped out from under " +
        "the sandbox; put the demo directory somewhere private (e.g. under your home)",
    );
  }
}

/**
 * The WHOLE ancestor chain must be trusted, not just the direct parent —
 * an untrusted directory anywhere above lets its owner rename a middle
 * component and splice in a symlink AFTER initialization, permanently
 * redirecting every later (path-based) operation. So every EXISTING
 * component is lstat-checked (a symlink anywhere refuses — namespace
 * laundering), and every directory that HOLDS a component's entry must
 * pass the same trust rule as the direct parent: ours or root's, no
 * group/world write unless sticky. Only the final leaf may be absent (it
 * is the one thing ensureSandboxRoot creates, non-recursively — and only
 * after this walk, so mkdir can never write through an unverified chain).
 * Re-run before every operation: a chain that was trusted at startup and
 * widened since refuses the next operation instead of becoming a swap
 * window. With every ancestor requiring THIS uid (or root, non-writable)
 * to modify, a swapped component is outside the demo's threat model —
 * which is exactly what makes the remaining path-based readdir/rename
 * sound where node offers no dirfd-relative alternative.
 */
function assertTrustedChain(lexical: string): void {
  const parts = lexical.split(sep).filter((p) => p !== "");
  let current: string = sep;
  const ancestors: string[] = [sep];
  for (let i = 0; i < parts.length - 1; i++) {
    current = join(current, parts[i]);
    ancestors.push(current);
  }
  for (const ancestor of ancestors) {
    let stat: Stats;
    try {
      stat = lstatSync(ancestor);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        throw new Error(
          `demo sandbox path component "${ancestor}" does not exist — only the final directory ` +
            "is created here; create (and own) the parent chain yourself, or use the default sandbox",
        );
      }
      throw err; // EACCES/ENOTDIR/… surface as themselves, never as "does not exist"
    }
    if (stat.isSymbolicLink()) {
      throw new Error(
        `demo sandbox path component "${ancestor}" is a symlink — an explicit sandbox path must ` +
          "not traverse symlinks anywhere (a resolved link would launder the namespace into a " +
          "different directory's trust); use the default sandbox, or a fully real path",
      );
    }
    assertTrustedParentDir(ancestor);
  }
  // the leaf itself: may be absent (created next); an existing one must
  // not be a symlink — its directory-ness/mode is assertRootBoundary's job
  try {
    if (lstatSync(lexical).isSymbolicLink()) {
      throw new Error(
        `demo sandbox root "${lexical}" is a symlink — refusing to follow it; remove the link and re-run`,
      );
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err; // EACCES/ENOTDIR/… surface as themselves
  }
}

/** the per-operation form: the root's WHOLE chain, then the root itself */
function assertParentTrusted(root: string): void {
  assertTrustedChain(root);
}

/**
 * Ensure the sandbox root exists and satisfies the WHOLE boundary above.
 * Returns the CANONICAL path — every later operation resolves from it.
 *
 * The rule that closes the laundering class outright: the lexical chain
 * must be symlink-free (checked component-by-component, above), the
 * parent must already EXIST and be trusted, the leaf is created
 * NON-recursively, and afterwards `realpath(lexical)` must equal the
 * lexical path itself — on a symlink-free chain the two can only differ
 * if something was swapped mid-sequence, and that difference refuses.
 * Nothing here ever follows a link, so there is no target whose trust
 * could be mistaken for the chain's.
 */
export function ensureSandboxRoot(dir: string): string {
  requireNoFollow(constants.O_NOFOLLOW);
  const lexical = resolve(dir);
  assertTrustedChain(lexical);
  try {
    mkdirSync(lexical, { mode: 0o700 }); // NON-recursive: only under the verified chain
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
  }
  if (lstatSync(lexical).isSymbolicLink()) {
    throw new Error(
      `demo sandbox root "${lexical}" is a symlink — refusing to follow it; remove the link and re-run`,
    );
  }
  const root = realpathSync(lexical);
  if (root !== lexical) {
    throw new Error(
      `demo sandbox root "${lexical}" canonicalizes to "${root}" — a symlink-free chain can only ` +
        "diverge from itself if a component was swapped; refusing the redirect",
    );
  }
  assertRootBoundary(root);
  return root;
}

/**
 * Open a sandbox file and verify the FD before any byte moves: regular,
 * un-hardlinked, ours. Returns the fd; the caller owns closing it.
 */
function safeOpen(root: string, name: string, flags: number): number {
  const O_NOFOLLOW = requireNoFollow(constants.O_NOFOLLOW);
  // BOTH halves of the boundary re-verified per operation: the root's own
  // state AND the parent that holds its entry — a parent whose permissions
  // widened since startup refuses instead of becoming a swap window
  assertRootBoundary(root);
  assertParentTrusted(root);
  const fd = openSync(
    resolve(root, validateName(name)),
    flags | O_NOFOLLOW | constants.O_NONBLOCK,
    0o600,
  );
  let stat: Stats;
  try {
    stat = fstatSync(fd);
  } catch (err) {
    closeSync(fd);
    throw err;
  }
  if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== ourUid()) {
    closeSync(fd);
    throw new Error(
      `refusing "${name}": the entry is not a plain, un-hardlinked file owned by this user ` +
        `(a planted hard link, FIFO, or device would reach OUTSIDE the sandbox) — remove ` +
        `${resolve(root, name)} and retry`,
    );
  }
  return fd;
}

/** read a sandbox file — symlinks, hard links, FIFOs and devices all refuse */
export function readSandboxFile(root: string, name: string): string {
  const fd = safeOpen(root, name, constants.O_RDONLY);
  try {
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}

/**
 * Write a sandbox file. Deliberately NO O_TRUNC on the open: truncation
 * happens only after the fd checks pass, so a planted hard link's target
 * is never destroyed by the very open that then refuses it.
 */
export function writeSandboxFile(root: string, name: string, content: string): number {
  const data = Buffer.from(content, "utf8");
  const fd = safeOpen(root, name, constants.O_WRONLY | constants.O_CREAT);
  try {
    ftruncateSync(fd, 0);
    let written = 0;
    while (written < data.length) {
      written += writeSync(fd, data, written, data.length - written);
    }
    return data.length;
  } finally {
    closeSync(fd);
  }
}

/**
 * List the sandbox — the SAME per-operation boundary as read/write/seed,
 * so the auto-allowed list_files cannot follow a swapped root where the
 * read would already refuse. The directory itself is additionally opened
 * O_DIRECTORY|O_NOFOLLOW and fd-verified (a real, owner-only directory of
 * ours) before its entries are read.
 */
export function listSandboxFiles(root: string): string[] {
  const O_NOFOLLOW = requireNoFollow(constants.O_NOFOLLOW);
  assertRootBoundary(root);
  assertParentTrusted(root);
  const fd = openSync(root, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | O_NOFOLLOW);
  try {
    const stat = fstatSync(fd);
    if (!stat.isDirectory() || stat.uid !== ourUid() || (stat.mode & 0o077) !== 0) {
      throw new Error(`refusing to list "${root}": not an owner-only directory of this user`);
    }
  } finally {
    closeSync(fd);
  }
  return readdirSync(root);
}

/**
 * Rename within the sandbox — boundary-checked like every other
 * operation; both names pass the basename rule, and rename moves the
 * directory ENTRY (a planted symlink moves as a link, its target
 * untouched).
 */
export function moveSandboxFile(root: string, from: string, to: string): void {
  requireNoFollow(constants.O_NOFOLLOW);
  assertRootBoundary(root);
  assertParentTrusted(root);
  renameSync(resolve(root, validateName(from)), resolve(root, validateName(to)));
}

/**
 * Seed a file if absent. EEXIST is the only swallowed outcome — and only
 * after checking WHAT exists: a benign regular file is the idempotent
 * no-op, a planted symlink/hardlink/FIFO at the seeded name is reported
 * loudly instead of being left to ambush a later read.
 */
export function seedSandboxFile(root: string, name: string, content: string): void {
  const O_NOFOLLOW = requireNoFollow(constants.O_NOFOLLOW);
  assertRootBoundary(root);
  assertParentTrusted(root);
  const path = resolve(root, validateName(name));
  let fd: number;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW, 0o600);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    const existing = lstatSync(path);
    if (!existing.isFile() || existing.nlink !== 1 || existing.uid !== ourUid()) {
      throw new Error(
        `a planted entry occupies the seeded name "${name}" (symlink, hard link, FIFO, or a ` +
          `foreign file) — remove ${path} and re-run the demo`,
      );
    }
    return; // already seeded with a benign regular file
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
