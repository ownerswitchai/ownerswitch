import { execFileSync } from "node:child_process";
import {
  chmodSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ensureSandboxRoot,
  listSandboxFiles,
  moveSandboxFile,
  readSandboxFile,
  requireNoFollow,
  seedSandboxFile,
  validateName,
  writeSandboxFile,
} from "./demo-sandbox.js";

/**
 * The demo sandbox's containment REGRESSIONS — both review rounds' exact
 * attacks: planted symlinks AND hard links must refuse (with write targets
 * untouched), a pre-existing over-permissive or foreign root refuses with
 * the fix named, an untrusted (swappable) parent refuses, FIFOs refuse
 * without hanging, names cannot express a path, the seed reports a planted
 * entry loudly, and a platform without O_NOFOLLOW refuses instead of
 * silently degrading.
 */
const dirs: string[] = [];
const fresh = () => {
  const dir = mkdtempSync(join(tmpdir(), "ownerswitch-demo-sbx-"));
  dirs.push(dir);
  return dir;
};
afterEach(() => {
  while (dirs.length > 0) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

describe("demo sandbox — symlinks AND hard links refuse, roots are verified, seed is honest", () => {
  it("a planted symlink at a file name is NOT read through — the secret stays unread", () => {
    const outside = fresh();
    const secret = join(outside, "id_ed25519");
    writeFileSync(secret, "PRIVATE KEY MATERIAL", { mode: 0o600 });
    const root = ensureSandboxRoot(join(fresh(), "sandbox"));
    symlinkSync(secret, join(root, "welcome.txt"));
    expect(() => readSandboxFile(root, "welcome.txt")).toThrow(/ELOOP|symlink/i);
  });

  it("a planted HARD LINK is not read through — nlink>1 refuses where O_NOFOLLOW cannot see", () => {
    const outside = fresh();
    const secret = join(outside, "id_ed25519");
    writeFileSync(secret, "PRIVATE KEY MATERIAL", { mode: 0o600 });
    const root = ensureSandboxRoot(join(fresh(), "sandbox"));
    linkSync(secret, join(root, "welcome.txt")); // same inode, not a symlink
    expect(() => readSandboxFile(root, "welcome.txt")).toThrow(/hard link/i);
  });

  it("a planted symlink at a write name is NOT written through — the target survives byte-for-byte", () => {
    const outside = fresh();
    const target = join(outside, "authorized_keys");
    writeFileSync(target, "original content", { mode: 0o600 });
    const root = ensureSandboxRoot(join(fresh(), "sandbox"));
    symlinkSync(target, join(root, "hello.txt"));
    expect(() => writeSandboxFile(root, "hello.txt", "attacker content")).toThrow(/ELOOP|symlink/i);
    expect(readFileSync(target, "utf8")).toBe("original content");
  });

  it("a planted HARD LINK at a write name refuses BEFORE truncation — the target keeps every byte", () => {
    const outside = fresh();
    const target = join(outside, "authorized_keys");
    writeFileSync(target, "original content", { mode: 0o600 });
    const root = ensureSandboxRoot(join(fresh(), "sandbox"));
    linkSync(target, join(root, "hello.txt"));
    // the write opens WITHOUT O_TRUNC and checks the fd first — a truncating
    // open would have emptied the target before any check could refuse
    expect(() => writeSandboxFile(root, "hello.txt", "attacker content")).toThrow(/hard link/i);
    expect(readFileSync(target, "utf8")).toBe("original content");
  });

  it("a planted FIFO refuses without hanging the open", () => {
    const root = ensureSandboxRoot(join(fresh(), "sandbox"));
    execFileSync("mkfifo", [join(root, "welcome.txt")]);
    // O_NONBLOCK on the open means no writer is awaited; the fstat type
    // check then refuses the non-regular entry
    expect(() => readSandboxFile(root, "welcome.txt")).toThrow(/hard link|not a plain/i);
  });

  it("a PRE-EXISTING over-permissive root refuses with the exact chmod named", () => {
    const parent = fresh();
    const root = join(parent, "sandbox");
    mkdirSync(root);
    chmodSync(root, 0o755); // group/world-readable — over-permissive for a sandbox
    expect(() => ensureSandboxRoot(root)).toThrow(/chmod 700/);
    chmodSync(root, 0o700);
    expect(() => ensureSandboxRoot(root)).not.toThrow();
  });

  it("an untrusted (world-writable, non-sticky) PARENT refuses — a swappable namespace is no boundary", () => {
    const grand = fresh();
    const parent = join(grand, "open-parent");
    mkdirSync(parent);
    chmodSync(parent, 0o777); // world-writable, NOT sticky (chmod — umask would mask mkdir's mode)
    expect(() => ensureSandboxRoot(join(parent, "sandbox"))).toThrow(/not a trusted directory/);
    // the same parent WITH the sticky bit (the /tmp model) is accepted
    chmodSync(parent, 0o1777);
    expect(() => ensureSandboxRoot(join(parent, "sandbox2"))).not.toThrow();
  });

  it("a ROOT symlink to an EXISTING owner-owned 0700 directory refuses — the ~/.ssh redirect", () => {
    // the review's exact attack: the target passes every post-realpath
    // check (real dir, ours, 0700), so only the pre-realpath lstat of the
    // LEXICAL leaf can see the redirect
    const fakeSsh = join(fresh(), "ssh");
    mkdirSync(fakeSsh, { mode: 0o700 });
    chmodSync(fakeSsh, 0o700);
    writeFileSync(join(fakeSsh, "id_ed25519"), "PRIVATE KEY MATERIAL", { mode: 0o600 });
    const rootLink = join(fresh(), "demo");
    symlinkSync(fakeSsh, rootLink);
    expect(() => ensureSandboxRoot(rootLink)).toThrow(/symlink/);
    // and nothing was seeded into the redirect target
    expect(readFileSync(join(fakeSsh, "id_ed25519"), "utf8")).toBe("PRIVATE KEY MATERIAL");
  });

  it("a DANGLING root symlink refuses; a symlinked PARENT canonicalizes and is judged by its real target", () => {
    const real = fresh();
    const linkParent = fresh();
    const rootLink = join(linkParent, "sandbox-link");
    symlinkSync(join(real, "nonexistent-dir"), rootLink);
    expect(() => ensureSandboxRoot(rootLink)).toThrow();
    // parent-as-symlink: resolves to a TRUSTED real dir → accepted, and the
    // returned root is the canonical path (operations never re-walk the link)
    const trustedReal = fresh();
    const parentLink = join(fresh(), "via-link");
    symlinkSync(trustedReal, parentLink);
    const root = ensureSandboxRoot(join(parentLink, "sandbox"));
    expect(root).toBe(join(lstatSync(trustedReal).isDirectory() ? trustedReal : "", "sandbox"));
  });

  it("a GROUP-writable non-sticky parent refuses too — group members can swap entries just as well", () => {
    const grand = fresh();
    const parent = join(grand, "group-parent");
    mkdirSync(parent);
    chmodSync(parent, 0o775); // group-write, NOT sticky
    expect(() => ensureSandboxRoot(join(parent, "sandbox"))).toThrow(/not a trusted directory/);
    chmodSync(parent, 0o770);
    expect(() => ensureSandboxRoot(join(parent, "sandbox"))).toThrow(/not a trusted directory/);
    // no group/world write at all → trusted (the typical 0755 $HOME shape)
    chmodSync(parent, 0o755);
    expect(() => ensureSandboxRoot(join(parent, "sandbox"))).not.toThrow();
  });

  it("the parent boundary is re-verified PER OPERATION — a widened parent refuses later reads", () => {
    const grand = fresh();
    const parent = join(grand, "was-safe");
    mkdirSync(parent);
    chmodSync(parent, 0o700);
    const root = ensureSandboxRoot(join(parent, "sandbox"));
    writeSandboxFile(root, "note.txt", "hi");
    chmodSync(parent, 0o777); // the namespace becomes swappable AFTER startup
    expect(() => readSandboxFile(root, "note.txt")).toThrow(/not a trusted directory/);
  });

  it("INIT authenticates the LEXICAL parent — a writable parent refuses even when a planted link's TARGET parent would be trusted", () => {
    // the review's TOCTOU shape, made static: the swap window only exists
    // in a writable lexical parent, so that parent must refuse BEFORE any
    // leaf is looked at — checking the (trusted) parent of the link's
    // target instead is exactly the bypass
    const attackerDir = join(fresh(), "attacker");
    mkdirSync(attackerDir);
    chmodSync(attackerDir, 0o777); // the swap arena: writable, not sticky
    const trustedTarget = join(fresh(), "victim-0700");
    mkdirSync(trustedTarget);
    chmodSync(trustedTarget, 0o700); // its parent (mkdtemp) is trusted too
    symlinkSync(trustedTarget, join(attackerDir, "demo")); // the swapped-in link
    expect(() => ensureSandboxRoot(join(attackerDir, "demo"))).toThrow(/not a trusted directory/);
  });

  it("list_files and move_file honor the SAME per-operation boundary — a widened parent refuses both", () => {
    const grand = fresh();
    const parent = join(grand, "was-safe");
    mkdirSync(parent);
    chmodSync(parent, 0o700);
    const root = ensureSandboxRoot(join(parent, "sandbox"));
    writeSandboxFile(root, "a.txt", "hi");
    expect(listSandboxFiles(root)).toContain("a.txt");
    moveSandboxFile(root, "a.txt", "b.txt");
    expect(listSandboxFiles(root)).toContain("b.txt");
    chmodSync(parent, 0o777); // the root entry becomes swappable
    expect(() => listSandboxFiles(root)).toThrow(/not a trusted directory/);
    expect(() => moveSandboxFile(root, "b.txt", "c.txt")).toThrow(/not a trusted directory/);
    // and a root SWAPPED to a symlink refuses the list outright (restore
    // the parent so only the root's own state is what refuses)
    chmodSync(parent, 0o700);
    rmSync(root, { recursive: true, force: true });
    const elsewhere = join(fresh(), "elsewhere");
    mkdirSync(elsewhere);
    chmodSync(elsewhere, 0o700);
    writeFileSync(join(elsewhere, "outside.txt"), "outside", { mode: 0o600 });
    symlinkSync(elsewhere, root);
    expect(() => listSandboxFiles(root)).toThrow();
  });

  it("the SEED reports a planted entry LOUDLY, is a no-op on a benign file, and surfaces non-EEXIST errors", () => {
    const outside = fresh();
    const target = join(outside, "target.txt");
    writeFileSync(target, "original", { mode: 0o600 });
    const root = ensureSandboxRoot(join(fresh(), "sandbox"));
    symlinkSync(target, join(root, "welcome.txt"));
    // a planted symlink at the seeded name is NAMED, never silently kept
    expect(() => seedSandboxFile(root, "welcome.txt", "seed body")).toThrow(/planted entry/);
    expect(readFileSync(target, "utf8")).toBe("original");
    // benign regular file → idempotent no-op
    writeSandboxFile(root, "note.txt", "hi");
    seedSandboxFile(root, "note.txt", "would-be-overwrite");
    expect(readSandboxFile(root, "note.txt")).toBe("hi");
    // a NON-EEXIST failure surfaces instead of being eaten
    expect(() => seedSandboxFile(join(root, "no-such-subdir"), "x.txt", "body")).toThrow();
  });

  it("names cannot express a path: separators, dot-dot, dotfiles, empties all refuse", () => {
    for (const name of ["../escape", "a/b", "a\\b", "..", ".", ".hidden", "", "x".repeat(200)]) {
      expect(() => validateName(name), name).toThrow(/invalid file name/);
    }
    expect(validateName("hello-world_1.txt")).toBe("hello-world_1.txt");
  });

  it("a platform without O_NOFOLLOW refuses instead of silently degrading to symlink-following", () => {
    expect(() => requireNoFollow(undefined)).toThrow(/O_NOFOLLOW/);
    expect(() => requireNoFollow(0)).toThrow(/O_NOFOLLOW/);
  });

  it("a fresh root is created owner-only and a normal write/read round-trips inside it", () => {
    const root = ensureSandboxRoot(join(fresh(), "sandbox"));
    expect(lstatSync(root).mode & 0o777).toBe(0o700);
    writeSandboxFile(root, "note.txt", "hi");
    expect(readSandboxFile(root, "note.txt")).toBe("hi");
    mkdirSync(join(root, "sub"));
    expect(() => readSandboxFile(root, "sub")).toThrow(); // a directory is not a file
  });
});
