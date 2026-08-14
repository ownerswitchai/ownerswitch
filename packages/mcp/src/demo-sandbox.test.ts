import { lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ensureSandboxRoot,
  readSandboxFile,
  seedSandboxFile,
  validateName,
  writeSandboxFile,
} from "../examples/demo-sandbox.js";

/**
 * The demo sandbox's containment REGRESSIONS (the review's exact attacks):
 * a planted symlink must refuse instead of reaching outside the directory,
 * names must not be able to express a path at all, a symlinked root is
 * refused, and the seed swallows EEXIST only. The demo runs on an
 * onboarding user's real filesystem — it must not be able to touch their
 * HOME even when an attacker pre-seeds the sandbox.
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

describe("demo sandbox — symlinks refuse, names cannot traverse, seed is honest", () => {
  it("a planted symlink at a file name is NOT read through — the secret stays unread", () => {
    const outside = fresh();
    const secret = join(outside, "id_ed25519");
    writeFileSync(secret, "PRIVATE KEY MATERIAL", { mode: 0o600 });
    const root = ensureSandboxRoot(join(fresh(), "sandbox"));
    symlinkSync(secret, join(root, "welcome.txt")); // the review's exact plant
    expect(() => readSandboxFile(root, "welcome.txt")).toThrow(/ELOOP|symlink/i);
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

  it("the SEED never overwrites through a planted entry, and swallows EEXIST only", () => {
    const outside = fresh();
    const target = join(outside, "target.txt");
    writeFileSync(target, "original", { mode: 0o600 });
    const root = ensureSandboxRoot(join(fresh(), "sandbox"));
    symlinkSync(target, join(root, "welcome.txt"));
    // planted entry occupies the name: O_EXCL answers EEXIST — swallowed,
    // and the symlink's target is untouched
    expect(() => seedSandboxFile(root, "welcome.txt", "seed body")).not.toThrow();
    expect(readFileSync(target, "utf8")).toBe("original");
    // a NON-EEXIST failure surfaces instead of being eaten
    expect(() => seedSandboxFile(join(root, "no-such-subdir"), "x.txt", "body")).toThrow();
  });

  it("a symlinked sandbox ROOT is refused outright", () => {
    const real = fresh();
    const linkParent = fresh();
    const link = join(linkParent, "sandbox-link");
    symlinkSync(real, link);
    expect(() => ensureSandboxRoot(link)).toThrow(/real directory/);
  });

  it("names cannot express a path: separators, dot-dot, dotfiles, empties all refuse", () => {
    for (const name of ["../escape", "a/b", "a\\b", "..", ".", ".hidden", "", "x".repeat(200)]) {
      expect(() => validateName(name), name).toThrow(/invalid file name/);
    }
    expect(validateName("hello-world_1.txt")).toBe("hello-world_1.txt");
  });

  it("a fresh root is created owner-only and a normal write/read round-trips inside it", () => {
    const root = ensureSandboxRoot(join(fresh(), "sandbox"));
    expect(lstatSync(root).mode & 0o777).toBe(0o700);
    writeSandboxFile(root, "note.txt", "hi");
    expect(readSandboxFile(root, "note.txt")).toBe("hi");
    // seeding an existing REGULAR file is the idempotent no-op
    seedSandboxFile(root, "note.txt", "would-be-overwrite");
    expect(readSandboxFile(root, "note.txt")).toBe("hi");
    // subdirs are not expressible, so mkdir games don't start
    mkdirSync(join(root, "sub"));
    expect(() => readSandboxFile(root, "sub")).toThrow(); // EISDIR — a directory is not a file
  });
});
