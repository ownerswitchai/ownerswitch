import { chmodSync, mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createJtiBurnStore } from "./burn-store.js";

const NOW = 1_800_000_000_000;

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "oswitch-burns-"));
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("createJtiBurnStore", () => {
  it("burns exactly once, across store instances (restart survival)", () => {
    const dir = join(root, "a");
    const store = createJtiBurnStore(dir, { now: () => NOW, unsafeAllowUntrustedAncestryForTests: true });
    expect(store.burn("jti-1", NOW + 120_000)).toBe("burned");
    expect(store.burn("jti-1", NOW + 120_000)).toBe("already-burned");
    // a fresh instance over the same directory — a restarted broker
    const reopened = createJtiBurnStore(dir, { now: () => NOW, unsafeAllowUntrustedAncestryForTests: true });
    expect(reopened.burn("jti-1", NOW + 120_000)).toBe("already-burned");
  });

  it("records and looks up the outcome; unknown jti is undefined", () => {
    const store = createJtiBurnStore(join(root, "b"), { now: () => NOW, unsafeAllowUntrustedAncestryForTests: true });
    store.burn("jti-2", NOW + 120_000);
    store.record("jti-2", { state: "performed", merged: true, sha: "abc" });
    expect(store.lookup("jti-2")).toMatchObject({ jti: "jti-2", state: "performed", merged: true });
    expect(store.lookup("never-burned")).toBeUndefined();
  });

  it("prunes only records safely past expiry + retention — a live burn stays burned", () => {
    let clock = NOW;
    const store = createJtiBurnStore(join(root, "c"), { now: () => clock, retentionMs: 60_000, unsafeAllowUntrustedAncestryForTests: true });
    store.burn("old", NOW + 1_000);
    store.burn("live", NOW + 10 * 60_000);
    clock = NOW + 2 * 60_000 + 1_001; // old is past expiry+retention; live is not
    expect(store.pruneExpired()).toBe(1);
    expect(store.lookup("old")).toBeUndefined();
    expect(store.burn("live", NOW + 10 * 60_000)).toBe("already-burned");
    expect(readdirSync(join(root, "c"))).toHaveLength(1);
  });

  it("throws when the burn cannot be persisted — never a silent memory-only burn", () => {
    const dir = join(root, "d");
    const store = createJtiBurnStore(dir, { now: () => NOW, unsafeAllowUntrustedAncestryForTests: true });
    // replace the directory with a FILE so writes fail with ENOTDIR — a
    // permission-bit approach cannot simulate this under root (CI runs as
    // root, and root ignores mode bits)
    rmSync(dir, { recursive: true, force: true });
    writeFileSync(dir, "not a directory");
    // the inode pin catches the substitution before the write even starts —
    // either way it must be a refusal, never a silent memory-only pass
    expect(() => store.burn("jti-3", NOW + 120_000)).toThrowError(
      /could not persist|no longer denotes/,
    );
  });

  it("refuses a group/world-accessible directory — records must not be deletable by peers", () => {
    const dir = join(root, "e");
    createJtiBurnStore(dir, { now: () => NOW, unsafeAllowUntrustedAncestryForTests: true }); // creates 0700
    chmodSync(dir, 0o770);
    expect(() => createJtiBurnStore(dir, { now: () => NOW, unsafeAllowUntrustedAncestryForTests: true })).toThrowError(/group or world access/);
  });

  it("refuses a relative path — a per-cwd namespace is not a durable boundary", () => {
    expect(() => createJtiBurnStore("relative/burns", { now: () => NOW, unsafeAllowUntrustedAncestryForTests: true })).toThrowError(/absolute/);
  });

  it("refuses a burn dir inside the agent workspace — the agent could delete burns", () => {
    const workspace = join(root, "ws");
    mkdirSync(workspace, { recursive: true });
    const inside = join(workspace, "burns");
    expect(() =>
      createJtiBurnStore(inside, { now: () => NOW, workspaceDir: workspace }),
    ).toThrowError(/inside the agent workspace/);
    // a sibling of the workspace is fine
    const outside = join(root, "outside-burns");
    expect(() =>
      createJtiBurnStore(outside, {
        now: () => NOW,
        workspaceDir: workspace,
        unsafeAllowUntrustedAncestryForTests: true,
      }),
    ).not.toThrow();
  });

  it("containment holds POST-realpath: an intermediate symlink cannot smuggle the store into the workspace", () => {
    const workspace = join(root, "ws2");
    mkdirSync(join(workspace, "sneaky"), { recursive: true });
    // the raw path looks OUTSIDE the workspace, but a symlink component
    // resolves it INSIDE — must be refused after canonicalization
    const link = join(root, "looks-outside");
    symlinkSync(join(workspace, "sneaky"), link);
    expect(() =>
      createJtiBurnStore(join(link, "burns"), {
        now: () => NOW,
        workspaceDir: workspace,
        unsafeAllowUntrustedAncestryForTests: true,
      }),
    ).toThrowError(/inside the agent workspace/);
  });

  it("refuses a symlinked burn directory — a retargetable link could un-burn grants", () => {
    const real = join(root, "real-burns");
    mkdirSync(real, { recursive: true, mode: 0o700 });
    const link = join(root, "linked-burns");
    symlinkSync(real, link);
    expect(() => createJtiBurnStore(link, { now: () => NOW, unsafeAllowUntrustedAncestryForTests: true })).toThrowError(/symlink/);
  });

  it("refuses an untrusted ancestry outside the explicit test escape — /tmp is world-writable", () => {
    // without the tests-only escape, a store under tmpdir must refuse: the
    // /tmp ancestor is world-writable, i.e. any local user could rename the
    // store away and substitute a fresh namespace
    expect(() => createJtiBurnStore(join(root, "strict"), { now: () => NOW })).toThrowError(
      /ancestor .*(writable|owned)/,
    );
  });

  it("refuses to burn once the pathname no longer denotes the PINNED directory inode", () => {
    const dir = join(root, "pinned");
    const store = createJtiBurnStore(dir, { now: () => NOW, unsafeAllowUntrustedAncestryForTests: true });
    expect(store.burn("jti-a", NOW + 120_000)).toBe("burned");
    // an "ancestor swap": the directory is renamed away and a fresh one
    // appears at the same pathname — burns must NOT land in the impostor
    renameSync(dir, join(root, "stolen"));
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    expect(() => store.burn("jti-b", NOW + 120_000)).toThrowError(/no longer denotes|substituted/);
  });
});
