import { chmodSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
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
    const store = createJtiBurnStore(dir, { now: () => NOW });
    expect(store.burn("jti-1", NOW + 120_000)).toBe("burned");
    expect(store.burn("jti-1", NOW + 120_000)).toBe("already-burned");
    // a fresh instance over the same directory — a restarted broker
    const reopened = createJtiBurnStore(dir, { now: () => NOW });
    expect(reopened.burn("jti-1", NOW + 120_000)).toBe("already-burned");
  });

  it("records and looks up the outcome; unknown jti is undefined", () => {
    const store = createJtiBurnStore(join(root, "b"), { now: () => NOW });
    store.burn("jti-2", NOW + 120_000);
    store.record("jti-2", { state: "performed", merged: true, sha: "abc" });
    expect(store.lookup("jti-2")).toMatchObject({ jti: "jti-2", state: "performed", merged: true });
    expect(store.lookup("never-burned")).toBeUndefined();
  });

  it("prunes only records safely past expiry + retention — a live burn stays burned", () => {
    let clock = NOW;
    const store = createJtiBurnStore(join(root, "c"), { now: () => clock, retentionMs: 60_000 });
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
    const store = createJtiBurnStore(dir, { now: () => NOW });
    // replace the directory with a FILE so writes fail with ENOTDIR — a
    // permission-bit approach cannot simulate this under root (CI runs as
    // root, and root ignores mode bits)
    rmSync(dir, { recursive: true, force: true });
    writeFileSync(dir, "not a directory");
    expect(() => store.burn("jti-3", NOW + 120_000)).toThrowError(/could not persist/);
  });

  it("refuses a group/world-accessible directory — records must not be deletable by peers", () => {
    const dir = join(root, "e");
    createJtiBurnStore(dir, { now: () => NOW }); // creates 0700
    chmodSync(dir, 0o770);
    expect(() => createJtiBurnStore(dir, { now: () => NOW })).toThrowError(/group or world access/);
  });
});
