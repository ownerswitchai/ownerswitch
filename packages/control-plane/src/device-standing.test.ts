import { chmodSync, chownSync, mkdtempSync, statSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  canonicalTrustedStandingPath,
  DeviceStandingFileStore,
  type PersistedDeviceStanding,
} from "./device-standing.js";

const tmp = () => mkdtempSync(join(tmpdir(), "ownerswitch-standing-"));

const state = (devices: PersistedDeviceStanding["devices"]): PersistedDeviceStanding => ({
  version: 1,
  devices,
});

describe("DeviceStandingFileStore — durable revocation standing", () => {
  it("round-trips standing atomically and reports durability", () => {
    const store = new DeviceStandingFileStore(join(tmp(), "standing.json"));
    expect(store.load()).toEqual({ outcome: "absent" });

    const saved = store.save(state({ "owner-phone": { generation: 2, revokedAt: 1_234 } }));
    expect(saved.durable).toBe(true);

    const loaded = store.load();
    expect(loaded.outcome).toBe("loaded");
    if (loaded.outcome === "loaded") {
      expect(loaded.state.devices["owner-phone"]).toEqual({ generation: 2, revokedAt: 1_234 });
    }
  });

  it("DELETING the standing file after a write loads as corrupt — deletion must not resurrect", () => {
    const file = join(tmp(), "standing.json");
    const store = new DeviceStandingFileStore(file);
    store.save(state({ d: { generation: 2, revokedAt: 99 } }));
    unlinkSync(file); // the resurrection attempt
    const loaded = store.load();
    expect(loaded.outcome).toBe("corrupt"); // marker exists, file missing
  });

  it("a store with NEITHER file is a genuine first boot (absent), not corruption", () => {
    const store = new DeviceStandingFileStore(join(tmp(), "standing.json"));
    expect(store.load().outcome).toBe("absent");
  });

  it("rejects shapes it would not have written: extra keys, bad generations, colon device ids", () => {
    const file = join(tmp(), "standing.json");
    const bad = [
      '{"version":2,"devices":{}}',
      '{"version":1,"devices":{},"extra":1}',
      '{"version":1,"devices":{"d":{"generation":0,"revokedAt":null}}}',
      '{"version":1,"devices":{"d":{"generation":1,"revokedAt":null,"x":1}}}',
      '{"version":1,"devices":{"a:b":{"generation":1,"revokedAt":null}}}',
      "not json",
    ];
    for (const content of bad) {
      writeFileSync(file, content);
      expect(new DeviceStandingFileStore(file).load().outcome).toBe("corrupt");
    }
  });

  it("publishes 0600 by default and 0640 in the group-readable (distinct-UID) model", () => {
    const dirA = tmp();
    const privateStore = new DeviceStandingFileStore(join(dirA, "standing.json"));
    privateStore.save(state({ d: { generation: 1, revokedAt: null } }));
    expect(statSync(join(dirA, "standing.json")).mode & 0o777).toBe(0o600);

    const dirB = tmp();
    const sharedStore = new DeviceStandingFileStore(join(dirB, "standing.json"), { fileMode: 0o640 });
    sharedStore.save(state({ d: { generation: 1, revokedAt: null } }));
    // the escalation group's read bit is present on the PUBLISHED file (and
    // the marker), pinned with fchmod before the rename — umask cannot mask it
    expect(statSync(join(dirB, "standing.json")).mode & 0o777).toBe(0o640);
    expect(statSync(sharedStore.markerPath).mode & 0o777).toBe(0o640);
    // group WRITE is never granted in either model
    expect(statSync(join(dirB, "standing.json")).mode & 0o022).toBe(0);
  });

  it("pins the file to an EXPLICIT gid (fchown before rename) and verifies the published boundary", () => {
    const gid = typeof process.getgid === "function" ? process.getgid() : 0;
    const dir = tmp();
    const file = join(dir, "standing.json");
    const store = new DeviceStandingFileStore(file, { fileMode: 0o640, group: gid });
    const saved = store.save(state({ d: { generation: 1, revokedAt: null } }));
    expect(saved.durable).toBe(true);
    const published = statSync(file);
    expect(published.gid).toBe(gid);
    expect(published.mode & 0o777).toBe(0o640);
    // the marker carries the same pinned mode (the fchmod the review found missing)
    expect(statSync(store.markerPath).mode & 0o777).toBe(0o640);
  });

  it("LOAD refuses any boundary that would let someone else write the registry (a protected dir does not protect a writable leaf)", () => {
    const gid = typeof process.getgid === "function" ? process.getgid() : 0;
    const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
    const setup = (opts?: ConstructorParameters<typeof DeviceStandingFileStore>[1]) => {
      const file = join(tmp(), "standing.json");
      const writer = new DeviceStandingFileStore(file, opts);
      writer.save(state({ d: { generation: 1, revokedAt: null } }));
      return file;
    };

    // group- or world-writable modes: well-formed JSON in a writable file IS
    // the resurrect-the-phone attack — corrupt, never standing
    for (const mode of [0o660, 0o644, 0o666, 0o620] as const) {
      const file = setup();
      chmodSync(file, mode);
      const loaded = new DeviceStandingFileStore(file).load();
      expect(loaded.outcome).toBe("corrupt");
      if (loaded.outcome === "corrupt") expect(loaded.detail).toMatch(/boundary/);
    }

    // 0640 found by a store with NO configured read-only group -> corrupt
    const file640 = setup({ fileMode: 0o640, group: gid });
    expect(new DeviceStandingFileStore(file640).load().outcome).toBe("corrupt");
    // ...but the properly configured reader (same expected gid) loads it
    expect(new DeviceStandingFileStore(file640, { fileMode: 0o640, group: gid }).load().outcome).toBe("loaded");

    if (isRoot) {
      // wrong OWNER: even 0600 under a foreign uid is someone else's pen
      const foreignOwner = setup();
      chownSync(foreignOwner, 12345, gid);
      const owned = new DeviceStandingFileStore(foreignOwner).load();
      expect(owned.outcome).toBe("corrupt");
      if (owned.outcome === "corrupt") expect(owned.detail).toMatch(/uid 12345/);
      // ...unless that uid is EXPLICITLY trusted (the reader's named CP uid)
      expect(
        new DeviceStandingFileStore(foreignOwner, { trustedOwnerUids: [0, 12345] }).load().outcome,
      ).toBe("loaded");

      // wrong GID on a 0640 file: read exposure to an unvetted group -> corrupt
      const wrongGid = setup({ fileMode: 0o640, group: gid });
      chownSync(wrongGid, 0, 54321);
      const badGid = new DeviceStandingFileStore(wrongGid, { fileMode: 0o640, group: gid }).load();
      expect(badGid.outcome).toBe("corrupt");
      if (badGid.outcome === "corrupt") expect(badGid.detail).toMatch(/gid 54321/);
    }
  });

  it("canonicalTrustedStandingPath REFUSES a chain with an untrusted-writable ancestor (public /tmp)", () => {
    // tmpdir chains through /tmp (mode 1777): a world-writable ancestor lets
    // the registry be replaced wholesale, so the walk refuses it
    const file = join(tmp(), "standing.json");
    expect(() => canonicalTrustedStandingPath(file)).toThrow(/world-writable|group- or world-writable/);
    // relative paths never reach the walk
    expect(() => canonicalTrustedStandingPath("relative/standing.json")).toThrow(/absolute/);
    // the test escape hatch resolves the CANONICAL path (realpathed parent)
    const canonical = canonicalTrustedStandingPath(file, { unsafeAllowUntrustedAncestryForTests: true });
    expect(canonical.endsWith("/standing.json")).toBe(true);
  });

  it("refuses a symlink planted at the standing path", () => {
    const dir = tmp();
    const real = join(dir, "elsewhere.json");
    writeFileSync(real, JSON.stringify(state({})));
    const file = join(dir, "standing.json");
    symlinkSync(real, file);
    expect(new DeviceStandingFileStore(file).load().outcome).toBe("corrupt");
  });
});
