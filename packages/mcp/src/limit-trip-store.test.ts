import { existsSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { PersistedLimitTrip } from "@ownerswitchai/gateway";
import { ConfigError } from "./config.js";
import { createFileLimitTripStore } from "./limit-trip-store.js";

const tempPath = () => join(mkdtempSync(join(tmpdir(), "ownerswitch-triplog-")), "trip.json");

const TRIP: PersistedLimitTrip = {
  ruleId: "spend",
  agentId: "agent-7",
  reason: 'limit "spend" tripped for agent "agent-7": total 1200 exceeded max 1000',
  at: 1_000,
  confirmed: false,
};

describe("createFileLimitTripStore", () => {
  it("a missing file is no pending trip; a saved record round-trips and clears", () => {
    const store = createFileLimitTripStore(tempPath());
    expect(store.load()).toBeNull();
    store.save(TRIP);
    expect(store.load()).toEqual(TRIP);
    store.save({ ...TRIP, confirmed: true });
    expect(store.load()).toEqual({ ...TRIP, confirmed: true });
    store.clear();
    expect(store.load()).toBeNull();
  });

  it("publishes by rename — no temp twin remains beside the record", () => {
    const path = tempPath();
    const store = createFileLimitTripStore(path);
    store.save(TRIP);
    expect(existsSync(path)).toBe(true);
    expect(readdirSync(dirname(path)).filter((n) => n.endsWith(".tmp"))).toEqual([]);
  });

  it("a record it would not have written is a STARTUP error, never a guess", () => {
    for (const raw of [
      "{torn",
      "[]",
      "{}",
      '{"ruleId":"r","agentId":"__proto__","reason":"x","at":1,"confirmed":false}',
      '{"ruleId":"r","agentId":"a","reason":"x","at":1,"confirmed":"yes"}',
      '{"ruleId":"r","agentId":"a","reason":"x","at":1,"confirmed":false,"extra":1}',
      '{"ruleId":"","agentId":"a","reason":"x","at":1,"confirmed":false}',
    ]) {
      const path = tempPath();
      writeFileSync(path, raw, "utf8");
      const store = createFileLimitTripStore(path);
      expect(() => store.load(), raw).toThrowError(ConfigError);
    }
  });

  it("refuses a file too large to be its own record", () => {
    const path = tempPath();
    writeFileSync(path, "x".repeat(20 * 1024), "utf8");
    expect(() => createFileLimitTripStore(path).load()).toThrowError(/bytes/);
  });
});
