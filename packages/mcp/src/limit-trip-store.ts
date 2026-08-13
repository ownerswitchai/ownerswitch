/**
 * File-backed LimitTripStore: where a kill-action limit trip survives a
 * gateway restart (gateway/limits.ts documents the lifecycle it carries).
 *
 * Durability, stated honestly: writes go to a same-directory temp file and
 * are published by rename, so a reader sees the old record or the new one,
 * never a torn write — and a PROCESS crash between trip and delivery keeps
 * the record. There is no fsync: a power cut in the same instant can lose
 * it. That bound is accepted for v0 (the kill-state file on the control
 * plane, the durable end of this pipeline, does the full fsync dance).
 *
 * Fail-closed rules:
 *  - a store path that cannot be prepared is a STARTUP error — limits that
 *    silently cannot persist their trips are the lie this file exists to
 *    prevent;
 *  - an existing record that cannot be parsed is a STARTUP error too: the
 *    operator inspects or deletes the file. Guessing (was it confirmed?
 *    whose trip?) could either free a tripped agent or brick a healthy one.
 */
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { LimitTripStore, PersistedLimitTrip } from "@ownerswitchai/gateway";
import { isValidAgentId } from "@ownerswitchai/shared";
import { ConfigError } from "./config.js";

const MAX_TRIP_FILE_BYTES = 16 * 1024;

function asPersistedLimitTrip(value: unknown): PersistedLimitTrip | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const { ruleId, agentId, reason, at, confirmed, ...rest } = value as Record<string, unknown>;
  if (Object.keys(rest).length > 0) return null;
  if (typeof ruleId !== "string" || ruleId === "" || ruleId.length > 256) return null;
  if (typeof agentId !== "string" || !isValidAgentId(agentId)) return null;
  if (typeof reason !== "string" || reason.length > 4096) return null;
  if (typeof at !== "number" || !Number.isFinite(at)) return null;
  if (typeof confirmed !== "boolean") return null;
  return { ruleId, agentId, reason, at, confirmed };
}

export function createFileLimitTripStore(path: string): LimitTripStore {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  } catch (err) {
    throw new ConfigError(
      `cannot prepare the limit trip state directory for "${path}": ` +
        `${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return {
    load(): PersistedLimitTrip | null {
      let raw: string;
      try {
        raw = readFileSync(path, "utf8");
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === "ENOENT") return null; // genuinely no pending trip
        throw new ConfigError(
          `cannot read the limit trip state file "${path}": ` +
            `${err instanceof Error ? err.message : String(err)}`,
        );
      }
      if (Buffer.byteLength(raw, "utf8") > MAX_TRIP_FILE_BYTES) {
        throw new ConfigError(
          `limit trip state file "${path}" is over ${MAX_TRIP_FILE_BYTES} bytes — ` +
            `not something this gateway wrote; inspect or remove it`,
        );
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        throw new ConfigError(
          `limit trip state file "${path}" is not valid JSON — a pending trip cannot be ` +
            `guessed at; inspect or remove the file`,
        );
      }
      const record = asPersistedLimitTrip(parsed);
      if (record === null) {
        throw new ConfigError(
          `limit trip state file "${path}" has a shape this gateway would not have written — ` +
            `inspect or remove it`,
        );
      }
      return record;
    },
    save(record: PersistedLimitTrip): void {
      const tmp = join(dirname(path), `.trip-${process.pid}-${Date.now().toString(36)}.tmp`);
      writeFileSync(tmp, `${JSON.stringify(record)}\n`, { mode: 0o600 });
      renameSync(tmp, path);
    },
    clear(): void {
      rmSync(path, { force: true });
    },
  };
}
