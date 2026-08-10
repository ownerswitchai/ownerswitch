/**
 * Dev-only control plane for the 5-minute quickstart: one process, an owner
 * session minted at boot and printed so YOU can play the owner with curl.
 * Not for production.
 *
 * Veto windows, ceremonies and sessions are in-memory and reset on restart —
 * but KILL STATE persists to a file and does not: a restart comes back in the
 * state it went down in, and only the 2GO ceremony restores. That asymmetry
 * is the product; the dev server does not soften it.
 *
 * Run with: pnpm --filter @ownerswitchai/mcp dev:control-plane
 */
import { createServer } from "node:http";
import { resolve } from "node:path";
import {
  createControlPlane,
  createOwnerSession,
  DEFAULT_KILL_STATE_FILE,
} from "@ownerswitchai/control-plane";

const port = Number(process.env.OWNERSWITCH_CONTROL_PLANE_PORT ?? 4600);
const deviceSecret = process.env.OWNERSWITCH_DEVICE_SECRET ?? "dev-device-secret";
const killStateFile =
  process.env.OWNERSWITCH_KILL_STATE_FILE ?? resolve(process.cwd(), DEFAULT_KILL_STATE_FILE);
// The grant key the executing merge broker verifies MergeGrants with — set it
// (matching the broker's OWNERSWITCH_GRANT_KEY) to exercise the broker path;
// unset, the control plane mints no grants and the broker deployment cannot run.
const grantKey = process.env.OWNERSWITCH_GRANT_KEY;

// dev: true — this is the quickstart instance; the kill-state path safety
// checks that production enforces (absolute path, protected directory) are
// deliberately off here, and createControlPlane says so loudly at boot.
const controlPlane = createControlPlane({
  deviceSecret,
  killStateFile,
  dev: true,
  ...(grantKey !== undefined && grantKey !== "" ? { grantKey } : {}),
});
const owner = createOwnerSession("owner-dev");

createServer(controlPlane.handler).listen(port, "127.0.0.1", () => {
  const base = `http://127.0.0.1:${port}`;
  console.log(`OwnerSwitch dev control plane listening on ${base}`);
  console.log(`  device secret : ${deviceSecret}  (put this in your gateway config)`);
  console.log(`  owner token   : ${owner.token}`);
  console.log(`                  (15 min TTL — restart to mint a fresh one)`);
  console.log(`  kill state    : ${controlPlane.killSwitch.killed ? "KILLED (restore takes the 2GO ceremony)" : "armed"}`);
  console.log(`                  persists at ${killStateFile}`);
  console.log(`                  (set OWNERSWITCH_KILL_STATE_FILE to move it)`);
  console.log(``);
  console.log(`Play the owner:`);
  console.log(`  kill everything   curl -X POST ${base}/kill -d '{"reason":"owner pressed stop"}'`);
  console.log(`  check kill state  curl ${base}/status`);
  console.log(`  watch a window    curl ${base}/veto/<id>`);
  console.log(`  veto a window     curl -X POST ${base}/veto/<id> \\`);
  console.log(`                      -H 'Authorization: Bearer ${owner.token}'`);
  console.log(``);
  console.log(`Sessions and veto windows reset on restart; the kill does NOT — restarting`);
  console.log(`is not a restore. To hard-reset a dev instance, stop it and delete the`);
  console.log(`kill-state file.`);
});
