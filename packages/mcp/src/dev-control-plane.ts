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
// The kill-state key that authenticates the broker's live kill-state channel
// (matching the broker's OWNERSWITCH_KILL_STATE_KEY). Unset, /kill-state is
// 501 and the broker cannot use its authenticated channel.
const killStateKey = process.env.OWNERSWITCH_KILL_STATE_KEY;
// DEV ONLY: with a grant key but no enrolled passkey, this instance would
// approve merges on a reusable owner session. That weaker boundary is fine
// for the quickstart but must be acknowledged explicitly — see
// packages/mcp/src/control-plane.ts for the PRODUCTION launcher that
// enrolls a passkey and runs dev:false.
const acceptSessionOnly = process.env.OWNERSWITCH_ACCEPT_SESSION_ONLY_APPROVAL_RISK === "1";

// dev: true — this is the quickstart instance; the kill-state path safety
// checks that production enforces (absolute path, protected directory) are
// deliberately off here, and createControlPlane says so loudly at boot.
const controlPlane = createControlPlane({
  deviceSecret,
  killStateFile,
  dev: true,
  ...(grantKey !== undefined && grantKey !== "" ? { grantKey } : {}),
  ...(killStateKey !== undefined && killStateKey !== "" ? { killStateKey } : {}),
  ...(acceptSessionOnly ? { acceptSessionOnlyApprovalRisk: true } : {}),
});
const owner = createOwnerSession("owner-dev");

const server = createServer(controlPlane.handler);

// A raw EADDRINUSE stack is the wrong first impression of a tool whose whole
// pitch is "every refusal says what to do about it" — and this one happens to
// nearly everyone, because the natural way to restart the quickstart is to
// open a second terminal and run it again.
server.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EADDRINUSE") {
    console.error(
      `[ownerswitch] port ${port} is already in use — a dev control plane is probably still ` +
        `running in another terminal.\n` +
        `  keep that one:   curl http://127.0.0.1:${port}/status\n` +
        `  or take it over: stop the other process, or start this one elsewhere with ` +
        `OWNERSWITCH_CONTROL_PLANE_PORT=4601\n` +
        `  (a second instance on another port needs its own OWNERSWITCH_KILL_STATE_FILE too — ` +
        `two control planes sharing one kill-state file will overwrite each other's answer)`,
    );
    process.exit(1);
  }
  throw err;
});

server.listen(port, "127.0.0.1", () => {
  const base = `http://127.0.0.1:${port}`;
  console.log(`OwnerSwitch dev control plane listening on ${base}`);
  console.log(`  device secret : ${deviceSecret}  (put this in your gateway config)`);
  console.log(`  owner token   : ${owner.token}`);
  console.log(`                  (15 min TTL — restart to mint a fresh one)`);
  console.log(`                  copy this ready line into EVERY owner terminal:`);
  console.log(`                    export OWNERSWITCH_OWNER_TOKEN='${owner.token}'`);
  console.log(`  kill state    : ${controlPlane.killSwitch.killed ? "KILLED (restore takes the 2GO ceremony)" : "armed"}`);
  console.log(`                  persists at ${killStateFile}`);
  console.log(`                  (set OWNERSWITCH_KILL_STATE_FILE to move it)`);
  console.log(``);
  console.log(`Play the owner:`);
  console.log(`  kill everything   curl -X POST ${base}/kill -d '{"reason":"owner pressed stop"}'`);
  console.log(`  check kill state  curl ${base}/status`);
  console.log(`  watch a window    curl ${base}/veto/<id>`);
  console.log(`  veto a window     curl -X POST ${base}/veto/<id> -H 'Authorization: Bearer ${owner.token}'`);
  console.log(``);
  console.log(`Sessions and veto windows reset on restart; the kill does NOT — restarting`);
  console.log(`is not a restore. To hard-reset a dev instance, stop it and delete the`);
  console.log(`kill-state file.`);
});
