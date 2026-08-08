/**
 * Dev-only control plane for the 5-minute quickstart: one process, in-memory
 * state, an owner session minted at boot and printed so YOU can play the
 * owner with curl. Not for production — restart it to reset everything.
 *
 * Run with: pnpm --filter @ownerswitchai/mcp dev:control-plane
 */
import { createServer } from "node:http";
import { createControlPlane, createOwnerSession } from "@ownerswitchai/control-plane";

const port = Number(process.env.OWNERSWITCH_CONTROL_PLANE_PORT ?? 4600);
const deviceSecret = process.env.OWNERSWITCH_DEVICE_SECRET ?? "dev-device-secret";

const controlPlane = createControlPlane({ deviceSecret });
const owner = createOwnerSession("owner-dev");

createServer(controlPlane.handler).listen(port, "127.0.0.1", () => {
  const base = `http://127.0.0.1:${port}`;
  console.log(`OwnerSwitch dev control plane listening on ${base}`);
  console.log(`  device secret : ${deviceSecret}  (put this in your gateway config)`);
  console.log(`  owner token   : ${owner.token}`);
  console.log(`                  (15 min TTL — restart to mint a fresh one)`);
  console.log(``);
  console.log(`Play the owner:`);
  console.log(`  kill everything   curl -X POST ${base}/kill -d '{"reason":"owner pressed stop"}'`);
  console.log(`  check kill state  curl ${base}/status`);
  console.log(`  watch a window    curl ${base}/veto/<id>`);
  console.log(`  veto a window     curl -X POST ${base}/veto/<id> \\`);
  console.log(`                      -H 'Authorization: Bearer ${owner.token}'`);
  console.log(``);
  console.log(`State is in-memory; restart to reset (e.g. to undo a kill).`);
});
