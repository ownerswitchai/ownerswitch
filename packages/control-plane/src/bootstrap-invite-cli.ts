#!/usr/bin/env node
/**
 * ownerswitch-bootstrap-invite — mint the FIRST device's enrolment invite
 * (apps/owner/DESIGN.md §2, bootstrap lane). Runs on the HOST, talks to the
 * control plane over the permission-protected Unix socket
 * (bootstrap-socket.ts) — never HTTP, so being able to run this at all IS
 * the authorization. All logic lives in bootstrap-invite-lib.ts, where the
 * tests drive it; this wrapper only moves process argv/env in and the
 * streams out.
 */
import process from "node:process";
import { runBootstrapInvite } from "./bootstrap-invite-lib.js";

runBootstrapInvite(process.argv.slice(2), process.env).then(
  (result) => {
    if (result.stdout !== "") process.stdout.write(result.stdout);
    if (result.stderr !== "") process.stderr.write(result.stderr);
    process.exit(result.exitCode);
  },
  (err: unknown) => {
    process.stderr.write(
      `ownerswitch-bootstrap-invite: ${err instanceof Error ? err.message : "failed"}\n`,
    );
    process.exit(1);
  },
);
