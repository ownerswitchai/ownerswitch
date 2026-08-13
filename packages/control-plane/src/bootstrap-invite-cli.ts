#!/usr/bin/env node
/**
 * ownerswitch-bootstrap-invite — mint the FIRST device's enrolment invite
 * (apps/owner/DESIGN.md §2, bootstrap lane). Runs on the HOST, talks to the
 * control plane over the permission-protected Unix socket (bootstrap-socket.ts)
 * — never HTTP, so being able to run this at all IS the authorization.
 *
 * The hash-commitment discipline, end to end in one process:
 *  1. the ≥128-bit secret is generated HERE, locally;
 *  2. only its SHA-256 goes over the socket (InviteMintRequest);
 *  3. the response carries the ceremony contract and NO secret;
 *  4. the device-to-device payload (EnrollmentInvite: the contract PLUS the
 *     local secret as `token`) is printed to STDOUT exactly once — show it
 *     to the new phone as a QR / typed code, and never write it to a log.
 *
 * Usage:
 *   ownerswitch-bootstrap-invite --owner <ownerId> --name "<deviceName>" \
 *     [--socket /run/ownerswitch/bootstrap.sock]
 * The socket path defaults to OWNERSWITCH_BOOTSTRAP_SOCKET.
 */
import { createHash, randomBytes } from "node:crypto";
import { connect } from "node:net";
import process from "node:process";

function fail(message: string): never {
  process.stderr.write(`ownerswitch-bootstrap-invite: ${message}\n`);
  process.exit(1);
}

function argValue(flag: string): string | undefined {
  const index = process.argv.indexOf(flag);
  if (index === -1 || index + 1 >= process.argv.length) return undefined;
  return process.argv[index + 1];
}

const socketPath = argValue("--socket") ?? process.env.OWNERSWITCH_BOOTSTRAP_SOCKET?.trim();
const ownerId = argValue("--owner");
const deviceName = argValue("--name");
if (socketPath === undefined || socketPath === "") {
  fail("no socket: pass --socket or set OWNERSWITCH_BOOTSTRAP_SOCKET");
}
if (ownerId === undefined || ownerId === "") fail("--owner <ownerId> is required");
if (deviceName === undefined || deviceName === "") fail('--name "<deviceName>" is required');

// the single-use bearer secret: 32 CSPRNG bytes, canonical base64url — the
// server sees only the commitment below
const token = randomBytes(32).toString("base64url");
const tokenHash = createHash("sha256").update(token, "utf8").digest("base64url");

const socket = connect(socketPath);
socket.setTimeout(5_000, () => {
  socket.destroy();
  fail("timed out talking to the bootstrap socket");
});
let buffered = "";
socket.on("connect", () => {
  socket.write(`${JSON.stringify({ tokenHash, ownerId, deviceName })}\n`);
});
socket.on("data", (chunk) => {
  buffered += chunk.toString("utf8");
});
socket.on("error", (err) => {
  fail(`cannot reach the bootstrap socket at ${socketPath}: ${err.message}`);
});
socket.on("close", () => {
  const line = buffered.split("\n", 1)[0] ?? "";
  let result: unknown;
  try {
    result = JSON.parse(line);
  } catch {
    fail("malformed response from the control plane");
  }
  const parsed = result as {
    ok?: unknown;
    error?: unknown;
    invite?: Record<string, unknown>;
  };
  if (parsed.ok !== true || typeof parsed.invite !== "object" || parsed.invite === null) {
    fail(typeof parsed.error === "string" ? parsed.error : "mint refused");
  }
  // the DEVICE-TO-DEVICE payload: the server's contract + the LOCAL secret.
  // stdout only — the operator shows it to the new phone and discards it.
  process.stdout.write(`${JSON.stringify({ ...parsed.invite, token }, null, 2)}\n`);
  process.stderr.write(
    "\nShow this to the NEW PHONE only (QR / typed code). It is single-use, expires in ~10\n" +
      "minutes, and never travels through a server. Do not paste it into logs or chats.\n",
  );
  process.exit(0);
});
