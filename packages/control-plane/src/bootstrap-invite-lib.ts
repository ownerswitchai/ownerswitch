/**
 * The bootstrap-invite CLI's whole brain, as a testable function: argument
 * parsing, local secret generation, the socket round, and — before ANYTHING
 * is printed — validation of the assembled device-to-device payload with
 * the SAME shared runtime validator the phone app uses
 * (@ownerswitchai/shared enrollmentInviteFromWire). A contract the phone
 * could not run never reaches stdout, so it never reaches a QR code.
 *
 * The bin wrapper (bootstrap-invite-cli.ts) only feeds process argv/env in
 * and writes the returned streams out — tests drive THIS function against a
 * real socket and assert on the exact bytes the operator would see.
 */
import { createHash, randomBytes } from "node:crypto";
import { connect } from "node:net";
import { enrollmentInviteFromWire } from "@ownerswitchai/shared";

export interface BootstrapInviteCliResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

function argValue(argv: readonly string[], flag: string): string | undefined {
  const index = argv.indexOf(flag);
  if (index === -1 || index + 1 >= argv.length) return undefined;
  return argv[index + 1];
}

export async function runBootstrapInvite(
  argv: readonly string[],
  env: Record<string, string | undefined>,
): Promise<BootstrapInviteCliResult> {
  const fail = (message: string): BootstrapInviteCliResult => ({
    exitCode: 1,
    stdout: "",
    stderr: `ownerswitch-bootstrap-invite: ${message}\n`,
  });

  const socketPath = argValue(argv, "--socket") ?? env.OWNERSWITCH_BOOTSTRAP_SOCKET?.trim();
  const ownerId = argValue(argv, "--owner");
  const deviceName = argValue(argv, "--name");
  if (socketPath === undefined || socketPath === "") {
    return fail("no socket: pass --socket or set OWNERSWITCH_BOOTSTRAP_SOCKET");
  }
  if (ownerId === undefined || ownerId === "") return fail("--owner <ownerId> is required");
  if (deviceName === undefined || deviceName === "") return fail('--name "<deviceName>" is required');

  // the single-use bearer secret: 32 CSPRNG bytes, canonical base64url. It
  // never rides the MINT socket and is never persisted server-side — it is
  // spent exactly once later, as the preimage in the enrolment POST body.
  const token = randomBytes(32).toString("base64url");
  const tokenHash = createHash("sha256").update(token, "utf8").digest("base64url");

  const responseLine = await new Promise<string | Error>((resolve) => {
    const socket = connect(socketPath);
    let buffered = "";
    socket.setTimeout(5_000, () => {
      socket.destroy();
      resolve(new Error("timed out talking to the bootstrap socket"));
    });
    socket.on("connect", () => {
      socket.write(`${JSON.stringify({ tokenHash, ownerId, deviceName })}\n`);
    });
    socket.on("data", (chunk) => {
      buffered += chunk.toString("utf8");
    });
    socket.on("error", (err) => {
      resolve(new Error(`cannot reach the bootstrap socket at ${socketPath}: ${err.message}`));
    });
    socket.on("close", () => resolve(buffered.split("\n", 1)[0] ?? ""));
  });
  if (responseLine instanceof Error) return fail(responseLine.message);

  let result: unknown;
  try {
    result = JSON.parse(responseLine);
  } catch {
    return fail("malformed response from the control plane");
  }
  const parsed = result as { ok?: unknown; error?: unknown; invite?: unknown };
  if (parsed.ok !== true || typeof parsed.invite !== "object" || parsed.invite === null) {
    return fail(typeof parsed.error === "string" ? parsed.error : "mint refused");
  }

  // the DEVICE-TO-DEVICE payload: the server's contract + the LOCAL secret —
  // validated with the phone's own validator BEFORE it is printed. A payload
  // the phone cannot run is a CLI bug, and it fails HERE, not at the QR code.
  const payload = enrollmentInviteFromWire({ ...(parsed.invite as Record<string, unknown>), token });
  if (payload === null) {
    return fail(
      "the control plane's mint response does not satisfy the pinned EnrollmentInvite contract — refusing to print an invite the phone cannot run",
    );
  }
  return {
    exitCode: 0,
    stdout: `${JSON.stringify(payload, null, 2)}\n`,
    stderr:
      "\nShow this to the NEW PHONE only (QR / typed code). It is single-use, expires in ~10\n" +
      "minutes, and the secret inside is spent exactly once, in the enrolment request itself.\n" +
      "stdout is the handoff: a shell redirect or terminal session recording would write it\n" +
      "to disk — display it, use it, and let it expire.\n",
  };
}
