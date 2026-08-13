import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createOwnerSession } from "./auth.js";
import { createBootstrapInviteSocket } from "./bootstrap-socket.js";
import {
  enrollmentSubmission,
  FIXTURE_ORIGIN,
  FIXTURE_RP_ID,
  phone,
} from "./enroll-fixture.js";
import { createControlPlane, type ControlPlane } from "./server.js";

/**
 * The BOOTSTRAP path end to end, through the real wire surfaces: the host
 * CLI's socket mints the invite (hash commitment in, contract out, no
 * secret anywhere), the phone's HTTP POST /devices/enroll spends it through
 * the registry's one door, and GET /devices shows the redacted summary.
 * The kill snapshot the registry receives is read off the REAL KillSwitch
 * inside the handler — these tests flip the switch itself to prove it.
 */
const dirs: string[] = [];
const servers: Array<{ close: () => void }> = [];
const freshDir = () => {
  const dir = mkdtempSync(join(tmpdir(), "ownerswitch-enroll-http-"));
  dirs.push(dir);
  return dir;
};
afterEach(() => {
  while (servers.length > 0) servers.pop()?.close();
  while (dirs.length > 0) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

const quiet = <T>(build: () => T): T => {
  const original = console.error;
  console.error = () => {};
  try {
    return build();
  } finally {
    console.error = original;
  }
};

const enrolledPlane = () =>
  quiet(() =>
    createControlPlane({
      dev: true,
      killStateFile: null,
      acceptSessionOnlyApprovalRisk: true,
      enrollment: {
        devicesFile: join(freshDir(), "devices.json"),
        rpId: FIXTURE_RP_ID,
        origin: FIXTURE_ORIGIN,
      },
    }),
  );

const start = (cp: ControlPlane): Promise<string> => {
  const server: Server = createServer(cp.handler);
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") throw new Error("no address");
      resolve(`http://127.0.0.1:${addr.port}`);
    });
  });
};

const SECRET = randomBytes(32).toString("base64url");
const commit = (secret: string) => createHash("sha256").update(secret, "utf8").digest("base64url");

const mintBootstrap = (cp: ControlPlane, secret = SECRET) =>
  cp.bootstrapMintInvite({
    tokenHash: commit(secret),
    ownerId: "owner-adam",
    deviceName: "Adam's phone",
  });

describe("bootstrap enrollment over HTTP — the wire around the registry's one door", () => {
  it("unconfigured: /devices/enroll and /devices are 501 and no registry exists", async () => {
    const cp = quiet(() =>
      createControlPlane({ dev: true, killStateFile: null, acceptSessionOnlyApprovalRisk: true }),
    );
    const base = await start(cp);
    const enroll = await fetch(`${base}/devices/enroll`, { method: "POST", body: "{}" });
    expect(enroll.status).toBe(501);
    const list = await fetch(`${base}/devices`);
    expect(list.status).toBe(501);
    expect(cp.enrolledDevices).toBeUndefined();
  });

  it("the full bootstrap arc: socket-shaped mint -> HTTP enroll 201 -> redacted owner-scoped list", async () => {
    const cp = enrolledPlane();
    const base = await start(cp);

    const minted = mintBootstrap(cp);
    expect(minted.ok).toBe(true);
    if (!minted.ok) return;
    // the mint response carries the contract and NO secret
    expect(JSON.stringify(minted)).not.toContain(SECRET);

    const p = phone();
    const submission = enrollmentSubmission(p, minted.invite, SECRET);
    const enroll = await fetch(`${base}/devices/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(submission),
    });
    expect(enroll.status).toBe(201);
    const body = (await enroll.json()) as { deviceId: string };
    expect(body.deviceId).toMatch(/^dev_/);
    // the pinned EnrollmentResponse: deviceId and NOTHING else
    expect(Object.keys(body)).toEqual(["deviceId"]);

    // spent: the same submission is 410 (gone), not survivable
    const again = await fetch(`${base}/devices/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(submission),
    });
    expect(again.status).toBe(410);

    // the list: owner session required; redacted; scoped to the owner
    expect((await fetch(`${base}/devices`)).status).toBe(401);
    const session = createOwnerSession("owner-adam");
    const list = await fetch(`${base}/devices`, {
      headers: { authorization: `Bearer ${session.token}` },
    });
    expect(list.status).toBe(200);
    const listBody = (await list.json()) as { devices: Array<Record<string, unknown>> };
    expect(listBody.devices).toHaveLength(1);
    expect(listBody.devices[0].name).toBe("Adam's phone");
    // REDACTED: no key material, no push material, anywhere in the response
    const raw = JSON.stringify(listBody);
    expect(raw).not.toMatch(/publicKeySpki|cheapLaneKeySpki|credentialId|userHandle/);
    // another owner's session sees an EMPTY list, not this device
    const stranger = createOwnerSession("owner-eve");
    const strangerList = await fetch(`${base}/devices`, {
      headers: { authorization: `Bearer ${stranger.token}` },
    });
    expect(((await strangerList.json()) as { devices: unknown[] }).devices).toHaveLength(0);
  });

  it("a failed proof is 400 with the invite alive; garbage is 400; oversized is 413", async () => {
    const cp = enrolledPlane();
    const base = await start(cp);
    const minted = mintBootstrap(cp);
    if (!minted.ok) throw new Error("mint failed");
    const p = phone();
    const honest = enrollmentSubmission(p, minted.invite, SECRET);

    const wrongSecret = await fetch(`${base}/devices/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...honest, token: randomBytes(32).toString("base64url") }),
    });
    expect(wrongSecret.status).toBe(400);
    expect(((await wrongSecret.json()) as { inviteSurvives: boolean }).inviteSurvives).toBe(true);

    expect(
      (
        await fetch(`${base}/devices/enroll`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "[1,2,3]",
        })
      ).status,
    ).toBe(400);

    const oversized = await fetch(`${base}/devices/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: `{"padding":"${"x".repeat(300 * 1024)}"}`,
    });
    expect(oversized.status).toBe(413);

    // the invite survived all of it — the honest chain still lands
    const honestRes = await fetch(`${base}/devices/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(honest),
    });
    expect(honestRes.status).toBe(201);
  });

  it("the kill snapshot comes from the REAL KillSwitch: engage() kills the mint, and burns an attempted spend", async () => {
    const cp = enrolledPlane();
    const base = await start(cp);
    const minted = mintBootstrap(cp);
    if (!minted.ok) throw new Error("mint failed");
    const submission = enrollmentSubmission(phone(), minted.invite, SECRET);

    cp.killSwitch.engage("api", "test kill");
    // nothing MINTS while killed — the refusal comes from the registry's
    // own witness gate, driven by the live switch
    const mintKilled = mintBootstrap(cp, randomBytes(32).toString("base64url"));
    expect(mintKilled.ok).toBe(false);
    if (!mintKilled.ok) expect(mintKilled.error).toMatch(/nothing MINTS while killed/);
    // and a spend attempted under kill BURNS the invite (410, not 400)
    const killedSpend = await fetch(`${base}/devices/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(submission),
    });
    expect(killedSpend.status).toBe(410);
    const killedBody = (await killedSpend.json()) as { error: string; inviteSurvives: boolean };
    expect(killedBody.error).toMatch(/kill switch/);
    expect(killedBody.inviteSurvives).toBe(false);
  });

  it("the second bootstrap mint refuses once a phone is enrolled — the lane self-closed", async () => {
    const cp = enrolledPlane();
    const base = await start(cp);
    const minted = mintBootstrap(cp);
    if (!minted.ok) throw new Error("mint failed");
    await fetch(`${base}/devices/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(enrollmentSubmission(phone(), minted.invite, SECRET)),
    });
    const second = mintBootstrap(cp, randomBytes(32).toString("base64url"));
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.error).toMatch(/EMPTY registry/);
  });

  it("the UNIX SOCKET carries the whole mint round: commitment in, contract out, then the HTTP enroll lands", async () => {
    const cp = enrolledPlane();
    const base = await start(cp);
    const socketPath = join(freshDir(), "bootstrap.sock");
    const socketServer = createBootstrapInviteSocket({
      socketPath,
      mint: cp.bootstrapMintInvite,
    });
    servers.push(socketServer);
    await new Promise((resolve) => socketServer.once("listening", resolve));

    const roundTrip = (line: string): Promise<string> =>
      new Promise((resolve, reject) => {
        const socket = connect(socketPath);
        let buffered = "";
        socket.on("connect", () => socket.write(line));
        socket.on("data", (chunk) => {
          buffered += chunk.toString("utf8");
        });
        socket.on("close", () => resolve(buffered));
        socket.on("error", reject);
      });

    const secret = randomBytes(32).toString("base64url");
    const response = JSON.parse(
      await roundTrip(
        `${JSON.stringify({ tokenHash: commit(secret), ownerId: "owner-adam", deviceName: "Adam's phone" })}\n`,
      ),
    ) as { ok: boolean; invite?: { inviteId: string; challenge: string; assertionChallenge: string; ownerId: string; deviceName: string } };
    expect(response.ok).toBe(true);
    if (!response.ok || response.invite === undefined) return;
    expect(JSON.stringify(response)).not.toContain(secret); // the socket never sees the secret

    const enroll = await fetch(`${base}/devices/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(enrollmentSubmission(phone(), response.invite, secret)),
    });
    expect(enroll.status).toBe(201);

    // hostile lines refuse without crashing the socket
    expect((JSON.parse(await roundTrip("not json\n")) as { ok: boolean }).ok).toBe(false);
    expect((JSON.parse(await roundTrip('"just a string"\n')) as { ok: boolean }).ok).toBe(false);
  });
});
