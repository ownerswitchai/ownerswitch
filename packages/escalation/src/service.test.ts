import { createHash, createHmac, generateKeyPairSync, sign as ecSign } from "node:crypto";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ownerDeviceSigPreimage } from "@ownerswitchai/shared";
import {
  createControlPlane,
  DeviceStandingFileStore,
  signDeviceRequest,
  VetoWindow,
  type ControlPlane,
} from "@ownerswitchai/control-plane";
import { afterEach, describe, expect, it } from "vitest";
import { createEscalationService, type EscalationService } from "./service.js";
import { escalationConfigFromEnv, type EscalationEnvConfig } from "./config.js";
import type { Channel, EscalationAlert } from "./types.js";

const DEVICE_SECRET = "escalation-shared-secret";

const clock = (start = 1_000_000) => {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
};

/** dev control plane, warning silenced, ephemeral kill state */
const controlPlane = (now: () => number): ControlPlane => {
  const original = console.error;
  console.error = () => {};
  try {
    return createControlPlane({
      now,
      dev: true,
      killStateFile: null,
      deviceSecret: DEVICE_SECRET,
      acceptSessionOnlyApprovalRisk: true,
    });
  } finally {
    console.error = original;
  }
};

const listen = (handler: (req: any, res: any) => void, servers: Server[]): Promise<string> => {
  const server = createServer(handler);
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") throw new Error("no address");
      resolve(`http://127.0.0.1:${addr.port}`);
    });
  });
};

const fakePush = () => {
  const sent: EscalationAlert[] = [];
  const channel: Channel = {
    kind: "push",
    verbs: { stop: true, confirmSeen: true, approve: false },
    async send(alert) {
      sent.push(alert);
      return { channel: "push", windowIds: alert.windowIds, at: 0, estimatedCostUsd: 0 };
    },
    handleCallback: () => [],
  };
  return { sent, channel };
};

const TWILIO = {
  accountSid: "ACxx",
  authToken: "twilio-token",
  from: "+15550001111",
  to: "+36301234567",
};

// The owner app's asymmetric device key (non-extractable P-256 in production).
const ownerKeypair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const OWNER_DEVICE_SPKI = ownerKeypair.publicKey.export({ format: "pem", type: "spki" }).toString();
const OWNER_DEVICE_KEYS: Record<string, string> = { "owner-app": OWNER_DEVICE_SPKI };

const baseConfig = (cpUrl: string, stateFile: string): EscalationEnvConfig => ({
  controlPlaneUrl: cpUrl,
  device: { id: "escalation", secret: DEVICE_SECRET },
  ownerDeviceKeys: OWNER_DEVICE_KEYS,
  listenHost: "127.0.0.1",
  listenPort: 0,
  webhookBaseUrl: "https://esc.example",
  stateFile,
  twilio: TWILIO,
  vapid: undefined as never, // channels injected in tests
  rungs: [{ afterMs: 0, channel: "push" }],
  limits: { maxVoiceCallsPer10Min: 2, maxSmsPerHour: 6, maxDailySpendUsd: 5 },
  pollMs: 5_000,
});

/** Twilio-style signed callback body+headers for the advertised URL. */
const twilioSigned = (url: string, form: Record<string, string>) => {
  const params = new URLSearchParams(form);
  let payload = url;
  for (const key of [...params.keys()].sort()) payload += key + (params.get(key) ?? "");
  return {
    body: params.toString(),
    signature: createHmac("sha1", TWILIO.authToken).update(payload).digest("base64"),
  };
};

describe("escalation service against a live control plane", () => {
  const servers: Server[] = [];
  afterEach(() => {
    for (const s of servers.splice(0)) s.close();
  });

  const setup = async (c = clock()) => {
    const cp = controlPlane(c.now);
    const cpUrl = await listen(cp.handler, servers);
    const stateFile = join(mkdtempSync(join(tmpdir(), "ownerswitch-esc-")), "state.json");
    const push = fakePush();
    const config = baseConfig(cpUrl, stateFile);
    const service = createEscalationService({
      config,
      channels: { push: push.channel },
      now: c.now,
      log: () => {},
    });
    return { c, cp, cpUrl, stateFile, push, service, config };
  };

  const openWindow = (cp: ControlPlane, c: { now: () => number }, id = "v-1") => {
    const window = new VetoWindow({ agentId: "agent-1", tool: "write_file" }, cp.killSwitch.epoch, {
      now: c.now,
    });
    cp.vetoWindows.set(id, window);
    return window;
  };

  it("discovers a pending window via GET /veto/pending and fires the push rung once", async () => {
    const { c, cp, push, service } = await setup();
    openWindow(cp, c);

    await service.tickOnce();
    expect(push.sent).toHaveLength(1);
    expect(push.sent[0]).toEqual({
      windowIds: ["v-1"],
      headline: 'OwnerSwitch: "write_file" held for your review',
      deadlineMs: 1_000_000 + 4 * 60_000,
    });

    await service.tickOnce();
    expect(push.sent).toHaveLength(1); // no re-fire
  });

  it("a delivered window stands the ladder down; a closed one ends the run", async () => {
    const { c, cp, push, service } = await setup();
    const window = openWindow(cp, c);
    await service.tickOnce();
    expect(push.sent).toHaveLength(1);

    window.markDelivered("app-1");
    await service.tickOnce(); // sees delivered=true from the listing

    window.veto("adam");
    await service.tickOnce(); // window left pending — closed and forgotten
    c.advance(60_000);
    await service.tickOnce();
    expect(push.sent).toHaveLength(1);
  });

  it("a signed Twilio reply-1 callback relays a veto the control plane records with channel attribution", async () => {
    const { c, cp, service } = await setup();
    const window = openWindow(cp, c);
    await service.tickOnce(); // service must know the window before the reply

    const url = await listen(service.webhookHandler, servers);
    const { body, signature } = twilioSigned("https://esc.example/twilio/sms", {
      From: TWILIO.to,
      Body: "1",
    });
    const res = await fetch(`${url}/twilio/sms`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "x-twilio-signature": signature,
      },
      body,
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("<Response/>");
    expect(window.state).toBe("vetoed");
    expect(window.vetoedBy).toBe("channel:sms-reply");
  });

  it("a press-1 DTMF callback answers stopping TwiML and vetoes; other digits stop nothing", async () => {
    const { c, cp, service } = await setup();
    const window = openWindow(cp, c);
    await service.tickOnce();
    const url = await listen(service.webhookHandler, servers);

    const wrong = twilioSigned("https://esc.example/twilio/voice-key", { Digits: "9", CallSid: "CA1" });
    const wrongRes = await fetch(`${url}/twilio/voice-key`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "x-twilio-signature": wrong.signature,
      },
      body: wrong.body,
    });
    expect(await wrongRes.text()).toContain("Nothing stopped");
    expect(window.state).toBe("pending");

    const press1 = twilioSigned("https://esc.example/twilio/voice-key", { Digits: "1", CallSid: "CA1" });
    const res = await fetch(`${url}/twilio/voice-key`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "x-twilio-signature": press1.signature,
      },
      body: press1.body,
    });
    expect(await res.text()).toContain("Stopped");
    expect(window.state).toBe("vetoed");
    expect(window.vetoedBy).toBe("channel:voice-dtmf");
  });

  it("an unsigned or mis-signed Twilio callback is a no-op", async () => {
    const { c, cp, service } = await setup();
    const window = openWindow(cp, c);
    await service.tickOnce();
    const url = await listen(service.webhookHandler, servers);

    const res = await fetch(`${url}/twilio/sms`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ From: TWILIO.to, Body: "1" }).toString(),
    });
    expect(res.status).toBe(200); // an attacker learns nothing from the response
    expect(window.state).toBe("pending");
  });

  it("push enrollment requires the OWNER-APP device signature (not the fleet secret), persists 0600, refuses replays", async () => {
    const { c, service, stateFile } = await setup();
    const url = await listen(service.webhookHandler, servers);
    const subscription = {
      endpoint: "https://push.example/send/abc",
      keys: { p256dh: "BPub", auth: "QXV0aA" },
    };
    const body = JSON.stringify({ subscription });
    const pathAndQuery = "/push/subscription";

    // owner-app asymmetric signature over the exact request
    const ownerSig = (nonce: string, at: number) => {
      const preimage = ownerDeviceSigPreimage({
        deviceId: "owner-app",
        method: "POST",
        pathAndQuery,
        bodyHash: new Uint8Array(createHash("sha256").update(body).digest()),
        timestamp: at,
        nonce,
      });
      return ecSign("sha256", preimage, { key: ownerKeypair.privateKey, dsaEncoding: "ieee-p1363" }).toString(
        "base64url",
      );
    };
    const enrollOwner = (nonce: string, at = c.now()) =>
      fetch(`${url}${pathAndQuery}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-device-id": "owner-app",
          "x-device-timestamp": String(at),
          "x-device-nonce": nonce,
          "x-device-signature": ownerSig(nonce, at),
        },
        body,
      });

    const unsigned = await fetch(`${url}${pathAndQuery}`, { method: "POST", body });
    expect(unsigned.status).toBe(401);
    expect(service.subscription()).toBeNull();

    // the FLEET device secret (an HMAC the escalation service itself holds)
    // must NOT be able to redirect the owner's push channel
    const at = c.now();
    const viaFleet = await fetch(`${url}${pathAndQuery}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-device-id": "owner-app",
        "x-device-timestamp": String(at),
        "x-device-nonce": "fleet-1",
        "x-device-signature": signDeviceRequest(
          { deviceId: "owner-app", timestamp: at, nonce: "fleet-1" },
          body,
          DEVICE_SECRET,
          { method: "POST", pathAndQuery },
        ),
      },
      body,
    });
    expect(viaFleet.status).toBe(401);
    expect(service.subscription()).toBeNull();

    // the owner's device signature enrolls
    const signed = await enrollOwner("n-1");
    expect(signed.status).toBe(200);
    expect(service.subscription()).toEqual(subscription);
    expect(JSON.parse(readFileSync(stateFile, "utf8"))).toEqual({ subscription, enrolledBy: "owner-app" });
    expect(statSync(stateFile).mode & 0o777).toBe(0o600);

    // a replayed enrollment (same nonce) is refused
    const replay = await enrollOwner("n-1");
    expect(replay.status).toBe(401);
  });

  it("REVOCATION standing (shared registry): a revoked device cannot enroll, and its subscription goes inactive", async () => {
    const c = clock();
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-esc-"));
    const stateFile = join(dir, "state.json");
    const standingFile = join(dir, "standing.json");
    const push = fakePush();
    const service = createEscalationService({
      config: {
        ...baseConfig("http://127.0.0.1:1", stateFile),
        ownerDeviceStandingFile: standingFile,
        unsafeAllowUntrustedStandingPathForTests: true,
      },
      channels: { push: push.channel },
      now: c.now,
      log: () => {},
    });
    const url = await listen(service.webhookHandler, servers);

    const subscription = {
      endpoint: "https://push.example/send/abc",
      keys: { p256dh: "BPub", auth: "QXV0aA" },
    };
    const body = JSON.stringify({ subscription });
    const pathAndQuery = "/push/subscription";
    const enroll = (nonce: string) => {
      const at = c.now();
      const preimage = ownerDeviceSigPreimage({
        deviceId: "owner-app",
        method: "POST",
        pathAndQuery,
        bodyHash: new Uint8Array(createHash("sha256").update(body).digest()),
        timestamp: at,
        nonce,
      });
      return fetch(`${url}${pathAndQuery}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-device-id": "owner-app",
          "x-device-timestamp": String(at),
          "x-device-nonce": nonce,
          "x-device-signature": ecSign("sha256", preimage, {
            key: ownerKeypair.privateKey,
            dsaEncoding: "ieee-p1363",
          }).toString("base64url"),
        },
        body,
      });
    };

    // an ABSENT registry is NOT trust: the control plane has never
    // initialized it, so nothing here may treat the device as active
    expect((await enroll("s-0")).status).toBe(403);

    // the CONTROL PLANE initializes the registry at its boot (active snapshot)
    const registry = new DeviceStandingFileStore(standingFile);
    registry.save({ version: 1, devices: { "owner-app": { generation: 1, revokedAt: null } } });

    // explicit active record — enrollment lands
    expect((await enroll("s-1")).status).toBe(200);
    expect(service.subscription()).toEqual(subscription);

    // a device with NO record in a loaded registry is untrusted too
    registry.save({ version: 1, devices: { "some-other": { generation: 1, revokedAt: null } } });
    expect(service.subscription()).toBeNull();
    expect((await enroll("s-1b")).status).toBe(403);

    // the CONTROL PLANE (another process) revokes the phone by writing the
    // SHARED standing registry; this service saw no event at all
    registry.save({
      version: 1,
      devices: { "owner-app": { generation: 2, revokedAt: c.now() } },
    });

    // the subscription the revoked phone enrolled is now INACTIVE — the lost
    // phone stops receiving decision-critical alerts...
    expect(service.subscription()).toBeNull();
    // ...and the revoked key cannot re-point the alert channel either
    expect((await enroll("s-2")).status).toBe(403);
  });

  it("UPGRADE: a legacy subscription (no enrolledBy) is INACTIVE under a standing regime until re-enrolled", async () => {
    const c = clock();
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-esc-"));
    const stateFile = join(dir, "state.json");
    const standingFile = join(dir, "standing.json");
    const subscription = {
      endpoint: "https://push.example/send/legacy",
      keys: { p256dh: "BPub", auth: "QXV0aA" },
    };
    // the pre-standing on-disk format: no enrolledBy at all
    writeFileSync(stateFile, JSON.stringify({ subscription }), { mode: 0o600 });
    // the device is even ACTIVE in the registry — but the legacy record names
    // no device, so no revocation could ever sever it; it must not be trusted
    new DeviceStandingFileStore(standingFile).save({
      version: 1,
      devices: { "owner-app": { generation: 1, revokedAt: null } },
    });
    const push = fakePush();
    const service = createEscalationService({
      config: {
        ...baseConfig("http://127.0.0.1:1", stateFile),
        ownerDeviceStandingFile: standingFile,
        unsafeAllowUntrustedStandingPathForTests: true,
      },
      channels: { push: push.channel },
      now: c.now,
      log: () => {},
    });
    expect(service.subscription()).toBeNull(); // fail closed: re-enrollment stamps it
  });

  it("PATH BOUNDARY: the reader refuses a standing path whose real ancestry is untrusted", () => {
    const c = clock();
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-esc-"));
    const push = fakePush();
    // no unsafe test flag: the canonical walk runs and /tmp (1777) refuses
    expect(() =>
      createEscalationService({
        config: {
          ...baseConfig("http://127.0.0.1:1", join(dir, "state.json")),
          ownerDeviceStandingFile: join(dir, "standing.json"),
        },
        channels: { push: push.channel },
        now: c.now,
        log: () => {},
      }),
    ).toThrow(/world-writable|group- or world-writable/);
  });

  it("PRODUCTION GUARD: owner device keys without the standing registry refuse to start", () => {
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-esc-"));
    const env = {
      OWNERSWITCH_DEVICE_SECRET: "s".repeat(64),
      OWNERSWITCH_OWNER_DEVICE_KEYS_FILE: join(dir, "keys.json"),
      // OWNERSWITCH_OWNER_DEVICE_STANDING_FILE deliberately unset
    };
    // the guard fires BEFORE the keys file is even opened
    expect(() => escalationConfigFromEnv(env)).toThrow(/STANDING_FILE/);
    // with the registry named, the config proceeds PAST the standing guard —
    // the next failure (if any) is about the keys file itself, never standing
    try {
      escalationConfigFromEnv({ ...env, OWNERSWITCH_OWNER_DEVICE_STANDING_FILE: join(dir, "standing.json") });
    } catch (err) {
      expect(String(err)).not.toMatch(/STANDING_FILE/);
    }
  });

  it("with no owner device enrolled, push enrollment is 501", async () => {
    const c = clock();
    const push = fakePush();
    const stateFile = join(mkdtempSync(join(tmpdir(), "ownerswitch-esc-")), "state.json");
    const { ownerDeviceKeys: _drop, ...noOwnerApp } = baseConfig("http://127.0.0.1:1", stateFile);
    const service = createEscalationService({
      config: noOwnerApp,
      channels: { push: push.channel },
      now: c.now,
      log: () => {},
    });
    const url = await listen(service.webhookHandler, servers);
    const res = await fetch(`${url}/push/subscription`, {
      method: "POST",
      body: JSON.stringify({ subscription: {} }),
    });
    expect(res.status).toBe(501);
  });

  it("an unreachable control plane pauses the ladder instead of crashing it", async () => {
    const c = clock();
    const push = fakePush();
    const stateFile = join(mkdtempSync(join(tmpdir(), "ownerswitch-esc-")), "state.json");
    const service = createEscalationService({
      config: baseConfig("http://127.0.0.1:1", stateFile),
      channels: { push: push.channel },
      now: c.now,
      log: () => {},
    });
    await service.tickOnce(); // no throw
    expect(push.sent).toHaveLength(0);
  });
});

describe("ceremony-enrolled (dev_) devices on the push-enrollment surface", () => {
  const servers: Server[] = [];
  afterEach(() => {
    for (const s of servers.splice(0)) s.close();
  });

  it("a dev_ device authenticates from the standing file's exported SPKI — and its revocation severs it here without any notification", async () => {
    const c = clock();
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-esc-dev-"));
    const stateFile = join(dir, "state.json");
    const standingFile = join(dir, "standing.json");
    // what the CONTROL PLANE exports at enrollment: the dev_ entry with the
    // cheap-lane public key (standing schema v2, written by the same store
    // class both processes share)
    const key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const spki = (key.publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64url");
    const store = new DeviceStandingFileStore(standingFile);
    expect(store.save({ version: 2, devices: { dev_abc: { generation: 1, revokedAt: null, spki } } }).durable).toBe(true);

    const service = createEscalationService({
      config: {
        ...baseConfig("http://127.0.0.1:1", stateFile),
        ownerDeviceKeys: {}, // NO keys file — the standing export is the ONLY credential source
        ownerDeviceStandingFile: standingFile,
        unsafeAllowUntrustedStandingPathForTests: true,
      },
      channels: { push: fakePush().channel },
      now: c.now,
      log: () => {},
    });
    const url = await listen(service.webhookHandler, servers);
    const subscription = {
      endpoint: "https://push.example/send/dev",
      keys: { p256dh: "BPub", auth: "QXV0aA" },
    };
    const body = JSON.stringify({ subscription });
    const enroll = (deviceId: string, nonce: string) => {
      const at = c.now();
      const preimage = ownerDeviceSigPreimage({
        deviceId,
        method: "POST",
        pathAndQuery: "/push/subscription",
        bodyHash: new Uint8Array(createHash("sha256").update(body).digest()),
        timestamp: at,
        nonce,
      });
      return fetch(`${url}/push/subscription`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-device-id": deviceId,
          "x-device-timestamp": String(at),
          "x-device-nonce": nonce,
          "x-device-signature": ecSign("sha256", preimage, { key: key.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url"),
        },
        body,
      });
    };

    // the dev_ identity enrolls — no OWNERSWITCH_OWNER_DEVICE_KEYS_FILE anywhere
    expect((await enroll("dev_abc", "n-dev-1")).status).toBe(200);
    expect(service.subscription()).toEqual(subscription);
    // an id the standing file does not carry resolves nothing
    expect((await enroll("dev_other", "n-dev-x")).status).toBe(401);

    // the control plane revokes and re-exports; THIS process reads the flip
    // at its very next decision — subscription inactive, re-enrollment refused
    expect(store.save({ version: 2, devices: { dev_abc: { generation: 2, revokedAt: c.now(), spki } } }).durable).toBe(true);
    expect(service.subscription()).toBeNull();
    expect((await enroll("dev_abc", "n-dev-2")).status).toBe(401);
  });

  it("no keys file and no SPKI-carrying standing entries → push enrollment is honestly 501", async () => {
    const c = clock();
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-esc-501-"));
    const standingFile = join(dir, "standing.json");
    // a standing file with only STATIC entries (no exported keys) wires nothing here
    new DeviceStandingFileStore(standingFile).save({
      version: 2,
      devices: { "owner-phone": { generation: 1, revokedAt: null } },
    });
    const service = createEscalationService({
      config: {
        ...baseConfig("http://127.0.0.1:1", join(dir, "state.json")),
        ownerDeviceKeys: {},
        ownerDeviceStandingFile: standingFile,
        unsafeAllowUntrustedStandingPathForTests: true,
      },
      channels: { push: fakePush().channel },
      now: c.now,
      log: () => {},
    });
    const url = await listen(service.webhookHandler, servers);
    const res = await fetch(`${url}/push/subscription`, { method: "POST", body: "{}" });
    expect(res.status).toBe(501);
  });

  it("a static key squatting on the dev_ namespace refuses the boot", () => {
    const key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const pem = key.publicKey.export({ format: "pem", type: "spki" }).toString();
    expect(() =>
      createEscalationService({
        config: {
          ...baseConfig("http://127.0.0.1:1", join(mkdtempSync(join(tmpdir(), "ownerswitch-esc-ns-")), "state.json")),
          ownerDeviceKeys: { dev_squatter: pem },
        },
        channels: {},
        log: () => {},
      }),
    ).toThrow(/reserved for/);
  });
});
