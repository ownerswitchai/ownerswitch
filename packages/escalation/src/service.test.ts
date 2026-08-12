import { createHmac } from "node:crypto";
import { readFileSync, mkdtempSync, statSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createControlPlane,
  signDeviceRequest,
  VetoWindow,
  type ControlPlane,
} from "@ownerswitchai/control-plane";
import { afterEach, describe, expect, it } from "vitest";
import { createEscalationService, type EscalationService } from "./service.js";
import type { EscalationEnvConfig } from "./config.js";
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

const baseConfig = (cpUrl: string, stateFile: string): EscalationEnvConfig => ({
  controlPlaneUrl: cpUrl,
  device: { id: "escalation", secret: DEVICE_SECRET },
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

  it("push subscription enrollment is device-signed and persisted 0600; bad signatures get 401", async () => {
    const { c, service, stateFile } = await setup();
    const url = await listen(service.webhookHandler, servers);
    const subscription = {
      endpoint: "https://push.example/send/abc",
      keys: { p256dh: "BPub", auth: "QXV0aA" },
    };
    const body = JSON.stringify({ subscription });

    const unsigned = await fetch(`${url}/push/subscription`, { method: "POST", body });
    expect(unsigned.status).toBe(401);
    expect(service.subscription()).toBeNull();

    const timestamp = c.now();
    const signed = await fetch(`${url}/push/subscription`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-device-id": "owner-app",
        "x-device-timestamp": String(timestamp),
        "x-device-nonce": "n-1",
        "x-device-signature": signDeviceRequest(
          { deviceId: "owner-app", timestamp, nonce: "n-1" },
          body,
          DEVICE_SECRET,
        ),
      },
      body,
    });
    expect(signed.status).toBe(200);
    expect(service.subscription()).toEqual(subscription);
    expect(JSON.parse(readFileSync(stateFile, "utf8"))).toEqual({ subscription });
    expect(statSync(stateFile).mode & 0o777).toBe(0o600);

    // a replayed enrollment (same nonce) is refused
    const replay = await fetch(`${url}/push/subscription`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-device-id": "owner-app",
        "x-device-timestamp": String(timestamp),
        "x-device-nonce": "n-1",
        "x-device-signature": signDeviceRequest(
          { deviceId: "owner-app", timestamp, nonce: "n-1" },
          body,
          DEVICE_SECRET,
        ),
      },
      body,
    });
    expect(replay.status).toBe(401);
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
