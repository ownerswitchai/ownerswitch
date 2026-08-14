import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControlPlane, VetoWindow, type ControlPlane } from "@ownerswitchai/control-plane";
import {
  createEscalationService,
  type EscalationEnvConfig,
  type EscalationService,
} from "@ownerswitchai/escalation";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installFakeIndexedDb, resetFakeIndexedDb } from "./idb-fake.js";

/**
 * THE PRODUCTION COMPOSITION, whole: not hand-signed requests but the OWNER
 * RUNTIME's own functions, driven exactly as app.js drives them after an
 * enrollment —
 *   ceremony (enroll-ceremony.mjs, runtime-custodied key)
 *   → adoptEnrolledIdentity (owner-runtime.mjs, fake-IDB persisted)
 *   → fetchDetail / ackBodyForRender / sendSeenAck (signingDeviceId = dev_)
 *   → subscribeAndEnroll against a REAL escalation service that reads the
 *     control plane's standing-file export (the push-rebind lane)
 *   → POST /devices/:dev_/revoke severs BOTH surfaces.
 * Every wire here is a real HTTP socket; the only synthetic parts are the
 * platform authenticator, IndexedDB, and the browser push manager.
 */
const RP_ID = "owner.example";
const ORIGIN = "https://owner.example";

installFakeIndexedDb();

const dirs: string[] = [];
const servers: Server[] = [];
beforeEach(() => {
  resetFakeIndexedDb();
  vi.resetModules();
});
afterEach(() => {
  while (servers.length > 0) servers.pop()?.close();
  while (dirs.length > 0) rmSync(dirs.pop() as string, { recursive: true, force: true });
  delete (globalThis as Record<string, unknown>).OWNERSWITCH_CONFIG;
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

const listen = (handler: (req: never, res: never) => void): Promise<string> => {
  const server = createServer(handler as Parameters<typeof createServer>[1]);
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") throw new Error("no address");
      resolve(`http://127.0.0.1:${addr.port}`);
    });
  });
};

/** a browser-shaped ServiceWorkerRegistration with a push manager */
const fakeRegistration = () => {
  const sub = {
    endpoint: "https://push.example/send/runtime",
    keys: { p256dh: "BPub", auth: "QXV0aA" },
  };
  return {
    registration: {
      pushManager: {
        getSubscription: async () => null,
        subscribe: async () => ({ toJSON: () => sub }),
      },
    },
    sub,
  };
};

describe("E2E: the runtime's OWN composition — enroll, adopt, ack, push-rebind, revoke", () => {
  it("after adoptEnrolledIdentity every runtime surface speaks as dev_, including push enrollment; one revoke severs it all", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-runtime-e2e-"));
    dirs.push(dir);
    const standingFile = join(dir, "standing.json");

    // 1. a real control plane WITH the standing export wired
    const cp: ControlPlane = quiet(() =>
      createControlPlane({
        dev: true,
        killStateFile: null,
        acceptSessionOnlyApprovalRisk: true,
        ownerDeviceStandingFile: standingFile,
        enrollment: {
          devicesFile: join(dir, "devices.json"),
          rpId: RP_ID,
          rpName: "OwnerSwitch",
          origin: ORIGIN,
        },
      }),
    );
    const cpUrl = await listen(cp.handler as never);

    // 2. a real escalation service whose ONLY owner-device credential source
    //    is the control plane's standing-file export (no keys file at all)
    const escConfig = {
      controlPlaneUrl: cpUrl,
      device: { id: "escalation", secret: "esc-secret" },
      ownerDeviceKeys: {},
      ownerDeviceStandingFile: standingFile,
      unsafeAllowUntrustedStandingPathForTests: true,
      listenHost: "127.0.0.1",
      listenPort: 0,
      webhookBaseUrl: "https://esc.example",
      stateFile: join(dir, "esc-state.json"),
      twilio: undefined,
      vapid: undefined,
      rungs: [],
      limits: { maxVoiceCallsPer10Min: 2, maxSmsPerHour: 6, maxDailySpendUsd: 5 },
      pollMs: 5_000,
    } as unknown as EscalationEnvConfig;
    const esc: EscalationService = createEscalationService({
      config: escConfig,
      channels: {},
      log: () => {},
    });
    const escUrl = await listen(esc.webhookHandler as never);

    // 3. the page config the runtime reads — the RETIRED config name on
    //    purpose: after adoption it must NOT be what signs
    (globalThis as Record<string, unknown>).self = globalThis;
    (globalThis as Record<string, unknown>).OWNERSWITCH_CONFIG = {
      deviceId: "config-name",
      controlPlaneUrl: cpUrl,
      escalationUrl: escUrl,
      vapidPublicKey: "QQ",
    };

    // 4. ceremony with the RUNTIME-custodied key, then adoption — app.js's path
    const rt = await import("../public/owner-runtime.mjs");
    const pair = await rt.ensureDeviceKey();
    const token = randomBytes(32).toString("base64url");
    const minted = cp.bootstrapMintInvite({
      tokenHash: createHash("sha256").update(token, "utf8").digest("base64url"),
      ownerId: "owner-adam",
      deviceName: "Adam's phone",
    });
    if (!minted.ok) throw new Error(minted.error);
    const { completeEnrollmentCeremony } = await import("../public/enroll-ceremony.mjs");
    const { syntheticAuthenticator } = await import("./webauthn-fake.js");
    const outcome = await completeEnrollmentCeremony(
      { ...minted.invite, token },
      {
        credentials: syntheticAuthenticator(RP_ID, ORIGIN).container,
        cheapLane: pair,
        fetchImpl: fetch,
        baseUrl: cpUrl,
      },
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const deviceId = outcome.deviceId;
    await rt.adoptEnrolledIdentity(deviceId);

    // 5. a live window; the runtime's fetchDetail + ackBodyForRender +
    //    sendSeenAck — the EXACT production functions — flip delivered as dev_
    const window = new VetoWindow(
      { agentId: "agent-1", tool: "stripe.payout", args: { amount: 5000, to: "acct_x" } },
      cp.killSwitch.epoch,
    );
    cp.vetoWindows.set("v-rt", window);
    const detail = (await rt.fetchDetail("v-rt")) as {
      renderable: { agentId: string; tool: string; summary: string };
      deliveryId: string;
    };
    expect(detail.deliveryId).toMatch(/^del_/);
    const ackBody = await rt.ackBodyForRender(detail, {
      agentId: detail.renderable.agentId,
      tool: detail.renderable.tool,
      summary: detail.renderable.summary,
    });
    expect(ackBody).not.toBeNull();
    const ack = await rt.sendSeenAck("v-rt", ackBody);
    expect(ack.ok).toBe(true);
    expect(window.isDelivered).toBe(true);
    expect(window.deliveredBy).toBe(deviceId); // the REGISTRY name, not "config-name"

    // 6. THE PUSH REBIND (app.js's post-adoption re-enrollment): the runtime's
    //    subscribeAndEnroll lands on the real escalation service, which
    //    authenticated the dev_ signature from the CP's standing export
    const { registration, sub } = fakeRegistration();
    await rt.subscribeAndEnroll(registration as never);
    expect(esc.subscription()).toEqual(sub);

    // 7. ONE revoke severs BOTH surfaces
    const revoke = await fetch(`${cpUrl}/devices/${deviceId}/revoke`, { method: "POST" });
    expect(revoke.status).toBe(200);
    // control plane: the runtime's signed read is refused
    await expect(rt.fetchDetail("v-rt")).rejects.toThrow(/401/);
    // escalation: the enrolled subscription went inactive on the next read,
    // and a re-enrollment attempt is refused outright
    expect(esc.subscription()).toBeNull();
    await expect(rt.subscribeAndEnroll(registration as never)).rejects.toThrow(/401/);
  });
});
