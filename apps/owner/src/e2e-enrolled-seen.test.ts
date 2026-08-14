import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControlPlane, VetoWindow, type ControlPlane } from "@ownerswitchai/control-plane";
import { afterEach, describe, expect, it } from "vitest";
import { completeEnrollmentCeremony } from "../public/enroll-ceremony.mjs";
// The DEPLOYED browser modules, end to end: the same code the phone runs.
import { generateOwnerDeviceKey, nonce, signRequestHeaders } from "../public/owner-crypto.mjs";
import { ackBodyForRender, type RenderedDomTexts } from "../public/owner-runtime.mjs";
import { renderContentHash, validateRenderableAlert } from "../public/renderable-alert.mjs";
import { syntheticAuthenticator } from "./webauthn-fake.js";

/**
 * The e2e-seen arc, but the phone's identity is the CEREMONY's: the device
 * enrolls through public/enroll-ceremony.mjs (registry-assigned dev_ id, key
 * admitted through the invite spend), then reads the detail and flips
 * delivered with THAT identity — no ownerDeviceKeys file anywhere. This is
 * the production path an enrolled phone actually walks: enroll once, then
 * every signed request authenticates against the durable registry.
 */
const RP_ID = "owner.example";
const ORIGIN = "https://owner.example";

const dirs: string[] = [];
const servers: Server[] = [];
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

async function liveServer(): Promise<{ cp: ControlPlane; base: string }> {
  const dir = mkdtempSync(join(tmpdir(), "ownerswitch-enrolled-seen-"));
  dirs.push(dir);
  const cp = quiet(() =>
    createControlPlane({
      dev: true,
      killStateFile: null,
      acceptSessionOnlyApprovalRisk: true,
      enrollment: {
        devicesFile: join(dir, "devices.json"),
        rpId: RP_ID,
        rpName: "OwnerSwitch",
        origin: ORIGIN,
      },
    }),
  );
  const server = createServer(cp.handler);
  servers.push(server);
  const base = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") throw new Error("no address");
      resolve(`http://127.0.0.1:${addr.port}`);
    });
  });
  return { cp, base };
}

describe("E2E: ceremony-enrolled device -> detail -> /veto/:id/seen", () => {
  it("the enrolled dev_ identity, born in the ceremony, confirms a merge window against the live registry", async () => {
    const { cp, base } = await liveServer();

    // 1. ENROLL: the same WebCrypto pair ensureDeviceKey() would persist runs
    //    the whole production ceremony against the live server
    const pair = await generateOwnerDeviceKey();
    const token = randomBytes(32).toString("base64url");
    const minted = cp.bootstrapMintInvite({
      tokenHash: createHash("sha256").update(token, "utf8").digest("base64url"),
      ownerId: "owner-adam",
      deviceName: "Adam's phone",
    });
    if (!minted.ok) throw new Error(`mint failed: ${minted.error}`);
    const outcome = await completeEnrollmentCeremony(
      { ...minted.invite, token },
      {
        credentials: syntheticAuthenticator(RP_ID, ORIGIN).container,
        cheapLane: pair,
        fetchImpl: fetch,
        baseUrl: base,
      },
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const deviceId = outcome.deviceId;
    expect(deviceId).toMatch(/^dev_/);

    // 2. a grant-eligible merge window, as the gateway would register it
    const window = new VetoWindow(
      {
        agentId: "deploy-bot",
        tool: "github.merge_pr",
        args: {
          owner: "ownerswitchai",
          repo: "ownerswitch",
          pullNumber: 43,
          expectedHeadSha: "b".repeat(40),
          expectedBaseRef: "main",
          mergeMethod: "squash",
        },
      },
      cp.killSwitch.epoch,
      { purpose: { connector: "github", operation: "merge_pull_request", policyVersion: "" } },
    );
    cp.vetoWindows.set("v-enrolled", window);

    // 3. every signed request now carries the REGISTRY's name for this key —
    //    exactly what signedFetch does after adoptEnrolledIdentity
    const signedFetch = async (method: string, path: string, body: string) => {
      const headers = await signRequestHeaders(pair.privateKey, {
        deviceId,
        method,
        pathAndQuery: path,
        body,
        timestamp: Date.now(),
        nonce: nonce(),
      });
      return fetch(`${base}${path}`, {
        method,
        headers: { "content-type": "application/json", ...headers },
        ...(method === "POST" ? { body } : {}),
      });
    };

    const detailRes = await signedFetch("GET", "/veto/v-enrolled/detail", "");
    expect(detailRes.status).toBe(200);
    const detail = (await detailRes.json()) as Record<string, unknown> & {
      renderable: { v: number; agentId: string; tool: string; summary: string };
      renderContentHash: string;
      deliveryId: string;
    };
    expect(validateRenderableAlert(detail.renderable)).toBeNull();
    expect(detail.renderable.summary).toBe(
      "Merge ownerswitchai/ownerswitch#43 into main — squash, head bbbbbbbbbbbb",
    );
    expect(await renderContentHash(detail.renderable)).toBe(detail.renderContentHash);

    // 4. render, echo, ack — the delivered bit flips under the dev_ identity
    const domTexts: RenderedDomTexts = {
      agentId: detail.renderable.agentId,
      tool: detail.renderable.tool,
      summary: detail.renderable.summary,
    };
    const ackBody = await ackBodyForRender(detail, domTexts);
    expect(ackBody).not.toBeNull();
    const seenRes = await signedFetch("POST", "/veto/v-enrolled/seen", JSON.stringify(ackBody));
    expect(seenRes.status).toBe(200);
    expect(((await seenRes.json()) as { delivered: boolean }).delivered).toBe(true);
    expect(window.isDelivered).toBe(true);
    expect(window.deliveredBy).toBe(deviceId);

    // 5. the pre-enrollment deployment-config name never worked and still
    //    does not: the registry is the only source of this device's standing
    const configNamed = await (async () => {
      const headers = await signRequestHeaders(pair.privateKey, {
        deviceId: "owner-phone",
        method: "GET",
        pathAndQuery: "/veto/v-enrolled/detail",
        body: "",
        timestamp: Date.now(),
        nonce: nonce(),
      });
      return fetch(`${base}/veto/v-enrolled/detail`, { headers: { ...headers } });
    })();
    expect(configNamed.status).toBe(401);
  });
});
