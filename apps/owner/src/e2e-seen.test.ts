import { createServer, type Server } from "node:http";
import { createControlPlane, VetoWindow } from "@ownerswitchai/control-plane";
import { afterEach, describe, expect, it } from "vitest";
// The DEPLOYED browser modules, end to end: the same code the phone runs.
import { exportPublicKeySpki, generateOwnerDeviceKey, nonce, signRequestHeaders } from "../public/owner-crypto.mjs";
import { ackBodyForRender, type RenderedDomTexts } from "../public/owner-runtime.mjs";
import { renderContentHash, validateRenderableAlert } from "../public/renderable-alert.mjs";

/**
 * THE cross-contract test the unit suites cannot give: a REAL control plane
 * mints the detail, and the REAL browser modules (WebCrypto key, signer,
 * validator, hash) verify and ack it over HTTP. If the two sides ever disagree
 * — hash alphabet (hex vs base64url), envelope shape (flat vs nested, extra
 * fields), canonicalization — this test fails immediately, instead of every
 * production ack silently refusing.
 */
describe("E2E: control-plane detail -> browser recompute -> /veto/:id/seen", () => {
  let server: Server | undefined;

  afterEach(() => {
    server?.close();
    server = undefined;
  });

  const start = (cp: { handler: Parameters<typeof createServer>[1] }) =>
    new Promise<string>((resolve) => {
      server = createServer(cp.handler);
      server.listen(0, "127.0.0.1", () => {
        const addr = server?.address();
        if (addr === null || addr === undefined || typeof addr === "string") throw new Error("no address");
        resolve(`http://127.0.0.1:${addr.port}`);
      });
    });

  it("the phone's own key, signer, validator, and hash confirm a merge window against a live server", async () => {
    // 1. the device key is born in WebCrypto, exactly as on the phone,
    //    and enrolled by its base64url SPKI export (the browser export form)
    const { publicKey, privateKey } = await generateOwnerDeviceKey();
    const spki = await exportPublicKeySpki(publicKey);

    const silenced = console.error;
    console.error = () => {};
    let cp;
    try {
      cp = createControlPlane({
        dev: true,
        killStateFile: null,
        acceptSessionOnlyApprovalRisk: true,
        ownerDeviceKeys: { "owner-phone": spki },
      });
    } finally {
      console.error = silenced;
    }
    const url = await start(cp);

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
    cp.vetoWindows.set("v-e2e", window);

    const signedFetch = async (method: string, path: string, body: string) => {
      const headers = await signRequestHeaders(privateKey, {
        deviceId: "owner-phone",
        method,
        pathAndQuery: path,
        body,
        timestamp: Date.now(),
        nonce: nonce(),
      });
      return fetch(`${url}${path}`, {
        method,
        headers: { "content-type": "application/json", ...headers },
        ...(method === "POST" ? { body } : {}),
      });
    };

    // 3. the device-signed detail read
    const detailRes = await signedFetch("GET", "/veto/v-e2e/detail", "");
    expect(detailRes.status).toBe(200);
    const detail = (await detailRes.json()) as Record<string, unknown> & {
      renderable: { v: number; agentId: string; tool: string; summary: string };
      renderContentHash: string;
      deliveryId: string;
    };

    // the nested wire envelope validates as V1 and names the CONCRETE merge
    expect(validateRenderableAlert(detail.renderable)).toBeNull();
    expect(detail.renderable.summary).toBe(
      "Merge ownerswitchai/ownerswitch#43 into main — squash, head bbbbbbbbbbbb",
    );
    // the decisive cross-contract assertion: the browser RECOMPUTES the exact
    // hash the server minted, from the wire envelope alone
    expect(await renderContentHash(detail.renderable)).toBe(detail.renderContentHash);

    // 4. the DOM "renders" the envelope fields; the gate builds the echo
    const domTexts: RenderedDomTexts = {
      agentId: detail.renderable.agentId,
      tool: detail.renderable.tool,
      summary: detail.renderable.summary,
    };
    const ackBody = await ackBodyForRender(detail, domTexts);
    expect(ackBody).not.toBeNull();

    // 5. the device-signed ack flips delivered on the live server
    const body = JSON.stringify(ackBody);
    const seenRes = await signedFetch("POST", "/veto/v-e2e/seen", body);
    expect(seenRes.status).toBe(200);
    expect(((await seenRes.json()) as { delivered: boolean }).delivered).toBe(true);
    expect(window.isDelivered).toBe(true);
    expect(window.deliveredBy).toBe("owner-phone");
  });

  it("a plain forwarded tool acks its exact canonical args the same way", async () => {
    const { publicKey, privateKey } = await generateOwnerDeviceKey();
    const spki = await exportPublicKeySpki(publicKey);
    const silenced = console.error;
    console.error = () => {};
    let cp;
    try {
      cp = createControlPlane({
        dev: true,
        killStateFile: null,
        acceptSessionOnlyApprovalRisk: true,
        ownerDeviceKeys: { "owner-phone": spki },
      });
    } finally {
      console.error = silenced;
    }
    const url = await start(cp);
    const window = new VetoWindow(
      { agentId: "agent-1", tool: "stripe.payout", args: { amount: 5000, to: "acct_x" } },
      cp.killSwitch.epoch,
    );
    cp.vetoWindows.set("v-e2e2", window);

    const headers = await signRequestHeaders(privateKey, {
      deviceId: "owner-phone",
      method: "GET",
      pathAndQuery: "/veto/v-e2e2/detail",
      body: "",
      timestamp: Date.now(),
      nonce: nonce(),
    });
    const detailRes = await fetch(`${url}/veto/v-e2e2/detail`, { headers: { ...headers } });
    const detail = (await detailRes.json()) as {
      renderable: { agentId: string; tool: string; summary: string };
      renderContentHash: string;
    };
    expect(detail.renderable.summary).toBe('{"amount":5000,"to":"acct_x"}');
    expect(await renderContentHash(detail.renderable)).toBe(detail.renderContentHash);
  });
});
