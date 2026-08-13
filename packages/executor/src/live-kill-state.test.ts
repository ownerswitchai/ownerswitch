import { createControlPlaneClient } from "@ownerswitchai/gateway";
import { describe, expect, it } from "vitest";
import { liveKillStateFromControlPlane } from "./live-kill-state.js";

const statusResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

/** The real gateway client against a fake /status — the wire the re-check reads. */
const clientServing = (body: unknown, status = 200) =>
  createControlPlaneClient({
    baseUrl: "http://control-plane.test",
    fetchImpl: async () => statusResponse(body, status),
  });

describe("liveKillStateFromControlPlane", () => {
  it("reads killed and epoch off GET /status through the real gateway client", async () => {
    const fetchLive = liveKillStateFromControlPlane(clientServing({ killed: false, epoch: 7, killedAgents: [] }));
    expect(await fetchLive()).toEqual({ killed: false, epoch: 7 });
  });

  it("a kill on /status reads as killed, epoch intact for the audit trail", async () => {
    const fetchLive = liveKillStateFromControlPlane(
      clientServing({ killed: true, reason: "red button", epoch: 3, killedAgents: [] }),
    );
    expect(await fetchLive()).toEqual({ killed: true, epoch: 3 });
  });

  it("an unreachable control plane reads as killed — fail closed", async () => {
    const fetchLive = liveKillStateFromControlPlane(
      createControlPlaneClient({
        baseUrl: "http://control-plane.test",
        fetchImpl: async () => {
          throw new Error("ECONNREFUSED");
        },
      }),
    );
    expect((await fetchLive()).killed).toBe(true);
  });

  it("a /status answer missing epoch fails the whole lookup closed, not epoch 0", async () => {
    // the gateway client already refuses to default a missing epoch to 0;
    // the adapter must surface that as killed, never as a usable epoch
    const fetchLive = liveKillStateFromControlPlane(clientServing({ killed: false }));
    expect((await fetchLive()).killed).toBe(true);
  });

  it("a hand-built client that omits epoch on a live answer still reads as killed", async () => {
    // the narrowing itself is fail-closed: "not killed, epoch unknown" must
    // not be able to authorize the ticket-epoch check
    const fetchLive = liveKillStateFromControlPlane({
      fetchKillState: async () => ({ killed: false }),
    });
    expect(await fetchLive()).toEqual({ killed: true, epoch: -1 });
  });
});
