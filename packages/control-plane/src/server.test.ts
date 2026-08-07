import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { createControlPlane, type ControlPlane } from "./server.js";
import { RestoreCeremony } from "./twogo.js";
import { VetoWindow } from "./veto.js";

const clock = (start = 0) => {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
};

describe("control-plane HTTP API", () => {
  let server: Server | undefined;

  const start = (cp: ControlPlane): Promise<string> => {
    server = createServer(cp.handler);
    return new Promise((resolve) => {
      server!.listen(0, "127.0.0.1", () => {
        const addr = server!.address();
        if (addr === null || typeof addr === "string") throw new Error("no address");
        resolve(`http://127.0.0.1:${addr.port}`);
      });
    });
  };

  afterEach(() => {
    server?.close();
    server = undefined;
  });

  it("GET /status before and after kill", async () => {
    const c = clock(1_000);
    const url = await start(createControlPlane({ now: c.now }));

    let res = await fetch(`${url}/status`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ killed: false });

    await fetch(`${url}/kill`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ source: "button", reason: "red button pressed" }),
    });

    res = await fetch(`${url}/status`);
    expect(await res.json()).toEqual({
      killed: true,
      reason: "red button pressed",
      at: 1_000,
    });
  });

  it("POST /kill with an empty body still engages (default source 'api')", async () => {
    const cp = createControlPlane({ now: clock().now });
    const url = await start(cp);

    const res = await fetch(`${url}/kill`, { method: "POST" });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ killed: true });

    expect(cp.killSwitch.killed).toBe(true);
    const [entry] = cp.killSwitch.auditLog();
    expect(entry.type === "kill" && entry.event.source).toBe("api");
  });

  it("POST /restore with a valid ceremony restores", async () => {
    const c = clock();
    const cp = createControlPlane({ now: c.now });
    const url = await start(cp);

    cp.killSwitch.engage("honeytoken", "decoy key touched");
    const ceremony = new RestoreCeremony("cer-1", "adam", { now: c.now });
    c.advance(30_000); // past the cooldown
    const auth = ceremony.confirm();

    const res = await fetch(`${url}/restore`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(auth),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ killed: false });
    expect(cp.killSwitch.killed).toBe(false);
  });

  it("replaying a restore authorization -> 409", async () => {
    const c = clock();
    const cp = createControlPlane({ now: c.now });
    const url = await start(cp);

    cp.killSwitch.engage("api");
    const ceremony = new RestoreCeremony("cer-1", "adam", { now: c.now });
    c.advance(30_000);
    const auth = ceremony.confirm();

    const post = () =>
      fetch(`${url}/restore`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(auth),
      });

    expect((await post()).status).toBe(200);

    cp.killSwitch.engage("api"); // killed again — same ceremony must not restore twice
    const replay = await post();
    expect(replay.status).toBe(409);
    expect((await replay.json()).error).toMatch(/single-use/);
    expect(cp.killSwitch.killed).toBe(true);
  });

  it("POST /veto/:id vetoes a pending window", async () => {
    const c = clock();
    const cp = createControlPlane({ now: c.now });
    const url = await start(cp);

    const window = new VetoWindow(
      { agentId: "agent-1", tool: "stripe.payout" },
      { now: c.now },
    );
    cp.vetoWindows.set("v-1", window);

    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ by: "adam" }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "vetoed" });
    expect(window.vetoedBy).toBe("adam");

    const status = await fetch(`${url}/veto/v-1`);
    expect(await status.json()).toEqual({ status: "vetoed" });
  });

  it("POST /veto/:id on a released window -> 409", async () => {
    const c = clock();
    const cp = createControlPlane({ now: c.now });
    const url = await start(cp);

    const window = new VetoWindow(
      { agentId: "agent-1", tool: "bash" },
      { now: c.now, windowMs: 4 * 60_000 },
    );
    window.markDelivered();
    cp.vetoWindows.set("v-1", window);

    c.advance(4 * 60_000); // deadline passes with delivery confirmed -> released
    const status = await fetch(`${url}/veto/v-1`);
    expect(await status.json()).toEqual({ status: "released" });

    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ by: "adam" }),
    });
    expect(res.status).toBe(409);
    expect((await res.json()).error).toMatch(/released/);
  });

  it("unknown route -> 404", async () => {
    const url = await start(createControlPlane({ now: clock().now }));

    expect((await fetch(`${url}/nope`)).status).toBe(404);
    expect((await fetch(`${url}/status`, { method: "POST" })).status).toBe(404);
    expect((await fetch(`${url}/veto/missing`)).status).toBe(404);
  });

  it("malformed JSON -> 400, and the process survives", async () => {
    const cp = createControlPlane({ now: clock().now });
    const url = await start(cp);

    const res = await fetch(`${url}/kill`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not json",
    });
    expect(res.status).toBe(400);

    // the server is still alive and well
    expect((await fetch(`${url}/status`)).status).toBe(200);
  });
});
