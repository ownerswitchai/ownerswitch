import { createServer, type Server } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createControlPlane,
  createOwnerSession,
  type ControlPlane,
} from "@ownerswitchai/control-plane";
import { afterEach, describe, expect, it } from "vitest";
import { createConsoleApi } from "./console-api.js";
import { createConsoleServer, type ListeningConsole } from "./console-server.js";
import { deviceSignedHeaders } from "./device-sig.js";
import {
  classifyKillState,
  pendingModel,
  vetoResultAction,
} from "../public/workspace-core.mjs";

const publicDir = join(dirname(fileURLToPath(import.meta.url)), "..", "public");
const DEVICE_SECRET = "fleet-secret";

/** A dev control plane (no persistence) — the server.test.ts harness shape. */
function ephemeralPlane(): ControlPlane {
  const original = console.error;
  console.error = () => {};
  try {
    return createControlPlane({
      acceptSessionOnlyApprovalRisk: true,
      deviceSecret: DEVICE_SECRET,
      dev: true,
      killStateFile: null,
    });
  } finally {
    console.error = original;
  }
}

describe("workspace console against a REAL control plane", () => {
  let planeServer: Server | undefined;
  let listening: ListeningConsole | undefined;

  const startPlane = (plane: ControlPlane): Promise<string> => {
    planeServer = createServer(plane.handler);
    return new Promise((resolve) => {
      planeServer!.listen(0, "127.0.0.1", () => {
        const addr = planeServer!.address();
        if (addr === null || typeof addr === "string") throw new Error("no address");
        resolve(`http://127.0.0.1:${addr.port}`);
      });
    });
  };

  const startConsole = async (controlPlaneUrl: string, ownerToken?: string): Promise<string> => {
    const api = createConsoleApi({
      controlPlaneUrl,
      deviceId: "workspace-console",
      deviceSecret: DEVICE_SECRET,
      timeoutMs: 2000,
      ...(ownerToken !== undefined ? { ownerToken } : {}),
    });
    const { listen } = createConsoleServer({ api, publicDir });
    listening = await listen(0, "127.0.0.1");
    return `http://127.0.0.1:${listening.port}`;
  };

  /** Register a veto window directly on the plane, device-signed. */
  const registerWindow = async (planeUrl: string, agentId: string, tool: string): Promise<string> => {
    const body = JSON.stringify({ call: { agentId, tool, args: { summary: "release the fix" } } });
    const res = await fetch(`${planeUrl}/veto`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...deviceSignedHeaders("workspace-console", DEVICE_SECRET, body, Date.now()),
      },
      body,
    });
    expect(res.status).toBe(201);
    const { id } = (await res.json()) as { id: string };
    return id;
  };

  afterEach(async () => {
    await listening?.close();
    listening = undefined;
    await new Promise<void>((resolve) => {
      if (planeServer === undefined) return resolve();
      planeServer.close(() => resolve());
    });
    planeServer = undefined;
  });

  it("walks the whole working surface: armed → window → veto → kill → unreachable", async () => {
    const planeUrl = await startPlane(ephemeralPlane());
    const base = await startConsole(planeUrl);

    // ARMED, and the browser core agrees
    const armed = await (await fetch(`${base}/api/status`)).json();
    const armedView = classifyKillState(armed);
    expect(armedView).toMatchObject({ state: "armed", badge: "ARMED", epoch: 0, treatAsKilled: false });

    // an empty pending list is an OK reading, not a guess
    const empty = pendingModel(await (await fetch(`${base}/api/veto/pending`)).json(), Date.now());
    expect(empty).toMatchObject({ kind: "ok", windows: [], dropped: 0 });

    // a gateway registers a review window; the console lists it
    const windowId = await registerWindow(planeUrl, "deploy-bot", "github.merge_pr");
    const listed = pendingModel(await (await fetch(`${base}/api/veto/pending`)).json(), Date.now());
    expect(listed.kind).toBe("ok");
    expect(listed.windows).toHaveLength(1);
    expect(listed.windows[0]).toMatchObject({
      id: windowId,
      status: "pending",
      agentId: "deploy-bot",
      tool: "github.merge_pr",
      delivered: false,
    });
    expect(listed.windows[0]?.msRemaining).toBeGreaterThan(0);

    // one click stops it — and only the server's explicit word says "stopped"
    const vetoRes = await fetch(`${base}/api/veto/${windowId}`, { method: "POST" });
    const vetoResult = await vetoRes.json();
    expect(vetoResultAction(windowId, windowId, vetoResult)).toBe("stopped");

    // the window leaves the pending list; the open read narrates the close
    const after = pendingModel(await (await fetch(`${base}/api/veto/pending`)).json(), Date.now());
    expect(after).toMatchObject({ kind: "ok", windows: [] });
    const finalStatus = await (await fetch(`${base}/api/veto/${windowId}`)).json();
    expect(finalStatus).toEqual({ status: "vetoed" });

    // re-vetoing a vetoed window stays a successful no-op (blind-retry safe)
    const again = await (await fetch(`${base}/api/veto/${windowId}`, { method: "POST" })).json();
    expect(vetoResultAction(windowId, windowId, again)).toBe("stopped");

    // the E-STOP: kill through the console, with its reason attributed
    const killResult = await (
      await fetch(`${base}/api/kill`, {
        method: "POST",
        body: JSON.stringify({ reason: "workspace console e-stop" }),
      })
    ).json();
    expect(killResult).toMatchObject({ ok: true, upstreamStatus: 200 });

    const killedView = classifyKillState(await (await fetch(`${base}/api/status`)).json());
    expect(killedView).toMatchObject({ state: "killed", badge: "KILLED", treatAsKilled: true, epoch: 1 });
    expect(killedView.detail).toContain("workspace console e-stop");

    // the plane goes away → the console proves nothing → treated as killed
    await new Promise<void>((resolve) => planeServer!.close(() => resolve()));
    planeServer = undefined;
    const gone = classifyKillState(await (await fetch(`${base}/api/status`)).json());
    expect(gone).toMatchObject({ state: "unreachable", badge: "UNREACHABLE", treatAsKilled: true });
  });

  it("devices lane: unconfigured without a token, honest upstream refusal with one", async () => {
    const planeUrl = await startPlane(ephemeralPlane());

    const bare = await startConsole(planeUrl);
    expect(await (await fetch(`${bare}/api/devices`)).json()).toEqual({
      kind: "unconfigured",
      missing: "OWNERSWITCH_OWNER_TOKEN",
    });
    await listening?.close();
    listening = undefined;

    // a real owner session, but this dev plane has no enrollment configured —
    // the console surfaces the 501 instead of inventing an empty device list
    const session = createOwnerSession("owner-grupa-rapid");
    const withToken = await startConsole(planeUrl, session.token);
    const reading = (await (await fetch(`${withToken}/api/devices`)).json()) as {
      kind: string;
      upstreamStatus?: number;
    };
    expect(reading.kind).toBe("refused");
    expect(reading.upstreamStatus).toBe(501);
  });

  it("a scope-killed agent shows up in the armed view's scoped kills", async () => {
    const planeUrl = await startPlane(ephemeralPlane());
    const base = await startConsole(planeUrl);

    const body = JSON.stringify({ source: "api", reason: "scoped stop", agentId: "docs-bot" });
    const res = await fetch(`${planeUrl}/kill`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...deviceSignedHeaders("workspace-console", DEVICE_SECRET, body, Date.now()),
      },
      body,
    });
    expect(res.status).toBe(200);

    const view = classifyKillState(await (await fetch(`${base}/api/status`)).json());
    expect(view.state).toBe("armed");
    expect(view.scopedKills).toEqual(["docs-bot"]);
    expect(view.detail).toContain("scope-killed");
  });
});
