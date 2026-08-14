import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { ConsoleApi } from "./console-api.js";
import { createConsoleServer, type ListeningConsole } from "./console-server.js";

const publicDir = join(dirname(fileURLToPath(import.meta.url)), "..", "public");

/** A recording stub upstream — the server suite is about the server. */
function stubApi() {
  const calls: Array<{ op: string; arg?: string }> = [];
  const api: ConsoleApi = {
    lanes: () => ({ device: true, ownerSession: true }),
    async status() {
      calls.push({ op: "status" });
      return { reachable: true, status: { killed: false, epoch: 0, killedAgents: [] } };
    },
    async pending() {
      calls.push({ op: "pending" });
      return { kind: "ok", windows: [] };
    },
    async devices() {
      calls.push({ op: "devices" });
      return { kind: "unconfigured", missing: "OWNERSWITCH_OWNER_TOKEN" };
    },
    async windowStatus(id: string) {
      calls.push({ op: "windowStatus", arg: id });
      return { status: "vetoed" };
    },
    async veto(id: string) {
      calls.push({ op: "veto", arg: id });
      return { ok: true, upstreamStatus: 200, body: { status: "vetoed" } };
    },
    async kill(reason: string) {
      calls.push({ op: "kill", arg: reason });
      return { ok: true, upstreamStatus: 200, body: { killed: true, epoch: 1 } };
    },
  };
  return { api, calls };
}

describe("console server", () => {
  let listening: ListeningConsole | undefined;

  const start = async (api: ConsoleApi): Promise<string> => {
    const { listen } = createConsoleServer({ api, publicDir });
    listening = await listen(0, "127.0.0.1");
    return `http://127.0.0.1:${listening.port}`;
  };

  afterEach(async () => {
    await listening?.close();
    listening = undefined;
  });

  it("serves the console page with the strict headers on every response", async () => {
    const base = await start(stubApi().api);
    const page = await fetch(`${base}/`);
    expect(page.status).toBe(200);
    expect(page.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(page.headers.get("content-security-policy")).toContain("script-src 'self'");
    expect(page.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(page.headers.get("x-content-type-options")).toBe("nosniff");
    expect(page.headers.get("cache-control")).toBe("no-store, max-age=0");
    expect(await page.text()).toContain("OwnerSwitch");

    const script = await fetch(`${base}/app.js`);
    expect(script.status).toBe(200);
    expect(script.headers.get("content-type")).toBe("text/javascript; charset=utf-8");
    const core = await fetch(`${base}/workspace-core.mjs`);
    expect(core.status).toBe(200);

    const api = await fetch(`${base}/api/status`);
    expect(api.headers.get("cache-control")).toBe("no-store, max-age=0");
    expect(api.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("refuses traversal, unknown extensions and non-GET on the static surface", async () => {
    const base = await start(stubApi().api);
    for (const path of [
      "/../package.json",
      "/%2e%2e/package.json",
      "/..%2fpackage.json",
      "/workspace-core.d.mts",
      "/nope.css",
      "/no-extension",
      "/sub/dir.html",
    ]) {
      const res = await fetch(base + path);
      expect(res.status, path).toBe(404);
    }
    expect((await fetch(`${base}/`, { method: "POST" })).status).toBe(405);
  });

  it("routes only the allow-listed /api surface", async () => {
    const { api, calls } = stubApi();
    const base = await start(api);

    const status = await fetch(`${base}/api/status`);
    expect(await status.json()).toMatchObject({ reachable: true });

    const pending = await fetch(`${base}/api/veto/pending`);
    expect(await pending.json()).toEqual({ kind: "ok", windows: [] });

    const devices = await fetch(`${base}/api/devices`);
    expect(await devices.json()).toMatchObject({ kind: "unconfigured" });

    const windowRead = await fetch(`${base}/api/veto/veto_8c21`);
    expect(await windowRead.json()).toEqual({ status: "vetoed" });

    const veto = await fetch(`${base}/api/veto/veto_8c21`, { method: "POST" });
    expect(await veto.json()).toMatchObject({ ok: true });

    expect((await fetch(`${base}/api/anything-else`)).status).toBe(404);
    expect((await fetch(`${base}/api/kill`)).status).toBe(405);
    expect((await fetch(`${base}/api/veto/veto_x`, { method: "DELETE" })).status).toBe(405);

    expect(calls.map((c) => c.op)).toEqual(["status", "pending", "devices", "windowStatus", "veto"]);
  });

  it("refuses window ids the upstream path must never see", async () => {
    const { api, calls } = stubApi();
    const base = await start(api);
    for (const id of ["a.b", "a%2Fb", "sp%20ace", "x".repeat(129)]) {
      const res = await fetch(`${base}/api/veto/${id}`, { method: "POST" });
      expect(res.status, id).toBe(400);
    }
    expect(calls).toEqual([]);
  });

  it("validates the kill reason and defaults it when the body is empty", async () => {
    const { api, calls } = stubApi();
    const base = await start(api);

    const defaulted = await fetch(`${base}/api/kill`, { method: "POST" });
    expect(defaulted.status).toBe(200);

    const custom = await fetch(`${base}/api/kill`, {
      method: "POST",
      body: JSON.stringify({ reason: "drill — console check" }),
    });
    expect(custom.status).toBe(200);

    for (const body of [
      "not json",
      JSON.stringify({ reason: 42 }),
      JSON.stringify({ reason: "" }),
      JSON.stringify({ reason: "line\nbreak" }),
      JSON.stringify({ reason: "x".repeat(257) }),
    ]) {
      const res = await fetch(`${base}/api/kill`, { method: "POST", body });
      expect(res.status, body.slice(0, 24)).toBe(400);
    }
    const oversized = await fetch(`${base}/api/kill`, {
      method: "POST",
      body: JSON.stringify({ reason: "r", padding: "x".repeat(8 * 1024) }),
    });
    expect(oversized.status).toBe(400);

    expect(calls.map((c) => c.arg)).toEqual(["workspace console e-stop", "drill — console check"]);
  });
});
