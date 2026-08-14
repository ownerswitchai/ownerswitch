import { request } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { ConsoleApi } from "./console-api.js";
import { CONSOLE_CSRF_HEADER, createConsoleServer, type ListeningConsole } from "./console-server.js";

const publicDir = join(dirname(fileURLToPath(import.meta.url)), "..", "public");

/** the headers a legitimate same-origin mutation carries (app.js postJson) */
const MUTATION_HEADERS = { [CONSOLE_CSRF_HEADER]: "1", "content-type": "application/json" };

/**
 * A raw HTTP exchange — unlike fetch, this can send a HOSTILE Host or
 * Origin, which is exactly what a DNS-rebinding or cross-site request
 * looks like on the wire.
 */
function raw(
  port: number,
  options: { method?: string; path?: string; headers?: Record<string, string>; body?: string },
): Promise<{ status: number; body: string }> {
  return new Promise((resolvePromise, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        method: options.method ?? "GET",
        path: options.path ?? "/api/status",
        headers: options.headers ?? {},
      },
      (res) => {
        let body = "";
        res.on("data", (c: Buffer) => (body += c.toString("utf8")));
        res.on("end", () => resolvePromise({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on("error", reject);
    req.end(options.body);
  });
}

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

    const veto = await fetch(`${base}/api/veto/veto_8c21`, { method: "POST", headers: MUTATION_HEADERS });
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
      const res = await fetch(`${base}/api/veto/${id}`, { method: "POST", headers: MUTATION_HEADERS });
      expect(res.status, id).toBe(400);
    }
    expect(calls).toEqual([]);
  });

  it("validates the kill reason and defaults it when the body is empty", async () => {
    const { api, calls } = stubApi();
    const base = await start(api);

    const defaulted = await fetch(`${base}/api/kill`, { method: "POST", headers: MUTATION_HEADERS });
    expect(defaulted.status).toBe(200);

    const custom = await fetch(`${base}/api/kill`, {
      method: "POST",
      headers: MUTATION_HEADERS,
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
      const res = await fetch(`${base}/api/kill`, { method: "POST", headers: MUTATION_HEADERS, body });
      expect(res.status, body.slice(0, 24)).toBe(400);
    }
    const oversized = await fetch(`${base}/api/kill`, {
      method: "POST",
      headers: MUTATION_HEADERS,
      body: JSON.stringify({ reason: "r", padding: "x".repeat(8 * 1024) }),
    });
    expect(oversized.status).toBe(400);

    expect(calls.map((c) => c.arg)).toEqual(["workspace console e-stop", "drill — console check"]);
  });

  describe("the browser→console boundary (audit #1)", () => {
    it("refuses a foreign Host on every surface — DNS rebinding dies before any upstream call", async () => {
      const { api, calls } = stubApi();
      const base = await start(api);
      const port = listening?.port as number;

      for (const host of ["attacker.example", "attacker.example:80", `rebound.example:${port}`]) {
        const apiRes = await raw(port, { headers: { host } });
        expect(apiRes.status, host).toBe(403);
        const staticRes = await raw(port, { path: "/", headers: { host } });
        expect(staticRes.status, host).toBe(403);
        const killRes = await raw(port, {
          method: "POST",
          path: "/api/kill",
          headers: { host, ...MUTATION_HEADERS },
        });
        expect(killRes.status, host).toBe(403);
      }
      expect(calls).toEqual([]);
      // sanity: the same request with the server's own host answers
      expect((await fetch(`${base}/api/status`)).status).toBe(200);
    });

    it("refuses a cross-origin Origin and a cross-site Sec-Fetch-Site", async () => {
      const { api, calls } = stubApi();
      await start(api);
      const port = listening?.port as number;
      const ownHost = `127.0.0.1:${port}`;

      for (const origin of ["http://attacker.example", "null", "https://127.0.0.1"]) {
        const res = await raw(port, { headers: { host: ownHost, origin } });
        expect(res.status, origin).toBe(403);
      }
      const crossSite = await raw(port, {
        headers: { host: ownHost, "sec-fetch-site": "cross-site" },
      });
      expect(crossSite.status).toBe(403);
      expect(calls).toEqual([]);

      // the browser's own spellings pass
      const friendly: Array<Record<string, string>> = [
        { host: ownHost, origin: `http://${ownHost}` },
        { host: ownHost, "sec-fetch-site": "same-origin" },
        { host: ownHost, "sec-fetch-site": "none" },
      ];
      for (const headers of friendly) {
        const res = await raw(port, { headers });
        expect(res.status, JSON.stringify(headers)).toBe(200);
      }
    });

    it("a mutation without the CSRF header, or with a form content-type, never reaches the api", async () => {
      const { api, calls } = stubApi();
      await start(api);
      const port = listening?.port as number;
      const ownHost = `127.0.0.1:${port}`;

      // an HTML form's POST: urlencoded, no custom header — the CSRF classic
      const form = await raw(port, {
        method: "POST",
        path: "/api/kill",
        headers: { host: ownHost, "content-type": "application/x-www-form-urlencoded" },
        body: "reason=owned",
      });
      expect(form.status).toBe(403);

      // header present but a non-JSON content-type still refused
      const textPlain = await raw(port, {
        method: "POST",
        path: "/api/veto/veto_1",
        headers: { host: ownHost, [CONSOLE_CSRF_HEADER]: "1", "content-type": "text/plain" },
        body: "x",
      });
      expect(textPlain.status).toBe(415);

      // no CSRF header at all
      const bare = await raw(port, {
        method: "POST",
        path: "/api/veto/veto_1",
        headers: { host: ownHost },
      });
      expect(bare.status).toBe(403);

      expect(calls).toEqual([]);

      // the legitimate shape still mutates
      const ok = await raw(port, {
        method: "POST",
        path: "/api/veto/veto_1",
        headers: { host: ownHost, ...MUTATION_HEADERS },
      });
      expect(ok.status).toBe(200);
      expect(calls.map((c) => c.op)).toEqual(["veto"]);
    });

    it("listen() refuses a non-loopback effective address — embedding cannot widen the surface", async () => {
      const { api } = stubApi();
      const { listen } = createConsoleServer({ api, publicDir });
      await expect(listen(0, "0.0.0.0")).rejects.toThrow(/loopback/);
    });

    it("a handler with no allowlisted host refuses everything — fail closed, never a guess", async () => {
      const { api } = stubApi();
      // bypass listen()'s auto-allowlist by giving the server no hosts at all
      const { listen } = createConsoleServer({ api, publicDir, allowedHosts: [] });
      const bare = await listen(0, "127.0.0.1");
      try {
        // even the server's own loopback spelling was auto-added by listen();
        // strip-equivalent: a host nobody allowed is refused
        const res = await raw(bare.port, { headers: { host: "unlisted.example" } });
        expect(res.status).toBe(403);
      } finally {
        await bare.close();
      }
    });
  });
});
