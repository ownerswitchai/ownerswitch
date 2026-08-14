import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";

/**
 * The failure matrix AND the wire contract for examples/two-go-demo.sh:
 * zero restore POSTs after any failed/malformed GO 1/2; a non-409 early
 * answer fails loudly; the happy path issues exactly two restore POSTs
 * carrying the SAME ceremony id, the Bearer, and application/json; a
 * hanging control plane is cut off by the script's own curl timeouts; and
 * a restore whose response is lost after the commit is reconciled against
 * /status instead of being reported as "refused" while the system is
 * ARMED. The stub control plane below scripts each scenario and records
 * every request.
 */

const SCRIPT = resolve(__dirname, "..", "examples", "two-go-demo.sh");
const CANONICAL_ID = `cer_${randomUUID()}`;

type Answer = [number, string] | "drop" | "hang";

interface StubPlan {
  go1?: Answer;
  /** answers for successive POST /restore calls */
  restore?: Answer[];
  /** answers for successive GET /restore/ceremony/:id reads */
  ceremonyRead?: Answer[];
  status?: Answer;
}

interface Recorded {
  method: string;
  url: string;
  authorization?: string;
  contentType?: string;
  body: string;
}

const servers: Server[] = [];
afterEach(() => {
  while (servers.length > 0) servers.pop()?.close();
});

function stubPlane(plan: StubPlan): Promise<{
  url: string;
  requests: Recorded[];
  restorePosts(): number;
}> {
  const requests: Recorded[] = [];
  let restoreCall = 0;
  let readCall = 0;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c: Buffer) => (body += c.toString("utf8")));
    req.on("end", () => {
      requests.push({
        method: req.method ?? "",
        url: req.url ?? "",
        ...(req.headers.authorization !== undefined ? { authorization: req.headers.authorization } : {}),
        ...(req.headers["content-type"] !== undefined ? { contentType: req.headers["content-type"] } : {}),
        body,
      });
      const answer = (a: Answer | undefined) => {
        if (a === undefined) a = [500, '{"error":"unplanned call"}'];
        if (a === "drop") {
          res.destroy();
          return;
        }
        if (a === "hang") return; // never answer; the script's --max-time must cut it
        res.writeHead(a[0], { "content-type": "application/json" });
        res.end(a[1]);
      };
      if (req.method === "POST" && req.url === "/restore/ceremony") return answer(plan.go1);
      if (req.method === "POST" && req.url === "/restore") return answer(plan.restore?.[restoreCall++]);
      if (req.method === "GET" && req.url?.startsWith("/restore/ceremony/")) {
        return answer(plan.ceremonyRead?.[Math.min(readCall++, (plan.ceremonyRead?.length ?? 1) - 1)]);
      }
      if (req.method === "GET" && req.url === "/status") return answer(plan.status);
      answer([404, '{"error":"unplanned route"}']);
    });
  });
  servers.push(server);
  return new Promise((resolvePromise) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") throw new Error("no address");
      resolvePromise({
        url: `http://127.0.0.1:${addr.port}`,
        requests,
        restorePosts: () => requests.filter((r) => r.method === "POST" && r.url === "/restore").length,
      });
    });
  });
}

function runScript(
  planeUrl: string,
  token = "tok-demo",
  extraEnv: Record<string, string> = {},
): Promise<{ code: number; output: string }> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn("bash", [SCRIPT], {
      env: {
        ...process.env,
        OWNERSWITCH_CONTROL_PLANE_URL: planeUrl,
        OWNERSWITCH_OWNER_TOKEN: token,
        ...extraEnv,
      },
    });
    let output = "";
    child.stdout.on("data", (c: Buffer) => (output += c.toString("utf8")));
    child.stderr.on("data", (c: Buffer) => (output += c.toString("utf8")));
    child.on("error", reject);
    child.on("close", (code) => resolvePromise({ code: code ?? -1, output }));
  });
}

describe("two-go-demo.sh — the tested 2GO walkthrough step", () => {
  it("refuses to run without an exported owner token, touching nothing", async () => {
    const stub = await stubPlane({ go1: [200, "{}"] });
    const run = await runScript(stub.url, "");
    expect(run.code).not.toBe(0);
    expect(run.output).toContain("OWNERSWITCH_OWNER_TOKEN");
    expect(stub.requests).toHaveLength(0);
  });

  it("refuses a non-loopback control-plane URL before any request", async () => {
    const run = await runScript("http://cp.example.com:4600");
    expect(run.code).not.toBe(0);
    expect(run.output).toContain("literal-loopback");
  });

  it("a failed or malformed GO 1/2 issues ZERO restore POSTs", async () => {
    const badGo1: Array<[number, string]> = [
      [401, '{"error":"unauthorized"}'],
      [200, "<html>proxy</html>"],
      [200, "{}"],
      [200, '{"id":null}'],
      [200, '{"id":false}'],
      [200, '{"id":{}}'],
      [200, '{"id":""}'],
      [200, '{"id":"evil"}'],
      [200, '{"id":"cer_../../etc"}'],
      [200, `{"id":"CER_${randomUUID()}"}`],
    ];
    for (const go1 of badGo1) {
      const stub = await stubPlane({ go1 });
      const run = await runScript(stub.url);
      expect(run.code, JSON.stringify(go1)).not.toBe(0);
      expect(stub.restorePosts(), JSON.stringify(go1)).toBe(0);
    }
  });

  it("a GO 1/2 redirect is NOT success — the status contract is exact, not curl -f's", async () => {
    const stub = await stubPlane({ go1: [302, ""] });
    const run = await runScript(stub.url);
    expect(run.code).not.toBe(0);
    expect(run.output).toContain("HTTP 302");
    expect(stub.restorePosts()).toBe(0);
  });

  it("an early GO 2/2 that is NOT 409 fails the walkthrough loudly — 200 above all", async () => {
    for (const early of [
      [200, '{"killed":false}'],
      [302, ""],
      [401, '{"error":"unauthorized"}'],
      [500, '{"error":"boom"}'],
    ] as Array<[number, string]>) {
      const stub = await stubPlane({
        go1: [201, `{"id":"${CANONICAL_ID}"}`],
        restore: [early],
        status: [200, '{"killed":true,"epoch":1,"killedAgents":[]}'],
      });
      const run = await runScript(stub.url);
      expect(run.code, JSON.stringify(early)).not.toBe(0);
      expect(run.output, JSON.stringify(early)).toContain("instead of 409");
      expect(stub.restorePosts(), JSON.stringify(early)).toBe(1);
    }
  });

  it("an early non-409 with the system ARMED says so — the worst case is named, not hidden", async () => {
    const stub = await stubPlane({
      go1: [201, `{"id":"${CANONICAL_ID}"}`],
      restore: [[200, '{"killed":false}']],
      status: [200, '{"killed":false,"epoch":1,"killedAgents":[]}'],
    });
    const run = await runScript(stub.url);
    expect(run.code).not.toBe(0);
    expect(run.output).toContain("ARMED");
  });

  it("the happy path keeps the exact wire contract: same ceremony, Bearer, json, two restore POSTs", async () => {
    const stub = await stubPlane({
      go1: [201, `{"id":"${CANONICAL_ID}"}`],
      restore: [
        [409, '{"error":"restore rejected"}'],
        [200, '{"killed":false}'],
      ],
      ceremonyRead: [
        [200, '{"state":"go1","cooldownRemainingMs":2000}'],
        [200, '{"state":"ready","cooldownRemainingMs":0}'],
      ],
    });
    const run = await runScript(stub.url);
    expect(run.output).toContain("HTTP 409");
    expect(run.output).toContain('{"killed":false}');
    expect(run.code).toBe(0);

    const restores = stub.requests.filter((r) => r.method === "POST" && r.url === "/restore");
    expect(restores).toHaveLength(2);
    for (const r of restores) {
      expect(r.body).toBe(`{"ceremonyId":"${CANONICAL_ID}"}`);
      expect(r.authorization).toBe("Bearer tok-demo");
      expect(r.contentType).toContain("application/json");
    }
    const reads = stub.requests.filter((r) => r.method === "GET" && r.url.startsWith("/restore/ceremony/"));
    expect(reads.length).toBeGreaterThanOrEqual(2); // positive cooldown, then 0
    for (const r of reads) {
      expect(r.url).toBe(`/restore/ceremony/${CANONICAL_ID}`);
      expect(r.authorization).toBe("Bearer tok-demo");
    }
    const go1 = stub.requests[0];
    expect(go1?.method).toBe("POST");
    expect(go1?.url).toBe("/restore/ceremony");
    expect(go1?.authorization).toBe("Bearer tok-demo");
  });

  it("a hanging control plane is cut off by the script's own curl timeout", async () => {
    const stub = await stubPlane({ go1: "hang" });
    const run = await runScript(stub.url, "tok-demo", { OWNERSWITCH_TWO_GO_MAX_TIME_S: "2" });
    expect(run.code).not.toBe(0);
    expect(stub.restorePosts()).toBe(0);
  }, 20_000);

  it("a restore committed but its response lost reconciles via /status — reported restored, not refused", async () => {
    const stub = await stubPlane({
      go1: [201, `{"id":"${CANONICAL_ID}"}`],
      restore: [
        [409, '{"error":"restore rejected"}'],
        "drop", // the commit happened; the socket died before the answer
      ],
      ceremonyRead: [[200, '{"state":"ready","cooldownRemainingMs":0}']],
      status: [200, '{"killed":false,"epoch":1,"killedAgents":[]}'],
    });
    const run = await runScript(stub.url);
    expect(run.code).toBe(0);
    expect(run.output).toContain("LANDED");
  });

  it("a lost restore response with /status unreachable says OUTCOME UNKNOWN — never a guess", async () => {
    const stub = await stubPlane({
      go1: [201, `{"id":"${CANONICAL_ID}"}`],
      restore: [
        [409, '{"error":"restore rejected"}'],
        "drop",
      ],
      ceremonyRead: [[200, '{"state":"ready","cooldownRemainingMs":0}']],
      status: "drop",
    });
    const run = await runScript(stub.url);
    expect(run.code).not.toBe(0);
    expect(run.output).toContain("RESTORE OUTCOME UNKNOWN");
    expect(run.output).toContain("do not assume killed");
  });

  it("a restore answer without killed:false is a failure, not a shrug", async () => {
    const stub = await stubPlane({
      go1: [201, `{"id":"${CANONICAL_ID}"}`],
      restore: [
        [409, '{"error":"restore rejected"}'],
        [200, '{"killed":true,"epoch":2}'],
      ],
      ceremonyRead: [[200, '{"state":"ready","cooldownRemainingMs":0}']],
    });
    const run = await runScript(stub.url);
    expect(run.code).not.toBe(0);
    expect(run.output).toContain("killed:false");
  });
});
