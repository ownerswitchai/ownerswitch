import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";

/**
 * The failure matrix for examples/two-go-demo.sh (the review's exact ask):
 * the script must issue ZERO restore POSTs after any failed or malformed
 * GO 1/2, must refuse to call a non-409 early answer a success, and must
 * complete the documented happy path — GO1, early 409, cooldown drain,
 * SAME-ceremony restore — with exactly the expected number of restore
 * calls. The stub control plane below scripts each scenario and counts.
 */

const SCRIPT = resolve(__dirname, "..", "examples", "two-go-demo.sh");
const CANONICAL_ID = `cer_${randomUUID()}`;

interface StubPlan {
  /** answer for POST /restore/ceremony: [status, rawBody] */
  go1: [number, string];
  /** answers for successive POST /restore calls */
  restore?: Array<[number, string]>;
  /** answer for GET /restore/ceremony/:id */
  ceremonyRead?: [number, string];
}

interface StubRecord {
  url: string;
  restorePosts: number;
  close(): Promise<void>;
}

const servers: Server[] = [];
afterEach(() => {
  while (servers.length > 0) servers.pop()?.close();
});

function stubPlane(plan: StubPlan): Promise<StubRecord> {
  const record = { restorePosts: 0 };
  let restoreCall = 0;
  const server = createServer((req, res) => {
    const answer = (pair: [number, string]) => {
      res.writeHead(pair[0], { "content-type": "application/json" });
      res.end(pair[1]);
    };
    if (req.method === "POST" && req.url === "/restore/ceremony") return answer(plan.go1);
    if (req.method === "POST" && req.url === "/restore") {
      record.restorePosts += 1;
      const scripted = plan.restore?.[restoreCall++];
      return answer(scripted ?? [500, '{"error":"unplanned restore call"}']);
    }
    if (req.method === "GET" && req.url?.startsWith("/restore/ceremony/")) {
      return answer(plan.ceremonyRead ?? [404, '{"error":"unplanned read"}']);
    }
    answer([404, '{"error":"unplanned route"}']);
  });
  servers.push(server);
  return new Promise((resolvePromise) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") throw new Error("no address");
      resolvePromise({
        url: `http://127.0.0.1:${addr.port}`,
        get restorePosts() {
          return record.restorePosts;
        },
        close: () => new Promise<void>((r) => server.close(() => r())),
      } as StubRecord);
    });
  });
}

function runScript(planeUrl: string, token = "tok-demo"): Promise<{ code: number; output: string }> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn("bash", [SCRIPT], {
      env: {
        ...process.env,
        OWNERSWITCH_CONTROL_PLANE_URL: planeUrl,
        ...(token === "" ? { OWNERSWITCH_OWNER_TOKEN: "" } : { OWNERSWITCH_OWNER_TOKEN: token }),
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
    expect(stub.restorePosts).toBe(0);
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
      expect(stub.restorePosts, JSON.stringify(go1)).toBe(0);
      await stub.close();
    }
  });

  it("an early GO 2/2 that is NOT 409 fails the walkthrough loudly — 200 above all", async () => {
    for (const early of [
      [200, '{"killed":false}'],
      [401, '{"error":"unauthorized"}'],
      [500, '{"error":"boom"}'],
    ] as Array<[number, string]>) {
      const stub = await stubPlane({
        go1: [200, `{"id":"${CANONICAL_ID}"}`],
        restore: [early],
      });
      const run = await runScript(stub.url);
      expect(run.code, JSON.stringify(early)).not.toBe(0);
      expect(run.output, JSON.stringify(early)).toContain("instead of 409");
      // exactly the one early attempt — a non-409 must not cascade into more
      expect(stub.restorePosts, JSON.stringify(early)).toBe(1);
      await stub.close();
    }
  });

  it("the documented happy path: GO1 -> early 409 -> drain -> SAME ceremony restores, exactly two restore POSTs", async () => {
    const stub = await stubPlane({
      go1: [200, `{"id":"${CANONICAL_ID}"}`],
      restore: [
        [409, '{"error":"restore rejected"}'],
        [200, '{"killed":false}'],
      ],
      ceremonyRead: [200, '{"state":"ready","cooldownRemainingMs":0}'],
    });
    const run = await runScript(stub.url);
    expect(run.output).toContain("HTTP 409");
    expect(run.output).toContain('{"killed":false}');
    expect(run.code).toBe(0);
    expect(stub.restorePosts).toBe(2);
  });

  it("a restore answer without killed:false is a failure, not a shrug", async () => {
    const stub = await stubPlane({
      go1: [200, `{"id":"${CANONICAL_ID}"}`],
      restore: [
        [409, '{"error":"restore rejected"}'],
        [200, '{"killed":true,"epoch":2}'],
      ],
      ceremonyRead: [200, '{"state":"ready","cooldownRemainingMs":0}'],
    });
    const run = await runScript(stub.url);
    expect(run.code).not.toBe(0);
    expect(run.output).toContain("killed:false");
  });
});
