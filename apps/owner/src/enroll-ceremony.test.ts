import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControlPlane, type ControlPlane } from "@ownerswitchai/control-plane";
import { ownerEnrollPopPreimage } from "@ownerswitchai/shared";
import { afterEach, describe, expect, it } from "vitest";
import {
  completeEnrollmentCeremony,
  ENROLL_POP_LABEL,
  enrollPopPreimage,
} from "../public/enroll-ceremony.mjs";
import { syntheticAuthenticator } from "./webauthn-fake.js";

/**
 * The PHONE's WHOLE ceremony (public/enroll-ceremony.mjs) against a REAL
 * control plane over real HTTP: only the platform authenticator is
 * synthetic (a Node keypair playing navigator.credentials); the invite
 * contract, the cheap-lane WebCrypto proof, the wire bytes, and the
 * registry admit are all the production code paths.
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

/** a live dev control plane with enrollment wired, listening on loopback */
async function liveServer(): Promise<{ cp: ControlPlane; base: string; devicesFile: string }> {
  const dir = mkdtempSync(join(tmpdir(), "ownerswitch-ceremony-"));
  dirs.push(dir);
  const devicesFile = join(dir, "devices.json");
  const cp = quiet(() =>
    createControlPlane({
      dev: true,
      killStateFile: null,
      acceptSessionOnlyApprovalRisk: true,
      enrollment: {
        devicesFile,
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
  return { cp, base, devicesFile };
}

function mintPayload(cp: ControlPlane) {
  const token = randomBytes(32).toString("base64url");
  const minted = cp.bootstrapMintInvite({
    tokenHash: createHash("sha256").update(token, "utf8").digest("base64url"),
    ownerId: "owner-adam",
    deviceName: "Adam's phone",
  });
  if (!minted.ok) throw new Error(`mint failed: ${minted.error}`);
  return { ...minted.invite, token };
}

/** a REAL WebCrypto cheap-lane pair, the shape ensureDeviceKey() hands over */
const cheapLanePair = () =>
  crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]) as Promise<{
    privateKey: CryptoKey;
    publicKey: CryptoKey;
  }>;

describe("public/enroll-ceremony.mjs — the phone's whole ceremony against a real control plane", () => {
  it("the PoP transcript is drift-pinned to @ownerswitchai/shared, byte for byte", () => {
    const credentialIdBytes = new Uint8Array(randomBytes(24));
    const spkiBytes = new Uint8Array(
      generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({
        type: "spki",
        format: "der",
      }) as Buffer,
    );
    const app = enrollPopPreimage({ inviteId: "inv-1", ownerId: "owner-adam", credentialIdBytes, spkiBytes });
    const shared = ownerEnrollPopPreimage({
      inviteId: "inv-1",
      ownerId: "owner-adam",
      credentialId: credentialIdBytes,
      spki: spkiBytes,
    });
    expect(Buffer.from(app).toString("hex")).toBe(Buffer.from(shared).toString("hex"));
    expect(ENROLL_POP_LABEL).toBe("ownerswitch/enroll-cheap-lane/v1");
    expect(() => enrollPopPreimage({ inviteId: "", ownerId: "o", credentialIdBytes, spkiBytes })).toThrow(
      /empty/,
    );
  });

  it("END TO END: paste the payload, run the ceremony, spend the invite over real HTTP — 201 and the device is durably admitted", async () => {
    const { cp, base, devicesFile } = await liveServer();
    const payload = mintPayload(cp);
    const authenticator = syntheticAuthenticator(RP_ID, ORIGIN);
    const outcome = await completeEnrollmentCeremony(payload, {
      credentials: authenticator.container,
      cheapLane: await cheapLanePair(),
      fetchImpl: fetch,
      baseUrl: base,
    });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.deviceId).toMatch(/^dev_/);
    // the PLATFORM received exactly the server's parameters — recorded by
    // the synthetic authenticator, asserted here (the review's gap)
    expect(authenticator.seen.create).toHaveLength(1);
    expect(authenticator.seen.create[0].rpId).toBe(RP_ID);
    expect(authenticator.seen.create[0].userVerification).toBe("required");
    expect(authenticator.seen.create[0].userIdB64).toBe(payload.user.id);
    expect(authenticator.seen.get).toHaveLength(1);
    expect(authenticator.seen.get[0].rpId).toBe(RP_ID);
    expect(authenticator.seen.get[0].userVerification).toBe("required");
    expect(authenticator.seen.get[0].allowCredentialIdsB64).toEqual([
      Buffer.from(authenticator.credentialId).toString("base64url"),
    ]);
    // the registry really admitted it — durable state, not a mock
    expect(cp.enrolledDevices?.activeDeviceCount).toBe(1);
    expect(cp.enrolledDevices?.get(outcome.deviceId)?.deviceName).toBe("Adam's phone");
    // and a CONTROL-PLANE RESTART over the same file still holds the device
    const restarted = quiet(() =>
      createControlPlane({
        dev: true,
        killStateFile: null,
        acceptSessionOnlyApprovalRisk: true,
        enrollment: { devicesFile, rpId: RP_ID, rpName: "OwnerSwitch", origin: ORIGIN },
      }),
    );
    expect(restarted.enrolledDevices?.activeDeviceCount).toBe(1);

    // REPLAY: the spent invite is gone, and the refusal says so honestly
    const replay = await completeEnrollmentCeremony(payload, {
      credentials: syntheticAuthenticator(RP_ID, ORIGIN).container,
      cheapLane: await cheapLanePair(),
      fetchImpl: fetch,
      baseUrl: base,
    });
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      // the spent invite fails the PREFLIGHT — refused before any prompt,
      // with no survival claim ("not vouched" covers spent and unknown alike)
      expect(replay.reason).toMatch(/does not vouch/);
      expect(replay.inviteSurvives).toBeUndefined();
    }
  });

  it("a REFUSED possession assertion stops the ceremony with the invite untouched — the honest retry then lands", async () => {
    const { cp, base } = await liveServer();
    const payload = mintPayload(cp);
    const authenticator = syntheticAuthenticator(RP_ID, ORIGIN).container;
    const refusing = {
      create: authenticator.create,
      get: async () => {
        throw Object.assign(new Error("cancelled"), { name: "NotAllowedError" });
      },
    };
    const refused = await completeEnrollmentCeremony(payload, {
      credentials: refusing,
      cheapLane: await cheapLanePair(),
      fetchImpl: fetch,
      baseUrl: base,
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.reason).toBe("the possession assertion was refused, unavailable, or dismissed");
    }
    // the server never saw a spend — the same payload still enrolls
    const retry = await completeEnrollmentCeremony(payload, {
      credentials: syntheticAuthenticator(RP_ID, ORIGIN).container,
      cheapLane: await cheapLanePair(),
      fetchImpl: fetch,
      baseUrl: base,
    });
    expect(retry.ok).toBe(true);
  });

  it("an UNREACHABLE control plane refuses at the PREFLIGHT — no prompt, no dispatch, no survival guess", async () => {
    const { cp } = await liveServer();
    const payload = mintPayload(cp);
    const outcome = await completeEnrollmentCeremony(payload, {
      credentials: syntheticAuthenticator(RP_ID, ORIGIN).container,
      cheapLane: await cheapLanePair(),
      fetchImpl: fetch,
      baseUrl: "http://127.0.0.1:9", // discard port — nothing listens
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      // the PREFLIGHT refuses first — no prompt was raised, nothing was
      // dispatched, and no survival claim is made (unknowable from here)
      expect(outcome.reason).toMatch(/does not vouch/);
      expect(outcome.inviteSurvives).toBeUndefined();
    }
  });

  it("TAMPERED payload (rp/user/challenge modified) refuses BEFORE any prompt — create() is never called", async () => {
    const { cp, base } = await liveServer();
    const payload = mintPayload(cp);
    const seenCreate: unknown[] = [];
    const spyContainer = {
      create: async (request: unknown) => {
        seenCreate.push(request);
        throw new Error("must not be reached");
      },
      get: async () => {
        throw new Error("must not be reached");
      },
    };
    for (const tampered of [
      { ...payload, rpId: "evil.example" },
      { ...payload, user: { ...payload.user, id: randomBytes(32).toString("base64url") } },
      { ...payload, challenge: randomBytes(32).toString("base64url") },
      { ...payload, rpName: "Evil" },
    ]) {
      const outcome = await completeEnrollmentCeremony(tampered, {
        credentials: spyContainer,
        cheapLane: await cheapLanePair(),
        fetchImpl: fetch,
        baseUrl: base,
      });
      expect(outcome.ok).toBe(false);
      if (!outcome.ok) expect(outcome.reason).toMatch(/does not match the control plane/);
    }
    expect(seenCreate).toHaveLength(0);
    // and the untouched honest chain still lands afterwards
    const honest = await completeEnrollmentCeremony(payload, {
      credentials: syntheticAuthenticator(RP_ID, ORIGIN).container,
      cheapLane: await cheapLanePair(),
      fetchImpl: fetch,
      baseUrl: base,
    });
    expect(honest.ok).toBe(true);
  });

  it("REDIRECTS: a 307 and a 308 on the enrolment POST are refused, and the redirect target receives ZERO body bytes", async () => {
    for (const status of [307, 308] as const) {
      const { cp, base } = await liveServer();
      const payload = mintPayload(cp);
      // the capture server: any byte arriving here is the leak
      let capturedBytes = 0;
      const capture = createServer((req, res) => {
        req.on("data", (chunk: Buffer) => {
          capturedBytes += chunk.length;
        });
        req.on("end", () => {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ deviceId: "dev_stolen" }));
        });
      });
      servers.push(capture);
      const captureBase = await new Promise<string>((resolve) => {
        capture.listen(0, "127.0.0.1", () => {
          const addr = capture.address();
          if (addr === null || typeof addr === "string") throw new Error("no address");
          resolve(`http://127.0.0.1:${addr.port}`);
        });
      });
      // the redirector: preflight GETs proxy through to the REAL control
      // plane (so the ceremony reaches the POST), the POST answers with the
      // METHOD-PRESERVING redirect toward the capture server
      const redirector = createServer((req, res) => {
        if (req.method === "GET") {
          void fetch(base + (req.url ?? "/")).then(
            async (upstream) => {
              res.writeHead(upstream.status, { "content-type": "application/json" });
              res.end(await upstream.text());
            },
            () => {
              res.writeHead(502);
              res.end();
            },
          );
          return;
        }
        req.resume();
        req.on("end", () => {
          res.writeHead(status, { location: `${captureBase}/devices/enroll` });
          res.end();
        });
      });
      servers.push(redirector);
      const redirectorBase = await new Promise<string>((resolve) => {
        redirector.listen(0, "127.0.0.1", () => {
          const addr = redirector.address();
          if (addr === null || typeof addr === "string") throw new Error("no address");
          resolve(`http://127.0.0.1:${addr.port}`);
        });
      });

      const outcome = await completeEnrollmentCeremony(payload, {
        credentials: syntheticAuthenticator(RP_ID, ORIGIN).container,
        cheapLane: await cheapLanePair(),
        fetchImpl: fetch,
        baseUrl: redirectorBase,
      });
      // redirect: "error" makes the fetch REJECT — a post-dispatch failure,
      // honestly UNKNOWN (the redirector could have proxied the spend)
      expect(outcome.ok).toBe(false);
      if (!outcome.ok) {
        expect(outcome.outcome).toBe("unknown");
        expect(outcome.reason).toMatch(/UNKNOWN/);
      }
      // and the credential bundle NEVER reached the redirect target
      expect(capturedBytes).toBe(0);
    }
  });

  it("LOST 201: the server commits, the connection dies before the response — the client reports UNKNOWN, never survival", async () => {
    const { cp, base } = await liveServer();
    const payload = mintPayload(cp);
    // a proxy that forwards the POST to the real control plane, waits for
    // the real response, then destroys the client socket without relaying
    const proxy = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        void fetch(base + (req.url ?? "/"), {
          method: req.method ?? "GET",
          headers: { "content-type": "application/json" },
          ...(req.method === "POST" ? { body: Buffer.concat(chunks).toString("utf8") } : {}),
        }).then(
          async (upstream) => {
            const text = await upstream.text();
            if (req.method === "POST") {
              // the review's exact scenario: the commit happened, the 201 is lost
              res.socket?.destroy();
              return;
            }
            res.writeHead(upstream.status, { "content-type": "application/json" });
            res.end(text);
          },
          () => {
            res.socket?.destroy();
          },
        );
      });
    });
    servers.push(proxy);
    const proxyBase = await new Promise<string>((resolve) => {
      proxy.listen(0, "127.0.0.1", () => {
        const addr = proxy.address();
        if (addr === null || typeof addr === "string") throw new Error("no address");
        resolve(`http://127.0.0.1:${addr.port}`);
      });
    });
    const outcome = await completeEnrollmentCeremony(payload, {
      credentials: syntheticAuthenticator(RP_ID, ORIGIN).container,
      cheapLane: await cheapLanePair(),
      fetchImpl: fetch,
      baseUrl: proxyBase,
    });
    // the SERVER really committed…
    expect(cp.enrolledDevices?.activeDeviceCount).toBe(1);
    // …and the client says UNKNOWN — not "the invite survived"
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.outcome).toBe("unknown");
      expect(outcome.reason).toMatch(/OUTCOME IS UNKNOWN/);
      expect("inviteSurvives" in outcome).toBe(false);
    }
  });

  it("a 201 that is not EXACTLY the pinned {deviceId} contract is UNKNOWN, not success", async () => {
    const { cp, base } = await liveServer();
    const payload = mintPayload(cp);
    const wrappedFetch: typeof fetch = async (input, init) => {
      if (init?.method === "POST") {
        // dispatch to the real server (the spend happens), then hand the
        // client a 201 with a smuggled extra field
        await fetch(input, init);
        return new Response(JSON.stringify({ deviceId: "dev_x", extra: 1 }), {
          status: 201,
          headers: { "content-type": "application/json" },
        });
      }
      return fetch(input, init);
    };
    const outcome = await completeEnrollmentCeremony(payload, {
      credentials: syntheticAuthenticator(RP_ID, ORIGIN).container,
      cheapLane: await cheapLanePair(),
      fetchImpl: wrappedFetch,
      baseUrl: base,
    });
    expect(cp.enrolledDevices?.activeDeviceCount).toBe(1); // the real spend landed
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.outcome).toBe("unknown");
      expect(outcome.reason).toMatch(/pinned \{deviceId\} contract/);
    }
  });

  it("a WRONG cheap-lane key (proof mismatch) is refused by the SERVER with the invite alive", async () => {
    const { cp, base } = await liveServer();
    const payload = mintPayload(cp);
    // sabotage: sign the PoP with a key OTHER than the submitted public key
    const submitted = await cheapLanePair();
    const signer = await cheapLanePair();
    const outcome = await completeEnrollmentCeremony(payload, {
      credentials: syntheticAuthenticator(RP_ID, ORIGIN).container,
      cheapLane: { privateKey: signer.privateKey, publicKey: submitted.publicKey },
      fetchImpl: fetch,
      baseUrl: base,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.reason).toMatch(/proof of possession/);
      expect(outcome.inviteSurvives).toBe(true);
    }
    expect(cp.enrolledDevices?.activeDeviceCount).toBe(0);
  });
});
