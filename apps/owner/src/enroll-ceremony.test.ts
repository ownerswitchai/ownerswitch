import { createHash, generateKeyPairSync, randomBytes, sign as ecSign } from "node:crypto";
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

/** minimal canonical CBOR encoder — maps, text, bytes, ints (the fixture subset) */
function cborEncode(value: unknown): Buffer {
  const head = (major: number, length: number): Buffer => {
    if (length < 24) return Buffer.from([(major << 5) | length]);
    if (length < 256) return Buffer.from([(major << 5) | 24, length]);
    return Buffer.from([(major << 5) | 25, (length >> 8) & 0xff, length & 0xff]);
  };
  if (typeof value === "number" && Number.isInteger(value)) {
    return value >= 0 ? head(0, value) : head(1, -value - 1);
  }
  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) {
    return Buffer.concat([head(2, value.length), Buffer.from(value)]);
  }
  if (value instanceof Map) {
    const parts: Buffer[] = [head(5, value.size)];
    for (const [k, v] of value) {
      parts.push(cborEncode(k), cborEncode(v));
    }
    return Buffer.concat(parts);
  }
  throw new Error("unsupported CBOR fixture value");
}

/**
 * The synthetic platform authenticator: a real P-256 keypair behind a
 * CredentialsContainer-shaped object. create() emits fmt:"none" attestation
 * over the SERVER's challenge; get() signs the SERVER's assertion challenge
 * with the same key — exactly what the ceremony must prove.
 */
function syntheticAuthenticator() {
  const webauthn = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const credentialId = randomBytes(24);
  let signCount = 2;
  const clientData = (type: string, challenge: Uint8Array) =>
    Buffer.from(JSON.stringify({ type, challenge: Buffer.from(challenge).toString("base64url"), origin: ORIGIN }));
  return {
    create: async (request: { publicKey: { challenge: Uint8Array; user: { id: Uint8Array } } }) => {
      const jwk = webauthn.publicKey.export({ format: "jwk" }) as { x: string; y: string };
      const cose = new Map<number, unknown>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, new Uint8Array(Buffer.from(jwk.x, "base64url"))],
        [-3, new Uint8Array(Buffer.from(jwk.y, "base64url"))],
      ]);
      signCount += 1;
      const authData = Buffer.concat([
        createHash("sha256").update(RP_ID, "utf8").digest(),
        Buffer.from([0x45]), // UP | UV | AT
        Buffer.from([0, 0, 0, signCount]),
        Buffer.alloc(16),
        Buffer.from([(credentialId.length >> 8) & 0xff, credentialId.length & 0xff]),
        credentialId,
        cborEncode(cose),
      ]);
      const attestationObject = cborEncode(
        new Map<unknown, unknown>([
          ["fmt", "none"],
          ["attStmt", new Map()],
          ["authData", new Uint8Array(authData)],
        ]),
      );
      return {
        rawId: new Uint8Array(credentialId).buffer,
        response: {
          clientDataJSON: new Uint8Array(clientData("webauthn.create", request.publicKey.challenge)).buffer,
          attestationObject: new Uint8Array(attestationObject).buffer,
          getTransports: () => ["internal"],
        },
      };
    },
    get: async (request: { publicKey: { challenge: Uint8Array } }) => {
      const cd = clientData("webauthn.get", request.publicKey.challenge);
      signCount += 1;
      const authenticatorData = Buffer.concat([
        createHash("sha256").update(RP_ID, "utf8").digest(),
        Buffer.from([0x05]), // UP | UV
        Buffer.from([0, 0, 0, signCount]),
      ]);
      const signature = ecSign(
        "sha256",
        Buffer.concat([authenticatorData, createHash("sha256").update(cd).digest()]),
        webauthn.privateKey,
      );
      return {
        rawId: new Uint8Array(credentialId).buffer,
        response: {
          clientDataJSON: new Uint8Array(cd).buffer,
          authenticatorData: new Uint8Array(authenticatorData).buffer,
          signature: new Uint8Array(signature).buffer,
          userHandle: null,
        },
      };
    },
  };
}

/** a live dev control plane with enrollment wired, listening on loopback */
async function liveServer(): Promise<{ cp: ControlPlane; base: string }> {
  const dir = mkdtempSync(join(tmpdir(), "ownerswitch-ceremony-"));
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
    const { cp, base } = await liveServer();
    const payload = mintPayload(cp);
    const outcome = await completeEnrollmentCeremony(payload, {
      credentials: syntheticAuthenticator(),
      cheapLane: await cheapLanePair(),
      fetchImpl: fetch,
      baseUrl: base,
    });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.deviceId).toMatch(/^dev_/);
    // the registry really admitted it — durable state, not a mock
    expect(cp.enrolledDevices?.activeDeviceCount).toBe(1);
    expect(cp.enrolledDevices?.get(outcome.deviceId)?.deviceName).toBe("Adam's phone");

    // REPLAY: the spent invite is gone, and the refusal says so honestly
    const replay = await completeEnrollmentCeremony(payload, {
      credentials: syntheticAuthenticator(),
      cheapLane: await cheapLanePair(),
      fetchImpl: fetch,
      baseUrl: base,
    });
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.inviteSurvives).toBe(false);
  });

  it("a REFUSED possession assertion stops the ceremony with the invite untouched — the honest retry then lands", async () => {
    const { cp, base } = await liveServer();
    const payload = mintPayload(cp);
    const authenticator = syntheticAuthenticator();
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
      credentials: syntheticAuthenticator(),
      cheapLane: await cheapLanePair(),
      fetchImpl: fetch,
      baseUrl: base,
    });
    expect(retry.ok).toBe(true);
  });

  it("an UNREACHABLE control plane reports inviteSurvives: true — nothing was spent", async () => {
    const { cp } = await liveServer();
    const payload = mintPayload(cp);
    const outcome = await completeEnrollmentCeremony(payload, {
      credentials: syntheticAuthenticator(),
      cheapLane: await cheapLanePair(),
      fetchImpl: fetch,
      baseUrl: "http://127.0.0.1:9", // discard port — nothing listens
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.reason).toMatch(/unreachable/);
      expect(outcome.inviteSurvives).toBe(true);
    }
  });

  it("a WRONG cheap-lane key (proof mismatch) is refused by the SERVER with the invite alive", async () => {
    const { cp, base } = await liveServer();
    const payload = mintPayload(cp);
    // sabotage: sign the PoP with a key OTHER than the submitted public key
    const submitted = await cheapLanePair();
    const signer = await cheapLanePair();
    const outcome = await completeEnrollmentCeremony(payload, {
      credentials: syntheticAuthenticator(),
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
