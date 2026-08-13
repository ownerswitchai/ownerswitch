/**
 * TEST-ONLY synthetic platform authenticator: a real P-256 keypair behind a
 * CredentialsContainer-shaped object. create() emits fmt:"none" attestation
 * over the caller-supplied challenge; get() signs with the same key. Every
 * request's parameters are RECORDED in `seen`, so tests can assert the
 * ceremony handed the platform exactly the server's rpId, credential id,
 * and userVerification requirement.
 */
import { createHash, generateKeyPairSync, randomBytes, sign as ecSign } from "node:crypto";

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

export interface SeenWebAuthnParams {
  create: Array<{ rpId: string; rpName: string; userVerification: string; userIdB64: string }>;
  get: Array<{ rpId: string; userVerification: string; allowCredentialIdsB64: string[] }>;
}

export function syntheticAuthenticator(rpId: string, origin: string) {
  const webauthn = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const credentialId = randomBytes(24);
  let signCount = 2;
  const seen: SeenWebAuthnParams = { create: [], get: [] };
  const clientData = (type: string, challenge: Uint8Array) =>
    Buffer.from(
      JSON.stringify({ type, challenge: Buffer.from(challenge).toString("base64url"), origin }),
    );
  const container = {
    create: async (request: {
      publicKey: {
        challenge: Uint8Array;
        rp: { id: string; name: string };
        user: { id: Uint8Array };
        authenticatorSelection: { userVerification: string };
      };
    }) => {
      seen.create.push({
        rpId: request.publicKey.rp.id,
        rpName: request.publicKey.rp.name,
        userVerification: request.publicKey.authenticatorSelection.userVerification,
        userIdB64: Buffer.from(request.publicKey.user.id).toString("base64url"),
      });
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
        createHash("sha256").update(rpId, "utf8").digest(),
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
          clientDataJSON: new Uint8Array(clientData("webauthn.create", request.publicKey.challenge))
            .buffer,
          attestationObject: new Uint8Array(attestationObject).buffer,
          getTransports: () => ["internal"],
        },
      };
    },
    get: async (request: {
      publicKey: {
        challenge: Uint8Array;
        rpId: string;
        userVerification: string;
        allowCredentials: Array<{ id: Uint8Array | ArrayBuffer }>;
      };
    }) => {
      seen.get.push({
        rpId: request.publicKey.rpId,
        userVerification: request.publicKey.userVerification,
        allowCredentialIdsB64: request.publicKey.allowCredentials.map((c) =>
          Buffer.from(c.id instanceof ArrayBuffer ? new Uint8Array(c.id) : c.id).toString("base64url"),
        ),
      });
      const cd = clientData("webauthn.get", request.publicKey.challenge);
      signCount += 1;
      const authenticatorData = Buffer.concat([
        createHash("sha256").update(rpId, "utf8").digest(),
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
  return { container, seen, credentialId };
}
