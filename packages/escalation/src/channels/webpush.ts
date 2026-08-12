import {
  createECDH,
  createCipheriv,
  createPrivateKey,
  createSign,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import type {
  Channel,
  ChannelAttempt,
  ChannelEvent,
  EscalationAlert,
  ProviderCallback,
} from "../types.js";

/**
 * The push rung — the ladder's strongest channel and the only one whose
 * surface (the owner app) can also CONFIRM. Spoken directly as Web Push:
 * VAPID (RFC 8292) request signing plus aes128gcm payload encryption
 * (RFC 8291 over RFC 8188), all with node:crypto — no SDK, nothing to
 * audit but this file.
 *
 * What the push SERVICE (FCM, Apple, Mozilla) sees: the subscription
 * endpoint, timing, and ciphertext. The alert payload — window ids and the
 * headline — is end-to-end encrypted to the enrolled device's subscription
 * keys, so unlike SMS/voice the intermediary never reads even the terse
 * text (DESIGN.md §5's provider-metadata concern, minimized).
 *
 * What this channel deliberately CANNOT do: confirm delivery. A push
 * accepted (201) is provider-accepted evidence, nothing more. The
 * confirming ack rides the owner app's own authenticated path to the
 * control plane (POST /veto/:id/seen) and never touches this file —
 * `handleCallback` is empty because Web Push has no provider callback, and
 * that emptiness is the design (DESIGN.md §3).
 *
 * Secrets: the VAPID private key arrives via config from the environment;
 * the subscription (endpoint + client keys) is enrolled at runtime by the
 * owner app and lives in the service's private state file. Neither belongs
 * in the repo; the repo is public and stays that way (README).
 */

export interface PushSubscriptionJson {
  endpoint: string;
  keys: {
    /** base64url, the client's 65-byte uncompressed P-256 public key */
    p256dh: string;
    /** base64url, the client's 16-byte auth secret */
    auth: string;
  };
}

export interface WebPushConfig {
  /** base64url uncompressed P-256 public point (87/88 chars) — the `k=` of every request */
  vapidPublicKey: string;
  /** base64url 32-byte P-256 private scalar */
  vapidPrivateKey: string;
  /** mailto: or https: contact, the JWT `sub` */
  subject: string;
  /** the enrolled device's live subscription, or null when none is enrolled */
  getSubscription: () => PushSubscriptionJson | null;
  fetch?: typeof fetch;
  now?: () => number;
  /** push service retention when the device is offline; default 300 s */
  ttlSec?: number;
}

const b64url = (buf: Buffer | Uint8Array) => Buffer.from(buf).toString("base64url");
const fromB64url = (text: string) => Buffer.from(text, "base64url");

/** Mint a fresh VAPID keypair (raw base64url forms) — enrollment tooling. */
export function generateVapidKeys(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = privateKey.export({ format: "jwk" });
  const pub = Buffer.concat([
    Buffer.from([0x04]),
    fromB64url(jwk.x as string),
    fromB64url(jwk.y as string),
  ]);
  void publicKey;
  return { publicKey: b64url(pub), privateKey: jwk.d as string };
}

/** The VAPID ES256 JWT for `audience`, signed raw r||s per JOSE. */
export function vapidAuthorization(
  cfg: Pick<WebPushConfig, "vapidPublicKey" | "vapidPrivateKey" | "subject">,
  audience: string,
  nowMs: number,
): string {
  const pub = fromB64url(cfg.vapidPublicKey);
  if (pub.length !== 65 || pub[0] !== 0x04) {
    throw new Error("vapidPublicKey must be a base64url uncompressed P-256 point (65 bytes)");
  }
  const key = createPrivateKey({
    format: "jwk",
    key: {
      kty: "EC",
      crv: "P-256",
      d: cfg.vapidPrivateKey,
      x: b64url(pub.subarray(1, 33)),
      y: b64url(pub.subarray(33, 65)),
    },
  });
  const header = b64url(Buffer.from(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64url(
    Buffer.from(
      JSON.stringify({
        aud: audience,
        exp: Math.floor(nowMs / 1000) + 12 * 3600,
        sub: cfg.subject,
      }),
    ),
  );
  const signer = createSign("sha256").update(`${header}.${claims}`);
  const signature = signer.sign({ key, dsaEncoding: "ieee-p1363" });
  return `vapid t=${header}.${claims}.${b64url(signature)}, k=${cfg.vapidPublicKey}`;
}

/**
 * RFC 8291 encryption of one push message: ECDH over the subscription's
 * p256dh key, the double HKDF schedule, then a single aes128gcm record
 * (RFC 8188) with the ephemeral public key as keyid. Exported so the tests
 * can prove a client holding the subscription keys decrypts it byte-exact.
 */
export function encryptPushPayload(
  subscription: PushSubscriptionJson,
  plaintext: Buffer,
): Buffer {
  const uaPublic = fromB64url(subscription.keys.p256dh);
  if (uaPublic.length !== 65 || uaPublic[0] !== 0x04) {
    throw new Error("subscription p256dh must be a 65-byte uncompressed P-256 point");
  }
  const authSecret = fromB64url(subscription.keys.auth);
  if (authSecret.length !== 16) throw new Error("subscription auth secret must be 16 bytes");

  const ephemeral = createECDH("prime256v1");
  ephemeral.generateKeys();
  const asPublic = ephemeral.getPublicKey(); // 65-byte uncompressed
  const ecdhSecret = ephemeral.computeSecret(uaPublic);

  // IKM = HKDF(salt=auth, ecdh_secret, "WebPush: info" || 0x00 || ua_public || as_public, 32)
  const keyInfo = Buffer.concat([Buffer.from("WebPush: info\0"), uaPublic, asPublic]);
  const ikm = Buffer.from(hkdfSync("sha256", ecdhSecret, authSecret, keyInfo, 32));

  const salt = randomBytes(16);
  const cek = Buffer.from(hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: aes128gcm\0"), 16));
  const nonce = Buffer.from(hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: nonce\0"), 12));

  // one record: plaintext || 0x02 (last-record delimiter), AES-128-GCM
  const cipher = createCipheriv("aes-128-gcm", cek, nonce);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.concat([plaintext, Buffer.from([0x02])])),
    cipher.final(),
    cipher.getAuthTag(),
  ]);

  // aes128gcm header: salt(16) | rs(4, uint32BE) | idlen(1) | keyid(=as_public)
  const header = Buffer.alloc(16 + 4 + 1);
  salt.copy(header, 0);
  header.writeUInt32BE(4096, 16);
  header.writeUInt8(asPublic.length, 20);
  return Buffer.concat([header, asPublic, ciphertext]);
}

export function createWebPushChannel(cfg: WebPushConfig): Channel {
  for (const key of ["vapidPublicKey", "vapidPrivateKey", "subject"] as const) {
    if (typeof cfg[key] !== "string" || cfg[key] === "") {
      throw new Error(`WebPushConfig.${key} is required`);
    }
  }
  // fail at construction, not at the first alert: a bad key must not wait
  // for an incident to be discovered
  vapidAuthorization(cfg, "https://validate.invalid", 0);
  const now = cfg.now ?? Date.now;
  return {
    kind: "push",
    verbs: { stop: true, confirmSeen: true, approve: false },
    async send(alert: EscalationAlert): Promise<ChannelAttempt> {
      const subscription = cfg.getSubscription();
      if (subscription === null) {
        throw new Error("no push subscription enrolled — the owner app has not registered one");
      }
      const endpoint = new URL(subscription.endpoint);
      if (endpoint.protocol !== "https:") {
        throw new Error("push subscription endpoint must be https://");
      }
      // the payload is end-to-end encrypted; ids and the deadline may ride
      // it (unlike SMS text) because the push service sees only ciphertext
      const payload = Buffer.from(
        JSON.stringify({
          type: "ownerswitch-alert",
          windowIds: alert.windowIds,
          headline: alert.headline,
          deadline: alert.deadlineMs,
        }),
      );
      const body = encryptPushPayload(subscription, payload);
      const doFetch = cfg.fetch ?? fetch;
      const res = await doFetch(subscription.endpoint, {
        method: "POST",
        headers: {
          authorization: vapidAuthorization(cfg, endpoint.origin, now()),
          "content-encoding": "aes128gcm",
          "content-type": "application/octet-stream",
          ttl: String(cfg.ttlSec ?? 300),
          urgency: "high",
        },
        body: new Uint8Array(body),
      });
      if (!res.ok) {
        // 404/410 mean the subscription is dead — surfaced by status so the
        // edge can drop it and the owner re-enrolls; response bodies stay
        // out of the error (nothing from the push service belongs in logs)
        throw new Error(`web push send failed: HTTP ${res.status}`);
      }
      return {
        channel: "push",
        windowIds: alert.windowIds,
        at: now(),
        estimatedCostUsd: 0,
      };
    },
    handleCallback(_callback: ProviderCallback): ChannelEvent[] {
      // Web Push has no provider callback surface, and that is load-bearing:
      // nothing a push service could POST here may become evidence. The
      // confirming ack arrives at the CONTROL PLANE from the owner app,
      // authenticated — never through this channel (DESIGN.md §3).
      return [];
    },
  };
}
