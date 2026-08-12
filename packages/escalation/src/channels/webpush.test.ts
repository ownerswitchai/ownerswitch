import { createDecipheriv, createECDH, createPublicKey, hkdfSync, verify as cryptoVerify } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { EscalationAlert } from "../types.js";
import {
  createWebPushChannel,
  encryptPushPayload,
  generateVapidKeys,
  vapidAuthorization,
  type PushSubscriptionJson,
  type WebPushConfig,
} from "./webpush.js";

const ALERT: EscalationAlert = {
  windowIds: ["v-1"],
  headline: 'OwnerSwitch: "write_file" held for your review',
  deadlineMs: 240_000,
};

/** A browser-side subscription: real P-256 keypair + 16-byte auth secret. */
const makeClient = () => {
  const ua = createECDH("prime256v1");
  ua.generateKeys();
  const auth = Buffer.from("0123456789abcdef"); // fixed 16 bytes for the test
  const subscription: PushSubscriptionJson = {
    endpoint: "https://push.example/send/abc123",
    keys: { p256dh: ua.getPublicKey().toString("base64url"), auth: auth.toString("base64url") },
  };
  return { ua, auth, subscription };
};

/** The CLIENT side of RFC 8291 — what a service worker's push event does. */
const clientDecrypt = (client: ReturnType<typeof makeClient>, body: Buffer): Buffer => {
  const salt = body.subarray(0, 16);
  const rs = body.readUInt32BE(16);
  expect(rs).toBe(4096);
  const idlen = body.readUInt8(20);
  expect(idlen).toBe(65);
  const asPublic = body.subarray(21, 21 + idlen);
  const ciphertext = body.subarray(21 + idlen);

  const ecdhSecret = client.ua.computeSecret(asPublic);
  const keyInfo = Buffer.concat([
    Buffer.from("WebPush: info\0"),
    client.ua.getPublicKey(),
    asPublic,
  ]);
  const ikm = Buffer.from(hkdfSync("sha256", ecdhSecret, client.auth, keyInfo, 32));
  const cek = Buffer.from(
    hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: aes128gcm\0"), 16),
  );
  const nonce = Buffer.from(
    hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: nonce\0"), 12),
  );
  const decipher = createDecipheriv("aes-128-gcm", cek, nonce);
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  const padded = Buffer.concat([
    decipher.update(ciphertext.subarray(0, ciphertext.length - 16)),
    decipher.final(),
  ]);
  expect(padded[padded.length - 1]).toBe(0x02); // last-record delimiter
  return padded.subarray(0, padded.length - 1);
};

describe("RFC 8291 payload encryption", () => {
  it("a client holding the subscription keys decrypts byte-exact", () => {
    const client = makeClient();
    const plaintext = Buffer.from(JSON.stringify({ hello: "owner" }));
    const body = encryptPushPayload(client.subscription, plaintext);
    expect(clientDecrypt(client, body)).toEqual(plaintext);
  });

  it("every message uses a fresh salt and ephemeral key — no two ciphertexts match", () => {
    const client = makeClient();
    const plaintext = Buffer.from("same bytes");
    const a = encryptPushPayload(client.subscription, plaintext);
    const b = encryptPushPayload(client.subscription, plaintext);
    expect(a.equals(b)).toBe(false);
    expect(clientDecrypt(client, a)).toEqual(clientDecrypt(client, b));
  });

  it("refuses malformed subscription keys", () => {
    const client = makeClient();
    expect(() =>
      encryptPushPayload(
        { ...client.subscription, keys: { ...client.subscription.keys, auth: "c2hvcnQ" } },
        Buffer.from("x"),
      ),
    ).toThrow(/16 bytes/);
    expect(() =>
      encryptPushPayload(
        { ...client.subscription, keys: { ...client.subscription.keys, p256dh: "AAAA" } },
        Buffer.from("x"),
      ),
    ).toThrow(/65-byte/);
  });
});

describe("VAPID (RFC 8292)", () => {
  it("generateVapidKeys mints a pair whose JWT verifies against the public key", () => {
    const { publicKey, privateKey } = generateVapidKeys();
    const header = vapidAuthorization(
      { vapidPublicKey: publicKey, vapidPrivateKey: privateKey, subject: "mailto:o@example.com" },
      "https://push.example",
      1_700_000_000_000,
    );
    expect(header).toMatch(/^vapid t=.+, k=.+$/);
    const jwt = /t=([^,]+),/.exec(header)![1];
    const [h, c, s] = jwt.split(".");
    const claims = JSON.parse(Buffer.from(c, "base64url").toString()) as Record<string, unknown>;
    expect(claims.aud).toBe("https://push.example");
    expect(claims.sub).toBe("mailto:o@example.com");
    expect(claims.exp).toBe(1_700_000_000 + 12 * 3600);

    const pub = Buffer.from(publicKey, "base64url");
    const key = createPublicKey({
      format: "jwk",
      key: {
        kty: "EC",
        crv: "P-256",
        x: pub.subarray(1, 33).toString("base64url"),
        y: pub.subarray(33, 65).toString("base64url"),
      },
    });
    const ok = cryptoVerify(
      "sha256",
      Buffer.from(`${h}.${c}`),
      { key, dsaEncoding: "ieee-p1363" },
      Buffer.from(s, "base64url"),
    );
    expect(ok).toBe(true);
  });

  it("a garbage public key is refused at construction, not at the first alert", () => {
    const { privateKey } = generateVapidKeys();
    expect(() =>
      createWebPushChannel({
        vapidPublicKey: "AAAA",
        vapidPrivateKey: privateKey,
        subject: "mailto:o@example.com",
        getSubscription: () => null,
      }),
    ).toThrow(/uncompressed P-256/);
  });
});

describe("the push channel", () => {
  const channelFor = (client: ReturnType<typeof makeClient>, doFetch: typeof fetch) => {
    const keys = generateVapidKeys();
    const cfg: WebPushConfig = {
      vapidPublicKey: keys.publicKey,
      vapidPrivateKey: keys.privateKey,
      subject: "mailto:o@example.com",
      getSubscription: () => client.subscription,
      fetch: doFetch,
      now: () => 42_000,
    };
    return createWebPushChannel(cfg);
  };

  it("POSTs an encrypted alert the subscribed device can decrypt, VAPID-signed for the endpoint origin", async () => {
    const client = makeClient();
    const doFetch = vi.fn(async () => new Response(null, { status: 201 }));
    const channel = channelFor(client, doFetch as unknown as typeof fetch);

    const attempt = await channel.send(ALERT);
    expect(attempt).toEqual({ channel: "push", windowIds: ["v-1"], at: 42_000, estimatedCostUsd: 0 });

    const [url, init] = doFetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(client.subscription.endpoint);
    const headers = init.headers as Record<string, string>;
    expect(headers.authorization).toMatch(/^vapid t=/);
    expect(headers["content-encoding"]).toBe("aes128gcm");
    expect(headers.ttl).toBe("300");
    expect(headers.urgency).toBe("high");

    const payload = JSON.parse(
      clientDecrypt(client, Buffer.from(init.body as Uint8Array)).toString(),
    ) as Record<string, unknown>;
    expect(payload).toEqual({
      type: "ownerswitch-alert",
      windowIds: ["v-1"],
      headline: ALERT.headline,
      deadline: 240_000,
    });
  });

  it("no enrolled subscription -> the send fails loudly (the rung degrades, fail closed)", async () => {
    const keys = generateVapidKeys();
    const channel = createWebPushChannel({
      vapidPublicKey: keys.publicKey,
      vapidPrivateKey: keys.privateKey,
      subject: "mailto:o@example.com",
      getSubscription: () => null,
    });
    await expect(channel.send(ALERT)).rejects.toThrow(/no push subscription/);
  });

  it("a dead subscription surfaces status-only; provider callbacks never become events", async () => {
    const client = makeClient();
    const doFetch = vi.fn(async () => new Response("gone body", { status: 410 }));
    const channel = channelFor(client, doFetch as unknown as typeof fetch);
    await expect(channel.send(ALERT)).rejects.toThrow(/HTTP 410/);

    expect(
      channel.handleCallback({ rawBody: "anything", headers: {}, url: "https://x.example" }),
    ).toEqual([]);
    expect(channel.verbs).toEqual({ stop: true, confirmSeen: true, approve: false });
  });
});
