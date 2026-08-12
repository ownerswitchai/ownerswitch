import { createHmac } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { EscalationAlert } from "../types.js";
import {
  alertTwiml,
  createTwilioSmsChannel,
  createTwilioVoiceChannel,
  TWILIO_PATHS,
  verifyTwilioSignature,
  type TwilioConfig,
} from "./twilio.js";

const ALERT: EscalationAlert = {
  windowIds: ["v-1", "v-2"],
  headline: "OwnerSwitch: 2 actions held for your review",
  deadlineMs: 240_000,
};

const cfg = (overrides: Partial<TwilioConfig> = {}): TwilioConfig => ({
  accountSid: "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  authToken: "test-auth-token",
  from: "+15550001111",
  to: "+36301234567",
  webhookBaseUrl: "https://escalation.example",
  now: () => 42_000,
  ...overrides,
});

/** A verified Twilio form callback for `url`, signed the way Twilio signs. */
const signedCallback = (authToken: string, url: string, form: Record<string, string>) => {
  const params = new URLSearchParams(form);
  const keys = [...params.keys()].sort();
  let payload = url;
  for (const key of keys) payload += key + (params.get(key) ?? "");
  return {
    rawBody: params.toString(),
    url,
    headers: {
      "X-Twilio-Signature": createHmac("sha1", authToken).update(payload).digest("base64"),
    },
  };
};

const okFetch = (sid: string) =>
  vi.fn(async () => new Response(JSON.stringify({ sid }), { status: 201 }));

describe("twilio SMS channel", () => {
  it("sends the terse alert form-encoded with basic auth, and reports the attempt", async () => {
    const doFetch = okFetch("SM123");
    const channel = createTwilioSmsChannel(cfg({ fetch: doFetch as unknown as typeof fetch }));
    const attempt = await channel.send(ALERT);

    expect(attempt).toEqual({
      channel: "sms",
      windowIds: ["v-1", "v-2"],
      at: 42_000,
      providerRef: "SM123",
      estimatedCostUsd: 0.008,
    });
    const [url, init] = doFetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(
      "https://api.twilio.com/2010-04-01/Accounts/ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/Messages.json",
    );
    const headers = init.headers as Record<string, string>;
    expect(headers.authorization).toMatch(/^Basic /);
    const body = new URLSearchParams(init.body as string);
    expect(body.get("To")).toBe("+36301234567");
    expect(body.get("Body")).toBe("OwnerSwitch: 2 actions held for your review. Reply 1 to stop.");
    expect(body.get("StatusCallback")).toBe("https://escalation.example/twilio/sms-status");
    // the terse rule: window ids and arguments never ride the SMS text
    expect(body.get("Body")).not.toContain("v-1");
  });

  it("a failed send throws status-only — the alert text must not leak into logs", async () => {
    const doFetch = vi.fn(async () => new Response("upstream text", { status: 401 }));
    const channel = createTwilioSmsChannel(cfg({ fetch: doFetch as unknown as typeof fetch }));
    await expect(channel.send(ALERT)).rejects.toThrow(/HTTP 401/);
    await expect(channel.send(ALERT)).rejects.not.toThrow(/upstream/);
  });

  it('an owner reply of "1" becomes a deny-only veto with honest attribution', () => {
    const c = cfg();
    const channel = createTwilioSmsChannel(c);
    const url = `${c.webhookBaseUrl}${TWILIO_PATHS.smsInbound}`;
    const events = channel.handleCallback(
      signedCallback(c.authToken, url, { From: "+36301234567", Body: " 1 " }),
    );
    expect(events).toEqual([
      { type: "veto", windowIds: [], channel: "sms", attribution: "channel:sms-reply" },
    ]);
  });

  it("replies from any other number, or any other text, yield nothing", () => {
    const c = cfg();
    const channel = createTwilioSmsChannel(c);
    const url = `${c.webhookBaseUrl}${TWILIO_PATHS.smsInbound}`;
    expect(
      channel.handleCallback(signedCallback(c.authToken, url, { From: "+15559999999", Body: "1" })),
    ).toEqual([]);
    expect(
      channel.handleCallback(signedCallback(c.authToken, url, { From: "+36301234567", Body: "ok" })),
    ).toEqual([]);
  });

  it("a delivery receipt is device-received evidence and can never mark delivered", () => {
    const c = cfg();
    const channel = createTwilioSmsChannel(c);
    const url = `${c.webhookBaseUrl}${TWILIO_PATHS.smsStatus}`;
    const events = channel.handleCallback(
      signedCallback(c.authToken, url, {
        MessageStatus: "delivered",
        MessageSid: "SM123",
        To: "+36301234567",
      }),
    );
    expect(events).toEqual([
      {
        type: "evidence",
        windowIds: [],
        evidence: {
          level: "device-received",
          channel: "sms",
          at: 42_000,
          providerRef: "SM123",
          marksDelivered: false,
        },
      },
    ]);
    // non-terminal statuses are noise
    expect(
      channel.handleCallback(signedCallback(c.authToken, url, { MessageStatus: "sent" })),
    ).toEqual([]);
  });

  it("a bad or missing signature yields no events — never a guess", () => {
    const c = cfg();
    const channel = createTwilioSmsChannel(c);
    const url = `${c.webhookBaseUrl}${TWILIO_PATHS.smsInbound}`;
    const good = signedCallback(c.authToken, url, { From: "+36301234567", Body: "1" });
    expect(channel.handleCallback({ ...good, headers: {} })).toEqual([]);
    expect(
      channel.handleCallback({
        ...good,
        headers: { "X-Twilio-Signature": "AAAA" + "A".repeat(24) },
      }),
    ).toEqual([]);
    // signed for a different URL (proxy confusion) — refused
    expect(
      channel.handleCallback({ ...good, url: "https://escalation.example/other" }),
    ).toEqual([]);
    // no URL at all — unverifiable, refused
    const { url: _dropped, ...withoutUrl } = good;
    expect(channel.handleCallback(withoutUrl)).toEqual([]);
  });
});

describe("twilio voice channel", () => {
  it("dials with inline TwiML that only ever offers to stop", async () => {
    const doFetch = okFetch("CA123");
    const channel = createTwilioVoiceChannel(cfg({ fetch: doFetch as unknown as typeof fetch }));
    const attempt = await channel.send(ALERT);
    expect(attempt).toMatchObject({ channel: "voice", providerRef: "CA123", estimatedCostUsd: 0.014 });

    const [url, init] = doFetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain("/Calls.json");
    const twiml = new URLSearchParams(init.body as string).get("Twiml")!;
    expect(twiml).toContain("Press 1 to stop it");
    expect(twiml).toContain('action="https://escalation.example/twilio/voice-key"');
    // the vishing-defeating invariant: no approval flow on any telephone
    // channel, ever — the word does not appear in the call script
    expect(twiml.toLowerCase()).not.toContain("approve");
    expect(twiml.toLowerCase()).not.toContain("code");
  });

  it("press-1 yields human-interacted evidence plus a deny-only veto", () => {
    const c = cfg();
    const channel = createTwilioVoiceChannel(c);
    const url = `${c.webhookBaseUrl}${TWILIO_PATHS.voiceKey}`;
    const events = channel.handleCallback(
      signedCallback(c.authToken, url, { Digits: "1", CallSid: "CA123" }),
    );
    expect(events).toEqual([
      {
        type: "evidence",
        windowIds: [],
        evidence: {
          level: "human-interacted",
          channel: "voice",
          at: 42_000,
          providerRef: "CA123",
          interaction: "dtmf:1",
          marksDelivered: false,
        },
      },
      { type: "veto", windowIds: [], channel: "voice", attribution: "channel:voice-dtmf" },
    ]);
  });

  it("any other keypress is evidence only — no verb", () => {
    const c = cfg();
    const channel = createTwilioVoiceChannel(c);
    const url = `${c.webhookBaseUrl}${TWILIO_PATHS.voiceKey}`;
    const events = channel.handleCallback(signedCallback(c.authToken, url, { Digits: "9" }));
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("evidence");
  });

  it("alertTwiml escapes markup out of the spoken text", () => {
    const twiml = alertTwiml(
      { windowIds: ["v-1"], headline: 'OwnerSwitch: "<script>" held', deadlineMs: 0 },
      "https://x.example/a",
    );
    expect(twiml).not.toContain("<script>");
    expect(twiml).toContain("&lt;script&gt;");
  });
});

describe("config and signature primitives", () => {
  it("refuses an http webhook base and missing credentials", () => {
    expect(() => createTwilioSmsChannel(cfg({ webhookBaseUrl: "http://x.example" }))).toThrow(
      /https/,
    );
    expect(() => createTwilioSmsChannel(cfg({ authToken: "" }))).toThrow(/authToken/);
  });

  it("verifyTwilioSignature is order-insensitive over params and constant-shape on garbage", () => {
    const url = "https://escalation.example/twilio/sms";
    const params = new URLSearchParams({ B: "2", A: "1" });
    let payload = url + "A1B2";
    const sig = createHmac("sha1", "tok").update(payload).digest("base64");
    expect(verifyTwilioSignature("tok", url, params, sig)).toBe(true);
    expect(verifyTwilioSignature("tok", url, params, undefined)).toBe(false);
    expect(verifyTwilioSignature("tok", url, params, "")).toBe(false);
    expect(verifyTwilioSignature("tok", url, params, "not-base64-!!")).toBe(false);
    expect(verifyTwilioSignature("other", url, params, sig)).toBe(false);
  });
});
