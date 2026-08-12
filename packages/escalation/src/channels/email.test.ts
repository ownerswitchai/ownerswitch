import { describe, expect, it, vi } from "vitest";
import type { EscalationAlert } from "../types.js";
import {
  createEmailChannel,
  createSesSender,
  sesSigV4Headers,
  type EmailChannelConfig,
  type EmailSender,
} from "./email.js";

/** A typed sendEmail spy so mock.calls carries the message shape. */
const spySender = (result = { messageId: "msg-1" }) => vi.fn<EmailSender>(async () => result);

const ALERT: EscalationAlert = {
  windowIds: ["veto_abc", "veto_def"],
  headline: "OwnerSwitch: 2 actions held for your review",
  deadlineMs: 240_000,
};

const channelCfg = (overrides: Partial<EmailChannelConfig> = {}): EmailChannelConfig => ({
  from: "alerts@owner.example",
  to: "owner@example.com",
  ownerAppUrl: "https://owner.example",
  sendEmail: spySender(),
  now: () => 42_000,
  ...overrides,
});

describe("email channel — deep-link only, no stop verb", () => {
  it("carries no verb at all: cannot stop, confirm, or approve", () => {
    const channel = createEmailChannel(channelCfg());
    expect(channel.verbs).toEqual({ stop: false, confirmSeen: false, approve: false });
  });

  it("deep-links into the owner app and never embeds a one-click stop or arguments", async () => {
    const sendEmail = spySender({ messageId: "msg-9" });
    const channel = createEmailChannel(channelCfg({ sendEmail }));
    const attempt = await channel.send(ALERT);

    expect(attempt).toEqual({
      channel: "email",
      windowIds: ["veto_abc", "veto_def"],
      at: 42_000,
      providerRef: "msg-9",
      estimatedCostUsd: 0.0001,
    });
    const msg = sendEmail.mock.calls[0][0];
    expect(msg.subject).toBe(ALERT.headline);
    expect(msg.text).toContain("https://owner.example/#alert=veto_abc"); // deep link to the FIRST window
    // no one-click stop URL, no approve-by-email, no arguments
    expect(msg.text).not.toMatch(/\/veto\/[^#]*\/stop|\?veto=|action=stop/i);
    expect(msg.text.toLowerCase()).toContain("never asks you to approve");
  });

  it("has no callback surface — inbound yields nothing", () => {
    const channel = createEmailChannel(channelCfg());
    expect(channel.handleCallback({ rawBody: "anything", headers: {} })).toEqual([]);
  });

  it("refuses an http owner-app URL and missing fields", () => {
    expect(() => createEmailChannel(channelCfg({ ownerAppUrl: "http://owner.example" }))).toThrow(/https/);
    expect(() => createEmailChannel(channelCfg({ from: "" }))).toThrow(/from/);
  });
});

describe("Amazon SES v2 sender (raw REST + SigV4)", () => {
  const when = new Date("2026-08-12T09:30:00.000Z");
  const sig = { region: "eu-central-1", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "SECRETKEY" };

  it("signs deterministically and binds the body (SigV4 regression pin)", () => {
    const headers = sesSigV4Headers(sig, "email.eu-central-1.amazonaws.com", "/v2/email/outbound-emails", "{}", when);
    expect(headers["x-amz-date"]).toBe("20260812T093000Z");
    expect(headers.authorization).toMatch(
      /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20260812\/eu-central-1\/ses\/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/,
    );
    // deterministic for the same inputs
    const again = sesSigV4Headers(sig, "email.eu-central-1.amazonaws.com", "/v2/email/outbound-emails", "{}", when);
    expect(again.authorization).toBe(headers.authorization);
    // a different body changes the payload hash AND the signature
    const other = sesSigV4Headers(sig, "email.eu-central-1.amazonaws.com", "/v2/email/outbound-emails", '{"x":1}', when);
    expect(other["x-amz-content-sha256"]).not.toBe(headers["x-amz-content-sha256"]);
    expect(other.authorization).not.toBe(headers.authorization);
  });

  it("POSTs the SES v2 SendEmail shape to the regional endpoint and returns the message id", async () => {
    const doFetch = vi.fn(async () => new Response(JSON.stringify({ MessageId: "0100-abc" }), { status: 200 }));
    const send = createSesSender({ ...sig, fetch: doFetch as unknown as typeof fetch, amzDate: () => when });
    const result = await send({ from: "a@x.com", to: "b@y.com", subject: "hi", text: "body" });
    expect(result).toEqual({ messageId: "0100-abc" });

    const [url, init] = doFetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://email.eu-central-1.amazonaws.com/v2/email/outbound-emails");
    const headers = init.headers as Record<string, string>;
    expect(headers.authorization).toMatch(/^AWS4-HMAC-SHA256 /);
    const body = JSON.parse(init.body as string);
    expect(body.FromEmailAddress).toBe("a@x.com");
    expect(body.Destination.ToAddresses).toEqual(["b@y.com"]);
    expect(body.Content.Simple.Subject.Data).toBe("hi");
    expect(body.Content.Simple.Body.Text.Data).toBe("body");
  });

  it("a failed send throws status-only (no recipient/message leak) and refuses missing creds", async () => {
    const doFetch = vi.fn(async () => new Response("recipient b@y.com rejected", { status: 400 }));
    const send = createSesSender({ ...sig, fetch: doFetch as unknown as typeof fetch, amzDate: () => when });
    await expect(send({ from: "a@x.com", to: "b@y.com", subject: "s", text: "t" })).rejects.toThrow(/HTTP 400/);
    await expect(send({ from: "a@x.com", to: "b@y.com", subject: "s", text: "t" })).rejects.not.toThrow(/b@y\.com/);
    expect(() => createSesSender({ ...sig, secretAccessKey: "" })).toThrow(/secretAccessKey/);
  });
});
