import { createHmac, timingSafeEqual } from "node:crypto";
import type {
  Channel,
  ChannelEvent,
  ChannelAttempt,
  EscalationAlert,
  ProviderCallback,
} from "../types.js";

/**
 * The SMS and voice rungs, spoken to Twilio's REST API directly — no SDK.
 * The interface stays provider-agnostic (`Channel`); nothing outside this
 * file may know which provider is behind it (DESIGN.md §6), and nothing in
 * this file may know a credential's value at rest: everything secret
 * arrives through TwilioConfig, which the service edge fills from the
 * environment. The PUBLIC repo carries the code; the credentials exist
 * only in the deployment's env (see README).
 *
 * Doctrine encoded here (DESIGN.md §2):
 *  - both channels carry exactly one verb back: STOP. A reply of "1" or a
 *    DTMF press of 1 becomes a veto event with an honest channel
 *    attribution — never a confirmation, never an approval
 *    (`verbs.approve` is the literal false and `confirmSeen` is false).
 *  - callbacks are signature-verified (X-Twilio-Signature) before they are
 *    believed; a bad signature yields no events, never a guess.
 *  - the alert text is terse: a tool name and a count at most. Arguments
 *    never ride an SMS or a phone call.
 */

export interface TwilioConfig {
  accountSid: string;
  authToken: string;
  /** the provisioned E.164 number sends and calls originate from */
  from: string;
  /** the owner's E.164 number */
  to: string;
  /**
   * Public base URL of the escalation service's webhook server
   * (e.g. https://escalation.example) — where Twilio posts DTMF keypresses,
   * inbound SMS and delivery receipts. Twilio signs callbacks over the full
   * advertised URL, so this must be the externally visible one.
   */
  webhookBaseUrl: string;
  /** injectable for tests; default globalThis.fetch */
  fetch?: typeof fetch;
  now?: () => number;
}

/** Webhook paths this channel advertises to Twilio, exported for the edge. */
export const TWILIO_PATHS = {
  smsInbound: "/twilio/sms",
  smsStatus: "/twilio/sms-status",
  voiceKey: "/twilio/voice-key",
} as const;

/** List-price estimates (DESIGN.md §6) for the spend ceiling — not billing truth. */
export const TWILIO_COST_USD = { sms: 0.008, voice: 0.014 } as const;

const API = "https://api.twilio.com/2010-04-01";

function assertConfig(cfg: TwilioConfig): void {
  for (const key of ["accountSid", "authToken", "from", "to", "webhookBaseUrl"] as const) {
    if (typeof cfg[key] !== "string" || cfg[key] === "") {
      throw new Error(`TwilioConfig.${key} is required`);
    }
  }
  if (!cfg.webhookBaseUrl.startsWith("https://")) {
    throw new Error(
      "TwilioConfig.webhookBaseUrl must be https:// — Twilio signs callbacks over the advertised " +
        "URL, and an http webhook hands the deny channel to any on-path attacker",
    );
  }
}

/**
 * X-Twilio-Signature over a form-encoded POST: base64(HMAC-SHA1(authToken,
 * url + concat(sortedKey + value))). Exported for the webhook edge's tests.
 * Constant-time comparison; an empty or absent signature never verifies.
 */
export function verifyTwilioSignature(
  authToken: string,
  url: string,
  params: URLSearchParams,
  signature: string | undefined,
): boolean {
  if (signature === undefined || signature === "") return false;
  const keys = [...new Set([...params.keys()])].sort();
  let payload = url;
  for (const key of keys) payload += key + (params.get(key) ?? "");
  const expected = createHmac("sha1", authToken).update(payload).digest();
  let provided: Buffer;
  try {
    provided = Buffer.from(signature, "base64");
  } catch {
    return false;
  }
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}

function headerOf(callback: ProviderCallback, name: string): string | undefined {
  for (const [key, value] of Object.entries(callback.headers)) {
    if (key.toLowerCase() === name) return value;
  }
  return undefined;
}

/** Verified form params of a Twilio callback, or null (bad/missing signature). */
function verifiedParams(cfg: TwilioConfig, callback: ProviderCallback): URLSearchParams | null {
  if (callback.url === undefined) return null;
  const params = new URLSearchParams(callback.rawBody);
  const signature = headerOf(callback, "x-twilio-signature");
  return verifyTwilioSignature(cfg.authToken, callback.url, params, signature) ? params : null;
}

async function twilioPost(
  cfg: TwilioConfig,
  resource: "Messages" | "Calls",
  form: Record<string, string>,
): Promise<string | undefined> {
  const doFetch = cfg.fetch ?? fetch;
  const res = await doFetch(`${API}/Accounts/${encodeURIComponent(cfg.accountSid)}/${resource}.json`, {
    method: "POST",
    headers: {
      authorization: `Basic ${Buffer.from(`${cfg.accountSid}:${cfg.authToken}`).toString("base64")}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(form).toString(),
  });
  if (!res.ok) {
    // No response body in the error: Twilio error payloads echo request
    // fields, and the alert text plus the owner's number must not leak into
    // logs by way of an exception message.
    throw new Error(`twilio ${resource} send failed: HTTP ${res.status}`);
  }
  const body = (await res.json().catch(() => ({}))) as { sid?: unknown };
  return typeof body.sid === "string" ? body.sid : undefined;
}

const xmlEscape = (text: string) =>
  text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");

/**
 * The under-a-minute alert call (DESIGN.md §6): read the alert, offer
 * press-1, hang up. A real OwnerSwitch call ONLY ever offers to stop —
 * never a code to read back, never a key to approve (§2); this TwiML is
 * that invariant.
 */
export function alertTwiml(alert: EscalationAlert, actionUrl: string): string {
  const say = xmlEscape(
    `${alert.headline}. Press 1 to stop it. If you do nothing, the system follows your policy.`,
  );
  return (
    `<?xml version="1.0" encoding="UTF-8"?><Response>` +
    `<Gather numDigits="1" timeout="10" action="${xmlEscape(actionUrl)}" method="POST">` +
    `<Say>${say}</Say></Gather>` +
    `<Say>No input received. Goodbye.</Say></Response>`
  );
}

export function createTwilioSmsChannel(cfg: TwilioConfig): Channel {
  assertConfig(cfg);
  const now = cfg.now ?? Date.now;
  return {
    kind: "sms",
    verbs: { stop: true, confirmSeen: false, approve: false },
    async send(alert: EscalationAlert): Promise<ChannelAttempt> {
      const sid = await twilioPost(cfg, "Messages", {
        To: cfg.to,
        From: cfg.from,
        Body: `${alert.headline}. Reply 1 to stop.`,
        StatusCallback: `${cfg.webhookBaseUrl}${TWILIO_PATHS.smsStatus}`,
      });
      return {
        channel: "sms",
        windowIds: alert.windowIds,
        at: now(),
        ...(sid !== undefined ? { providerRef: sid } : {}),
        estimatedCostUsd: TWILIO_COST_USD.sms,
      };
    },
    handleCallback(callback: ProviderCallback): ChannelEvent[] {
      const params = verifiedParams(cfg, callback);
      if (params === null) return [];
      // inbound reply: a "1" from the owner's number is a stop — deny-only,
      // honestly attributed to the channel (a SIM swap can forge it, and
      // forging it only makes the system more conservative)
      if (params.has("Body") && !params.has("MessageStatus")) {
        if (params.get("From") !== cfg.to) return []; // not the owner's number: ignore
        if (params.get("Body")?.trim() !== "1") return [];
        return [
          { type: "veto", windowIds: [], channel: "sms", attribution: "channel:sms-reply" },
        ];
      }
      // delivery receipt: proof A HANDSET got the bytes — device-received,
      // marksDelivered stays false forever on this path (DESIGN.md §3)
      if (params.get("MessageStatus") === "delivered") {
        const ref = params.get("MessageSid") ?? params.get("SmsSid");
        return [
          {
            type: "evidence",
            windowIds: [],
            evidence: {
              level: "device-received",
              channel: "sms",
              at: now(),
              ...(ref !== null ? { providerRef: ref } : {}),
              marksDelivered: false,
            },
          },
        ];
      }
      return [];
    },
  };
}

export function createTwilioVoiceChannel(cfg: TwilioConfig): Channel {
  assertConfig(cfg);
  const now = cfg.now ?? Date.now;
  return {
    kind: "voice",
    verbs: { stop: true, confirmSeen: false, approve: false },
    async send(alert: EscalationAlert): Promise<ChannelAttempt> {
      const sid = await twilioPost(cfg, "Calls", {
        To: cfg.to,
        From: cfg.from,
        Twiml: alertTwiml(alert, `${cfg.webhookBaseUrl}${TWILIO_PATHS.voiceKey}`),
      });
      return {
        channel: "voice",
        windowIds: alert.windowIds,
        at: now(),
        ...(sid !== undefined ? { providerRef: sid } : {}),
        estimatedCostUsd: TWILIO_COST_USD.voice,
      };
    },
    handleCallback(callback: ProviderCallback): ChannelEvent[] {
      const params = verifiedParams(cfg, callback);
      if (params === null) return [];
      const digits = params.get("Digits");
      if (digits === null) return [];
      const ref = params.get("CallSid");
      // any keypress proves a human at that number interacted — evidence,
      // never delivery; "1" additionally carries the one verb this channel
      // has: stop
      const events: ChannelEvent[] = [
        {
          type: "evidence",
          windowIds: [],
          evidence: {
            level: "human-interacted",
            channel: "voice",
            at: now(),
            ...(ref !== null ? { providerRef: ref } : {}),
            interaction: `dtmf:${digits}`,
            marksDelivered: false,
          },
        },
      ];
      if (digits === "1") {
        events.push({
          type: "veto",
          windowIds: [],
          channel: "voice",
          attribution: "channel:voice-dtmf",
        });
      }
      return events;
    },
  };
}
