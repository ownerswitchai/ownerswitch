import { createHash, createHmac } from "node:crypto";
import type { Channel, ChannelAttempt, ChannelEvent, EscalationAlert, ProviderCallback } from "../types.js";

/**
 * The email rung — the odd channel out (DESIGN.md §2). Email gets NO direct
 * stop verb: a one-click veto link would hand every mail scanner that
 * prefetches URLs a way to stop actions at random (fail-closed spam). So the
 * email only DEEP-LINKS into the owner app, where both the veto tap and the
 * ack are authenticated. Its verbs are all false — it cannot stop, cannot
 * confirm, cannot approve — and it has no callback surface (an SMTP accept or
 * an open-pixel proves approximately nothing, DESIGN.md §3). It earns its
 * rung by costing almost nothing and surviving a dead phone.
 *
 * Transport is injected (`sendEmail`) so the channel logic is provider-
 * agnostic and testable; a built-in Amazon SES v2 sender (raw REST + SigV4,
 * no SDK) is provided below.
 */

export interface EmailSendResult {
  /** provider message id, for the audit trail */
  messageId?: string;
}

export type EmailSender = (message: {
  from: string;
  to: string;
  subject: string;
  text: string;
}) => Promise<EmailSendResult>;

export interface EmailChannelConfig {
  from: string;
  to: string;
  /** base URL of the owner app; the alert deep-links to `${ownerAppUrl}/#alert=<windowId>` */
  ownerAppUrl: string;
  sendEmail: EmailSender;
  now?: () => number;
}

export const EMAIL_COST_USD = 0.0001;

function assertConfig(cfg: EmailChannelConfig): void {
  for (const key of ["from", "to", "ownerAppUrl"] as const) {
    if (typeof cfg[key] !== "string" || cfg[key] === "") throw new Error(`EmailChannelConfig.${key} is required`);
  }
  if (!/^https:\/\//.test(cfg.ownerAppUrl)) {
    throw new Error("EmailChannelConfig.ownerAppUrl must be https:// — the deep link opens the owner app");
  }
}

export function createEmailChannel(cfg: EmailChannelConfig): Channel {
  assertConfig(cfg);
  const now = cfg.now ?? Date.now;
  const base = cfg.ownerAppUrl.replace(/\/+$/, "");
  return {
    kind: "email",
    verbs: { stop: false, confirmSeen: false, approve: false },
    async send(alert: EscalationAlert): Promise<ChannelAttempt> {
      // Terse, like every rung: the provider sees this. A tool name and a
      // deep link at most — never arguments, and NO one-click stop.
      const link =
        alert.windowIds.length > 0 ? `${base}/#alert=${encodeURIComponent(alert.windowIds[0])}` : `${base}/#alert`;
      const text =
        `${alert.headline}\n\n` +
        `Open OwnerSwitch to review and, if needed, stop it:\n${link}\n\n` +
        "This link only opens the app — stopping happens there, authenticated. " +
        "OwnerSwitch never asks you to approve anything by email.";
      const result = await cfg.sendEmail({ from: cfg.from, to: cfg.to, subject: alert.headline, text });
      return {
        channel: "email",
        windowIds: alert.windowIds,
        at: now(),
        ...(result.messageId !== undefined ? { providerRef: result.messageId } : {}),
        estimatedCostUsd: EMAIL_COST_USD,
      };
    },
    handleCallback(_callback: ProviderCallback): ChannelEvent[] {
      // No inbound: email carries no verb and no evidence that counts.
      return [];
    },
  };
}

/* --------------------------- Amazon SES v2 sender --------------------------- */

export interface SesConfig {
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  fetch?: typeof fetch;
  /** injectable clock for the SigV4 date; default Date.now via new Date() at call */
  amzDate?: () => Date;
}

const sha256Hex = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
const hmac = (key: Buffer | string, data: string) => createHmac("sha256", key).update(data).digest();

/**
 * AWS SigV4 signing headers for a POST. Exported for tests. `amzDate` is the
 * request instant; the derived signing key rotates daily by date + region +
 * service, per the spec.
 */
export function sesSigV4Headers(
  cfg: Pick<SesConfig, "region" | "accessKeyId" | "secretAccessKey">,
  host: string,
  path: string,
  body: string,
  when: Date,
): Record<string, string> {
  const amz = when.toISOString().replace(/[:-]|\.\d{3}/g, ""); // YYYYMMDDTHHMMSSZ
  const date = amz.slice(0, 8);
  const service = "ses";
  const payloadHash = sha256Hex(body);
  const canonicalHeaders = `content-type:application/json\nhost:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amz}\n`;
  const signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
  const canonicalRequest = ["POST", path, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${date}/${cfg.region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amz, scope, sha256Hex(canonicalRequest)].join("\n");
  const kDate = hmac(`AWS4${cfg.secretAccessKey}`, date);
  const kRegion = hmac(kDate, cfg.region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, "aws4_request");
  const signature = createHmac("sha256", kSigning).update(stringToSign).digest("hex");
  return {
    "content-type": "application/json",
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amz,
    authorization:
      `AWS4-HMAC-SHA256 Credential=${cfg.accessKeyId}/${scope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

/** A built-in EmailSender backed by Amazon SES v2 (raw REST + SigV4, no SDK). */
export function createSesSender(cfg: SesConfig): EmailSender {
  for (const key of ["region", "accessKeyId", "secretAccessKey"] as const) {
    if (typeof cfg[key] !== "string" || cfg[key] === "") throw new Error(`SesConfig.${key} is required`);
  }
  const doFetch = cfg.fetch ?? fetch;
  const host = `email.${cfg.region}.amazonaws.com`;
  const path = "/v2/email/outbound-emails";
  return async ({ from, to, subject, text }) => {
    const body = JSON.stringify({
      FromEmailAddress: from,
      Destination: { ToAddresses: [to] },
      Content: { Simple: { Subject: { Data: subject }, Body: { Text: { Data: text } } } },
    });
    const when = cfg.amzDate ? cfg.amzDate() : new Date();
    const headers = sesSigV4Headers(cfg, host, path, body, when);
    const res = await doFetch(`https://${host}${path}`, { method: "POST", headers, body });
    if (!res.ok) {
      // status only: SES error bodies can echo the recipient and message
      throw new Error(`SES send failed: HTTP ${res.status}`);
    }
    const parsed = (await res.json().catch(() => ({}))) as { MessageId?: unknown };
    return typeof parsed.MessageId === "string" ? { messageId: parsed.MessageId } : {};
  };
}
