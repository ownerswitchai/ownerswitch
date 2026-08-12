import { DEFAULT_LIMITS } from "./ladder.js";
import type { LadderRung, RateLimits } from "./types.js";

/**
 * Environment-only configuration for the escalation service.
 *
 * THE LINE BETWEEN PUBLIC AND PRIVATE, stated once and enforced here: this
 * repository — code, rung offsets, the shape of every request — is public.
 * Everything that identifies YOUR deployment is private and arrives
 * exclusively through the environment at process start: the Twilio
 * credentials and phone numbers, the VAPID keypair, the device secret
 * shared with the control plane. Nothing in this package reads a config
 * file for secrets, nothing accepts them as CLI arguments (argv is visible
 * to every same-host process), and nothing ever writes one back to disk —
 * except the push subscription store, which holds the owner app's
 * subscription (a capability to send, not an account credential) in a
 * 0600 file at OWNERSWITCH_ESCALATION_STATE_FILE.
 *
 * Channels are OPTIONAL per deployment (DESIGN.md §6): rungs assemble from
 * what the environment actually provides. No Twilio env → no SMS/voice
 * rungs; no VAPID env → no push rung. A deployment with nothing configured
 * refuses to start rather than pretending to escalate.
 */

export interface EscalationEnvConfig {
  controlPlaneUrl: string;
  device: { id: string; secret: string };
  /**
   * The OWNER APP's own secret (distinct from `device.secret`), required to
   * enroll a push subscription (POST /push/subscription). Enrollment picks
   * who receives every future alert, so it must not ride the fleet device
   * secret the escalation service itself holds — otherwise a fleet-secret
   * holder could redirect the owner's push channel to their own endpoint.
   * Absent → enrollment is 501 and no subscription can be set over HTTP.
   */
  ownerAppSecret?: string;
  /** where the webhook server listens */
  listenHost: string;
  listenPort: number;
  /** public https base Twilio callbacks arrive at (required with Twilio) */
  webhookBaseUrl?: string;
  /** 0600 JSON file holding the enrolled push subscription */
  stateFile?: string;
  twilio?: { accountSid: string; authToken: string; from: string; to: string };
  vapid?: { publicKey: string; privateKey: string; subject: string };
  rungs: LadderRung[];
  limits: RateLimits;
  /** control-plane poll cadence; default 5000 ms */
  pollMs: number;
}

const DEFAULT_PORT = 4190;
const DEFAULT_POLL_MS = 5_000;

function requireEnv(env: Record<string, string | undefined>, name: string): string {
  const value = env[name];
  if (value === undefined || value === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

function intEnv(env: Record<string, string | undefined>, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer`);
  return value;
}

export function escalationConfigFromEnv(
  env: Record<string, string | undefined> = process.env,
): EscalationEnvConfig {
  const controlPlaneUrl = env.OWNERSWITCH_CONTROL_PLANE_URL ?? "http://127.0.0.1:4181";
  const device = {
    id: env.OWNERSWITCH_ESCALATION_DEVICE_ID ?? "escalation",
    secret: requireEnv(env, "OWNERSWITCH_DEVICE_SECRET"),
  };
  if (device.id.includes(".")) throw new Error('OWNERSWITCH_ESCALATION_DEVICE_ID must not contain "."');

  const ownerAppSecret = env.OWNERSWITCH_OWNER_APP_SECRET?.trim();
  if (ownerAppSecret !== undefined && ownerAppSecret !== "" && ownerAppSecret === device.secret) {
    throw new Error(
      "OWNERSWITCH_OWNER_APP_SECRET must differ from OWNERSWITCH_DEVICE_SECRET — the owner app's " +
        "push-enrollment credential is deliberately separate from the fleet device secret the " +
        "escalation service holds",
    );
  }

  const sid = env.OWNERSWITCH_TWILIO_ACCOUNT_SID;
  const twilioVars = [
    env.OWNERSWITCH_TWILIO_ACCOUNT_SID,
    env.OWNERSWITCH_TWILIO_AUTH_TOKEN,
    env.OWNERSWITCH_TWILIO_FROM,
    env.OWNERSWITCH_OWNER_PHONE,
  ];
  const twilioSet = twilioVars.filter((v) => v !== undefined && v !== "").length;
  if (twilioSet > 0 && twilioSet < 4) {
    // half a phone channel is a silent hole in the ladder — refuse loudly
    throw new Error(
      "partial Twilio configuration: set all of OWNERSWITCH_TWILIO_ACCOUNT_SID, " +
        "OWNERSWITCH_TWILIO_AUTH_TOKEN, OWNERSWITCH_TWILIO_FROM, OWNERSWITCH_OWNER_PHONE — or none",
    );
  }
  const twilio =
    twilioSet === 4
      ? {
          accountSid: sid as string,
          authToken: env.OWNERSWITCH_TWILIO_AUTH_TOKEN as string,
          from: env.OWNERSWITCH_TWILIO_FROM as string,
          to: env.OWNERSWITCH_OWNER_PHONE as string,
        }
      : undefined;

  const vapidVars = [
    env.OWNERSWITCH_VAPID_PUBLIC_KEY,
    env.OWNERSWITCH_VAPID_PRIVATE_KEY,
    env.OWNERSWITCH_VAPID_SUBJECT,
  ];
  const vapidSet = vapidVars.filter((v) => v !== undefined && v !== "").length;
  if (vapidSet > 0 && vapidSet < 3) {
    throw new Error(
      "partial VAPID configuration: set all of OWNERSWITCH_VAPID_PUBLIC_KEY, " +
        "OWNERSWITCH_VAPID_PRIVATE_KEY, OWNERSWITCH_VAPID_SUBJECT — or none " +
        "(mint a pair with: ownerswitch-escalation vapid-keys)",
    );
  }
  const vapid =
    vapidSet === 3
      ? {
          publicKey: env.OWNERSWITCH_VAPID_PUBLIC_KEY as string,
          privateKey: env.OWNERSWITCH_VAPID_PRIVATE_KEY as string,
          subject: env.OWNERSWITCH_VAPID_SUBJECT as string,
        }
      : undefined;

  if (twilio === undefined && vapid === undefined) {
    throw new Error(
      "no channel is configured — the escalation service would poll and never reach the owner. " +
        "Configure Web Push (VAPID) and/or Twilio; see packages/escalation/README.md",
    );
  }

  const webhookBaseUrl = env.OWNERSWITCH_ESCALATION_WEBHOOK_BASE_URL;
  if (twilio !== undefined && (webhookBaseUrl === undefined || webhookBaseUrl === "")) {
    throw new Error(
      "OWNERSWITCH_ESCALATION_WEBHOOK_BASE_URL is required with Twilio — the reply-1 and press-1 " +
        "stops arrive as callbacks, and a phone channel that cannot carry its stop verb is not a channel",
    );
  }

  const stateFile = env.OWNERSWITCH_ESCALATION_STATE_FILE;
  if (vapid !== undefined && (stateFile === undefined || stateFile === "")) {
    throw new Error(
      "OWNERSWITCH_ESCALATION_STATE_FILE is required with VAPID — the owner app's push " +
        "subscription must survive a service restart",
    );
  }

  // Rungs assemble from what exists (DESIGN.md §1 offsets). Email has no
  // shipped channel yet, so it earns no rung — a rung that silently does
  // nothing would be a lie in the audit trail.
  const rungs: LadderRung[] = [];
  if (vapid !== undefined) rungs.push({ afterMs: 0, channel: "push" });
  if (twilio !== undefined) {
    rungs.push({ afterMs: 2.5 * 60_000, channel: "sms" });
    rungs.push({ afterMs: 5 * 60_000, channel: "voice" });
  }

  const limits: RateLimits = {
    maxVoiceCallsPer10Min: intEnv(
      env,
      "OWNERSWITCH_ESCALATION_MAX_VOICE_PER_10MIN",
      DEFAULT_LIMITS.maxVoiceCallsPer10Min,
    ),
    maxSmsPerHour: intEnv(env, "OWNERSWITCH_ESCALATION_MAX_SMS_PER_HOUR", DEFAULT_LIMITS.maxSmsPerHour),
    maxDailySpendUsd: Number(env.OWNERSWITCH_ESCALATION_MAX_DAILY_SPEND_USD ?? DEFAULT_LIMITS.maxDailySpendUsd),
  };
  if (!Number.isFinite(limits.maxDailySpendUsd) || limits.maxDailySpendUsd < 0) {
    throw new Error("OWNERSWITCH_ESCALATION_MAX_DAILY_SPEND_USD must be a non-negative number");
  }

  return {
    controlPlaneUrl,
    device,
    ...(ownerAppSecret !== undefined && ownerAppSecret !== "" ? { ownerAppSecret } : {}),
    listenHost: env.OWNERSWITCH_ESCALATION_HOST ?? "127.0.0.1",
    listenPort: intEnv(env, "OWNERSWITCH_ESCALATION_PORT", DEFAULT_PORT),
    ...(webhookBaseUrl !== undefined && webhookBaseUrl !== "" ? { webhookBaseUrl } : {}),
    ...(stateFile !== undefined && stateFile !== "" ? { stateFile } : {}),
    ...(twilio !== undefined ? { twilio } : {}),
    ...(vapid !== undefined ? { vapid } : {}),
    rungs,
    limits,
    pollMs: intEnv(env, "OWNERSWITCH_ESCALATION_POLL_MS", DEFAULT_POLL_MS),
  };
}
