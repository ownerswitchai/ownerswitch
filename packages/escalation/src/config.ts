import { loadOwnerDeviceKeysFile } from "@ownerswitchai/control-plane";
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
   * The owner app's enrolled device PUBLIC keys (deviceId → ECDSA P-256 SPKI
   * PEM), required to authenticate a push-subscription enrollment
   * (POST /push/subscription). Enrollment picks who receives every future
   * alert, so it is gated on the owner's ASYMMETRIC device signature — the
   * same non-extractable key that signs the delivery ack — not the fleet
   * device secret this service holds. A fleet-secret holder therefore cannot
   * redirect the owner's push channel. Absent/empty → enrollment is 501.
   */
  ownerDeviceKeys?: Record<string, string>;
  /**
   * The SAME durable standing registry the control plane writes
   * ({deviceId → {generation, revokedAt}}, device-standing.ts). Re-read on
   * every owner-device operation here, so a revocation on the control plane
   * severs this service's surfaces too: a revoked phone can no longer update
   * the push subscription, and a subscription it enrolled stops receiving
   * alerts. Absent → standing is not consulted (dev), matching an ephemeral
   * control plane. A corrupt registry reads as ALL devices revoked.
   */
  ownerDeviceStandingFile?: string;
  /**
   * The control plane's uid, for the distinct-UID model: the standing path's
   * real ancestry must be owned by root, THIS process, or this explicitly
   * named uid (never guessed from the filesystem). Unset when CP and
   * escalation share a user. Env: OWNERSWITCH_OWNER_DEVICE_STANDING_TRUSTED_UID.
   */
  ownerDeviceStandingTrustedUid?: number;
  /**
   * The shared read-only group's gid — the SAME value the control plane
   * publishes the 0640 file with (OWNERSWITCH_OWNER_DEVICE_STANDING_GID on
   * both services). The reader's load-time boundary check accepts a 0640
   * registry only when its gid matches this; unset, only a private 0600
   * registry is accepted (the same-user model).
   */
  ownerDeviceStandingGid?: number;
  /** test-only: skip the trusted-ancestry walk (public tmp roots fail it by design) */
  unsafeAllowUntrustedStandingPathForTests?: boolean;
  /** where the webhook server listens */
  listenHost: string;
  listenPort: number;
  /** public https base Twilio callbacks arrive at (required with Twilio) */
  webhookBaseUrl?: string;
  /** 0600 JSON file holding the enrolled push subscription */
  stateFile?: string;
  twilio?: { accountSid: string; authToken: string; from: string; to: string };
  vapid?: { publicKey: string; privateKey: string; subject: string };
  email?: {
    from: string;
    to: string;
    /** https base of the owner app; alerts deep-link here (no one-click stop) */
    ownerAppUrl: string;
    ses: { region: string; accessKeyId: string; secretAccessKey: string };
  };
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

/** Owner-app device public keys (deviceId → P-256 SPKI PEM) from a hardened JSON file. */
function loadOwnerDeviceKeys(file: string | undefined): Record<string, string> {
  if (file === undefined || file === "") return {};
  return loadOwnerDeviceKeysFile(file);
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

  // The same production stance as the control plane, checked BEFORE the keys
  // even load: enrolled owner devices WITHOUT the shared standing registry
  // would leave this service trusting a phone the control plane has revoked
  // (it would keep accepting the key and keep pushing alerts to it) — a
  // configuration fail-open. Refuse to start instead; the control plane
  // writes the file, this service only reads it.
  const ownerDeviceKeysFile = env.OWNERSWITCH_OWNER_DEVICE_KEYS_FILE?.trim();
  const standingFileEnv = env.OWNERSWITCH_OWNER_DEVICE_STANDING_FILE?.trim();
  if (
    ownerDeviceKeysFile !== undefined &&
    ownerDeviceKeysFile !== "" &&
    (standingFileEnv === undefined || standingFileEnv === "")
  ) {
    throw new Error(
      "OWNERSWITCH_OWNER_DEVICE_KEYS_FILE is set but OWNERSWITCH_OWNER_DEVICE_STANDING_FILE is not — " +
        "without the shared standing registry a revoked phone stays trusted here. Point it at the " +
        "same file the control plane persists standing to.",
    );
  }
  const ownerDeviceKeys = loadOwnerDeviceKeys(ownerDeviceKeysFile);

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

  const emailVars = [
    env.OWNERSWITCH_EMAIL_FROM,
    env.OWNERSWITCH_EMAIL_TO,
    env.OWNERSWITCH_OWNER_APP_URL,
    env.OWNERSWITCH_SES_REGION,
    env.OWNERSWITCH_SES_ACCESS_KEY_ID,
    env.OWNERSWITCH_SES_SECRET_ACCESS_KEY,
  ];
  const emailSet = emailVars.filter((v) => v !== undefined && v !== "").length;
  if (emailSet > 0 && emailSet < 6) {
    throw new Error(
      "partial email configuration: set all of OWNERSWITCH_EMAIL_FROM, OWNERSWITCH_EMAIL_TO, " +
        "OWNERSWITCH_OWNER_APP_URL, OWNERSWITCH_SES_REGION, OWNERSWITCH_SES_ACCESS_KEY_ID, " +
        "OWNERSWITCH_SES_SECRET_ACCESS_KEY — or none",
    );
  }
  const email =
    emailSet === 6
      ? {
          from: env.OWNERSWITCH_EMAIL_FROM as string,
          to: env.OWNERSWITCH_EMAIL_TO as string,
          ownerAppUrl: env.OWNERSWITCH_OWNER_APP_URL as string,
          ses: {
            region: env.OWNERSWITCH_SES_REGION as string,
            accessKeyId: env.OWNERSWITCH_SES_ACCESS_KEY_ID as string,
            secretAccessKey: env.OWNERSWITCH_SES_SECRET_ACCESS_KEY as string,
          },
        }
      : undefined;

  if (twilio === undefined && vapid === undefined && email === undefined) {
    throw new Error(
      "no channel is configured — the escalation service would poll and never reach the owner. " +
        "Configure Web Push (VAPID), Twilio, and/or email (SES); see packages/escalation/README.md",
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

  // Rungs assemble from what exists (DESIGN.md §1 offsets): push + email at
  // 0:00, SMS at 2:30, voice at 5:00. A channel with no config earns no rung
  // — a rung that silently does nothing would be a lie in the audit trail.
  const rungs: LadderRung[] = [];
  if (vapid !== undefined) rungs.push({ afterMs: 0, channel: "push" });
  if (email !== undefined) rungs.push({ afterMs: 0, channel: "email" });
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

  const ownerDeviceStandingFile = standingFileEnv;
  const trustedUidRaw = env.OWNERSWITCH_OWNER_DEVICE_STANDING_TRUSTED_UID?.trim();
  let ownerDeviceStandingTrustedUid: number | undefined;
  if (trustedUidRaw !== undefined && trustedUidRaw !== "") {
    const parsed = Number(trustedUidRaw);
    if (!Number.isInteger(parsed) || parsed < 0) {
      throw new Error("OWNERSWITCH_OWNER_DEVICE_STANDING_TRUSTED_UID must be a non-negative integer uid");
    }
    ownerDeviceStandingTrustedUid = parsed;
  }
  const standingGidRaw = env.OWNERSWITCH_OWNER_DEVICE_STANDING_GID?.trim();
  let ownerDeviceStandingGid: number | undefined;
  if (standingGidRaw !== undefined && standingGidRaw !== "") {
    const parsed = Number(standingGidRaw);
    if (!Number.isInteger(parsed) || parsed < 0) {
      throw new Error("OWNERSWITCH_OWNER_DEVICE_STANDING_GID must be a non-negative integer gid");
    }
    ownerDeviceStandingGid = parsed;
  }
  return {
    controlPlaneUrl,
    device,
    ...(Object.keys(ownerDeviceKeys).length > 0 ? { ownerDeviceKeys } : {}),
    ...(ownerDeviceStandingFile !== undefined && ownerDeviceStandingFile !== ""
      ? { ownerDeviceStandingFile }
      : {}),
    ...(ownerDeviceStandingTrustedUid !== undefined ? { ownerDeviceStandingTrustedUid } : {}),
    ...(ownerDeviceStandingGid !== undefined ? { ownerDeviceStandingGid } : {}),
    listenHost: env.OWNERSWITCH_ESCALATION_HOST ?? "127.0.0.1",
    listenPort: intEnv(env, "OWNERSWITCH_ESCALATION_PORT", DEFAULT_PORT),
    ...(webhookBaseUrl !== undefined && webhookBaseUrl !== "" ? { webhookBaseUrl } : {}),
    ...(stateFile !== undefined && stateFile !== "" ? { stateFile } : {}),
    ...(twilio !== undefined ? { twilio } : {}),
    ...(vapid !== undefined ? { vapid } : {}),
    ...(email !== undefined ? { email } : {}),
    rungs,
    limits,
    pollMs: intEnv(env, "OWNERSWITCH_ESCALATION_POLL_MS", DEFAULT_POLL_MS),
  };
}
