/**
 * @ownerswitchai/escalation — the owner escalation ladder: the delivery arm
 * of the veto lane (DESIGN.md). The engine is pure (ladder.ts), the
 * channels speak their providers directly with no SDK (channels/), and the
 * service edge (service.ts) owns the clocks, sockets and credentials —
 * which arrive exclusively from the environment (config.ts).
 */
export type {
  Channel,
  ChannelAttempt,
  ChannelEvent,
  ChannelKind,
  ChannelVerbs,
  DeliveryEvidence,
  EscalationAlert,
  EscalationRecord,
  Ladder,
  LadderAction,
  LadderConfig,
  LadderRung,
  ProviderCallback,
  RateLimits,
} from "./types.js";

export { DEFAULT_COST_USD, DEFAULT_LIMITS, DEFAULT_RUNGS, LadderEngine } from "./ladder.js";
export type { LadderEngineOptions } from "./ladder.js";

export {
  alertTwiml,
  createTwilioSmsChannel,
  createTwilioVoiceChannel,
  TWILIO_COST_USD,
  TWILIO_PATHS,
  verifyTwilioSignature,
} from "./channels/twilio.js";
export type { TwilioConfig } from "./channels/twilio.js";

export {
  createWebPushChannel,
  encryptPushPayload,
  generateVapidKeys,
  vapidAuthorization,
} from "./channels/webpush.js";
export type { PushSubscriptionJson, WebPushConfig } from "./channels/webpush.js";

export { escalationConfigFromEnv } from "./config.js";
export type { EscalationEnvConfig } from "./config.js";

export { createEscalationService } from "./service.js";
export type { EscalationService, EscalationServiceOptions } from "./service.js";
