/**
 * @ownerswitchai/escalation — the owner escalation ladder (design + types
 * only; see DESIGN.md). No provider SDK, no live sends, no webhook server.
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
