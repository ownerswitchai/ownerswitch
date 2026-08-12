import type { ToolCall } from "@ownerswitchai/shared";

/**
 * Scaffold types for the owner escalation ladder — the delivery arm of the
 * veto lane. See DESIGN.md; nothing here executes, and this PR ships no
 * provider SDK, no webhook server, and no live sends.
 *
 * The load-bearing asymmetry (DESIGN.md §2/§3), encoded in the types:
 *  - every channel may carry a STOP;
 *  - no channel may APPROVE — `ChannelVerbs.approve` is the literal type
 *    `false`, so a channel claiming otherwise does not compile;
 *  - only the owner app's ack may flip VetoWindow.markDelivered() —
 *    `marksDelivered: true` exists on exactly one member of
 *    DeliveryEvidence, and that member does not arrive through a Channel
 *    at all (the app reports straight to the control plane).
 */

export type ChannelKind = "push" | "email" | "sms" | "voice";

/**
 * What a channel may do. `approve: false` is deliberate type-level
 * doctrine, in the same spirit as evaluate() refusing to compile without
 * kill state: the question "can this channel approve?" must have a
 * visible answer, and the only representable answer is no.
 */
export interface ChannelVerbs {
  /** may this channel carry a veto? (all shipped channels: yes) */
  stop: boolean;
  /**
   * May evidence from this channel flip markDelivered()? True only for
   * the push→owner-app channel, and even there the confirming ack rides
   * the app's own authenticated path to the control plane, not the
   * provider callback (DESIGN.md §3).
   */
  confirmSeen: boolean;
  /** never. Approval is the owner's passkey through 2GO, full stop. */
  approve: false;
}

/**
 * The evidence ladder of DESIGN.md §3, weakest to strongest. Only the
 * last member may release anything, and the type says so per member:
 *
 *  - provider-accepted : we handed the message off; proves sending
 *  - device-received   : platform/carrier receipt (e.g. SMS DLR); proves
 *                        a handset got the bytes — after a SIM swap,
 *                        the attacker's handset
 *  - human-interacted  : a keypress (DTMF) or answered-and-navigated
 *                        call; proves a human at that number, not which
 *                        human
 *  - owner-app-ack     : the enrolled device rendered the alert in front
 *                        of a human and said so over an authenticated
 *                        channel. The only evidence that counts as
 *                        "the owner saw it".
 */
export type DeliveryEvidence =
  | {
      level: "provider-accepted";
      channel: ChannelKind;
      /** unix ms */
      at: number;
      /** provider's message/call id, for the audit trail */
      providerRef?: string;
      marksDelivered: false;
    }
  | {
      level: "device-received";
      channel: ChannelKind;
      at: number;
      providerRef?: string;
      marksDelivered: false;
    }
  | {
      level: "human-interacted";
      channel: ChannelKind;
      at: number;
      providerRef?: string;
      /** e.g. "dtmf:1" — what the human did, never who they were */
      interaction?: string;
      marksDelivered: false;
    }
  | {
      level: "owner-app-ack";
      /** which enrolled device acked — released-on-silence must be explainable */
      deviceId: string;
      at: number;
      marksDelivered: true;
    };

/**
 * What a rung sends. Deliberately terse: the provider sees this text
 * (DESIGN.md §5), so it carries a tool name and window ids at most —
 * never arguments. Detail lives in the owner app.
 */
export interface EscalationAlert {
  /** every window this alert covers — >1 when a storm is coalesced */
  windowIds: string[];
  /** e.g. `OwnerSwitch: "write_file" held for your review` or "3 actions held" */
  headline: string;
  /** unix ms of the earliest covered window's current deadline */
  deadlineMs: number;
}

/** One send, recorded whether or not anything ever comes back. */
export interface ChannelAttempt {
  channel: ChannelKind;
  windowIds: string[];
  /** unix ms of the send */
  at: number;
  providerRef?: string;
  /** list-price estimate, so the spend ceiling can be enforced */
  estimatedCostUsd?: number;
}

/**
 * A provider callback, unparsed. Signature verification happens inside
 * the channel that owns the provider relationship; nothing outside it
 * may assume the payload is authentic.
 */
export interface ProviderCallback {
  rawBody: string;
  headers: Record<string, string>;
  /**
   * The exact public URL the provider was told to call (scheme, host, path,
   * query) — providers that sign callbacks (Twilio) sign over it, so the
   * webhook edge must pass the URL it advertised, not the one the local
   * socket saw behind a proxy.
   */
  url?: string;
}

/** What comes back from a channel, after verification. */
export type ChannelEvent =
  | { type: "evidence"; windowIds: string[]; evidence: DeliveryEvidence }
  | {
      type: "veto";
      windowIds: string[];
      channel: ChannelKind;
      /** honest, weak attribution — e.g. "channel:voice-dtmf", "channel:sms-reply" */
      attribution: string;
    };

/**
 * One channel — push, email, SMS, or voice. `send()` resolving means the
 * provider ACCEPTED the message, nothing more; everything the channel
 * later learns arrives asynchronously through `handleCallback()`. There
 * is deliberately no verb for confirming delivery: the one confirming
 * signal does not pass through any Channel (DESIGN.md §3).
 */
export interface Channel {
  readonly kind: ChannelKind;
  readonly verbs: ChannelVerbs;
  /** Hand the alert to the provider. Resolving means accepted, not delivered. */
  send(alert: EscalationAlert): Promise<ChannelAttempt>;
  /**
   * Verify and parse one provider callback into events. An invalid
   * signature or an unrecognized payload yields no events — never a
   * guess.
   */
  handleCallback(callback: ProviderCallback): ChannelEvent[];
}

/** One rung: fire `channel` this long after the window opened. */
export interface LadderRung {
  afterMs: number;
  channel: ChannelKind;
}

/**
 * Ceilings, not knobs to zero out: a cap stops spending and lets windows
 * go `held` (fail closed). No limit may ever cause a release.
 */
export interface RateLimits {
  maxVoiceCallsPer10Min: number;
  maxSmsPerHour: number;
  maxDailySpendUsd: number;
}

export interface LadderConfig {
  /** default: push+email at 0:00, sms at 2:30, voice at 5:00 */
  rungs: LadderRung[];
  limits: RateLimits;
}

/**
 * What tick() tells the edge to do. The ladder's entire influence on the
 * veto state machine is here: relay a stop, or nothing. It has no action
 * that extends, releases, or approves.
 */
export type LadderAction =
  | { type: "send"; channel: ChannelKind; alert: EscalationAlert }
  | { type: "relay-veto"; windowIds: string[]; channel: ChannelKind; attribution: string }
  | {
      type: "stand-down";
      windowIds: string[];
      reason: "confirmed" | "vetoed" | "window-closed" | "cap-hit";
    };

/**
 * Sequences channels against an injected clock, house style: tick() is
 * pure and returns the actions to perform; side effects live at the
 * edge (the process that owns the channels and the control-plane
 * client).
 */
export interface Ladder {
  /** A veto window opened; begin (or coalesce into) this owner's ladder. */
  windowOpened(windowId: string, call: ToolCall, deadlineMs: number): void;
  /** Evidence or a veto came back from some channel. */
  channelEvent(event: ChannelEvent): void;
  /** Advance; returns sends to make, vetoes to relay, stand-downs to record. */
  tick(nowMs: number): LadderAction[];
}

/**
 * What the control plane stores per window — the audit trail that makes
 * a later "released on silence" explainable after the fact: every
 * attempt, every piece of evidence at its honest level, and a `seen`
 * bit that can only have come from an owner-app ack.
 */
export interface EscalationRecord {
  windowId: string;
  attempts: ChannelAttempt[];
  evidence: DeliveryEvidence[];
  /** mirrors VetoWindow's delivered bit; true only via owner-app-ack */
  seen: boolean;
  vetoRelayed?: { channel: ChannelKind; at: number; attribution: string };
}
