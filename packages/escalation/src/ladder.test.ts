import { describe, expect, it } from "vitest";
import { DEFAULT_LIMITS, DEFAULT_RUNGS, LadderEngine } from "./ladder.js";
import type { LadderAction } from "./types.js";

const MIN = 60_000;

const sends = (actions: LadderAction[]) =>
  actions.filter((a): a is Extract<LadderAction, { type: "send" }> => a.type === "send");

describe("LadderEngine — rung scheduling", () => {
  it("fires push+email at 0:00, sms at 2:30, voice at 5:00 against the injected clock", () => {
    const ladder = new LadderEngine();
    ladder.windowOpened("v-1", '"write_file"', 4 * MIN);

    const t0 = sends(ladder.tick(0));
    expect(t0.map((a) => a.channel).sort()).toEqual(["email", "push"]);
    expect(t0[0].alert).toEqual({
      windowIds: ["v-1"],
      headline: 'OwnerSwitch: "write_file" held for your review',
      deadlineMs: 4 * MIN,
    });

    expect(sends(ladder.tick(2 * MIN))).toHaveLength(0);
    expect(sends(ladder.tick(2.5 * MIN)).map((a) => a.channel)).toEqual(["sms"]);
    expect(sends(ladder.tick(4 * MIN))).toHaveLength(0);
    expect(sends(ladder.tick(5 * MIN)).map((a) => a.channel)).toEqual(["voice"]);
    // nothing re-fires
    expect(sends(ladder.tick(60 * MIN))).toHaveLength(0);
  });

  it("a rung fires once even when ticks are late — late degrades, never repeats", () => {
    const ladder = new LadderEngine();
    ladder.windowOpened("v-1", '"bash"', 4 * MIN);
    ladder.tick(0);
    // one very late tick sees sms AND voice due; both fire exactly once
    const late = sends(ladder.tick(30 * MIN));
    expect(late.map((a) => a.channel).sort()).toEqual(["sms", "voice"]);
    expect(sends(ladder.tick(31 * MIN))).toHaveLength(0);
  });

  it("the rung clock starts at the first tick, not at windowOpened", () => {
    const ladder = new LadderEngine();
    ladder.windowOpened("v-1", '"bash"', 10 * MIN);
    // first tick at t=7min arms the run; sms is due 2.5min later, not already
    expect(sends(ladder.tick(7 * MIN)).map((a) => a.channel).sort()).toEqual(["email", "push"]);
    expect(sends(ladder.tick(9 * MIN))).toHaveLength(0);
    expect(sends(ladder.tick(9.5 * MIN)).map((a) => a.channel)).toEqual(["sms"]);
  });
});

describe("LadderEngine — coalescing (one run per storm)", () => {
  it("windows opened mid-run join it: no rung re-fires, later alerts count them", () => {
    const ladder = new LadderEngine();
    ladder.windowOpened("v-1", '"write_file"', 4 * MIN);
    ladder.tick(0);

    for (let i = 2; i <= 1000; i++) ladder.windowOpened(`v-${i}`, '"bash"', 5 * MIN);
    const atSms = sends(ladder.tick(2.5 * MIN));
    expect(atSms).toHaveLength(1); // one SMS for a thousand windows
    expect(atSms[0].alert.windowIds).toHaveLength(1000);
    expect(atSms[0].alert.headline).toBe("OwnerSwitch: 1000 actions held for your review");
    // the earliest covered deadline paces the alert
    expect(atSms[0].alert.deadlineMs).toBe(4 * MIN);
  });

  it("a run ends when its last window closes; the next window starts a fresh run", () => {
    const ladder = new LadderEngine();
    ladder.windowOpened("v-1", '"bash"', 4 * MIN);
    ladder.tick(0);
    ladder.windowClosed("v-1");
    const closing = ladder.tick(MIN);
    expect(closing).toContainEqual({
      type: "stand-down",
      windowIds: ["v-1"],
      reason: "window-closed",
    });
    expect(ladder.active).toBe(false);

    ladder.windowOpened("v-2", '"bash"', 10 * MIN);
    expect(sends(ladder.tick(2 * MIN)).map((a) => a.channel).sort()).toEqual(["email", "push"]);
  });
});

describe("LadderEngine — confirmation and vetoes", () => {
  it("an owner-app confirmation stands the remaining rungs down: a push acked early costs zero SMS and zero calls", () => {
    const ladder = new LadderEngine();
    ladder.windowOpened("v-1", '"bash"', 4 * MIN);
    ladder.tick(0);
    ladder.windowDelivered("v-1");
    const after = ladder.tick(0.5 * MIN);
    expect(after).toContainEqual({ type: "stand-down", windowIds: ["v-1"], reason: "confirmed" });
    expect(sends(after)).toHaveLength(0);
    expect(sends(ladder.tick(10 * MIN))).toHaveLength(0);
  });

  it("confirmation stands down only when EVERY open window is confirmed", () => {
    const ladder = new LadderEngine();
    ladder.windowOpened("v-1", '"bash"', 4 * MIN);
    ladder.windowOpened("v-2", '"bash"', 4 * MIN);
    ladder.tick(0);
    ladder.windowDelivered("v-1");
    expect(sends(ladder.tick(2.5 * MIN)).map((a) => a.channel)).toEqual(["sms"]);
  });

  it("a channel veto relays against every open window in the run — bulk stop is the safe direction", () => {
    const ladder = new LadderEngine();
    ladder.windowOpened("v-1", '"bash"', 4 * MIN);
    ladder.windowOpened("v-2", '"bash"', 4 * MIN);
    ladder.tick(0);
    ladder.channelEvent({ type: "veto", windowIds: [], channel: "sms", attribution: "channel:sms-reply" });
    const actions = ladder.tick(MIN);
    expect(actions[0]).toEqual({
      type: "relay-veto",
      windowIds: ["v-1", "v-2"],
      channel: "sms",
      attribution: "channel:sms-reply",
    });
  });

  it("a targeted veto relays only the named window", () => {
    const ladder = new LadderEngine();
    ladder.windowOpened("v-1", '"bash"', 4 * MIN);
    ladder.windowOpened("v-2", '"bash"', 4 * MIN);
    ladder.tick(0);
    ladder.channelEvent({
      type: "veto",
      windowIds: ["v-2"],
      channel: "voice",
      attribution: "channel:voice-dtmf",
    });
    expect(ladder.tick(MIN)[0]).toMatchObject({ type: "relay-veto", windowIds: ["v-2"] });
  });

  it("evidence events do not relay anything — only vetoes cross back", () => {
    const ladder = new LadderEngine();
    ladder.windowOpened("v-1", '"bash"', 4 * MIN);
    ladder.tick(0);
    ladder.channelEvent({
      type: "evidence",
      windowIds: ["v-1"],
      evidence: { level: "device-received", channel: "sms", at: 1, marksDelivered: false },
    });
    expect(ladder.tick(MIN).filter((a) => a.type === "relay-veto")).toHaveLength(0);
  });
});

describe("LadderEngine — ceilings (fail closed)", () => {
  it("the voice cap stops dialing and reports cap-hit, never a release", () => {
    const ladder = new LadderEngine({
      rungs: [{ afterMs: 0, channel: "voice" }],
      limits: { ...DEFAULT_LIMITS, maxVoiceCallsPer10Min: 2 },
    });
    // three storms in quick succession, each its own run
    for (let i = 1; i <= 3; i++) {
      ladder.windowOpened(`v-${i}`, '"bash"', 100 * MIN);
      const actions = ladder.tick(i * MIN);
      if (i <= 2) {
        expect(sends(actions).map((a) => a.channel)).toEqual(["voice"]);
      } else {
        expect(sends(actions)).toHaveLength(0);
        expect(actions).toContainEqual({
          type: "stand-down",
          windowIds: [`v-${i}`],
          reason: "cap-hit",
        });
      }
      ladder.windowClosed(`v-${i}`);
      ladder.tick(i * MIN);
    }
  });

  it("the voice cap is a sliding 10 min horizon", () => {
    const ladder = new LadderEngine({ rungs: [{ afterMs: 0, channel: "voice" }] });
    const dial = (id: string, at: number) => {
      ladder.windowOpened(id, '"bash"', 1000 * MIN);
      const out = sends(ladder.tick(at));
      ladder.windowClosed(id);
      ladder.tick(at);
      return out.length;
    };
    expect(dial("v-1", 0)).toBe(1);
    expect(dial("v-2", MIN)).toBe(1);
    expect(dial("v-3", 2 * MIN)).toBe(0); // capped
    expect(dial("v-4", 11 * MIN)).toBe(1); // the first call aged out
  });

  it("the daily spend ceiling caps every priced channel and resets on the UTC day", () => {
    const ladder = new LadderEngine({
      rungs: [{ afterMs: 0, channel: "sms" }],
      limits: { maxVoiceCallsPer10Min: 100, maxSmsPerHour: 100, maxDailySpendUsd: 0.02 },
    });
    const send = (id: string, at: number) => {
      ladder.windowOpened(id, '"bash"', Number.MAX_SAFE_INTEGER);
      const out = sends(ladder.tick(at)).length;
      ladder.windowClosed(id);
      ladder.tick(at);
      return out;
    };
    expect(send("v-1", 0)).toBe(1); // $0.008
    expect(send("v-2", MIN)).toBe(1); // $0.016
    expect(send("v-3", 2 * MIN)).toBe(0); // $0.024 > $0.02 — capped
    expect(send("v-4", 86_400_000 + MIN)).toBe(1); // new day, fresh budget
  });

  it("push is free and never capped by spend", () => {
    const ladder = new LadderEngine({
      rungs: [{ afterMs: 0, channel: "push" }],
      limits: { maxVoiceCallsPer10Min: 0, maxSmsPerHour: 0, maxDailySpendUsd: 0 },
    });
    ladder.windowOpened("v-1", '"bash"', 4 * MIN);
    expect(sends(ladder.tick(0)).map((a) => a.channel)).toEqual(["push"]);
  });

  it("refuses nonsense configuration up front", () => {
    expect(() => new LadderEngine({ rungs: [{ afterMs: -1, channel: "push" }] })).toThrow(/afterMs/);
    expect(
      () =>
        new LadderEngine({
          limits: { maxVoiceCallsPer10Min: -1, maxSmsPerHour: 0, maxDailySpendUsd: 0 },
        }),
    ).toThrow(/maxVoiceCallsPer10Min/);
  });

  it("default rungs match the documented ladder", () => {
    expect(DEFAULT_RUNGS).toEqual([
      { afterMs: 0, channel: "push" },
      { afterMs: 0, channel: "email" },
      { afterMs: 150_000, channel: "sms" },
      { afterMs: 300_000, channel: "voice" },
    ]);
  });
});
