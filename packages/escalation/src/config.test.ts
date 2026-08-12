import { describe, expect, it } from "vitest";
import { escalationConfigFromEnv } from "./config.js";

const VAPID = {
  OWNERSWITCH_VAPID_PUBLIC_KEY: "pub",
  OWNERSWITCH_VAPID_PRIVATE_KEY: "priv",
  OWNERSWITCH_VAPID_SUBJECT: "mailto:o@example.com",
};
const TWILIO = {
  OWNERSWITCH_TWILIO_ACCOUNT_SID: "ACxx",
  OWNERSWITCH_TWILIO_AUTH_TOKEN: "tok",
  OWNERSWITCH_TWILIO_FROM: "+15550001111",
  OWNERSWITCH_OWNER_PHONE: "+36301234567",
  OWNERSWITCH_ESCALATION_WEBHOOK_BASE_URL: "https://esc.example",
};
const BASE = { OWNERSWITCH_DEVICE_SECRET: "device-secret" };

describe("escalationConfigFromEnv", () => {
  it("assembles rungs from what the environment actually provides", () => {
    const pushOnly = escalationConfigFromEnv({
      ...BASE,
      ...VAPID,
      OWNERSWITCH_ESCALATION_STATE_FILE: "/var/lib/ownerswitch/esc.json",
    });
    expect(pushOnly.rungs).toEqual([{ afterMs: 0, channel: "push" }]);

    const both = escalationConfigFromEnv({
      ...BASE,
      ...VAPID,
      ...TWILIO,
      OWNERSWITCH_ESCALATION_STATE_FILE: "/var/lib/ownerswitch/esc.json",
    });
    expect(both.rungs).toEqual([
      { afterMs: 0, channel: "push" },
      { afterMs: 150_000, channel: "sms" },
      { afterMs: 300_000, channel: "voice" },
    ]);
    expect(both.twilio?.authToken).toBe("tok");
    expect(both.controlPlaneUrl).toBe("http://127.0.0.1:4181");
  });

  it("refuses a channel-less deployment — polling forever while reaching nobody is not escalation", () => {
    expect(() => escalationConfigFromEnv(BASE)).toThrow(/no channel is configured/);
  });

  it("refuses HALF a configuration: partial Twilio, partial VAPID, Twilio without a webhook base, VAPID without a state file", () => {
    expect(() =>
      escalationConfigFromEnv({ ...BASE, OWNERSWITCH_TWILIO_ACCOUNT_SID: "ACxx" }),
    ).toThrow(/partial Twilio/);
    expect(() =>
      escalationConfigFromEnv({ ...BASE, OWNERSWITCH_VAPID_PUBLIC_KEY: "pub" }),
    ).toThrow(/partial VAPID/);
    const noWebhook = { ...BASE, ...TWILIO } as Record<string, string | undefined>;
    delete noWebhook.OWNERSWITCH_ESCALATION_WEBHOOK_BASE_URL;
    expect(() => escalationConfigFromEnv(noWebhook)).toThrow(/WEBHOOK_BASE_URL/);
    expect(() => escalationConfigFromEnv({ ...BASE, ...VAPID })).toThrow(/STATE_FILE/);
  });

  it("requires the device secret and a dot-free device id", () => {
    expect(() => escalationConfigFromEnv({ ...VAPID })).toThrow(/OWNERSWITCH_DEVICE_SECRET/);
    expect(() =>
      escalationConfigFromEnv({
        ...BASE,
        ...VAPID,
        OWNERSWITCH_ESCALATION_STATE_FILE: "/tmp/x.json",
        OWNERSWITCH_ESCALATION_DEVICE_ID: "esc.1",
      }),
    ).toThrow(/must not contain/);
  });

  it("ceilings come from env but may never go negative", () => {
    const cfg = escalationConfigFromEnv({
      ...BASE,
      ...VAPID,
      OWNERSWITCH_ESCALATION_STATE_FILE: "/tmp/x.json",
      OWNERSWITCH_ESCALATION_MAX_SMS_PER_HOUR: "2",
      OWNERSWITCH_ESCALATION_MAX_DAILY_SPEND_USD: "1.5",
    });
    expect(cfg.limits).toEqual({ maxVoiceCallsPer10Min: 2, maxSmsPerHour: 2, maxDailySpendUsd: 1.5 });
    expect(() =>
      escalationConfigFromEnv({
        ...BASE,
        ...VAPID,
        OWNERSWITCH_ESCALATION_STATE_FILE: "/tmp/x.json",
        OWNERSWITCH_ESCALATION_MAX_DAILY_SPEND_USD: "-1",
      }),
    ).toThrow(/non-negative/);
  });
});
