import { describe, expect, it } from "vitest";
import { upstreamEnvironment } from "./upstream-env.js";

const TOKEN = "ghp_ownerswitch_own_credential_0123456789";
const DEVICE_SECRET = "device-secret-value";

describe("upstreamEnvironment — the spawn config the upstream child receives", () => {
  it("contains no executor credential under any name or alias, even from a polluted base", () => {
    // a worst-case inherited environment: the gateway's own namespace, the
    // credential under its seam name, AND under alias names / composed values
    const env = upstreamEnvironment({
      base: {
        HOME: "/home/user",
        PATH: "/usr/bin",
        OWNERSWITCH_GITHUB_TOKEN: TOKEN,
        OWNERSWITCH_DEVICE_SECRET: DEVICE_SECRET,
        OWNERSWITCH_CANARY_KEY: "canary-key",
        OWNERSWITCH_CONTROL_PLANE_URL: "http://127.0.0.1:4600",
        GITHUB_TOKEN: TOKEN, // alias name, same credential
        GH_TOKEN: TOKEN,
        AUTH_HEADER: `Bearer ${TOKEN}`, // credential composed into a value
      },
      secretValues: [DEVICE_SECRET, TOKEN],
    });

    const serialized = JSON.stringify(env);
    expect(serialized).not.toContain(TOKEN);
    expect(serialized).not.toContain(DEVICE_SECRET);
    expect(Object.keys(env).some((k) => k.startsWith("OWNERSWITCH_"))).toBe(false);
    // the safe base survives — this is a filter, not a blackout
    expect(env).toMatchObject({ HOME: "/home/user", PATH: "/usr/bin" });
  });

  it("strips a credential even when upstream.env explicitly re-adds it under a new name", () => {
    const env = upstreamEnvironment({
      base: { PATH: "/usr/bin" },
      configured: {
        MY_UPSTREAM_FLAG: "on",
        SNEAKY: TOKEN, // an operator mistake must not become an inheritance
        OWNERSWITCH_GITHUB_TOKEN: TOKEN,
      },
      secretValues: [TOKEN],
    });
    expect(JSON.stringify(env)).not.toContain(TOKEN);
    expect(env.MY_UPSTREAM_FLAG).toBe("on"); // legitimate configured env passes
  });

  it("the upstream's OWN credentials pass through — only the gateway's are stripped", () => {
    // the upstream may legitimately hold its own token (it is the guarded
    // tool); the filter removes the GATEWAY's secrets, not the upstream's
    const env = upstreamEnvironment({
      base: { PATH: "/usr/bin" },
      configured: { UPSTREAM_API_KEY: "upstream-own-key" },
      secretValues: [TOKEN, DEVICE_SECRET],
    });
    expect(env.UPSTREAM_API_KEY).toBe("upstream-own-key");
  });

  it("empty or undefined secret values never blank the environment", () => {
    const env = upstreamEnvironment({
      base: { PATH: "/usr/bin", HOME: "/h" },
      secretValues: ["", undefined],
    });
    expect(env).toEqual({ PATH: "/usr/bin", HOME: "/h" });
  });
});
