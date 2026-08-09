import { describe, expect, it } from "vitest";
import { DOWNSTREAM_CREDENTIAL_NAMES, buildRestrictedAgentEnv } from "./env.js";

describe("buildRestrictedAgentEnv", () => {
  it("keeps what the agent needs to run: PATH, HOME, and its own model auth", () => {
    const env = buildRestrictedAgentEnv({
      PATH: "/usr/bin",
      HOME: "/home/agent",
      ANTHROPIC_API_KEY: "sk-ant-model-auth",
      CLAUDE_CODE_OAUTH_TOKEN: "oauth-model-auth",
    });
    expect(env.PATH).toBe("/usr/bin");
    expect(env.HOME).toBe("/home/agent");
    // model auth is NOT a downstream credential — it must survive
    expect(env.ANTHROPIC_API_KEY).toBe("sk-ant-model-auth");
    expect(env.CLAUDE_CODE_OAUTH_TOKEN).toBe("oauth-model-auth");
  });

  it("strips every OWNERSWITCH_* variable by name", () => {
    const env = buildRestrictedAgentEnv({
      PATH: "/usr/bin",
      OWNERSWITCH_DEVICE_SECRET: "device-secret",
      OWNERSWITCH_GITHUB_TOKEN: "ghp_downstream",
      OWNERSWITCH_CANARY_KEY: "canary",
      OWNERSWITCH_CONTROL_PLANE_URL: "http://cp",
    });
    expect(env.OWNERSWITCH_DEVICE_SECRET).toBeUndefined();
    expect(env.OWNERSWITCH_GITHUB_TOKEN).toBeUndefined();
    expect(env.OWNERSWITCH_CANARY_KEY).toBeUndefined();
    expect(env.OWNERSWITCH_CONTROL_PLANE_URL).toBeUndefined();
    expect(env.PATH).toBe("/usr/bin");
  });

  it("strips known downstream credential names", () => {
    const source: Record<string, string> = { PATH: "/usr/bin" };
    for (const name of DOWNSTREAM_CREDENTIAL_NAMES) source[name] = `secret-${name}`;
    const env = buildRestrictedAgentEnv(source);
    for (const name of DOWNSTREAM_CREDENTIAL_NAMES) {
      expect(env[name], `${name} should be stripped`).toBeUndefined();
    }
    expect(env.PATH).toBe("/usr/bin");
  });

  it("strips a credential riding under an unexpected name (by value)", () => {
    const env = buildRestrictedAgentEnv({
      PATH: "/usr/bin",
      GITHUB_TOKEN: "ghp_verysecret",
      // same secret copied into a name the list doesn't know
      MY_CUSTOM_ALIAS: "ghp_verysecret",
    });
    expect(env.GITHUB_TOKEN).toBeUndefined();
    expect(env.MY_CUSTOM_ALIAS).toBeUndefined();
  });

  it("strips OWNERSWITCH_* values that reappear under another name", () => {
    const env = buildRestrictedAgentEnv({
      PATH: "/usr/bin",
      OWNERSWITCH_DEVICE_SECRET: "dev-secret-xyz",
      LEAKED_COPY: "dev-secret-xyz",
    });
    expect(env.OWNERSWITCH_DEVICE_SECRET).toBeUndefined();
    expect(env.LEAKED_COPY).toBeUndefined();
  });

  it("honors extra secret names and values", () => {
    const env = buildRestrictedAgentEnv(
      { PATH: "/usr/bin", ACME_API_KEY: "acme-123", RENAMED: "raw-value" },
      { extraSecretNames: ["ACME_API_KEY"], extraSecretValues: ["raw-value"] },
    );
    expect(env.ACME_API_KEY).toBeUndefined();
    expect(env.RENAMED).toBeUndefined();
    expect(env.PATH).toBe("/usr/bin");
  });

  it("drops undefined process.env holes without crashing", () => {
    const env = buildRestrictedAgentEnv({ PATH: "/usr/bin", MAYBE: undefined });
    expect(env.PATH).toBe("/usr/bin");
    expect("MAYBE" in env).toBe(false);
  });
});
