import { describe, expect, it } from "vitest";
import { ConfigError } from "./config.js";
import { resolveGitHubConnectorEnv } from "./github-app-env.js";

const TRIPLE = {
  OWNERSWITCH_GITHUB_APP_ID: "12345",
  OWNERSWITCH_GITHUB_APP_INSTALLATION_ID: "67890",
  OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE: "/etc/ownerswitch/github-app.pem",
};
const ACK = { OWNERSWITCH_GITHUB_APP_ACCEPT_SAME_UID_KEY_RISK: "1" };

describe("resolveGitHubConnectorEnv", () => {
  it("returns undefined when nothing is configured — running without the connector is a choice", () => {
    expect(resolveGitHubConnectorEnv({})).toBeUndefined();
  });

  it("resolves broker mode from the socket variable — the recommended shape", () => {
    expect(
      resolveGitHubConnectorEnv({ OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET: "/run/oswitch/broker.sock" }),
    ).toEqual({ mode: "broker", socketPath: "/run/oswitch/broker.sock" });
  });

  it("REFUSES the same-process triple without the explicit same-uid risk acknowledgment", () => {
    expect(() => resolveGitHubConnectorEnv(TRIPLE)).toThrowError(ConfigError);
    expect(() => resolveGitHubConnectorEnv(TRIPLE)).toThrowError(
      /shares a uid with the agent.*token broker/s,
    );
  });

  it("resolves same-process mode only with the acknowledgment set", () => {
    expect(resolveGitHubConnectorEnv({ ...TRIPLE, ...ACK })).toEqual({
      mode: "same-process",
      appId: "12345",
      installationId: "67890",
      privateKeyFile: "/etc/ownerswitch/github-app.pem",
    });
  });

  it("refuses broker AND triple together — the credential lives in exactly one place", () => {
    expect(() =>
      resolveGitHubConnectorEnv({
        ...TRIPLE,
        ...ACK,
        OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET: "/run/oswitch/broker.sock",
      }),
    ).toThrowError(/both set/);
  });

  it("refuses a partial triple at startup, naming what is missing", () => {
    const { OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE: _dropped, ...partial } = TRIPLE;
    expect(() => resolveGitHubConnectorEnv({ ...partial, ...ACK })).toThrowError(
      /OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE missing/,
    );
  });

  it("treats empty and whitespace-only values as missing, not as configuration", () => {
    expect(() =>
      resolveGitHubConnectorEnv({ ...TRIPLE, ...ACK, OWNERSWITCH_GITHUB_APP_ID: "  " }),
    ).toThrowError(/OWNERSWITCH_GITHUB_APP_ID missing/);
  });

  it("refuses a non-numeric installation id", () => {
    expect(() =>
      resolveGitHubConnectorEnv({
        ...TRIPLE,
        ...ACK,
        OWNERSWITCH_GITHUB_APP_INSTALLATION_ID: "my-org",
      }),
    ).toThrowError(/numeric installation id/);
  });
});
