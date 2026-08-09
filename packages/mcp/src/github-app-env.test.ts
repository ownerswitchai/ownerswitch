import { describe, expect, it } from "vitest";
import { ConfigError } from "./config.js";
import { resolveGitHubAppEnv } from "./github-app-env.js";

const FULL = {
  OWNERSWITCH_GITHUB_APP_ID: "12345",
  OWNERSWITCH_GITHUB_APP_INSTALLATION_ID: "67890",
  OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE: "/etc/ownerswitch/github-app.pem",
};

describe("resolveGitHubAppEnv", () => {
  it("returns undefined when nothing is configured — running without the connector is a choice", () => {
    expect(resolveGitHubAppEnv({})).toBeUndefined();
  });

  it("resolves the full triple", () => {
    expect(resolveGitHubAppEnv(FULL)).toEqual({
      appId: "12345",
      installationId: "67890",
      privateKeyFile: "/etc/ownerswitch/github-app.pem",
    });
  });

  it("refuses a partial configuration at startup, naming what is missing", () => {
    const { OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE: _dropped, ...partial } = FULL;
    expect(() => resolveGitHubAppEnv(partial)).toThrowError(ConfigError);
    expect(() => resolveGitHubAppEnv(partial)).toThrowError(
      /OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE missing/,
    );
  });

  it("treats empty and whitespace-only values as missing, not as configuration", () => {
    expect(() =>
      resolveGitHubAppEnv({ ...FULL, OWNERSWITCH_GITHUB_APP_ID: "  " }),
    ).toThrowError(/OWNERSWITCH_GITHUB_APP_ID missing/);
  });

  it("refuses a non-numeric installation id — the value from the installation URL, not the App id slug", () => {
    expect(() =>
      resolveGitHubAppEnv({ ...FULL, OWNERSWITCH_GITHUB_APP_INSTALLATION_ID: "my-org" }),
    ).toThrowError(/numeric installation id/);
  });
});
