import { ConfigError } from "./config.js";

/**
 * The GitHub App credential seam — environment only, never the config file
 * and never argv (CONTRIBUTING.md: secrets never come from argv; the config
 * file is checked into deployments too casually to carry a key path that
 * doubles as a security boundary).
 *
 * All-or-nothing: a deployment that sets SOME of the three variables is a
 * misconfiguration in progress, and silently running without the connector
 * would surface as "not configured" only at the first approved merge —
 * after an owner said yes and a single-use ticket burned. Refuse at startup
 * instead, naming exactly what is missing. Setting NONE is a choice (the
 * gateway runs, routed merges fail cleanly as not-configured) and stays
 * allowed.
 */
export interface GitHubAppEnv {
  /** OWNERSWITCH_GITHUB_APP_ID — the App id (or client id); not a secret */
  appId: string;
  /** OWNERSWITCH_GITHUB_APP_INSTALLATION_ID — numeric installation id */
  installationId: string;
  /**
   * OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE — absolute path to the App's
   * PEM key, OUTSIDE the agent's workspace (enforced at load,
   * packages/executor/src/github-app-key.ts)
   */
  privateKeyFile: string;
}

const VAR_NAMES = [
  "OWNERSWITCH_GITHUB_APP_ID",
  "OWNERSWITCH_GITHUB_APP_INSTALLATION_ID",
  "OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE",
] as const;

export function resolveGitHubAppEnv(
  env: Record<string, string | undefined>,
): GitHubAppEnv | undefined {
  const values = VAR_NAMES.map((name) => {
    const raw = env[name]?.trim();
    return raw === "" ? undefined : raw;
  });
  const missing = VAR_NAMES.filter((_, i) => values[i] === undefined);
  if (missing.length === VAR_NAMES.length) return undefined;
  if (missing.length > 0) {
    throw new ConfigError(
      `partial GitHub App configuration: ${missing.join(" and ")} missing — set all of ` +
        `${VAR_NAMES.join(", ")}, or none to run without the GitHub connector`,
    );
  }
  const [appId, installationId, privateKeyFile] = values as [string, string, string];
  if (!/^\d+$/.test(installationId)) {
    throw new ConfigError(
      "OWNERSWITCH_GITHUB_APP_INSTALLATION_ID must be the numeric installation id (the number " +
        "in the installation's settings URL) — got a non-numeric value",
    );
  }
  return { appId, installationId, privateKeyFile };
}
