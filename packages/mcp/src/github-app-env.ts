import { ConfigError } from "./config.js";

/**
 * The GitHub connector's credential seam — environment only, never the
 * config file and never argv (CONTRIBUTING.md: secrets never come from
 * argv; the config file is checked into deployments too casually to carry
 * a key path that doubles as a security boundary).
 *
 * Two modes, mutually exclusive:
 *
 *  - **broker** (recommended, and the only shape that isolates the key):
 *    `OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET` names the UNIX socket of a
 *    executing merge broker running under its OWN uid
 *    (ownerswitch-merge-broker), which validates a control-plane grant and
 *    performs the merge itself — the gateway never holds the key or a token.
 *    The gateway never reads the private key at all. This is the mode the
 *    threat model's key-isolation claims are about: in the stdio MCP
 *    deployment the client spawns the gateway, so gateway and agent share
 *    a uid — a key file the gateway could read, the agent could read too.
 *
 *  - **same-process** (degraded, explicit opt-in): the
 *    `OWNERSWITCH_GITHUB_APP_*` triple loads the key INTO the gateway
 *    process. Because that makes the key readable by anything sharing the
 *    gateway's uid — in stdio deployments, the agent — it REFUSES to start
 *    unless `OWNERSWITCH_GITHUB_APP_ACCEPT_SAME_UID_KEY_RISK=1` is set,
 *    and it starts loudly when it is. Never silently: a deployment gets
 *    this mode by writing down that it accepted the risk.
 *
 * All-or-nothing within the triple: a deployment that sets SOME of the
 * three variables is a misconfiguration in progress, refused at startup
 * naming exactly what is missing. Setting NONE is a choice (the gateway
 * runs, routed merges refuse cleanly as not-configured) and stays allowed.
 */
export type GitHubConnectorEnv =
  | {
      mode: "broker";
      /** OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET — the broker's UNIX socket */
      socketPath: string;
    }
  | {
      mode: "same-process";
      /** OWNERSWITCH_GITHUB_APP_ID — the App id (or client id); not a secret */
      appId: string;
      /** OWNERSWITCH_GITHUB_APP_INSTALLATION_ID — numeric installation id */
      installationId: string;
      /** OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE — absolute path to the PEM */
      privateKeyFile: string;
    };

const TRIPLE = [
  "OWNERSWITCH_GITHUB_APP_ID",
  "OWNERSWITCH_GITHUB_APP_INSTALLATION_ID",
  "OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE",
] as const;

const BROKER_VAR = "OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET";
const ACK_VAR = "OWNERSWITCH_GITHUB_APP_ACCEPT_SAME_UID_KEY_RISK";

export function resolveGitHubConnectorEnv(
  env: Record<string, string | undefined>,
): GitHubConnectorEnv | undefined {
  const clean = (name: string): string | undefined => {
    const raw = env[name]?.trim();
    return raw === "" ? undefined : raw;
  };
  const brokerSocket = clean(BROKER_VAR);
  const values = TRIPLE.map((name) => clean(name));
  const present = TRIPLE.filter((_, i) => values[i] !== undefined);

  if (brokerSocket !== undefined && present.length > 0) {
    throw new ConfigError(
      `${BROKER_VAR} and ${present.join("/")} are both set — the credential lives in exactly ` +
        `one place: the broker (recommended) or this process (degraded). Unset one.`,
    );
  }
  if (brokerSocket !== undefined) {
    return { mode: "broker", socketPath: brokerSocket };
  }
  if (present.length === 0) return undefined;
  if (present.length < TRIPLE.length) {
    const missing = TRIPLE.filter((_, i) => values[i] === undefined);
    throw new ConfigError(
      `partial GitHub App configuration: ${missing.join(" and ")} missing — set all of ` +
        `${TRIPLE.join(", ")}, or none to run without the GitHub connector`,
    );
  }
  const [appId, installationId, privateKeyFile] = values as [string, string, string];
  if (!/^\d+$/.test(installationId)) {
    throw new ConfigError(
      "OWNERSWITCH_GITHUB_APP_INSTALLATION_ID must be the numeric installation id (the number " +
        "in the installation's settings URL) — got a non-numeric value",
    );
  }
  if (clean(ACK_VAR) !== "1") {
    throw new ConfigError(
      `the OWNERSWITCH_GITHUB_APP_* triple loads the App PRIVATE KEY into the gateway process. ` +
        `In the stdio deployment the gateway shares a uid with the agent, so the agent could ` +
        `read the key — file modes do not protect against a same-uid process. Use the token ` +
        `broker instead (ownerswitch-merge-broker + ${BROKER_VAR}), or set ${ACK_VAR}=1 to ` +
        `accept that risk explicitly.`,
    );
  }
  return { mode: "same-process", appId, installationId, privateKeyFile };
}
