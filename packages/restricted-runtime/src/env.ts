import { upstreamEnvironment } from "@ownerswitchai/mcp";

/**
 * Environment variable NAMES that, by convention, carry a credential to a
 * DOWNSTREAM system the agent might act on — a GitHub token, a cloud key, a
 * database URL. These are stripped from the agent process's environment so
 * that a denied-but-attempted action has nothing ambient to spend: even if
 * the agent reaches a network path the profile did not foresee, it holds no
 * key to authenticate with. This is the profile's software-level stand-in
 * for the credential-broker model that THREAT-MODEL.md §3(a) ranks first —
 * weaker than a broker (a broker keeps the keys on another machine), but it
 * removes the specific failure the broker removes: ambient authority sitting
 * in the agent's env.
 *
 * Deliberately NOT here: the agent's OWN model credential
 * (ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN, …). That authenticates the
 * agent to Claude; it grants no access to any resource the OwnerSwitch policy
 * guards, and stripping it would simply stop the agent from running. The line
 * this list draws is "credentials to things the agent acts ON", not "every
 * secret".
 *
 * OWNERSWITCH_* names are stripped independently by upstreamEnvironment()
 * regardless of this list — the gateway's own device secret, canary key and
 * connector tokens must never sit in the agent's env (the gateway child reads
 * them from its --config file instead, see the launcher).
 */
export const DOWNSTREAM_CREDENTIAL_NAMES: readonly string[] = [
  // OwnerSwitch's own seams (also matched by name in packages/mcp/src/cli.ts)
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "GITHUB_PAT",
  "DEVICE_SECRET",
  "CANARY_KEY",
  // common cloud / SaaS / VCS / registry credentials
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GCP_SERVICE_ACCOUNT_KEY",
  "AZURE_CLIENT_SECRET",
  "GITLAB_TOKEN",
  "SLACK_TOKEN",
  "SLACK_BOT_TOKEN",
  "NPM_TOKEN",
  "DOCKER_PASSWORD",
  "STRIPE_SECRET_KEY",
  "OPENAI_API_KEY",
  // datastore credentials
  "DATABASE_URL",
  "PGPASSWORD",
  "MYSQL_PWD",
  "REDIS_URL",
];

export interface RestrictedEnvOptions {
  /**
   * Extra credential NAMES to strip beyond DOWNSTREAM_CREDENTIAL_NAMES, for a
   * deployment that carries its own conventions (e.g. "ACME_API_KEY").
   */
  extraSecretNames?: readonly string[];
  /**
   * Extra credential VALUES to strip regardless of the name they appear
   * under — pass the literal secrets the deployment holds so one cannot ride
   * into the agent under an unexpected alias.
   */
  extraSecretValues?: readonly string[];
}

/**
 * Build the environment for the restricted Claude Code process: everything in
 * `source` EXCEPT the credentials that would give a bypassing agent ambient
 * authority. Reuses packages/mcp/src/upstream-env.ts's upstreamEnvironment()
 * verbatim — the same filter the gateway already trusts to keep credentials
 * out of the upstream child — because the restricted agent is exactly another
 * "untrusted side of the boundary" that must hold no downstream key.
 *
 * What upstreamEnvironment() removes from the merged env:
 *   - every OWNERSWITCH_* variable, by name (the gateway's own namespace);
 *   - every variable whose NAME is a known credential alias (secretNames);
 *   - every variable whose VALUE contains a known credential (secretValues),
 *     so a token cannot survive by being renamed.
 * Everything else — PATH, HOME, the agent's model auth, proxy config — passes
 * through, so the agent still runs and can still reach the gateway.
 */
export function buildRestrictedAgentEnv(
  source: NodeJS.ProcessEnv,
  opts: RestrictedEnvOptions = {},
): Record<string, string> {
  // upstreamEnvironment() wants a Record<string,string>; process.env values
  // are string | undefined, so drop the undefined holes first.
  const base: Record<string, string> = {};
  for (const [key, value] of Object.entries(source)) {
    if (typeof value === "string") base[key] = value;
  }

  const secretNames = [...DOWNSTREAM_CREDENTIAL_NAMES, ...(opts.extraSecretNames ?? [])];

  // Strip by value too: collect the concrete values of the named credentials
  // AND of every OWNERSWITCH_* variable present, so a credential that has been
  // copied into an unrecognised name is still caught. (upstreamEnvironment()
  // ignores empty/undefined entries.)
  const secretValues: string[] = [...(opts.extraSecretValues ?? [])];
  for (const name of secretNames) {
    const v = base[name];
    if (v) secretValues.push(v);
  }
  for (const [key, value] of Object.entries(base)) {
    if (/^OWNERSWITCH_/i.test(key) && value) secretValues.push(value);
  }

  return upstreamEnvironment({ base, secretNames, secretValues });
}
