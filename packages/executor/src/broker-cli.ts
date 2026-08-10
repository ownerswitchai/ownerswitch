#!/usr/bin/env node
/**
 * ownerswitch-token-broker — the standalone credential broker process
 * (token-broker.ts). Run it under its OWN uid, one the agent and gateway
 * do not share; it alone reads the GitHub App private key, and it serves
 * short-lived single-repository installation tokens over a UNIX socket.
 *
 * Environment (all secrets via env or file, never argv — CONTRIBUTING.md):
 *   OWNERSWITCH_GITHUB_APP_ID                the App id (iss claim)
 *   OWNERSWITCH_GITHUB_APP_INSTALLATION_ID   numeric installation id
 *   OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE  absolute path, broker-owned,
 *                                            0600, outside the agent
 *                                            workspace
 *   OWNERSWITCH_AGENT_WORKSPACE              the agent's workspace dir —
 *                                            passed EXPLICITLY so the key
 *                                            placement check runs against
 *                                            the real workspace, not this
 *                                            process's cwd
 *   OWNERSWITCH_BROKER_SOCKET                socket path; parent dir must
 *                                            be broker-owned, mode 0750,
 *                                            gateway's user in its group
 *   OWNERSWITCH_CONTROL_PLANE_URL            kill state — checked live
 *                                            before every token response
 *   OWNERSWITCH_BROKER_ALLOWED_REPOS         optional comma-separated repo
 *                                            names the broker will mint for
 *   OWNERSWITCH_TIMEOUT_MS                   optional control-plane timeout
 */
import { createControlPlaneClient } from "@ownerswitchai/gateway";
import { createInstallationTokenSource } from "./github-app-auth.js";
import { loadGitHubAppPrivateKey } from "./github-app-key.js";
import { liveKillStateFromControlPlane } from "./live-kill-state.js";
import { createSecretLedger } from "./secret-ledger.js";
import { createTokenBroker } from "./token-broker.js";

function required(env: Record<string, string | undefined>, name: string): string {
  const value = env[name]?.trim();
  if (value === undefined || value === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

async function main(): Promise<void> {
  const env = process.env;
  const appId = required(env, "OWNERSWITCH_GITHUB_APP_ID");
  const installationId = required(env, "OWNERSWITCH_GITHUB_APP_INSTALLATION_ID");
  const keyFile = required(env, "OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE");
  const agentWorkspace = required(env, "OWNERSWITCH_AGENT_WORKSPACE");
  const socketPath = required(env, "OWNERSWITCH_BROKER_SOCKET");
  const controlPlaneUrl = required(env, "OWNERSWITCH_CONTROL_PLANE_URL");
  const allowedRaw = env.OWNERSWITCH_BROKER_ALLOWED_REPOS?.trim();
  const allowedRepos =
    allowedRaw === undefined || allowedRaw === ""
      ? undefined
      : allowedRaw.split(",").map((r) => r.trim()).filter((r) => r !== "");
  const timeoutMs = env.OWNERSWITCH_TIMEOUT_MS !== undefined ? Number(env.OWNERSWITCH_TIMEOUT_MS) : 1500;

  const ledger = createSecretLedger();
  const key = loadGitHubAppPrivateKey(keyFile, { workspaceDir: agentWorkspace });
  ledger.add(key.pem);

  const broker = createTokenBroker({
    tokens: createInstallationTokenSource({
      app: { appId, installationId, privateKey: key.key },
      ledger,
    }),
    ledger,
    fetchLiveKillState: liveKillStateFromControlPlane(
      createControlPlaneClient({ baseUrl: controlPlaneUrl, timeoutMs }),
    ),
    ...(allowedRepos !== undefined ? { allowedRepos } : {}),
    log: (line) => console.error(line),
  });

  await broker.listen(socketPath);
  console.error(
    `[token-broker] App ${appId}, installation ${installationId}; ` +
      `allowed repos: ${allowedRepos === undefined ? "(installation-bounded)" : allowedRepos.join(", ")}; ` +
      `kill state: ${controlPlaneUrl} (checked before every mint, fail closed)`,
  );

  const shutdown = (): void => {
    void broker.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err: unknown) => {
  console.error(`[token-broker] failed to start: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
