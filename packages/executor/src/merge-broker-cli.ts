#!/usr/bin/env node
/**
 * ownerswitch-merge-broker — the standalone EXECUTING credential broker
 * (merge-broker.ts). Run it under its OWN uid, one the agent and gateway do
 * not share; it alone reads the GitHub App private key, alone holds the
 * control-plane grant key, and NEVER returns a token — it validates a signed
 * grant and performs the merge itself.
 *
 * Environment (all secrets via env or file, never argv — CONTRIBUTING.md):
 *   OWNERSWITCH_GITHUB_APP_ID                the App id (iss claim)
 *   OWNERSWITCH_GITHUB_APP_INSTALLATION_ID   numeric installation id
 *   OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE  absolute path, broker-owned,
 *                                            0600, outside the agent workspace
 *   OWNERSWITCH_AGENT_WORKSPACE              the agent's workspace, passed
 *                                            EXPLICITLY so the key placement
 *                                            check runs against the real
 *                                            workspace, not this process's cwd
 *   OWNERSWITCH_GRANT_KEY                    HMAC key shared ONLY with the
 *                                            control plane; verifies grants
 *   OWNERSWITCH_BROKER_SOCKET                socket path; parent dir must be
 *                                            broker-owned, setgid 02750, with
 *                                            the gateway's user in its group
 *   OWNERSWITCH_BROKER_SOCKET_GID            optional: the gid the socket must
 *                                            end up owned by; refuses to serve
 *                                            on a mismatch
 *   OWNERSWITCH_CONTROL_PLANE_URL            kill state — checked live before
 *                                            every pin and every merge
 *   OWNERSWITCH_BROKER_ALLOWED_REPOS         optional comma-separated repos
 *   OWNERSWITCH_TIMEOUT_MS                   optional control-plane timeout
 */
import { createControlPlaneClient } from "@ownerswitchai/gateway";
import { createInstallationTokenSource } from "./github-app-auth.js";
import { loadGitHubAppPrivateKey } from "./github-app-key.js";
import { liveKillStateFromControlPlane } from "./live-kill-state.js";
import { createMergeBroker } from "./merge-broker.js";
import { createSecretLedger } from "./secret-ledger.js";

function required(env: Record<string, string | undefined>, name: string): string {
  const value = env[name]?.trim();
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}

async function main(): Promise<void> {
  const env = process.env;
  const appId = required(env, "OWNERSWITCH_GITHUB_APP_ID");
  const installationId = required(env, "OWNERSWITCH_GITHUB_APP_INSTALLATION_ID");
  const keyFile = required(env, "OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE");
  const agentWorkspace = required(env, "OWNERSWITCH_AGENT_WORKSPACE");
  const grantKey = required(env, "OWNERSWITCH_GRANT_KEY");
  const socketPath = required(env, "OWNERSWITCH_BROKER_SOCKET");
  const controlPlaneUrl = required(env, "OWNERSWITCH_CONTROL_PLANE_URL");
  const allowedRaw = env.OWNERSWITCH_BROKER_ALLOWED_REPOS?.trim();
  const allowedRepos =
    allowedRaw === undefined || allowedRaw === ""
      ? undefined
      : allowedRaw.split(",").map((r) => r.trim()).filter((r) => r !== "");
  const socketGidRaw = env.OWNERSWITCH_BROKER_SOCKET_GID?.trim();
  const socketGid = socketGidRaw !== undefined && socketGidRaw !== "" ? Number(socketGidRaw) : undefined;
  const timeoutMs = env.OWNERSWITCH_TIMEOUT_MS !== undefined ? Number(env.OWNERSWITCH_TIMEOUT_MS) : 1500;

  const ledger = createSecretLedger();
  const key = loadGitHubAppPrivateKey(keyFile, { workspaceDir: agentWorkspace });
  ledger.add(key.pem);
  ledger.add(grantKey);

  const broker = createMergeBroker({
    tokens: createInstallationTokenSource({
      app: { appId, installationId, privateKey: key.key },
      ledger,
    }),
    ledger,
    grantKey,
    fetchLiveKillState: liveKillStateFromControlPlane(
      createControlPlaneClient({ baseUrl: controlPlaneUrl, timeoutMs }),
    ),
    ...(allowedRepos !== undefined ? { allowedRepos } : {}),
    ...(socketGid !== undefined ? { socketGid } : {}),
    log: (line) => console.error(line),
  });

  await broker.listen(socketPath);
  console.error(
    `[merge-broker] EXECUTING broker — App ${appId}, installation ${installationId}; ` +
      `never returns a token or the key; grants verified against the shared control-plane key; ` +
      `kill state: ${controlPlaneUrl} (checked before every pin and every merge, fail closed)`,
  );

  const shutdown = (): void => {
    void broker.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err: unknown) => {
  console.error(`[merge-broker] failed to start: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
