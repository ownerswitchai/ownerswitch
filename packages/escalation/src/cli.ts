#!/usr/bin/env node
import { createServer } from "node:http";
import { generateVapidKeys } from "./channels/webpush.js";
import { escalationConfigFromEnv } from "./config.js";
import { createEscalationService } from "./service.js";

/**
 * ownerswitch-escalation — run the ladder, or mint enrollment keys.
 *
 *   ownerswitch-escalation              run the service from the environment
 *   ownerswitch-escalation vapid-keys   mint a VAPID keypair (prints, never stores)
 *
 * Secrets come from the environment only (config.ts states the doctrine);
 * there are deliberately no flags to pass them on argv.
 */

const command = process.argv[2];

if (command === "vapid-keys") {
  const keys = generateVapidKeys();
  // stdout is the delivery: the operator pipes this into their secret
  // store. The private key is printed exactly once and never written.
  console.log(`OWNERSWITCH_VAPID_PUBLIC_KEY=${keys.publicKey}`);
  console.log(`OWNERSWITCH_VAPID_PRIVATE_KEY=${keys.privateKey}`);
  console.log(`OWNERSWITCH_VAPID_SUBJECT=mailto:you@example.com`);
  console.error("# keep the private key out of the repo: env / secret store only");
  process.exit(0);
}

if (command !== undefined && command !== "run") {
  console.error(`unknown command "${command}" — usage: ownerswitch-escalation [run|vapid-keys]`);
  process.exit(2);
}

let config;
try {
  config = escalationConfigFromEnv();
} catch (err) {
  console.error(`[ownerswitch-escalation] ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}

const service = createEscalationService({ config });
const server = createServer(service.webhookHandler);
server.listen(config.listenPort, config.listenHost, () => {
  const channels = [
    ...(config.vapid !== undefined ? ["push"] : []),
    ...(config.twilio !== undefined ? ["sms", "voice"] : []),
  ];
  console.error(
    `[ownerswitch-escalation] webhook on http://${config.listenHost}:${config.listenPort} — ` +
      `channels: ${channels.join(", ")}; polling ${config.controlPlaneUrl} every ${config.pollMs} ms`,
  );
});

const loop = setInterval(() => {
  void service.tickOnce();
}, config.pollMs);

const shutdown = () => {
  clearInterval(loop);
  server.close(() => process.exit(0));
  // a webhook that lingers must not block the stop of the stopper
  setTimeout(() => process.exit(0), 2_000).unref();
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
