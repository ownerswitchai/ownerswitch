#!/usr/bin/env node
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { generateLicenseKeys, mintLicense, verifyLicense, type LicensePlan } from "./license.js";

/**
 * ownerswitch-license — VENDOR-side tooling for 2GO licenses. Customers
 * never need this; a deployment only needs the vendor PUBLIC key and its
 * own token (see license.ts for the doctrine: stopping is free forever,
 * 2GO restore is the product, expiry carries a 72 h anti-ransom grace).
 *
 *   ownerswitch-license keygen [dir]
 *       mint the vendor Ed25519 keypair into <dir> (default .):
 *       license-signing.key.pem (0600) and license-verifying.pub.pem
 *
 *   ownerswitch-license mint --key <private.pem> --licensee "Name" \
 *       [--plan team|enterprise] [--days 365] [--deployment <id>]
 *       sign a license and print the token to stdout. --deployment binds it
 *       to one OWNERSWITCH_DEPLOYMENT_ID — a stolen bound token licenses
 *       nothing anywhere else; prefer it whenever the customer has an id.
 *
 *   ownerswitch-license inspect --pub <public.pem> --token <osl1...>
 *       verify a token and print its payload + state
 *
 * Key MATERIAL travels by file path only — argv carries paths and public
 * facts (licensee, plan), never a private key.
 */

const args = process.argv.slice(2);
const command = args[0];

function flag(name: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
}

function fail(message: string): never {
  console.error(`ownerswitch-license: ${message}`);
  process.exit(1);
}

if (command === "keygen") {
  const dir = resolve(args[1] ?? ".");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const keys = generateLicenseKeys();
  const privatePath = join(dir, "license-signing.key.pem");
  const publicPath = join(dir, "license-verifying.pub.pem");
  writeFileSync(privatePath, keys.privateKeyPem, { mode: 0o600, flag: "wx" }); // never overwrite a signing key
  writeFileSync(publicPath, keys.publicKeyPem, { mode: 0o644 });
  console.error(`signing key   ${privatePath}  (0600 — this IS the business; back it up offline)`);
  console.error(`verifying key ${publicPath}  (ships to deployments via OWNERSWITCH_LICENSE_PUBLIC_KEY_FILE)`);
  process.exit(0);
}

if (command === "mint") {
  const keyFile = flag("key") ?? fail("--key <private.pem> is required");
  const licensee = flag("licensee") ?? fail('--licensee "Name" is required');
  const plan = (flag("plan") ?? "team") as LicensePlan;
  if (plan !== "team" && plan !== "enterprise") fail('--plan must be "team" or "enterprise"');
  const days = Number(flag("days") ?? 365);
  if (!Number.isFinite(days) || days <= 0) fail("--days must be a positive number");
  const deploymentId = flag("deployment");
  const issuedAt = Date.now();
  const token = mintLicense(
    {
      v: 1,
      jti: `lic_${randomBytes(8).toString("hex")}`,
      plan,
      licensee,
      ...(deploymentId !== undefined ? { deploymentId } : {}),
      issuedAt,
      expiresAt: issuedAt + Math.round(days * 86_400_000),
    },
    readFileSync(keyFile, "utf8"),
  );
  console.log(token); // stdout only: pipe it straight to the customer channel
  process.exit(0);
}

if (command === "inspect") {
  const pubFile = flag("pub") ?? fail("--pub <public.pem> is required");
  const token = flag("token") ?? fail("--token <osl1...> is required");
  const verdict = verifyLicense(token, readFileSync(pubFile, "utf8"), Date.now());
  if (!verdict.ok) {
    console.error(`INVALID: ${verdict.reason}`);
    process.exit(1);
  }
  console.log(JSON.stringify({ state: verdict.state, ...verdict.license }, null, 2));
  process.exit(0);
}

fail(`unknown command "${command ?? ""}" — usage: keygen | mint | inspect`);
