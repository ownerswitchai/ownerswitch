import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateHoneytoken, type Honeytoken } from "./generate.js";

/**
 * Plant decoy credential files: a fake `.env.backup` and a fake
 * `credentials.json` — the two shapes a credential sweep greps for first.
 * Every "secret" in them is a honeytoken; nothing else in the files is real
 * either. Each file gets its own tokens, so a trip's canary id also says
 * WHICH file was touched.
 *
 * The canary-id → file/key mapping is returned to the caller and belongs
 * somewhere the decoys are not (the CLI prints it; --manifest can save it).
 * A mapping stored next to the bait is a shopping list of what to avoid.
 */

export const DECOY_FILENAMES = [".env.backup", "credentials.json"] as const;

export interface PlantOptions {
  dir: string;
  /** Replace existing files of the same names. Off by default: never destroy a real backup. */
  force?: boolean;
}

export interface PlantedToken {
  token: Honeytoken;
  /** Absolute-or-as-given path of the file the token sits in. */
  file: string;
  /** The env var or JSON path the value sits under. */
  key: string;
}

export interface PlantResult {
  /** Paths written, in DECOY_FILENAMES order. */
  files: string[];
  planted: PlantedToken[];
}

export function plantHoneytokens(opts: PlantOptions): PlantResult {
  mkdirSync(opts.dir, { recursive: true });

  // Check every target before writing any: a real file with one of these
  // names is exactly what this package must never destroy, and a partial
  // plant (one file written, then a refusal) would leave confusing bait.
  for (const name of DECOY_FILENAMES) {
    const path = join(opts.dir, name);
    if (!opts.force && existsSync(path)) {
      throw new Error(`refusing to overwrite ${path} — it already exists (use force to replace it)`);
    }
  }

  const planted: PlantedToken[] = [];
  const mint = (kind: Honeytoken["kind"], file: string, key: string): string => {
    const token = generateHoneytoken({ kind, label: `${file} ${key}` });
    planted.push({ token, file, key });
    return token.value;
  };

  const envPath = join(opts.dir, ".env.backup");
  const envContent = [
    "# saved before the credential rotation — do not commit",
    "NODE_ENV=production",
    `AWS_ACCESS_KEY_ID=${mint("aws", envPath, "AWS_ACCESS_KEY_ID")}`,
    `AWS_SECRET_ACCESS_KEY=${mint("generic", envPath, "AWS_SECRET_ACCESS_KEY")}`,
    `STRIPE_SECRET_KEY=${mint("stripe", envPath, "STRIPE_SECRET_KEY")}`,
    `OPENAI_API_KEY=${mint("openai", envPath, "OPENAI_API_KEY")}`,
    "",
  ].join("\n");

  const credsPath = join(opts.dir, "credentials.json");
  const credsContent = `${JSON.stringify(
    {
      aws: {
        access_key_id: mint("aws", credsPath, "aws.access_key_id"),
        secret_access_key: mint("generic", credsPath, "aws.secret_access_key"),
      },
      stripe: { secret_key: mint("stripe", credsPath, "stripe.secret_key") },
      openai: { api_key: mint("openai", credsPath, "openai.api_key") },
    },
    null,
    2,
  )}\n`;

  writeFileSync(envPath, envContent);
  writeFileSync(credsPath, credsContent);

  return { files: [envPath, credsPath], planted };
}
