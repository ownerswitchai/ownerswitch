/**
 * Resolving the canary key without ever putting it on the command line.
 *
 * `--canary-key` used to be a CLI flag. That was the same mistake fixed for
 * `--owner-token` in packages/mcp (PR #19): a long-lived secret on argv
 * leaks into shell history and `ps`/process listings, and — worse for a
 * long-running `watch` daemon — stays visible in process metadata for as
 * long as the process runs, not just for one command's duration. Anyone who
 * reads it can mint a registry containing an attacker-chosen "decoy" value,
 * i.e. forge a kill trigger.
 *
 * This module mirrors packages/mcp/src/verify.ts's resolution order exactly:
 * the environment variable first, then an interactive, echo-suppressed
 * prompt — never argv.
 */

export interface HiddenLineInput {
  isTTY?: boolean;
  isRaw?: boolean;
  setRawMode?: (mode: boolean) => unknown;
  setEncoding?: (encoding: BufferEncoding) => unknown;
  resume: () => unknown;
  pause: () => unknown;
  on: (event: "data", listener: (chunk: string) => void) => unknown;
  removeListener: (event: "data", listener: (chunk: string) => void) => unknown;
}
export interface HiddenLineOutput {
  write: (chunk: string) => void;
}

/**
 * Reads one line from `input` without ever echoing the typed characters to
 * `output` — raw mode disables the terminal's own echo, and this function
 * writes nothing back except the literal prompt and a trailing newline once
 * the user presses Enter. Used for the canary-key prompt so a pasted secret
 * never lands in terminal scrollback or a captured recording.
 *
 * Fails closed if `setRawMode` is unavailable: without it there is no way to
 * suppress the terminal's own echo, so reading anyway would silently
 * downgrade "hidden" to "typed in the open" — the one outcome this function
 * exists to prevent. Nothing is written and nothing is read in that case;
 * the caller sees the same `undefined` it would get from an empty line (the
 * same fallback `promptCanaryKeyFromTty` already uses one level up for "not
 * a TTY at all").
 */
export async function readHiddenLine(
  promptText: string,
  input: HiddenLineInput,
  output: HiddenLineOutput,
): Promise<string | undefined> {
  if (input.setRawMode === undefined) return undefined;
  output.write(promptText);
  const wasRaw = input.isRaw ?? false;
  input.setEncoding?.("utf8");
  input.setRawMode(true);
  input.resume();

  // Control characters compared by code point, not string literals — a raw
  // control byte in source is invisible and easy to corrupt in transit; a
  // numeric comparison against a named constant isn't.
  const ENTER_CODES = new Set([10, 13]); // \n, \r
  const CTRL_C_CODE = 3; // ETX
  const BACKSPACE_CODES = new Set([8, 127]); // BS, DEL

  return new Promise((resolve) => {
    let value = "";
    const onData = (chunk: string): void => {
      for (const char of chunk) {
        const code = char.codePointAt(0);
        if (code !== undefined && ENTER_CODES.has(code)) {
          cleanup();
          output.write("\n");
          resolve(value === "" ? undefined : value);
          return;
        }
        if (code === CTRL_C_CODE) {
          // Raw mode suppresses the terminal's own SIGINT generation, so
          // this is the only place Ctrl-C can be handled — restore the
          // terminal and exit the same way an uncaught SIGINT would.
          cleanup();
          output.write("\n");
          process.exit(130);
          return;
        }
        if (code !== undefined && BACKSPACE_CODES.has(code)) {
          value = value.slice(0, -1);
          continue;
        }
        value += char;
      }
    };
    const cleanup = (): void => {
      input.removeListener("data", onData);
      input.setRawMode?.(wasRaw);
      input.pause();
    };
    input.on("data", onData);
  });
}

/**
 * The canary key, from the environment or an interactive, echo-suppressed
 * prompt — never argv, which `ps` and shell history record.
 */
export async function resolveCanaryKey(
  env: Record<string, string | undefined>,
  promptImpl?: () => Promise<string | undefined>,
): Promise<string | undefined> {
  const fromEnv = env.OWNERSWITCH_CANARY_KEY?.trim();
  if (fromEnv !== undefined && fromEnv !== "") return fromEnv;
  const prompt = promptImpl ?? promptCanaryKeyFromTty;
  return prompt();
}

async function promptCanaryKeyFromTty(): Promise<string | undefined> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return undefined;
  const trimmed = (
    await readHiddenLine(
      "Canary key (dedicated per-deployment secret — never the device secret): ",
      process.stdin,
      process.stdout,
    )
  )?.trim();
  return trimmed === undefined || trimmed === "" ? undefined : trimmed;
}

/** Message shown when `--canary-key` appears on argv — names the exact leak, matching --owner-token's fix. */
export const CANARY_KEY_FLAG_ERROR =
  "--canary-key was removed: a secret on the command line leaks into shell history and process " +
  "listings, and (for `watch`, which keeps running) stays visible in process metadata for as long " +
  "as the process is alive. Set OWNERSWITCH_CANARY_KEY, or run this command in a terminal and paste " +
  "the key at the prompt.";

/** True if argv contains the removed --canary-key flag, bare or `--canary-key=value` form. */
export function hasCanaryKeyFlag(argv: string[]): boolean {
  return argv.some((arg) => arg === "--canary-key" || arg.startsWith("--canary-key="));
}
