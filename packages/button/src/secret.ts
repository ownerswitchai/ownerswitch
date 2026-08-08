/**
 * Resolves the device HMAC secret without ever accepting it as a CLI flag —
 * mirrors resolveOwnerToken/readHiddenLine in packages/mcp/src/verify.ts. A
 * flag leaks into shell history and process listings, and this secret signs
 * every `POST /kill` the daemon sends, so a leaked secret lets anyone forge
 * an attributed kill.
 */

/**
 * Minimal shape of the streams readHiddenLine needs — matches
 * process.stdin/process.stdout, kept narrow so tests can pass plain fakes
 * instead of real TTYs.
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
 * the user presses Enter. Used for the device-secret prompt so a pasted
 * secret never lands in terminal scrollback or a captured recording.
 */
export async function readHiddenLine(
  promptText: string,
  input: HiddenLineInput,
  output: HiddenLineOutput,
): Promise<string | undefined> {
  output.write(promptText);
  const wasRaw = input.isRaw ?? false;
  input.setEncoding?.("utf8");
  input.setRawMode?.(true);
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
 * The device secret, from the environment or an interactive, echo-suppressed
 * prompt — never argv, which `ps` and shell history record.
 */
export async function resolveDeviceSecret(
  env: Record<string, string | undefined>,
  promptImpl?: () => Promise<string | undefined>,
): Promise<string | undefined> {
  const fromEnv = env.OWNERSWITCH_DEVICE_SECRET?.trim();
  if (fromEnv !== undefined && fromEnv !== "") return fromEnv;
  const prompt = promptImpl ?? promptDeviceSecretFromTty;
  return prompt();
}

async function promptDeviceSecretFromTty(): Promise<string | undefined> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return undefined;
  const trimmed = (
    await readHiddenLine("Device secret (signs kill requests, input hidden): ", process.stdin, process.stdout)
  )?.trim();
  return trimmed === undefined || trimmed === "" ? undefined : trimmed;
}
