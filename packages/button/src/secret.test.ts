import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { readHiddenLine, resolveDeviceSecret } from "./secret.js";

describe("resolveDeviceSecret", () => {
  it("prefers OWNERSWITCH_DEVICE_SECRET, trimmed, and never prompts when it is set", async () => {
    const prompt = vi.fn();
    await expect(
      resolveDeviceSecret({ OWNERSWITCH_DEVICE_SECRET: "  env-secret  " }, prompt as never),
    ).resolves.toBe("env-secret");
    expect(prompt).not.toHaveBeenCalled();
  });

  it("falls back to the prompt when the env var is unset or blank", async () => {
    await expect(resolveDeviceSecret({}, async () => "typed-secret")).resolves.toBe("typed-secret");
    await expect(
      resolveDeviceSecret({ OWNERSWITCH_DEVICE_SECRET: "   " }, async () => "typed-secret"),
    ).resolves.toBe("typed-secret");
    await expect(resolveDeviceSecret({}, async () => undefined)).resolves.toBeUndefined();
  });
});

/** A fake TTY-like stdin: emits raw "keystrokes" as 'data' events, tracks raw-mode toggles. */
function fakeTtyInput() {
  const emitter = new EventEmitter();
  const rawModeCalls: boolean[] = [];
  let resumed = 0;
  let paused = 0;
  const input = Object.assign(emitter, {
    isTTY: true as const,
    isRaw: false,
    setRawMode: (mode: boolean) => {
      rawModeCalls.push(mode);
      input.isRaw = mode;
    },
    setEncoding: () => {},
    resume: () => {
      resumed++;
    },
    pause: () => {
      paused++;
    },
  });
  return {
    input,
    type: (text: string) => emitter.emit("data", text),
    rawModeCalls,
    get resumed() {
      return resumed;
    },
    get paused() {
      return paused;
    },
  };
}

function fakeOutput() {
  const written: string[] = [];
  return { output: { write: (chunk: string) => void written.push(chunk) }, written };
}

describe("readHiddenLine", () => {
  it("writes the prompt but NEVER echoes typed characters, and returns the typed line on Enter", async () => {
    const tty = fakeTtyInput();
    const out = fakeOutput();
    const resultPromise = readHiddenLine("Device secret: ", tty.input, out.output);
    tty.type("s3cr3t-device-key");
    tty.type("\n");
    await expect(resultPromise).resolves.toBe("s3cr3t-device-key");

    // Only the prompt itself and the final newline ever reached output —
    // the secret characters do not appear anywhere in what was written.
    expect(out.written).toEqual(["Device secret: ", "\n"]);
    expect(out.written.join("")).not.toContain("s3cr3t-device-key");
    expect(tty.rawModeCalls).toEqual([true, false]); // enabled, then restored
  });

  it("supports backspace without ever echoing a character", async () => {
    const tty = fakeTtyInput();
    const out = fakeOutput();
    const resultPromise = readHiddenLine("secret: ", tty.input, out.output);
    tty.type("abcX");
    tty.type("\x7f"); // DEL — erase the stray "X"
    tty.type("d");
    tty.type("\r");
    await expect(resultPromise).resolves.toBe("abcd");
    expect(out.written.join("")).toBe("secret: \n");
  });

  it("returns undefined for an empty line", async () => {
    const tty = fakeTtyInput();
    const out = fakeOutput();
    const resultPromise = readHiddenLine("secret: ", tty.input, out.output);
    tty.type("\n");
    await expect(resultPromise).resolves.toBeUndefined();
  });

  it("restores raw mode and exits on Ctrl-C, without ever echoing what was typed so far", async () => {
    const tty = fakeTtyInput();
    const out = fakeOutput();
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((_code?: number) => {
      throw new Error("__exit__");
    }) as never);
    try {
      void readHiddenLine("secret: ", tty.input, out.output).catch(() => undefined);
      tty.type("partial-sec");
      expect(() => tty.type("\x03")).toThrow("__exit__");
      expect(exitSpy).toHaveBeenCalledWith(130);
      expect(out.written.join("")).not.toContain("partial-sec");
      expect(tty.rawModeCalls).toEqual([true, false]);
    } finally {
      exitSpy.mockRestore();
    }
  });
});
