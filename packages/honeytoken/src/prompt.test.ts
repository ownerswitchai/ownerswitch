import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { CANARY_KEY_FLAG_ERROR, hasCanaryKeyFlag, readHiddenLine, resolveCanaryKey } from "./prompt.js";

describe("hasCanaryKeyFlag", () => {
  it("catches the bare flag and the --canary-key=value form", () => {
    expect(hasCanaryKeyFlag(["plant", "--canary-key", "s3cret", "--dir", "x"])).toBe(true);
    expect(hasCanaryKeyFlag(["plant", "--canary-key=s3cret", "--dir", "x"])).toBe(true);
  });

  it("is false when the flag is absent, including for unrelated flags", () => {
    expect(hasCanaryKeyFlag(["plant", "--dir", "x", "--registry", "r.json"])).toBe(false);
    expect(hasCanaryKeyFlag([])).toBe(false);
    // must not false-positive on a flag that merely contains the substring
    expect(hasCanaryKeyFlag(["--not-canary-key-related=1"])).toBe(false);
  });
});

describe("CANARY_KEY_FLAG_ERROR", () => {
  it("names the leak and points at the replacement", () => {
    expect(CANARY_KEY_FLAG_ERROR).toMatch(/shell history/);
    expect(CANARY_KEY_FLAG_ERROR).toMatch(/OWNERSWITCH_CANARY_KEY/);
  });
});

describe("resolveCanaryKey", () => {
  it("prefers OWNERSWITCH_CANARY_KEY, trimmed, and never prompts when it is set", async () => {
    const prompt = vi.fn();
    await expect(
      resolveCanaryKey({ OWNERSWITCH_CANARY_KEY: "  env-canary-key  " }, prompt as never),
    ).resolves.toBe("env-canary-key");
    expect(prompt).not.toHaveBeenCalled();
  });

  it("falls back to the prompt when the env var is unset or blank", async () => {
    await expect(resolveCanaryKey({}, async () => "typed-key")).resolves.toBe("typed-key");
    await expect(resolveCanaryKey({ OWNERSWITCH_CANARY_KEY: "  " }, async () => "typed-key")).resolves.toBe(
      "typed-key",
    );
    await expect(resolveCanaryKey({}, async () => undefined)).resolves.toBeUndefined();
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

/** A stdin-like object with NO setRawMode at all — e.g. a non-TTY stream. */
function fakeInputWithoutRawMode() {
  const emitter = new EventEmitter();
  let resumed = 0;
  let onCalls = 0;
  const input = {
    on: (event: "data", listener: (chunk: string) => void) => {
      onCalls++;
      emitter.on(event, listener);
    },
    removeListener: (event: "data", listener: (chunk: string) => void) => emitter.removeListener(event, listener),
    resume: () => {
      resumed++;
    },
    pause: () => {},
    // setEncoding present, setRawMode deliberately absent
    setEncoding: () => {},
  };
  return {
    input,
    get resumed() {
      return resumed;
    },
    get onCalls() {
      return onCalls;
    },
  };
}

describe("readHiddenLine", () => {
  it("fails closed when setRawMode is unavailable: no prompt written, no input ever read", async () => {
    const tty = fakeInputWithoutRawMode();
    const out = fakeOutput();

    await expect(readHiddenLine("Canary key: ", tty.input, out.output)).resolves.toBeUndefined();

    // Nothing was written — not even the prompt — and no attempt was made to
    // read: getting this wrong would mean SOME input path exists that reads
    // characters without a guarantee they aren't echoed by the terminal.
    expect(out.written).toEqual([]);
    expect(tty.onCalls).toBe(0);
    expect(tty.resumed).toBe(0);
  });

  it("writes the prompt but NEVER echoes typed characters, and returns the typed line on Enter", async () => {
    const tty = fakeTtyInput();
    const out = fakeOutput();
    const resultPromise = readHiddenLine("Canary key: ", tty.input, out.output);
    tty.type("s3cr3t-canary-key");
    tty.type("\n");
    await expect(resultPromise).resolves.toBe("s3cr3t-canary-key");

    // Only the prompt itself and the final newline ever reached output —
    // the secret characters do not appear anywhere in what was written.
    expect(out.written).toEqual(["Canary key: ", "\n"]);
    expect(out.written.join("")).not.toContain("s3cr3t-canary-key");
    expect(tty.rawModeCalls).toEqual([true, false]); // enabled, then restored
  });

  it("supports backspace without ever echoing a character", async () => {
    const tty = fakeTtyInput();
    const out = fakeOutput();
    const resultPromise = readHiddenLine("key: ", tty.input, out.output);
    tty.type("abcX");
    tty.type("\x7f"); // DEL — erase the stray "X"
    tty.type("d");
    tty.type("\r");
    await expect(resultPromise).resolves.toBe("abcd");
    expect(out.written.join("")).toBe("key: \n");
  });

  it("returns undefined for an empty line", async () => {
    const tty = fakeTtyInput();
    const out = fakeOutput();
    const resultPromise = readHiddenLine("key: ", tty.input, out.output);
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
      void readHiddenLine("key: ", tty.input, out.output).catch(() => undefined);
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
