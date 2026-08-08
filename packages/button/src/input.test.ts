import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { createHttpSource, createKeyboardSource } from "./input.js";

class FakeStdin extends EventEmitter {
  isTTY = true;
  raw: boolean | null = null;
  flowing: boolean | null = null;

  setRawMode(mode: boolean): this {
    this.raw = mode;
    return this;
  }
  resume(): this {
    this.flowing = true;
    return this;
  }
  pause(): this {
    this.flowing = false;
    return this;
  }
}

describe("keyboard press source", () => {
  it("emits a press for the configured key only (default: space)", async () => {
    const stdin = new FakeStdin();
    const source = createKeyboardSource({ stdin });
    const presses = vi.fn();
    source.onPress(presses);
    await source.start();

    expect(stdin.raw).toBe(true);
    expect(stdin.flowing).toBe(true);

    stdin.emit("data", Buffer.from(" "));
    stdin.emit("data", Buffer.from("x"));
    stdin.emit("data", Buffer.from("  ")); // a chunk can carry several presses
    expect(presses).toHaveBeenCalledTimes(3);
  });

  it('supports "enter" and single-character keys', async () => {
    const enterStdin = new FakeStdin();
    const enterPresses = vi.fn();
    const enter = createKeyboardSource({ stdin: enterStdin, key: "enter" });
    enter.onPress(enterPresses);
    await enter.start();
    enterStdin.emit("data", Buffer.from("\r"));
    enterStdin.emit("data", Buffer.from("\n"));
    enterStdin.emit("data", Buffer.from(" "));
    expect(enterPresses).toHaveBeenCalledTimes(2);

    const kStdin = new FakeStdin();
    const kPresses = vi.fn();
    const k = createKeyboardSource({ stdin: kStdin, key: "k" });
    k.onPress(kPresses);
    await k.start();
    kStdin.emit("data", Buffer.from("k"));
    kStdin.emit("data", Buffer.from(" "));
    expect(kPresses).toHaveBeenCalledTimes(1);
  });

  it("rejects unknown key names", () => {
    expect(() => createKeyboardSource({ stdin: new FakeStdin(), key: "spacebar" })).toThrow(
      /unknown key/,
    );
  });

  it("routes Ctrl+C to onInterrupt instead of pressing", async () => {
    const stdin = new FakeStdin();
    const presses = vi.fn();
    const onInterrupt = vi.fn();
    const source = createKeyboardSource({ stdin, onInterrupt });
    source.onPress(presses);
    await source.start();

    stdin.emit("data", Buffer.from("\u0003"));
    expect(onInterrupt).toHaveBeenCalledTimes(1);
    expect(presses).not.toHaveBeenCalled();
  });

  it("stop() restores the terminal and detaches from stdin", async () => {
    const stdin = new FakeStdin();
    const presses = vi.fn();
    const source = createKeyboardSource({ stdin });
    source.onPress(presses);
    await source.start();
    await source.stop();

    expect(stdin.raw).toBe(false);
    expect(stdin.flowing).toBe(false);
    stdin.emit("data", Buffer.from(" "));
    expect(presses).not.toHaveBeenCalled();
  });
});

describe("http press source", () => {
  it("POST /press emits a press and confirms; other requests do not", async () => {
    const source = createHttpSource({ port: 0 });
    const presses = vi.fn();
    source.onPress(presses);
    await source.start();
    try {
      const res = await fetch(source.url(), { method: "POST" });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ pressed: true });
      expect(presses).toHaveBeenCalledTimes(1);

      const get = await fetch(source.url());
      expect(get.status).toBe(405);
      const elsewhere = await fetch(new URL("/nope", source.url()), { method: "POST" });
      expect(elsewhere.status).toBe(404);
      expect(presses).toHaveBeenCalledTimes(1);
    } finally {
      await source.stop();
    }
  });

  it("unsubscribe detaches the listener; stop() closes the endpoint", async () => {
    const source = createHttpSource({ port: 0 });
    const presses = vi.fn();
    const unsubscribe = source.onPress(presses);
    await source.start();
    const url = source.url();

    unsubscribe();
    const res = await fetch(url, { method: "POST" });
    expect(res.status).toBe(200);
    expect(presses).not.toHaveBeenCalled();

    await source.stop();
    await expect(fetch(url, { method: "POST" })).rejects.toThrow();
  });
});
