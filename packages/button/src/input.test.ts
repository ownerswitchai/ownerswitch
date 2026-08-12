import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { createHttpSource, createKeyboardSource, createSerialSource } from "./input.js";

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

class FakeSerial extends EventEmitter {
  destroyed = false;
  destroy(): void {
    this.destroyed = true;
    this.emit("close");
  }
}

describe("serial press source", () => {
  it("presses only on the trigger line (default KILL), buffering across chunks", async () => {
    const serial = new FakeSerial();
    const source = createSerialSource({ device: "/dev/fake", open: () => serial, reconnectMs: 0 });
    const presses = vi.fn();
    source.onPress(presses);
    await source.start();

    serial.emit("data", Buffer.from("READY\n")); // not the trigger
    expect(presses).not.toHaveBeenCalled();

    serial.emit("data", Buffer.from("KI")); // a trigger split across two reads...
    serial.emit("data", Buffer.from("LL\n")); // ...is still exactly one press
    expect(presses).toHaveBeenCalledTimes(1);

    serial.emit("data", Buffer.from("KILL\nKILL\n")); // two lines in one chunk
    expect(presses).toHaveBeenCalledTimes(3);

    serial.emit("data", Buffer.from("  KILL \n")); // trimmed
    expect(presses).toHaveBeenCalledTimes(4);

    serial.emit("data", Buffer.from("kill\n")); // case-sensitive: not a press
    serial.emit("data", "KILLSWITCH\n"); // exact-line match, not substring: not a press
    expect(presses).toHaveBeenCalledTimes(4);

    await source.stop();
  });

  it("rejects an empty or multiline trigger (a blank line must never press)", () => {
    expect(() => createSerialSource({ device: "/dev/fake", trigger: "" })).toThrow(
      /non-empty single line/,
    );
    expect(() => createSerialSource({ device: "/dev/fake", trigger: "   " })).toThrow(
      /non-empty single line/,
    );
    expect(() => createSerialSource({ device: "/dev/fake", trigger: "KILL\nNOW" })).toThrow(
      /non-empty single line/,
    );
  });

  it("trims a padded trigger so it can actually match the trimmed line", async () => {
    const serial = new FakeSerial();
    const source = createSerialSource({
      device: "/dev/fake",
      trigger: " STOP ",
      open: () => serial,
      reconnectMs: 0,
    });
    const presses = vi.fn();
    source.onPress(presses);
    await source.start();
    serial.emit("data", Buffer.from("STOP\n"));
    expect(presses).toHaveBeenCalledTimes(1);
    await source.stop();
  });

  it("honours a custom trigger and describes itself", async () => {
    const serial = new FakeSerial();
    const source = createSerialSource({
      device: "/dev/fake",
      trigger: "STOP",
      open: () => serial,
      reconnectMs: 0,
    });
    const presses = vi.fn();
    source.onPress(presses);
    await source.start();

    serial.emit("data", Buffer.from("STOP\n"));
    serial.emit("data", Buffer.from("KILL\n")); // the default trigger no longer matches
    expect(presses).toHaveBeenCalledTimes(1);
    expect(source.describe()).toBe('serial — /dev/fake (trigger "STOP")');

    await source.stop();
  });

  it("re-opens the device after it drops (flaky cable)", async () => {
    const opened: FakeSerial[] = [];
    const fire: Array<() => void> = [];
    const source = createSerialSource({
      device: "/dev/fake",
      open: () => {
        const s = new FakeSerial();
        opened.push(s);
        return s;
      },
      reconnectMs: 5,
      schedule: (fn) => {
        fire.push(fn);
        return () => {};
      },
    });
    const presses = vi.fn();
    source.onPress(presses);
    await source.start();
    expect(opened).toHaveLength(1);

    opened[0].emit("close"); // cable dropped
    expect(fire).toHaveLength(1);
    fire[0](); // the reconnect fires -> re-open
    expect(opened).toHaveLength(2);

    opened[1].emit("data", Buffer.from("KILL\n"));
    expect(presses).toHaveBeenCalledTimes(1);

    await source.stop();
  });

  it("reports a device error and, with reconnect disabled, gives up without pressing", async () => {
    const serial = new FakeSerial();
    const onError = vi.fn();
    const source = createSerialSource({
      device: "/dev/fake",
      open: () => serial,
      reconnectMs: 0,
      onError,
    });
    const presses = vi.fn();
    source.onPress(presses);
    await source.start();

    serial.emit("error", new Error("ENODEV")); // a lost device is NOT a press
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(Error);
    expect(presses).not.toHaveBeenCalled();

    await source.stop();
  });

  it("stop() destroys the active device and ignores late data", async () => {
    const serial = new FakeSerial();
    const source = createSerialSource({ device: "/dev/fake", open: () => serial, reconnectMs: 0 });
    const presses = vi.fn();
    source.onPress(presses);
    await source.start();

    await source.stop();
    expect(serial.destroyed).toBe(true);

    serial.emit("data", Buffer.from("KILL\n")); // late data from the old device
    expect(presses).not.toHaveBeenCalled();
  });

  it("stop() cancels a pending reconnect", async () => {
    const serial = new FakeSerial();
    const cancel = vi.fn();
    const source = createSerialSource({
      device: "/dev/fake",
      open: () => serial,
      reconnectMs: 10,
      schedule: () => cancel, // returns a spy canceller; never actually fires
    });
    source.onPress(vi.fn());
    await source.start();

    serial.emit("close"); // device dropped -> a reconnect is scheduled
    await source.stop(); // stop must cancel it
    expect(cancel).toHaveBeenCalledTimes(1);
  });
});
