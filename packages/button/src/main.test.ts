import { describe, expect, it, vi } from "vitest";
import { checkSecretFlag, fetchAuditStatus, main } from "./main.js";

describe("checkSecretFlag", () => {
  it("flags --secret and --secret=... in either position", () => {
    expect(checkSecretFlag(["--secret", "s3cr3t"])).toMatch(/shell history/);
    expect(checkSecretFlag(["--secret=s3cr3t"])).toMatch(/shell history/);
    expect(checkSecretFlag(["--url", "http://x", "--secret", "s3cr3t"])).toMatch(/shell history/);
  });

  it("is undefined for argv with no --secret flag", () => {
    expect(checkSecretFlag(["--url", "http://x", "--device-id", "d"])).toBeUndefined();
    expect(checkSecretFlag([])).toBeUndefined();
  });
});

describe("main() — --secret refusal", () => {
  it("refuses --secret before parsing anything else — no network call, no other args needed to trigger it", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`__exit_${code}__`);
    }) as never);
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      throw new Error("must not be called");
    });

    try {
      // --url and --device-id are both missing — proving the --secret check
      // runs before any other required-argument validation, not after it
      await expect(main(["--secret", "leaked"], {})).rejects.toThrow("__exit_1__");
      expect(errorSpy).toHaveBeenCalledTimes(1);
      expect(errorSpy.mock.calls[0][0]).toMatch(/--secret was removed/);
      expect(errorSpy.mock.calls[0][0]).toMatch(/shell history/);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      errorSpy.mockRestore();
      exitSpy.mockRestore();
      fetchSpy.mockRestore();
    }
  });

  it("also refuses the --secret=value form", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`__exit_${code}__`);
    }) as never);
    try {
      await expect(main(["--secret=leaked", "--url", "http://x"], {})).rejects.toThrow("__exit_1__");
      expect(errorSpy.mock.calls[0][0]).toMatch(/--secret was removed/);
    } finally {
      errorSpy.mockRestore();
      exitSpy.mockRestore();
    }
  });
});

describe("fetchAuditStatus", () => {
  it("returns the parsed status on a normal response", async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ killed: true, reason: "x", at: 123 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as typeof fetch;
    await expect(fetchAuditStatus("http://cp.test", fetchImpl)).resolves.toEqual({
      killed: true,
      reason: "x",
      at: 123,
    });
  });

  it("aborts a hung request after the timeout and resolves undefined instead of stalling", async () => {
    vi.useFakeTimers();
    try {
      const fetchImpl = ((_url: URL | RequestInfo, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        })) as typeof fetch;

      const resultPromise = fetchAuditStatus("http://cp.test", fetchImpl, 50);
      await vi.advanceTimersByTimeAsync(50);
      await expect(resultPromise).resolves.toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});
