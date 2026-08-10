import { describe, expect, it } from "vitest";
import { boundedRequest, readBoundedBody } from "./github-http.js";

describe("readBoundedBody", () => {
  it("returns the body when under the cap", async () => {
    expect(await readBoundedBody(new Response("hello"), 1024)).toBe("hello");
  });

  it("cancels and returns null the moment the stream exceeds the cap — never buffers past it", async () => {
    let pulled = 0;
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        controller.enqueue(new Uint8Array(1024).fill(120));
      },
    });
    const res = new Response(endless);
    expect(await readBoundedBody(res, 4 * 1024)).toBeNull();
    // the cap tripped after ~5 chunks; an after-the-fact truncation would
    // have pulled forever
    expect(pulled).toBeLessThan(10);
  });

  it("treats a null body as empty", async () => {
    expect(await readBoundedBody(new Response(null, { status: 204 }), 10)).toBe("");
  });
});

describe("boundedRequest", () => {
  it("stamps redirect:'error' on every request — an authenticated request never follows a Location", async () => {
    let seen: RequestRedirect | undefined;
    const fetchImpl: typeof fetch = async (_input, init) => {
      seen = init?.redirect;
      return new Response("{}");
    };
    await boundedRequest(fetchImpl, "https://api.github.com/x", {}, 1000, 1024);
    expect(seen).toBe("error");
  });

  it("one timeout covers connect AND body: a body that stalls past the deadline aborts the exchange", async () => {
    // headers arrive instantly; the body never delivers a byte. A timer
    // cleared at header-time would leave this read hanging forever — the
    // deadline must still fire, and undici surfaces it by erroring the
    // body stream when the signal aborts. Emulate exactly that.
    let controllerRef: ReadableStreamDefaultController<Uint8Array> | undefined;
    const stalled = new ReadableStream<Uint8Array>({
      start(controller) {
        controllerRef = controller;
      },
    });
    const fetchImpl: typeof fetch = async (_input, init) => {
      init?.signal?.addEventListener("abort", () =>
        controllerRef?.error(Object.assign(new Error("body aborted"), { name: "AbortError" })),
      );
      return new Response(stalled);
    };
    await expect(
      boundedRequest(fetchImpl, "https://api.github.com/x", {}, 50, 1024),
    ).rejects.toThrowError(/aborted/);
  });
});
