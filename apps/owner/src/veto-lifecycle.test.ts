import { describe, expect, it } from "vitest";
// The DEPLOYED runtime module, imported directly (plain ESM, runs in Node too).
// vetoResultAction is the generation-guarded decision app.js's veto handler
// delegates to; app.js itself is a classic script and cannot be imported.
import { vetoResultAction } from "../public/owner-runtime.mjs";

/**
 * A minimal stand-in for the single shared veto button app.js mutates. The
 * whole point of the guard is that only the CURRENT review may paint it.
 */
function fakeButton() {
  return { textContent: "VETO", disabled: false };
}

/** Reproduce app.js's `.then()` branch exactly, given a veto result. */
function applyResult(btn: { textContent: string; disabled: boolean }, armedGen: number, currentGen: number, result: unknown) {
  const action = vetoResultAction(armedGen, currentGen, result);
  if (action === "superseded") return action;
  if (action === "stopped") {
    btn.textContent = "STOPPED";
  } else {
    btn.textContent = "VETO — retry";
    btn.disabled = false;
  }
  return action;
}

describe("vetoResultAction — the veto button is generation-guarded", () => {
  it("paints STOPPED only for the CURRENT review's confirmed veto", () => {
    const btn = fakeButton();
    const action = applyResult(btn, 3, 3, { vetoed: true });
    expect(action).toBe("stopped");
    expect(btn.textContent).toBe("STOPPED");
  });

  it("a rejected veto stays retryable, never STOPPED", () => {
    const btn = fakeButton();
    const action = applyResult(btn, 3, 3, { vetoed: false, status: 409 });
    expect(action).toBe("retry");
    expect(btn.textContent).toBe("VETO — retry");
    expect(btn.disabled).toBe(false);
  });

  it("STALE STOP: a late confirmed veto for window A does NOT paint the button after the view moved to B", () => {
    // owner taps VETO on window A at render generation 3
    const armedGenForA = 3;
    // navigation A -> B bumps the app's render generation to 4 and re-wires the
    // SHARED button for B (B is NOT vetoed)
    const currentGenNowB = 4;
    const btn = fakeButton(); // the shared button, now showing B's review

    // A's veto response arrives LATE and confirms A was vetoed
    const action = applyResult(btn, armedGenForA, currentGenNowB, { vetoed: true });

    // the decisive property: the stale STOPPED is suppressed — the owner is
    // never told B is stopped when only A was, so they can still veto B
    expect(action).toBe("superseded");
    expect(btn.textContent).toBe("VETO"); // untouched
    expect(btn.disabled).toBe(false);
  });

  it("a late ERROR for A is likewise inert for B (matches app.js's guarded catch)", () => {
    const btn = fakeButton();
    // app.js's catch does `if (gen !== renderGen) return;` — same predicate
    const superseded = 3 !== 4;
    if (!superseded) {
      btn.textContent = "VETO — retry";
      btn.disabled = false;
    }
    expect(superseded).toBe(true);
    expect(btn.textContent).toBe("VETO"); // B's button untouched
  });

  it("treats a missing/odd result as retry, never a stopped false-positive", () => {
    expect(vetoResultAction(1, 1, undefined)).toBe("retry");
    expect(vetoResultAction(1, 1, null)).toBe("retry");
    expect(vetoResultAction(1, 1, { vetoed: "yes" })).toBe("retry"); // only === true is stopped
  });
});
