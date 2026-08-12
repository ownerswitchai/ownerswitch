import { describe, expect, it } from "vitest";
// The DEPLOYED runtime module, imported directly (plain ESM, runs in Node too).
// armVetoButton + vetoResultAction are what app.js's veto handler delegates to;
// app.js itself is a classic script and cannot be imported.
import { armVetoButton, vetoResultAction, type VetoButtonLike } from "../public/owner-runtime.mjs";

/**
 * A minimal stand-in for the single shared veto button app.js mutates. The
 * whole point of the guards is that only the CURRENT review may paint it.
 */
function fakeButton(overrides: Partial<VetoButtonLike> = {}): VetoButtonLike {
  return { textContent: "VETO", disabled: false, ...overrides };
}

// Two generations and two window ids, typed as string/number so comparisons
// are legitimate (no literal-narrowing).
const GEN_A: number = 3;
const GEN_B: number = 4;
const WIN_A = "veto_a";
const WIN_B = "veto_b";

/** Reproduce app.js's `.then()` branch exactly, given a veto result. */
function applyResult(
  btn: VetoButtonLike,
  armedGen: number,
  currentGen: number,
  result: unknown,
  armedWindowId?: string,
  currentWindowId?: string,
) {
  const action = vetoResultAction(armedGen, currentGen, result, armedWindowId, currentWindowId);
  if (action === "superseded") return action;
  if (action === "stopped") {
    btn.textContent = "STOPPED";
  } else {
    btn.textContent = "VETO — retry";
    btn.disabled = false;
  }
  return action;
}

describe("armVetoButton — every render fully resets the shared button", () => {
  it("wipes a prior window's STOPPED text and re-enables — B never inherits A's label", () => {
    // after A's confirmed veto the shared button reads STOPPED and is disabled
    const btn = fakeButton({ textContent: "STOPPED", disabled: true });
    // navigation to B re-arms it via the same path app.js uses
    armVetoButton(btn);
    expect(btn.textContent).toBe("VETO"); // NOT "STOPPED"
    expect(btn.disabled).toBe(false);
  });

  it("also wipes a prior 'VETO — retry' label", () => {
    const btn = fakeButton({ textContent: "VETO — retry", disabled: false });
    armVetoButton(btn);
    expect(btn.textContent).toBe("VETO");
  });

  it("clears aria-disabled when the button exposes removeAttribute", () => {
    const removed: string[] = [];
    const btn = fakeButton({ removeAttribute: (n: string) => removed.push(n) });
    armVetoButton(btn);
    expect(removed).toContain("aria-disabled");
  });
});

describe("vetoResultAction — the veto button is generation- and window-guarded", () => {
  it("paints STOPPED only for the CURRENT review's confirmed veto", () => {
    const btn = fakeButton();
    const action = applyResult(btn, GEN_A, GEN_A, { vetoed: true }, WIN_A, WIN_A);
    expect(action).toBe("stopped");
    expect(btn.textContent).toBe("STOPPED");
  });

  it("a rejected veto stays retryable, never STOPPED", () => {
    const btn = fakeButton();
    const action = applyResult(btn, GEN_A, GEN_A, { vetoed: false, status: 409 }, WIN_A, WIN_A);
    expect(action).toBe("retry");
    expect(btn.textContent).toBe("VETO — retry");
    expect(btn.disabled).toBe(false);
  });

  it("STALE STOP (generation advanced): a late confirmed veto for A does NOT paint B's button", () => {
    const btn = fakeButton(); // shared button, now showing B's review
    const action = applyResult(btn, GEN_A, GEN_B, { vetoed: true }, WIN_A, WIN_B);
    expect(action).toBe("superseded");
    expect(btn.textContent).toBe("VETO"); // untouched
    expect(btn.disabled).toBe(false);
  });

  it("STALE STOP (windowId advanced even at the same generation): still superseded", () => {
    // defense in depth: same generation number, but the current window moved
    const btn = fakeButton();
    const action = applyResult(btn, GEN_A, GEN_A, { vetoed: true }, WIN_A, WIN_B);
    expect(action).toBe("superseded");
    expect(btn.textContent).toBe("VETO");
  });

  it("treats a missing/odd result as retry, never a stopped false-positive", () => {
    expect(vetoResultAction(1, 1, undefined, WIN_A, WIN_A)).toBe("retry");
    expect(vetoResultAction(1, 1, null, WIN_A, WIN_A)).toBe("retry");
    expect(vetoResultAction(1, 1, { vetoed: "yes" }, WIN_A, WIN_A)).toBe("retry"); // only === true is stopped
  });
});
