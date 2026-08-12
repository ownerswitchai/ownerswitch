import { createHash } from "node:crypto";
import {
  canonicalRenderableAlert as sharedCanonical,
  validateRenderableAlert as sharedValidate,
} from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
// The DEPLOYED browser modules, imported directly (plain ESM, run in Node too).
import { ackBodyForRender, type RenderedDomTexts } from "../public/owner-runtime.mjs";
import {
  canonicalRenderableAlert as browserCanonical,
  renderContentHash as browserHash,
  validateRenderableAlert as browserValidate,
} from "../public/renderable-alert.mjs";

const ok = { v: 1, agentId: "agent-7", tool: "github.merge_pr", summary: "Merge o/r#7 into main — merge, head aaaaaaaaaaaa" };

/** The control plane's renderContentHashOf, reproduced byte-for-byte. */
const serverHash = (alert: unknown) =>
  createHash("sha256").update(sharedCanonical(alert), "utf8").digest("base64url");

describe("public/renderable-alert.mjs — drift-pinned to @ownerswitchai/shared", () => {
  it("validates exactly like shared across the whole violation battery", () => {
    const cases: unknown[] = [
      ok,
      { ...ok, v: 2 },
      { ...ok, extra: "x" },
      { ...ok, tool: 42 },
      { ...ok, agentId: "a".repeat(65) },
      { ...ok, summary: "s".repeat(201) },
      { ...ok, summary: `a${String.fromCodePoint(0x202e)}b` }, // RLO
      { ...ok, tool: `a${String.fromCodePoint(0x200b)}b` }, // ZWSP
      { ...ok, agentId: `a\nb` },
      null,
      "alert",
      [ok],
      (() => {
        const m: Record<string, unknown> = { ...ok };
        delete m.summary;
        return m;
      })(),
    ];
    for (const alert of cases) {
      expect(browserValidate(alert)).toEqual(sharedValidate(alert));
    }
  });

  it("canonicalizes identically to shared (key order independent)", () => {
    expect(browserCanonical(ok)).toBe(sharedCanonical(ok));
    const reordered = { summary: ok.summary, v: 1, tool: ok.tool, agentId: ok.agentId };
    expect(browserCanonical(reordered)).toBe(sharedCanonical(ok));
  });

  it("recomputes EXACTLY the control plane's renderContentHash (base64url sha256)", async () => {
    expect(await browserHash(ok)).toBe(serverHash(ok));
    const other = { ...ok, summary: "Merge o/r#8 into main — merge, head bbbbbbbbbbbb" };
    expect(await browserHash(other)).toBe(serverHash(other));
    expect(await browserHash(other)).not.toBe(serverHash(ok));
  });
});

describe("ackBodyForRender — the evidence gate in front of /veto/:id/seen", () => {
  const detailFor = (alert: typeof ok) => ({
    ...alert,
    windowId: "v-1",
    status: "pending",
    revision: 1,
    deliveryId: "del_abc",
    renderContentHash: serverHash(alert),
    deadline: 999_999,
  });
  const domFor = (alert: typeof ok): RenderedDomTexts => ({
    agentId: alert.agentId,
    tool: alert.tool,
    summary: alert.summary,
  });

  it("yields the echo body — with the RECOMPUTED hash — when envelope, hash, and DOM all agree", async () => {
    const detail = detailFor(ok);
    const body = await ackBodyForRender(detail, domFor(ok));
    expect(body).toEqual({ deliveryId: "del_abc", revision: 1, renderContentHash: serverHash(ok) });
  });

  it("refuses without a deliveryId — a terminal or non-ackable window has no evidence to give", async () => {
    const detail = { ...detailFor(ok), deliveryId: null };
    expect(await ackBodyForRender(detail, domFor(ok))).toBeNull();
  });

  it("refuses when the server's hash does not match the RECOMPUTED one — a parroted hash is not evidence", async () => {
    // the server (or a middle box) sends text A but the hash of text B
    const detail = { ...detailFor(ok), renderContentHash: serverHash({ ...ok, summary: "something else" }) };
    expect(await ackBodyForRender(detail, domFor(ok))).toBeNull();
  });

  it("refuses a non-conformant envelope — a bidi override in a field can lie on screen", async () => {
    const evil = { ...ok, summary: `pay${String.fromCodePoint(0x202e)}ee` };
    const detail = { ...detailFor(ok), summary: evil.summary, renderContentHash: serverHash(ok) };
    expect(await ackBodyForRender(detail, domFor(evil))).toBeNull();
  });

  it("refuses when the painted DOM differs from the envelope — a mutated or missed render acks nothing", async () => {
    const detail = detailFor(ok);
    // summary node was overwritten between render and the two-rAF read-back
    expect(await ackBodyForRender(detail, { ...domFor(ok), summary: "This review could not be loaded" })).toBeNull();
    // a missing node reads back null — likewise refused
    expect(await ackBodyForRender(detail, { ...domFor(ok), agentId: null })).toBeNull();
    expect(await ackBodyForRender(detail, null)).toBeNull();
  });
});
