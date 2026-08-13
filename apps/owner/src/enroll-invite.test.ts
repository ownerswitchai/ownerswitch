import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControlPlane } from "@ownerswitchai/control-plane";
import { enrollmentInviteFromWire } from "@ownerswitchai/shared";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  base64urlToBytes,
  beginEnrollmentCeremony,
  creationOptionsFromInvite,
  parseEnrollmentInvite,
} from "../public/enroll-invite.mjs";
import type { EnrollmentInvite } from "./types.js";

/**
 * The PHONE's production parse/adapt/create path (public/enroll-invite.mjs):
 * drift-pinned to the shared validator, byte-checked against the server's
 * minted contract, and proven — with a mock CredentialsContainer — to hand
 * navigator.credentials.create() EXACTLY the server's challenge, user
 * entity, and RP, or nothing at all.
 */
const dirs: string[] = [];
afterEach(() => {
  while (dirs.length > 0) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

const quiet = <T>(build: () => T): T => {
  const original = console.error;
  console.error = () => {};
  try {
    return build();
  } finally {
    console.error = original;
  }
};

/** a REAL server-minted contract + a locally generated token — the CLI's exact output shape */
function realPayload() {
  const dir = mkdtempSync(join(tmpdir(), "ownerswitch-enroll-invite-"));
  dirs.push(dir);
  const cp = quiet(() =>
    createControlPlane({
      dev: true,
      killStateFile: null,
      acceptSessionOnlyApprovalRisk: true,
      enrollment: {
        devicesFile: join(dir, "devices.json"),
        rpId: "owner.example",
        rpName: "OwnerSwitch",
        origin: "https://owner.example",
      },
    }),
  );
  const token = randomBytes(32).toString("base64url");
  const minted = cp.bootstrapMintInvite({
    tokenHash: createHash("sha256").update(token, "utf8").digest("base64url"),
    ownerId: "owner-adam",
    deviceName: "Adam's phone",
  });
  if (!minted.ok) throw new Error(`mint failed: ${minted.error}`);
  return { ...minted.invite, token };
}

const VALID: EnrollmentInvite = {
  inviteId: "inv_pin",
  token: Buffer.from("t".repeat(24)).toString("base64url"),
  expiresAt: 1,
  ownerId: "owner-adam",
  rpId: "owner.example",
  rpName: "OwnerSwitch",
  user: {
    id: Buffer.from("u".repeat(32)).toString("base64url"),
    name: "owner-adam",
    displayName: "owner-adam",
  },
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  authenticatorSelection: {
    authenticatorAttachment: "platform",
    residentKey: "preferred",
    userVerification: "required",
  },
  challenge: Buffer.from("c".repeat(24)).toString("base64url"),
  assertionChallenge: Buffer.from("a".repeat(24)).toString("base64url"),
  deviceName: "Adam's phone",
};

describe("public/enroll-invite.mjs — drift-pinned to @ownerswitchai/shared", () => {
  it("agrees with the shared validator on accept AND reject, vector for vector", () => {
    const { authenticatorSelection: _s, ...missingSelection } = VALID;
    const { deviceName: _d, ...missingDeviceName } = VALID;
    const vectors: unknown[] = [
      VALID,
      realPayload(),
      { ...VALID, extra: true },
      missingSelection,
      missingDeviceName,
      { ...VALID, token: "AB=CD" }, // non-canonical secret
      { ...VALID, user: { ...VALID.user, id: "A" } }, // impossible b64url length
      { ...VALID, pubKeyCredParams: [{ type: "public-key", alg: -257 }] }, // RS256 is not the pin
      { ...VALID, authenticatorSelection: { ...VALID.authenticatorSelection, userVerification: "preferred" } },
      { ...VALID, expiresAt: "soon" },
      Object.create(VALID as object), // inherited fields are not a payload
      null,
      [],
      "text",
    ];
    for (const vector of vectors) {
      const app = parseEnrollmentInvite(vector);
      const shared = enrollmentInviteFromWire(vector);
      // identical VERDICTS...
      expect(app === null, JSON.stringify(vector)?.slice(0, 80)).toBe(shared === null);
      // ...and identical accepted values
      if (app !== null && shared !== null) expect(app).toEqual(shared);
    }
  });

  it("adapts the invite into EXACT creation options: server bytes, pinned constants, attestation none", () => {
    const invite = parseEnrollmentInvite(VALID);
    expect(invite).not.toBeNull();
    if (invite === null) return;
    const options = creationOptionsFromInvite(invite);
    expect(options.rp).toEqual({ id: "owner.example", name: "OwnerSwitch" });
    expect(Buffer.from(options.challenge).toString("base64url")).toBe(VALID.challenge);
    expect(Buffer.from(options.user.id).toString("base64url")).toBe(VALID.user.id);
    expect(options.user.name).toBe("owner-adam");
    expect(options.pubKeyCredParams).toEqual([{ type: "public-key", alg: -7 }]);
    expect(options.authenticatorSelection).toEqual({
      authenticatorAttachment: "platform",
      residentKey: "preferred",
      userVerification: "required",
    });
    expect(options.attestation).toBe("none");
  });

  it("MOCK WEBAUTHN: a real server-minted payload drives create() with the SERVER's challenge/user/RP — and retains the ceremony's rest", async () => {
    const payload = realPayload();
    const created = { id: "mock-credential" };
    const create = vi.fn().mockResolvedValue(created);
    const outcome = await beginEnrollmentCeremony(payload, { create });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(create).toHaveBeenCalledTimes(1);
    const options = create.mock.calls[0][0].publicKey;
    // the bytes create() saw ARE the server's minted bytes
    expect(Buffer.from(options.challenge).toString("base64url")).toBe(payload.challenge);
    expect(Buffer.from(options.user.id).toString("base64url")).toBe(payload.user.id);
    expect(options.rp).toEqual({ id: payload.rpId, name: payload.rpName });
    expect(options.attestation).toBe("none");
    // and the pieces the ENROLLMENT REQUEST needs are retained verbatim
    expect(outcome.credential).toBe(created);
    expect(outcome.assertionChallenge).toBe(payload.assertionChallenge);
    expect(outcome.token).toBe(payload.token);
    expect(outcome.deviceName).toBe(payload.deviceName);
    expect(outcome.inviteId).toBe(payload.inviteId);
  });

  it("a payload the validator rejects NEVER reaches create(); a dismissed create() is an honest refusal", async () => {
    const create = vi.fn().mockResolvedValue({ id: "never" });
    const refused = await beginEnrollmentCeremony({ not: "an invite" }, { create });
    expect(refused.ok).toBe(false);
    expect(create).not.toHaveBeenCalled();

    const dismissed = await beginEnrollmentCeremony(realPayload(), {
      create: vi.fn().mockResolvedValue(null),
    });
    expect(dismissed.ok).toBe(false);
    if (!dismissed.ok) expect(dismissed.reason).toMatch(/refused, unavailable, or dismissed/);
  });

  it("a REJECTED create() — the real cancel/timeout shape — folds into the same fixed refusal, never an escaping exception", async () => {
    const payload = realPayload();
    // the browser's actual cancel: a rejected promise with NotAllowedError
    const notAllowed = Object.assign(new Error("The operation either timed out or was not allowed."), {
      name: "NotAllowedError",
    });
    const cancelled = await beginEnrollmentCeremony(payload, {
      create: vi.fn().mockRejectedValue(notAllowed),
    });
    expect(cancelled.ok).toBe(false);
    if (!cancelled.ok) {
      expect(cancelled.reason).toBe("credential creation was refused, unavailable, or dismissed");
      // FIXED string: no exception text, no credential fragments echoed
      expect(cancelled.reason).not.toMatch(/timed out|NotAllowed/);
    }
    // a generic rejection is the same refusal
    const generic = await beginEnrollmentCeremony(payload, {
      create: vi.fn().mockRejectedValue(new Error("boom")),
    });
    expect(generic.ok).toBe(false);
    // a MISSING or broken CredentialsContainer refuses without throwing
    expect((await beginEnrollmentCeremony(payload, undefined)).ok).toBe(false);
    expect((await beginEnrollmentCeremony(payload, null)).ok).toBe(false);
    expect(
      (await beginEnrollmentCeremony(payload, {} as unknown as { create: () => Promise<unknown> })).ok,
    ).toBe(false);
    // none of the refusals produced any success-shaped partial state
    for (const outcome of [cancelled, generic]) {
      expect("credential" in outcome).toBe(false);
      expect("token" in outcome).toBe(false);
    }
  });

  it("an EXPIRED invite refuses BEFORE the platform prompt — create() is never raised for a dead invite", async () => {
    const create = vi.fn().mockResolvedValue({ id: "never" });
    const expired = await beginEnrollmentCeremony(
      { ...realPayload(), expiresAt: 1 },
      { create },
    );
    expect(expired.ok).toBe(false);
    if (!expired.ok) expect(expired.reason).toMatch(/expired/);
    expect(create).not.toHaveBeenCalled();
    // an explicit clock makes the boundary exact: at expiresAt it is dead
    const payload = realPayload();
    const atBoundary = await beginEnrollmentCeremony(payload, { create }, () => payload.expiresAt);
    expect(atBoundary.ok).toBe(false);
  });

  it("base64urlToBytes is canonical: repairable spellings decode to null", () => {
    expect(base64urlToBytes(Buffer.from([1, 2, 3]).toString("base64url"))).toEqual(
      new Uint8Array([1, 2, 3]),
    );
    expect(base64urlToBytes("AB")).toBeNull(); // pad-bit variant
    expect(base64urlToBytes("A")).toBeNull(); // impossible length
    expect(base64urlToBytes("a+b/")).toBeNull(); // wrong alphabet
    expect(base64urlToBytes("")).toBeNull();
  });
});
