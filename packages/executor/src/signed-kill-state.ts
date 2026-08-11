import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { canonicalJson } from "@ownerswitchai/shared";
import type { LiveKillState } from "./executor.js";

/**
 * The broker's AUTHENTICATED live kill-state reader.
 *
 * The plain `/status` channel is unauthenticated loopback HTTP. If the
 * isolated control plane stops, a hostile process under any local uid can
 * bind that unprivileged port and answer `{killed:false, epoch:<whatever a
 * captured grant needs>}` — passing the broker's "is it killed?" check and
 * defeating the entire point of fail-closed. `SO_PEERCRED`-style checks
 * don't help (the impostor is a legitimate local process); the answer has
 * to be UNFORGEABLE.
 *
 * So the broker calls `GET /kill-state?nonce=<fresh>` and requires the
 * response to be HMAC-signed, with the shared kill-state key, over exactly
 * {killed, epoch, nonce, expiresAt}. An impostor without the key cannot
 * produce the signature; a replay of a real past response carries a stale
 * nonce (and a passed `expiresAt`) the broker rejects. EVERY failure mode —
 * unreachable, non-200, unparseable, bad signature, wrong/again nonce,
 * expired envelope, missing epoch — reads as KILLED. Uncertainty is a stop.
 */

export interface SignedKillStateOptions {
  /** the control plane's base URL, e.g. http://127.0.0.1:8787 */
  baseUrl: string;
  /** the shared kill-state signing key (OWNERSWITCH_KILL_STATE_KEY) */
  killStateKey: string;
  /** abort the call after this many ms; default 500 */
  timeoutMs?: number;
  /** injectable for tests */
  fetchImpl?: typeof fetch;
  now?: () => number;
  /** injectable nonce source (tests); defaults to 16 random bytes hex */
  nonce?: () => string;
}

const KILLED: LiveKillState = { killed: true, epoch: -1 };

export function signedLiveKillStateFromControlPlane(
  options: SignedKillStateOptions,
): (probe?: { jti: string; commit?: boolean }) => Promise<LiveKillState> {
  const {
    baseUrl,
    killStateKey,
    timeoutMs = 500,
    fetchImpl = fetch,
    now = Date.now,
    nonce: mintNonce = () => randomBytes(16).toString("hex"),
  } = options;

  if (killStateKey === "") {
    throw new Error(
      "the signed kill-state reader requires a kill-state key (OWNERSWITCH_KILL_STATE_KEY) — " +
        "without one it cannot tell the control plane from an impostor",
    );
  }

  const hmac = (payload: unknown): Buffer =>
    createHmac("sha256", killStateKey).update(canonicalJson(payload)).digest();

  return async (probe?: { jti: string; commit?: boolean }): Promise<LiveKillState> => {
    const nonce = mintNonce();
    const isCommit = probe?.commit === true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let body: unknown;
    try {
      let res: Response;
      if (isCommit) {
        // The ATOMIC commit-for-dispatch: a state-changing request the
        // control plane performs only for the broker, so it is HMAC-signed
        // with the shared key (an agent cannot forge it to pre-commit a
        // grant ahead of the owner's veto). ts bounds replay; the response
        // nonce bounds the answer.
        const ts = now();
        const request = { jti: probe!.jti, nonce, ts };
        res = await fetchImpl(new URL("/kill-state/commit", baseUrl), {
          method: "POST",
          signal: controller.signal,
          cache: "no-store",
          headers: { "content-type": "application/json", "cache-control": "no-store, no-cache" },
          body: JSON.stringify({ ...request, sig: hmac(request).toString("hex") }),
        });
      } else {
        const url = new URL("/kill-state", baseUrl);
        url.searchParams.set("nonce", nonce);
        // a read-only grant-liveness probe: the control plane answers (and
        // SIGNS) whether it still vouches for this specific grant — false
        // once its window is vetoed, unknown, or the control plane restarted
        if (probe !== undefined) url.searchParams.set("jti", probe.jti);
        res = await fetchImpl(url, {
          signal: controller.signal,
          cache: "no-store",
          headers: { "cache-control": "no-store, no-cache", pragma: "no-cache" },
        });
      }
      if (!res.ok) return KILLED;
      body = await res.json();
    } catch {
      return KILLED;
    } finally {
      clearTimeout(timer);
    }

    if (typeof body !== "object" || body === null) return KILLED;
    const {
      killed,
      epoch,
      nonce: echoed,
      expiresAt,
      sig,
      jti: echoedJti,
      grantLive,
      committed,
    } = body as Record<string, unknown>;

    // Shape first — a field that is the wrong type can never be trusted.
    if (typeof killed !== "boolean") return KILLED;
    if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 0) return KILLED;
    if (typeof expiresAt !== "number" || !Number.isFinite(expiresAt)) return KILLED;
    if (typeof echoed !== "string" || typeof sig !== "string" || sig === "") return KILLED;
    if (probe !== undefined && echoedJti !== probe.jti) return KILLED;
    if (isCommit) {
      if (typeof committed !== "boolean") return KILLED;
    } else if (probe !== undefined && typeof grantLive !== "boolean") {
      // a read probe that dodges the question does not vouch for the grant
      return KILLED;
    }

    // The nonce must be OURS, echoed back — this is what makes a replay of a
    // real past response useless.
    if (echoed !== nonce) return KILLED;
    // Freshness — the envelope is short-lived; a stale one is not trusted.
    if (now() >= expiresAt) return KILLED;

    // The signature must verify over exactly the signed fields, in the
    // control plane's canonical form. timing-safe, and length-guarded so
    // malformed hex lands here rather than throwing.
    const signedPayload = isCommit
      ? { killed, epoch, nonce: echoed, expiresAt, jti: echoedJti, committed }
      : probe !== undefined
        ? { killed, epoch, nonce: echoed, expiresAt, jti: echoedJti, grantLive }
        : { killed, epoch, nonce: echoed, expiresAt };
    const expected = hmac(signedPayload);
    const provided = Buffer.from(sig, "hex");
    if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
      return KILLED;
    }

    // Verified. A killed answer's epoch is irrelevant (killed refuses before
    // the epoch is compared); a live answer carries the real epoch.
    const base = killed ? { killed: true as const, epoch } : { killed: false as const, epoch };
    if (isCommit) return { ...base, committed: committed === true };
    return probe !== undefined ? { ...base, grantLive: grantLive === true } : base;
  };
}
