/*
 * owner-runtime.mjs — the foreground runtime: device-key custody, push
 * enrollment, and the two signed sends the veto lane needs (the delivery ack
 * and the one-tap veto). Built entirely on the tested owner-crypto.mjs; this
 * file is browser glue (fetch, IndexedDB, the push manager) and carries no
 * cryptographic logic of its own.
 *
 * Deployment config comes from a same-origin `window.OWNERSWITCH_CONFIG`
 * object (set by a config.js the deployment serves — never hard-coded here):
 *   { deviceId, controlPlaneUrl, escalationUrl, vapidPublicKey }
 *
 * The device's PRIVATE key is generated non-extractable and persisted as a
 * CryptoKey in IndexedDB (structured-cloneable, still non-extractable at
 * rest) — it signs but never serializes.
 */
import { exportPublicKeySpki, generateOwnerDeviceKey, nonce, signRequestHeaders } from "./owner-crypto.mjs";
import { renderContentHash, validateRenderableAlert } from "./renderable-alert.mjs";

const DB = "ownerswitch";
const STORE = "keys";
const KEY_ID = "cheap-lane";

function cfg() {
  const c = self.OWNERSWITCH_CONFIG;
  if (!c || !c.deviceId || !c.controlPlaneUrl) {
    throw new Error("OWNERSWITCH_CONFIG missing — set { deviceId, controlPlaneUrl, escalationUrl, vapidPublicKey }");
  }
  return c;
}

function idb() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}

function idbGet(db, key) {
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbPut(db, key, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Load the device keypair, generating and persisting it on first run. */
export async function ensureDeviceKey() {
  const db = await idb();
  let pair = await idbGet(db, KEY_ID);
  if (!pair || !pair.privateKey) {
    pair = await generateOwnerDeviceKey();
    await idbPut(db, KEY_ID, pair); // CryptoKey persists non-extractable
  }
  return pair;
}

/** The device's PUBLIC key (base64url SPKI) — hand this to the operator to enroll. */
export async function enrolledPublicKeySpki() {
  const { publicKey } = await ensureDeviceKey();
  return exportPublicKeySpki(publicKey);
}

/**
 * Device-signed fetch: sign the exact method+path+body, then send it. An
 * optional `guard()` is re-checked AFTER the key is retrieved and IMMEDIATELY
 * before signing — the permissive ack must not be produced if the review
 * surface stopped being valid (hidden, blurred, framed, navigated away)
 * during the async key access. A false/throwing guard aborts before any
 * signature exists.
 */
async function signedFetch(baseUrl, path, method, body, guard) {
  const { privateKey } = await ensureDeviceKey();
  if (guard && !guard()) throw new Error("aborted: review surface no longer valid before signing");
  const headers = await signRequestHeaders(privateKey, {
    deviceId: cfg().deviceId,
    method,
    pathAndQuery: path, // byte-exact as sent
    body: body ?? "",
    timestamp: Date.now(),
    nonce: nonce(),
  });
  // Re-check AFTER the async WebCrypto sign and IMMEDIATELY before the fetch:
  // hide/blur/navigation during signing must not still send the ack. The
  // signature is single-use (server nonce), so an unsent one is simply wasted.
  if (guard && !guard()) throw new Error("aborted: review surface no longer valid after signing");
  return fetch(baseUrl + path, {
    method,
    cache: "no-store",
    redirect: "error", // a redirected control-plane response is never trusted
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
    ...(method === "POST" ? { body: body ?? "" } : {}),
  });
}

function b64urlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "===".slice((b64.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * Subscribe to Web Push (VAPID applicationServerKey — the server refuses an
 * unrestricted subscription) and enroll the subscription with the escalation
 * service, device-signed. Idempotent: safe to call on every app open.
 */
export async function subscribeAndEnroll(registration) {
  const c = cfg();
  if (!c.vapidPublicKey || !c.escalationUrl) throw new Error("vapidPublicKey and escalationUrl required for push");
  const existing = await registration.pushManager.getSubscription();
  const sub =
    existing ??
    (await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: b64urlToBytes(c.vapidPublicKey),
    }));
  const body = JSON.stringify({ subscription: sub.toJSON() });
  const res = await signedFetch(c.escalationUrl, "/push/subscription", "POST", body);
  if (!res.ok) throw new Error(`push enrollment failed: HTTP ${res.status}`);
  return sub;
}

/** Used by the service worker's pushsubscriptionchange handler. */
export async function resubscribeFromWorker(registration) {
  return subscribeAndEnroll(registration);
}

/**
 * Fetch the window's foreground-detail (device-signed GET /veto/:id/detail):
 * the RenderableAlertV1 the view must render AND a single-use delivery
 * {deliveryId, revision, renderContentHash} the ack must echo. The ack proves
 * "I rendered THIS content at THIS revision", so a blank or stale render can
 * never confirm the window.
 */
export async function fetchDetail(windowId) {
  const res = await signedFetch(cfg().controlPlaneUrl, `/veto/${encodeURIComponent(windowId)}/detail`, "GET");
  if (!res.ok) throw new Error(`detail read failed: HTTP ${res.status}`);
  return res.json();
}

/**
 * The evidence gate in front of the ack: build the V1 envelope from the
 * detail's OWN fields, validate it, RECOMPUTE its hash, and require the
 * painted DOM to still carry exactly those fields — only then is there an ack
 * body to send. Returns the {deliveryId, revision, renderContentHash} echo, or
 * null when the render is not evidence:
 *  - no deliveryId (the window is terminal or non-ackable server-side);
 *  - the envelope fails V1 conformance (an oversized or bidi-carrying field
 *    reached the client somehow — never ack what could lie on screen);
 *  - the RECOMPUTED hash differs from the server's renderContentHash (the ack
 *    must prove "I rendered these bytes", not parrot a hash from the same
 *    payload that carried the text — a tampered or desynced detail acks
 *    nothing);
 *  - the DOM texts read back after the paint differ from the envelope (the
 *    view was mutated between render and ack, or the render never landed).
 * Pure over its inputs (detail + the read-back texts) and exported for the
 * regression tests; app.js reads the DOM and calls this after the two-rAF.
 */
export async function ackBodyForRender(detail, domTexts) {
  if (!detail || typeof detail.deliveryId !== "string" || detail.deliveryId === "") return null;
  // Validate the WIRE object verbatim — detail.renderable, version included.
  // Never rebuild the envelope from picked fields with a client-written v:1:
  // that would "validate" an object of our own making, and a v2 wire envelope
  // with V1-shaped fields would slide through as V1 (the gate must refuse a
  // version it does not implement, not rewrite it).
  const alert = detail.renderable;
  if (validateRenderableAlert(alert) !== null) return null;
  const recomputed = await renderContentHash(alert);
  if (recomputed !== detail.renderContentHash) return null;
  if (!domTextsMatch(alert, domTexts)) return null;
  // echo the RECOMPUTED hash — provably derived from the rendered fields
  return { deliveryId: detail.deliveryId, revision: detail.revision, renderContentHash: recomputed };
}

/** The painted nodes carry exactly the envelope's fields — nothing else acks. */
export function domTextsMatch(alert, domTexts) {
  return (
    !!alert &&
    !!domTexts &&
    domTexts.agentId === alert.agentId &&
    domTexts.tool === alert.tool &&
    domTexts.summary === alert.summary
  );
}

/**
 * The FULL evidence guard the ack send re-checks all the way down: the base
 * surface guard (generation, windowId, top-level, visible, focused) AND a
 * fresh DOM read-back equal to the hashed envelope. signedFetch re-evaluates
 * this after the key is retrieved AND after the WebCrypto sign, immediately
 * before the fetch — so a DOM mutated during the async digest/sign window
 * aborts the ack before any signature leaves the page.
 */
export function evidenceGuard(alert, readDomTexts, baseGuard) {
  return () => {
    if (baseGuard && !baseGuard()) return false;
    try {
      return domTextsMatch(alert, readDomTexts());
    } catch {
      return false;
    }
  };
}

/**
 * The delivery ack — the production caller of markDelivered(). Send it ONLY
 * after the concrete action summary has actually rendered in the foreground
 * detail view (document visible and focused, a paint completed). Returns the
 * server's verdict; a 409 inside the response floor means "re-ack against the
 * new deadline", a 501 means no owner device is enrolled server-side.
 */
export async function sendSeenAck(windowId, ackBody, guard) {
  const body = JSON.stringify(ackBody ?? {});
  const res = await signedFetch(
    cfg().controlPlaneUrl,
    `/veto/${encodeURIComponent(windowId)}/seen`,
    "POST",
    body,
    guard,
  );
  return { ok: res.ok, status: res.status, body: await res.json().catch(() => ({})) };
}

/**
 * The one-tap veto — the deliberate second action after the tap opened the
 * app. Device-signed, idempotent server-side (re-vetoing a vetoed window is a
 * successful no-op). Returns `vetoed: true` ONLY when the server response
 * explicitly confirms the window is vetoed — a 4xx/5xx is NOT success, so the
 * UI must never report "stopped" on a rejected veto (it stays retryable).
 */
export async function sendVeto(windowId) {
  const res = await signedFetch(cfg().controlPlaneUrl, `/veto/${encodeURIComponent(windowId)}`, "POST", "");
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, vetoed: res.ok && body.status === "vetoed", body };
}

export const VETO_BUTTON_LABEL = "VETO";

/**
 * ARM the (shared) veto button for the CURRENT review — a FULL canonical reset,
 * so it can never inherit a prior window's "STOPPED"/"VETO — retry" text after
 * an A-success then a navigation to B (the button element is reused across
 * windows). Enabled, labelled VETO, aria-disabled cleared. Mutates in place;
 * exported so the deployed app and its regression test share one definition.
 */
export function armVetoButton(btn) {
  btn.textContent = VETO_BUTTON_LABEL;
  btn.disabled = false;
  if (typeof btn.removeAttribute === "function") btn.removeAttribute("aria-disabled");
}

/**
 * What a veto RESPONSE may do to the (shared) veto button, guarded by the
 * render generation AND the current windowId the click was armed under. Pure
 * and doubly-checked so a stale response for window A cannot paint the button
 * after the view moved to B: a click on A arms `armedGen`/`armedWindowId`;
 * navigating to B bumps the render generation and changes the current windowId;
 * A's late response then returns "superseded" — the caller touches nothing.
 * (Generation alone would suffice today, since a route change bumps it; the
 * explicit windowId is defense in depth against any future path that advances
 * one without the other.) Only an explicitly confirmed veto
 * (`result.vetoed === true`) yields "stopped"; everything else is "retry".
 * Exported for the deployed app AND its regression test (app.js is a classic
 * script and cannot be imported, so the decision lives here where it can be).
 */
export function vetoResultAction(armedGen, currentGen, result, armedWindowId, currentWindowId) {
  if (armedGen !== currentGen) return "superseded";
  if (armedWindowId !== undefined && armedWindowId !== currentWindowId) return "superseded";
  return result && result.vetoed === true ? "stopped" : "retry";
}
