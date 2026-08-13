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
const IDENTITY_ID = "enrolled-identity";

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

function idbAdd(db, key, value) {
  // ADD, not put: the atomic create-if-absent — a second writer gets
  // ConstraintError instead of silently overwriting the first key
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).add(value, key);
    tx.oncomplete = () => resolve(true);
    tx.onerror = (event) => {
      const err = tx.error ?? event?.target?.error;
      if (err && err.name === "ConstraintError") resolve(false);
      else reject(err);
    };
    tx.onabort = () => {
      const err = tx.error;
      if (err && err.name === "ConstraintError") resolve(false);
      else reject(err ?? new Error("transaction aborted"));
    };
  });
}

// PAGE-LEVEL SINGLE-FLIGHT: the push path, the enrollment click, and any
// other caller share ONE in-flight ensure — two concurrent calls in this
// page can never both see "no key" and both generate.
let keyFlight = null;

/**
 * Load the device keypair — the DESIGN §2 step-4 custody discipline, all of
 * it, on every first run:
 *  1. best-effort durable-storage request (navigator.storage.persist);
 *  2. ATOMIC create-if-absent (IndexedDB add; on ConstraintError the racing
 *     winner's key is read back and this one is discarded) — cross-context
 *     safe, not just page-safe;
 *  3. the database is CLOSED and REOPENED, and the pair READ BACK from
 *     disk — the pair this function returns is always the persisted one,
 *     never the in-memory original;
 *  4. a PROBE SIGNATURE is produced with the read-back private key — a key
 *     that cannot sign after its persistence round-trip never enrolls and
 *     never acks. (The service-worker path exercises the same stored key on
 *     every push — sw.js signs with what THIS custody persisted.)
 */
export async function ensureDeviceKey() {
  if (!keyFlight) {
    keyFlight = ensureDeviceKeyOnce().catch((err) => {
      keyFlight = null; // a failed ensure must not poison every later call
      throw err;
    });
  }
  return keyFlight;
}

async function ensureDeviceKeyOnce() {
  try {
    await navigator.storage?.persist?.();
  } catch {
    /* best effort — persistence REQUEST only; the round-trip below is the test */
  }
  let db = await idb();
  let pair = await idbGet(db, KEY_ID);
  if (!pair || !pair.privateKey) {
    const fresh = await generateOwnerDeviceKey();
    await idbAdd(db, KEY_ID, fresh); // loser's key is garbage-collected
  }
  // CLOSE and REOPEN: the returned pair is what DISK holds, not what this
  // context happened to generate
  db.close();
  db = await idb();
  pair = await idbGet(db, KEY_ID);
  if (!pair || !pair.privateKey || !pair.publicKey) {
    throw new Error("device key did not survive its persistence round-trip — refusing to use it");
  }
  // PROBE: the read-back key must actually sign
  const probe = new Uint8Array([111, 119, 110, 101, 114, 115, 119, 105, 116, 99, 104]);
  const buf = new ArrayBuffer(probe.byteLength);
  new Uint8Array(buf).set(probe);
  await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, buf);
  return pair;
}

/**
 * Adopt the server-assigned enrolled identity, DURABLY, next to the key it
 * names: after a 201 from /devices/enroll the registry knows this key as
 * `deviceId` — every signed request from here on must use THAT id, or the
 * freshly enrolled phone cannot authenticate as its own registry record.
 * Written with read-back verification; refuses malformed ids.
 */
export async function adoptEnrolledIdentity(deviceId) {
  if (typeof deviceId !== "string" || !/^dev_[A-Za-z0-9_-]{1,64}$/.test(deviceId)) {
    throw new Error("not a control-plane device id — refusing to adopt it");
  }
  let db = await idb();
  await idbPut(db, IDENTITY_ID, { deviceId });
  db.close();
  db = await idb();
  const stored = await idbGet(db, IDENTITY_ID);
  if (!stored || stored.deviceId !== deviceId) {
    throw new Error("enrolled identity did not survive its persistence round-trip");
  }
  return stored.deviceId;
}

/** The durably adopted enrolled deviceId, or null before enrolment. */
export async function enrolledIdentity() {
  const db = await idb();
  const stored = await idbGet(db, IDENTITY_ID);
  return stored && typeof stored.deviceId === "string" ? stored.deviceId : null;
}

/**
 * The id every signed request uses: the ENROLLED identity once one exists
 * (the registry record's name for this key), else the deployment-config id
 * (the operator-provisioned keys-file model).
 */
async function signingDeviceId() {
  return (await enrolledIdentity()) ?? cfg().deviceId;
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
  const deviceId = await signingDeviceId();
  if (guard && !guard()) throw new Error("aborted: review surface no longer valid before signing");
  const headers = await signRequestHeaders(privateKey, {
    deviceId,
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
