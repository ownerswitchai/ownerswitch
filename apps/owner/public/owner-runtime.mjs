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
  return fetch(baseUrl + path, {
    method,
    cache: "no-store",
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
