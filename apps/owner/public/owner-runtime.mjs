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

/** Device-signed fetch: sign the exact method+path+body, then send it. */
async function signedFetch(baseUrl, path, method, body) {
  const { privateKey } = await ensureDeviceKey();
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
 * Fetch the window's renderable detail (device-signed GET), for the
 * foreground detail view to render. The read is what the ack later echoes.
 */
export async function fetchWindow(windowId) {
  const res = await signedFetch(cfg().controlPlaneUrl, `/veto/${encodeURIComponent(windowId)}`, "GET");
  if (!res.ok) throw new Error(`window read failed: HTTP ${res.status}`);
  return res.json();
}

/**
 * The delivery ack — the production caller of markDelivered(). Send it ONLY
 * after the concrete action summary has actually rendered in the foreground
 * detail view (document visible and focused, a paint completed). Returns the
 * server's verdict; a 409 inside the response floor means "re-ack against the
 * new deadline", a 501 means no owner device is enrolled server-side.
 */
export async function sendSeenAck(windowId) {
  const res = await signedFetch(cfg().controlPlaneUrl, `/veto/${encodeURIComponent(windowId)}/seen`, "POST", "");
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

/**
 * The one-tap veto — the deliberate second action after the tap opened the
 * app. Device-signed, idempotent server-side (re-vetoing a vetoed window is a
 * successful no-op), so a retry after an uncertain send never double-stops.
 */
export async function sendVeto(windowId) {
  const res = await signedFetch(cfg().controlPlaneUrl, `/veto/${encodeURIComponent(windowId)}`, "POST", "");
  return { status: res.status, body: await res.json().catch(() => ({})) };
}
