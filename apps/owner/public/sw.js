/*
 * Service worker STUB — static design scaffold only (see ../DESIGN.md §6).
 *
 * Registration is exercised so the scaffold shows the shape; nothing
 * serves this app, so nothing installs it. It performs NO push handling,
 * NO caching, NO network interception. The handlers below exist to
 * document the flow the real implementation must follow — each body is a
 * no-op.
 */

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  /*
   * REAL FLOW (not implemented here — no VAPID keys, no live push in
   * this PR):
   *
   *  1. Parse the encrypted payload as OwnerAlertPush (src/types.ts):
   *     a pointer — { kind, windowId, deadline } — never the content.
   *  2. Fetch HeldWindowDetail with a device-signed GET /veto/:id.
   *  3. showNotification() with the CONCRETE action summary and a VETO
   *     action button, then — only after that resolves — send the
   *     device-signed POST /veto/:id/seen ack (SeenAck). The ack means
   *     "this window's summary rendered on this enrolled device";
   *     DESIGN.md §4 says exactly how much that proves.
   *  4. If step 2 fails: show a generic "an action is being held" and
   *     DO NOT ack — the owner couldn't judge what is pending, so
   *     silence must not release it. Fail closed on partial delivery.
   *
   * All of it inside event.waitUntil(), or the OS may kill the worker
   * between render and ack.
   */
  void event;
});

self.addEventListener("notificationclick", (event) => {
  /*
   * REAL FLOW (not implemented here):
   *  - action === "veto": the ENTIRE send lives inside event.waitUntil()
   *    — the OS may kill the worker the moment this handler returns, and
   *    a veto lost in flight is a stop that never happened. The
   *    notification stays OPEN until the server confirms: close() only
   *    on a confirmed response, so a failed send remains visible and
   *    tappable. The relay is idempotent server-side (re-vetoing a
   *    vetoed window succeeds as a no-op — DESIGN.md §5 row 2), so the
   *    worker retries blindly and never double-stops.
   *  - otherwise: focus or open the app on #alert for this window, also
   *    inside event.waitUntil().
   *
   * Deliberately NOT calling event.notification.close() here: closing
   * before the server confirms would make a killed-in-flight veto look
   * done.
   */
  void event;
});

self.addEventListener("pushsubscriptionchange", (event) => {
  /*
   * REAL FLOW (not implemented here): re-subscribe and upsert via the
   * device-signed PUT /devices/:id/push-subscription — a subscription
   * that silently rotted is an unreachable owner, and the veto lane
   * would quietly run extend→held on every window until it's fixed.
   */
  void event;
});
