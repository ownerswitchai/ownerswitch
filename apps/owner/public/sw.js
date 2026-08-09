/*
 * Service worker STUB — static design scaffold only (see ../DESIGN.md §6).
 *
 * Registration is exercised so the scaffold shows the shape. The
 * repository provides no supported install path; manually serving the
 * scaffold may register this no-op worker, but no functional OwnerSwitch
 * app results. It performs NO push handling, NO caching, NO network
 * interception. The handlers below exist to document the flow the real
 * implementation must follow — each body is a no-op.
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
   * this PR). Designed for the iOS cold-start defect (WebKit 283793):
   * a cold-woken worker may find indexedDB undefined, so the key store
   * — and with it every device signature — can be unreachable. The
   * payload carries the renderable summary and delivery coordinates,
   * and NO authority of any kind (DESIGN.md §3):
   *
   *  1. Parse the encrypted payload as OwnerAlertPush (src/types.ts):
   *     windowId, revision, deliveryId, status, the renderable
   *     summary, deadline. Oversized/truncated/unparseable payload →
   *     show a generic "an action is waiting for review" and DO NOT
   *     ack.
   *  2. WARM (key reachable): prefer the authoritative fetch — the
   *     device-signed GET /veto/:id returns the CURRENT revision and
   *     mints the Delivery this render belongs to; render THAT, then —
   *     only after the render resolved — device-sign
   *     POST /veto/:id/seen with {windowId, revision, deliveryId,
   *     renderedPayloadHash, renderedAt, surface}. Rendering the
   *     fetched truth and acking its own delivery is what stops a
   *     forged or stale push from turning this worker into an
   *     ack-signing oracle (DESIGN.md §3, "Versioned delivery").
   *  3. COLD (indexedDB undefined): render from the payload — that is
   *     what it is for — and DO NOT ack; there is no key to sign with
   *     and no substitute for it. The ack happens later, signed, from
   *     the opened app if the window is still live. Every summary
   *     string renders as TEXT (title/body), never markup.
   *  4. Copy {windowId, revision, deliveryId, expiry} into
   *     NotificationOptions.data — PushEvent.data does NOT survive to
   *     notificationclick, and nothing may ride in a navigation URL
   *     (DESIGN.md §3). Add a VETO action button only where
   *     Notification.maxActions > 0; set the notification tag to the
   *     windowId so a superseding revision replaces the display
   *     (best-effort).
   *
   * All of it inside event.waitUntil(), or the OS may kill the worker
   * between render and ack.
   */
  void event;
});

self.addEventListener("notificationclick", (event) => {
  /*
   * REAL FLOW (not implemented here). Reads windowId/revision/
   * deliveryId from event.notification.data — never from a URL.
   *  - action === "veto" (platforms with action buttons — where the
   *    key IS reachable): the ENTIRE send lives inside
   *    event.waitUntil() — the OS may kill the worker the moment this
   *    handler returns, and a veto lost in flight is a stop that never
   *    happened. Device-sign POST /veto/:id. The notification stays
   *    OPEN until the server confirms: close() only on a confirmed
   *    response, so a failed send remains visible and tappable. The
   *    relay is idempotent server-side (re-vetoing a vetoed window
   *    succeeds as a no-op — DESIGN.md §5 row 2), so the worker
   *    retries blindly and never double-stops.
   *  - plain notification tap (the iOS path, and the default
   *    everywhere): focus or open the app on the alert view, inside
   *    event.waitUntil(); the foreground app signs the veto — and the
   *    ack, if the window is still open. The tap itself is NEVER the
   *    veto — a veto is irreversible and notification taps are
   *    accidental too often (DESIGN.md §3). If iOS loses the handoff
   *    and launches the manifest root, the app reconciles via the
   *    device-signed GET /veto inbox and acks only the ONE window it
   *    actually renders.
   *
   * Deliberately NOT calling event.notification.close() here: closing
   * before the server confirms would make a killed-in-flight veto look
   * done.
   */
  void event;
});

self.addEventListener("pushsubscriptionchange", (event) => {
  /*
   * REAL FLOW (not implemented here): re-subscribe with the configured
   * VAPID applicationServerKey (RFC 8292 — the server refuses an
   * unrestricted subscription) and upsert via the device-signed
   * PUT /devices/:id/push-subscription — a subscription that silently
   * rotted is an unreachable owner, and the veto lane would quietly
   * run extend→held on every window until it's fixed.
   */
  void event;
});
