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
   * payload therefore carries everything a keyless worker needs
   * (DESIGN.md §3, "The iOS cold-push path"):
   *
   *  1. Parse the encrypted payload as OwnerAlertPush (src/types.ts):
   *     windowId, status, the renderable summary, deadline, and a
   *     single-use VETO-ONLY capability.
   *  2. showNotification() with the CONCRETE summary FROM THE PAYLOAD —
   *     no fetch required. Add a VETO action button only where
   *     Notification.maxActions > 0 (Safari does not reliably honour
   *     action buttons — DESIGN.md §3).
   *  3. Ack only if the key is reachable: feature-detect indexedDB,
   *     retrieve the cheap-lane key, and device-sign
   *     POST /veto/:id/seen (SeenAck) — only after the render resolved.
   *     The capability NEVER acks: the ack is the permissive direction
   *     and never rides in a payload. A cold worker that cannot reach
   *     its key renders without acking — fail closed; the ack comes
   *     later from a warm context or the opened app if the window is
   *     still live (DESIGN.md §3, §4).
   *  4. If the payload is unreadable: show a generic "an action is
   *     waiting for review" and DO NOT ack.
   *
   * All of it inside event.waitUntil(), or the OS may kill the worker
   * between render and ack.
   */
  void event;
});

self.addEventListener("notificationclick", (event) => {
  /*
   * REAL FLOW (not implemented here):
   *  - action === "veto" (platforms with action buttons): the ENTIRE
   *    send lives inside event.waitUntil() — the OS may kill the worker
   *    the moment this handler returns, and a veto lost in flight is a
   *    stop that never happened. Sign with the device key if the store
   *    is reachable; otherwise present the payload's single-use veto
   *    capability (VetoTap.capability — veto only, DESIGN.md §3). The
   *    notification stays OPEN until the server confirms: close() only
   *    on a confirmed response, so a failed send remains visible and
   *    tappable. The relay is idempotent server-side (re-vetoing a
   *    vetoed window succeeds as a no-op — DESIGN.md §5 row 2), so the
   *    worker retries blindly and never double-stops.
   *  - plain notification tap (the Safari path, and the default
   *    everywhere): focus or open the app on #alert for this window,
   *    inside event.waitUntil(). The tap itself is NEVER the veto —
   *    a veto is irreversible and notification taps are accidental too
   *    often; the veto is a deliberate second tap in the app
   *    (DESIGN.md §3).
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
