/*
 * Service worker — push rendering and the notification-tap handoff.
 *
 * SCOPE (apps/owner/DESIGN.md §3): a service worker ALERTS, it never produces
 * EVIDENCE. The push payload carries the renderable summary and delivery
 * coordinates and NO authority; this worker shows a notification and, on tap,
 * hands off to the foreground app. It NEVER sends /veto/:id/seen — the ack is
 * foreground-only (owner-runtime.mjs), because a platform reports no
 * truncation/visibility result to a worker and the server refuses an ack that
 * names a notification-class delivery. The device key is not touched here.
 *
 * The signing module is loaded as an ES module (module worker), the same
 * owner-crypto.mjs the app uses — CSP script-src 'self' permits it; there is
 * no bundler and no third-party code. It is imported only for the
 * pushsubscriptionchange re-enroll path, where the key IS reachable.
 */

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

/** Parse the browser-decrypted push payload; never trust its shape. */
function parseAlert(event) {
  try {
    const data = event.data ? event.data.json() : {};
    if (typeof data !== "object" || data === null) return null;
    return data;
  } catch {
    return null;
  }
}

self.addEventListener("push", (event) => {
  event.waitUntil(
    (async () => {
      const alert = parseAlert(event);
      // Every string rendered as TEXT — the platform escapes title/body, but
      // we also never build markup from these agent-influenced values.
      const count = Array.isArray(alert?.windowIds) ? alert.windowIds.length : 0;
      const title =
        alert && typeof alert.headline === "string" && alert.headline.length <= 200
          ? alert.headline
          : "OwnerSwitch — an action is waiting for your review";
      const windowId = typeof alert?.windowIds?.[0] === "string" ? alert.windowIds[0] : undefined;
      // Coordinates travel in notification.data — PushEvent.data does NOT
      // survive to notificationclick, and nothing rides a navigation URL.
      const data = {
        windowIds: Array.isArray(alert?.windowIds) ? alert.windowIds.slice(0, 64) : [],
        deadline: typeof alert?.deadline === "number" ? alert.deadline : undefined,
      };
      await self.registration.showNotification(title, {
        body: count > 1 ? `${count} actions held — open OwnerSwitch to review` : "Open OwnerSwitch to review",
        tag: windowId ?? "ownerswitch-alert", // a superseding revision replaces the display
        renotify: true,
        requireInteraction: true,
        data,
      });
    })(),
  );
});

self.addEventListener("notificationclick", (event) => {
  // The tap is NEVER the veto (a veto is irreversible; taps are accidental
  // too often — DESIGN.md §3). Focus or open the app on the alert view; the
  // FOREGROUND app renders the window and, only from that render, sends the
  // ack and offers the deliberate one-tap veto.
  event.notification.close();
  const windowId = event.notification.data?.windowIds?.[0];
  const target = windowId ? `./#alert=${encodeURIComponent(windowId)}` : "./#alert";
  event.waitUntil(
    (async () => {
      const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const client of all) {
        if ("focus" in client) {
          // NAVIGATE BEFORE FOCUS: focusing first would run the existing
          // page's pending two-rAF ack for whatever window it was already
          // showing, before this notification's target navigation lands. The
          // route change bumps the render generation and abandons that ack.
          if ("navigate" in client) {
            try {
              await client.navigate(target);
            } catch (e) {
              /* navigation may be disallowed cross-origin; focus still helps */
            }
          }
          await client.focus();
          return;
        }
      }
      if (self.clients.openWindow) await self.clients.openWindow(target);
    })(),
  );
});

self.addEventListener("pushsubscriptionchange", (event) => {
  // A subscription that silently rotted is an unreachable owner — every
  // window would walk extend→held until it is fixed. Re-subscribe and
  // re-enroll, device-signed, using the config the page persisted. Best
  // effort inside the worker; the app also reconciles on next foreground.
  event.waitUntil(
    (async () => {
      try {
        const mod = await import("./owner-runtime.mjs");
        await mod.resubscribeFromWorker(self.registration);
      } catch {
        /* the foreground app will reconcile on next open */
      }
    })(),
  );
});
