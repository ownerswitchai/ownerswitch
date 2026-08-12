/* Owner app — foreground controller. External file so the strict CSP
   (script-src 'self', no unsafe-inline) holds; see DESIGN.md §4.

   Two modes:
   - CONFIGURED (window.OWNERSWITCH_CONFIG present, set by a deployment-served
     config.js): the app is live — it registers the service worker, ensures
     the device key, enrolls for push, and on an #alert=<windowId> deep link
     renders the window and sends the delivery ack from that render.
   - SCAFFOLD (no config): the static design shell, nothing wired — the
     repository ships no config, so serving public/ alone stays a demo. */
(function () {
  var tabsEl = document.getElementById("tabs");
  var tabs = tabsEl ? tabsEl.querySelectorAll("a") : [];

  function currentHash() {
    // supports "#alert", "#alert=veto_abc", "#approve", …
    var raw = (location.hash || "#alert").slice(1);
    var eq = raw.indexOf("=");
    return { tab: eq === -1 ? raw : raw.slice(0, eq), arg: eq === -1 ? "" : raw.slice(eq + 1) };
  }

  function syncTabs() {
    var cur = currentHash().tab;
    tabs.forEach(function (a) {
      a.classList.toggle("active", a.dataset.tab === cur);
    });
  }

  // Agent-supplied strings are TEXT, never markup (DESIGN.md §4): assign only
  // via textContent so a hostile agentId/tool/summary can never be XSS on the
  // owner-app origin, right next to the device key.
  function setText(id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value == null ? "" : String(value);
  }

  var config = self.OWNERSWITCH_CONFIG;

  if (!config) {
    // SCAFFOLD MODE — placeholder data, nothing live.
    var sample = {
      agent: "deploy-bot",
      tool: "github.merge_pr",
      action: "Merge pull request ownerswitchai/ownerswitch#7",
      window: "veto_3f9a21c04b7d",
    };
    Object.keys(sample).forEach(function (k) {
      setText("kv-" + k, sample[k]);
    });
    window.addEventListener("hashchange", syncTabs);
    syncTabs();
    return;
  }

  // LIVE MODE.
  window.addEventListener("hashchange", function () {
    syncTabs();
    routeAlert();
  });
  syncTabs();

  var runtime = null;
  function loadRuntime() {
    if (!runtime) runtime = import("./owner-runtime.mjs");
    return runtime;
  }

  // Register the service worker (module worker so it can import owner-crypto),
  // then ensure the device key and enroll for push — best effort; a failure
  // here degrades to SMS/voice/held, never to a false "reached".
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker
      .register("sw.js", { type: "module" })
      .then(function (reg) {
        return loadRuntime().then(function (rt) {
          return rt.ensureDeviceKey().then(function () {
            return rt.subscribeAndEnroll(reg).catch(function () {
              /* push may be unavailable (e.g. iOS not installed); non-fatal */
            });
          });
        });
      })
      .catch(function () {
        /* no service worker → no push; the app still renders and acks */
      });
  }

  // The foreground detail view: on #alert=<windowId>, fetch the window, render
  // its concrete summary as TEXT, and only from that render send the ack.
  function routeAlert() {
    var h = currentHash();
    if (h.tab !== "alert" || !h.arg) return;
    var windowId = h.arg;
    loadRuntime().then(function (rt) {
      rt.fetchWindow(windowId)
        .then(function (win) {
          // render as TEXT
          setText("kv-agent", win.agentId);
          setText("kv-tool", win.tool);
          setText("kv-action", win.summary || win.tool);
          setText("kv-window", windowId);
          wireVeto(rt, windowId);
          // Only pending/extended windows can be acked; the server enforces
          // the full rule (revision, floor, class) and we simply report it.
          if (win.status === "pending" || win.status === "extended") {
            // ack after a paint completes and the view is visible/focused
            requestAnimationFrame(function () {
              requestAnimationFrame(function () {
                if (document.visibilityState === "visible" && document.hasFocus()) {
                  rt.sendSeenAck(windowId).catch(function () {});
                }
              });
            });
          }
        })
        .catch(function () {
          setText("kv-action", "This review could not be loaded — reopen from the notification.");
        });
    });
  }

  function wireVeto(rt, windowId) {
    var btn = document.querySelector("#alert .veto-btn");
    if (!btn) return;
    btn.disabled = false;
    btn.removeAttribute("aria-disabled");
    btn.addEventListener(
      "click",
      function () {
        btn.disabled = true;
        rt.sendVeto(windowId)
          .then(function () {
            btn.textContent = "STOPPED";
          })
          .catch(function () {
            btn.disabled = false; // failed send stays retryable (idempotent server-side)
          });
      },
      { once: false },
    );
  }

  routeAlert();
})();
