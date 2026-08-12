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
  // A render generation: every route change / navigation / hide / blur that
  // could make the current review invalid bumps it. A pending ack (and the
  // veto handler) captures the generation it was armed under and refuses to
  // act once it is superseded — so a two-rAF ack armed for window A can never
  // fire after the view moved to B, and a stale click can't stop the wrong one.
  var renderGen = 0;
  function invalidateRender() {
    renderGen++;
  }
  window.addEventListener("hashchange", function () {
    invalidateRender(); // any hash change abandons the previous review
    syncTabs();
    routeAlert();
  });
  document.addEventListener("visibilitychange", invalidateRender);
  window.addEventListener("pagehide", invalidateRender);
  window.addEventListener("blur", invalidateRender);
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

  // A top-level, non-framed document is a precondition for producing ack
  // evidence: `visibilityState === "visible"` and `hasFocus()` do NOT prove a
  // reviewable surface if the app is a tiny/covered iframe. The deployment
  // MUST also send `Content-Security-Policy: frame-ancestors 'none'` as an
  // HTTP header (a meta tag cannot express it); this is the in-page belt.
  function isTopLevel() {
    try {
      return window.top === window.self;
    } catch (e) {
      return false; // cross-origin framer → access throws → treat as framed
    }
  }

  // The foreground detail view: on #alert=<windowId>, fetch the foreground
  // detail, render its concrete fields as TEXT, and only from that render —
  // guarded, top-level, visible, focused, unchanged — echo the delivery ack.
  function routeAlert() {
    var h = currentHash();
    // Any route entry supersedes the previous review's pending ack/veto and
    // disables the stale control immediately, BEFORE the new detail loads.
    var gen = ++renderGen;
    var btn = document.querySelector("#alert .veto-btn");
    if (btn) {
      btn.disabled = true;
      btn.onclick = null;
    }
    if (h.tab !== "alert" || !h.arg) return;
    var windowId = h.arg;
    if (!isTopLevel()) return; // never render/ack a framed review surface

    loadRuntime().then(function (rt) {
      rt.fetchDetail(windowId)
        .then(function (detail) {
          if (gen !== renderGen) return; // superseded while loading
          // render as TEXT (agent-supplied strings are never markup)
          setText("kv-agent", detail.agentId);
          setText("kv-tool", detail.tool);
          setText("kv-action", detail.summary || detail.tool);
          setText("kv-window", windowId);
          wireVeto(rt, windowId, gen);

          if ((detail.status === "pending" || detail.status === "extended") && detail.deliveryId) {
            // The guard is re-checked inside signedFetch AFTER the key is
            // retrieved and again immediately before the fetch: if the surface
            // stopped being a valid top-level, visible, focused, CURRENT-
            // generation view of THIS window, no signature is sent.
            var stillValid = function () {
              var cur = currentHash();
              return (
                gen === renderGen &&
                isTopLevel() &&
                document.visibilityState === "visible" &&
                document.hasFocus() &&
                cur.tab === "alert" &&
                cur.arg === windowId
              );
            };
            var ackBody = {
              deliveryId: detail.deliveryId,
              revision: detail.revision,
              renderContentHash: detail.renderContentHash,
            };
            // wait for a real paint, then ack
            requestAnimationFrame(function () {
              requestAnimationFrame(function () {
                if (stillValid()) rt.sendSeenAck(windowId, ackBody, stillValid).catch(function () {});
              });
            });
          }
        })
        .catch(function () {
          if (gen === renderGen) setText("kv-action", "This review could not be loaded — reopen from the notification.");
        });
    });
  }

  function wireVeto(rt, windowId, gen) {
    var btn = document.querySelector("#alert .veto-btn");
    if (!btn) return;
    btn.disabled = false;
    btn.removeAttribute("aria-disabled");
    // ASSIGN (not addEventListener): one active handler, so a click after the
    // view moved to another window cannot fire a stale window's veto.
    btn.onclick = function () {
      if (gen !== renderGen) return; // stale view — ignore
      btn.disabled = true;
      rt.sendVeto(windowId)
        .then(function (result) {
          // The response for window A must not paint the SHARED button after
          // the view moved to B: the click handler was replaced, but this
          // in-flight promise still closes over the old button. The generation-
          // guarded decision (tested in owner-runtime) reports "superseded" so
          // a stale STOPPED can never tell the owner B is stopped when only A
          // was; "stopped" only on an explicitly confirmed veto (a 4xx/5xx is
          // NOT success and stays retryable).
          var action = rt.vetoResultAction(gen, renderGen, result);
          if (action === "superseded") return;
          if (action === "stopped") {
            btn.textContent = "STOPPED";
          } else {
            btn.textContent = "VETO — retry";
            btn.disabled = false;
          }
        })
        .catch(function () {
          if (gen !== renderGen) return; // superseded — do not touch B's button
          btn.textContent = "VETO — retry";
          btn.disabled = false; // network failure stays retryable (idempotent server-side)
        });
    };
  }

  routeAlert();
})();
