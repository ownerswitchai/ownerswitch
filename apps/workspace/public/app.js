/* Workspace console — DOM glue. External file so the strict CSP holds
   (script-src 'self', no unsafe-inline). Every decision lives in
   workspace-core.mjs (imported below, tested directly by the vitest suite);
   this file only fetches, schedules, and paints.

   Rendering rule (the apps/owner discipline): every value that originated
   outside this page — agent ids, tools, reasons, device names, errors — is
   assigned via textContent, never markup. */
(function () {
  "use strict";

  var STATUS_POLL_MS = 2000;
  var DEVICES_POLL_MS = 10000;
  var TICK_MS = 500;
  var FETCH_TIMEOUT_MS = 4000;

  var CORE = null;
  var journal = null;
  var lastKillView = null;
  var pendingIds = [];
  // Map/Set instead of plain {}: window ids arrive from OUTSIDE this page,
  // and a plain object would let "__proto__"/"constructor"/"toString" keys
  // collide with inherited members (post-merge audit #9)
  var windowFacts = new Map(); // id -> { agentId, tool } for journal wording after close
  var inFlight = new Set(); // ids with a veto POST out
  var stopped = new Set(); // ids the server confirmed vetoed
  // ORDERING guards (post-merge audit #2): polls are serial (the next one is
  // scheduled only after the previous completes) AND generation-checked, so
  // a late, stale answer can never repaint a newer state; a freshness TTL
  // (watched from the tick) forces UNREACHABLE when nothing fresh arrives —
  // a hung fetch or a resumed background tab cannot keep yesterday's ARMED.
  var statusGen = 0;
  var lastStatusAt = null;
  var showingStale = false;

  function $(id) {
    return document.getElementById(id);
  }

  function setText(id, value) {
    var el = $(id);
    if (el) el.textContent = value == null ? "" : String(value);
  }

  /** GET an /api path with a hard timeout; null on ANY failure — the caller
      renders fail closed. Without the AbortController a hung request would
      pin the serial poll loop (and the last painted state) forever. */
  function getJson(path) {
    var ctl = new AbortController();
    var timer = setTimeout(function () {
      ctl.abort();
    }, FETCH_TIMEOUT_MS);
    return fetch(path, { cache: "no-store", signal: ctl.signal })
      .then(function (res) {
        clearTimeout(timer);
        if (!res.ok) return null;
        return res.json().catch(function () {
          return null;
        });
      })
      .catch(function () {
        clearTimeout(timer);
        return null;
      });
  }

  function postJson(path, body) {
    return fetch(path, {
      method: "POST",
      cache: "no-store",
      // x-workspace-console is the server's CSRF gate: a foreign page's form
      // POST cannot set it, and a cross-origin fetch that tries preflights
      // into a refusal — only this same-origin script can mutate
      headers: { "content-type": "application/json", "x-workspace-console": "1" },
      body: JSON.stringify(body || {}),
    })
      .then(function (res) {
        return res.json().catch(function () {
          return null;
        });
      })
      .catch(function () {
        return null;
      });
  }

  function note(at, kind, text, tone) {
    if (journal) journal.push(at, kind, text, tone);
    renderJournal();
  }

  /* ---------------- kill state ---------------- */

  function renderKillState(view) {
    var pill = $("killstate");
    pill.textContent = view.badge;
    pill.className = "killstate " + view.state;
    setText("epoch", view.epoch === null ? "epoch —" : "epoch " + view.epoch);

    var banner = $("banner");
    var showBanner = view.treatAsKilled || view.warnings.length > 0 || view.scopedKills.length > 0;
    banner.hidden = !showBanner;
    banner.className = view.treatAsKilled ? "banner" : "banner warn";
    var lines = [];
    if (view.treatAsKilled) lines.push(view.detail);
    if (!view.treatAsKilled && view.scopedKills.length > 0) {
      lines.push("scope-killed agents: " + view.scopedKills.join(", "));
    }
    for (var i = 0; i < view.warnings.length; i++) lines.push(view.warnings[i]);
    setText("banner-text", lines.join(" · "));

    $("restore-card").hidden = view.state !== "killed";
    var plane = $("sb-plane");
    plane.textContent = view.state === "unreachable" ? "unreachable" : "live";
    plane.className = view.state === "unreachable" ? "down" : "live";
  }

  function pollStatus() {
    var gen = ++statusGen;
    return getJson("/api/status").then(function (reading) {
      // a response that is no longer the newest ask paints NOTHING — a
      // stale ARMED must not overwrite a fresher KILLED (audit #2)
      if (gen !== statusGen) return;
      var view = CORE.reduceKillView(lastKillView, CORE.classifyKillState(reading));
      var events = CORE.killStateTransitionEvents(lastKillView, view);
      for (var i = 0; i < events.length; i++) {
        note(Date.now(), events[i].kind, events[i].text, events[i].tone);
      }
      lastKillView = view;
      lastStatusAt = Date.now();
      showingStale = false;
      renderKillState(view);
      setText("sb-poll", CORE.formatClock(Date.now()) + " UTC");
    });
  }

  /* ---------------- pending veto windows ---------------- */

  function vetoButtonFor(windowId) {
    var cards = document.querySelectorAll(".vetocard");
    for (var i = 0; i < cards.length; i++) {
      if (cards[i].getAttribute("data-window") === windowId) {
        return cards[i].querySelector(".vetobtn");
      }
    }
    return null;
  }

  function onVetoClick(windowId) {
    if (inFlight.has(windowId) || stopped.has(windowId)) return;
    inFlight.add(windowId);
    var btn = vetoButtonFor(windowId);
    if (btn) {
      btn.disabled = true;
      btn.textContent = "VETO …";
    }
    postJson("/api/veto/" + encodeURIComponent(windowId), {}).then(function (result) {
      inFlight.delete(windowId);
      var current = vetoButtonFor(windowId) === null ? null : windowId;
      var action = CORE.vetoResultAction(windowId, current, result);
      var live = vetoButtonFor(windowId);
      if (action === "stopped") {
        stopped.add(windowId);
        if (live) {
          live.disabled = true;
          live.textContent = "STOPPED";
        }
        note(Date.now(), "veto", "veto " + windowId + " — stopped", "stop");
      } else if (action === "retry") {
        if (live) {
          live.disabled = false;
          live.textContent = "VETO — retry";
        }
        var why =
          result && typeof result === "object" && result.body && typeof result.body === "object" &&
          typeof result.body.error === "string"
            ? result.body.error
            : "no confirmed veto in the answer";
        note(Date.now(), "veto", "veto " + windowId + " not confirmed — " + why, "warn");
      } else {
        note(Date.now(), "veto", "veto answer for " + windowId + " arrived after the window left the view", "info");
      }
      pollPending();
    });
  }

  function buildVetoCard(w) {
    var card = document.createElement("div");
    card.className = "vetocard";
    card.setAttribute("data-window", w.id);
    card.setAttribute("data-deadline", String(w.deadline));

    var h = document.createElement("h3");
    h.appendChild(document.createTextNode("Veto window "));
    var tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = w.status === "extended" ? "EXTENDED" : "OPEN";
    h.appendChild(tag);
    if (w.delivered) {
      var seen = document.createElement("span");
      seen.className = "tag";
      seen.textContent = "SEEN";
      h.appendChild(seen);
    }
    card.appendChild(h);

    var line = document.createElement("div");
    line.className = "vetoline";
    var agent = document.createElement("b");
    agent.textContent = w.agentId;
    line.appendChild(agent);
    line.appendChild(document.createTextNode(" · " + w.tool));
    card.appendChild(line);

    var idLine = document.createElement("div");
    idLine.className = "vetoline";
    idLine.textContent = w.id;
    card.appendChild(idLine);

    var wrap = document.createElement("div");
    wrap.className = "countwrap";
    var count = document.createElement("span");
    count.className = "count";
    count.textContent = w.label;
    wrap.appendChild(count);
    var bar = document.createElement("div");
    bar.className = "bar";
    var fill = document.createElement("i");
    fill.style.width = Math.round(w.fraction * 100) + "%";
    bar.appendChild(fill);
    wrap.appendChild(bar);
    card.appendChild(wrap);

    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "vetobtn";
    if (stopped.has(w.id)) {
      btn.disabled = true;
      btn.textContent = "STOPPED";
    } else if (inFlight.has(w.id)) {
      btn.disabled = true;
      btn.textContent = "VETO …";
    } else {
      btn.textContent = "VETO";
    }
    btn.addEventListener("click", function () {
      onVetoClick(w.id);
    });
    card.appendChild(btn);

    var sub = document.createElement("div");
    sub.className = "vetosub";
    sub.textContent = "silence releases it — one click stops it · deny-only, signed by the console server";
    card.appendChild(sub);

    return card;
  }

  function renderPending(model, reading) {
    var chip = $("pending-chip");
    var noteEl = $("pending-note");
    var listEl = $("windows");

    if (model.kind === "ok") {
      chip.textContent = model.windows.length + " open";
      chip.className = model.windows.length > 0 ? "chip w" : "chip";
    } else {
      chip.textContent = "—";
      chip.className = "chip s";
    }

    var noteText = "";
    if (model.kind === "unconfigured") {
      noteText =
        "device lane not configured on the console server (OWNERSWITCH_DEVICE_SECRET) — cannot list veto windows; fail closed";
    } else if (model.kind === "unreachable") {
      var why = reading && typeof reading === "object" && typeof reading.error === "string" ? reading.error : "no usable answer";
      noteText = "cannot list veto windows — " + why + " — fail closed (this is NOT an empty list)";
    } else if (model.dropped > 0) {
      noteText = model.dropped + " unrenderable entr" + (model.dropped === 1 ? "y" : "ies") + " withheld";
    }
    noteEl.hidden = noteText === "";
    noteEl.textContent = noteText;

    while (listEl.firstChild) listEl.removeChild(listEl.firstChild);
    if (model.kind === "ok" && model.windows.length === 0) {
      var empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "no open veto windows";
      listEl.appendChild(empty);
      return;
    }
    for (var i = 0; i < model.windows.length; i++) {
      listEl.appendChild(buildVetoCard(model.windows[i]));
    }
  }

  function journalWindowChanges(model) {
    if (model.kind !== "ok") return;
    var nextIds = [];
    for (var i = 0; i < model.windows.length; i++) {
      var w = model.windows[i];
      nextIds.push(w.id);
      windowFacts.set(w.id, { agentId: w.agentId, tool: w.tool });
    }
    var diff = CORE.diffWindowIds(pendingIds, nextIds);
    pendingIds = nextIds;
    diff.appeared.forEach(function (id) {
      var facts = windowFacts.get(id) || { agentId: "?", tool: "?" };
      note(Date.now(), "window-open", "veto window " + id + " opened — " + facts.agentId + " · " + facts.tool, "warn");
    });
    diff.disappeared.forEach(function (id) {
      stopped.delete(id);
      getJson("/api/veto/" + encodeURIComponent(id)).then(function (answer) {
        var finalStatus = answer && typeof answer === "object" ? answer.status : null;
        note(Date.now(), "window-close", CORE.closedWindowText(id, finalStatus), CORE.closedWindowTone(finalStatus));
        windowFacts.delete(id);
      });
    });
  }

  function pollPending() {
    return getJson("/api/veto/pending").then(function (reading) {
      var model = CORE.pendingModel(reading, Date.now());
      renderPending(model, reading);
      journalWindowChanges(model);
      var lane = $("sb-device");
      if (reading && reading.kind === "unconfigured") {
        lane.textContent = "absent";
        lane.className = "";
      } else if (reading) {
        lane.textContent = "configured";
        lane.className = "live";
      } else {
        lane.textContent = "console server unreachable";
        lane.className = "down";
      }
    });
  }

  /** Re-label countdowns between polls; deadlines come from data attributes.
      ALSO the freshness watchdog: a hung poll or a tab resumed from the
      BFCache must not keep showing the last painted state — past the TTL
      the view is forced to STALE/UNREACHABLE until a fresh answer lands. */
  function tickCountdowns() {
    if (!showingStale && CORE.isStatusStale(lastStatusAt, Date.now())) {
      showingStale = true;
      var stale = CORE.staleKillView(lastKillView);
      note(Date.now(), "kill-state:stale", stale.detail, "warn");
      lastKillView = stale;
      renderKillState(stale);
    }
    var cards = document.querySelectorAll(".vetocard");
    var now = Date.now();
    for (var i = 0; i < cards.length; i++) {
      var deadline = Number(cards[i].getAttribute("data-deadline"));
      if (!isFinite(deadline)) continue;
      var parts = CORE.countdown(deadline, now);
      var count = cards[i].querySelector(".count");
      if (count) count.textContent = parts.label;
      var fill = cards[i].querySelector(".bar i");
      if (fill) fill.style.width = Math.round(parts.fraction * 100) + "%";
    }
  }

  /* ---------------- devices ---------------- */

  function renderDevices(model, reading) {
    var noteEl = $("devices-note");
    var listEl = $("devices");
    var lane = $("sb-session");

    var noteText = "";
    if (model.kind === "unconfigured") {
      noteText = "owner session not configured on the console server (OWNERSWITCH_OWNER_TOKEN) — devices panel disabled";
      lane.textContent = "absent";
      lane.className = "";
    } else if (model.kind === "refused") {
      noteText = "device listing refused (HTTP " + model.upstreamStatus + ") — " + model.error;
      lane.textContent = "configured";
      lane.className = "live";
    } else if (model.kind === "unreachable") {
      var why = reading && typeof reading === "object" && typeof reading.error === "string" ? reading.error : "no usable answer";
      noteText = "cannot list devices — " + why + " — fail closed";
      lane.textContent = reading ? "configured" : "console server unreachable";
      lane.className = reading ? "live" : "down";
    } else {
      lane.textContent = "configured";
      lane.className = "live";
    }
    noteEl.hidden = noteText === "";
    noteEl.textContent = noteText;

    while (listEl.firstChild) listEl.removeChild(listEl.firstChild);
    if (model.kind !== "ok") return;
    if (model.devices.length === 0) {
      var empty = document.createElement("div");
      empty.textContent = "no enrolled devices";
      listEl.appendChild(empty);
      return;
    }
    for (var i = 0; i < model.devices.length; i++) {
      var d = model.devices[i];
      var row = document.createElement("div");
      row.className = "row";
      var dot = document.createElement("span");
      dot.className = d.revoked ? "dot off" : "dot";
      dot.textContent = "●";
      row.appendChild(dot);
      var name = document.createElement("span");
      name.className = d.revoked ? "name revoked" : "name";
      name.textContent = d.name;
      row.appendChild(name);
      var meta = document.createElement("span");
      meta.className = "meta";
      meta.textContent = (d.revoked ? "revoked · " : "") + "enrolled " + d.enrolledOn + " · push " + (d.pushRegistered ? "on" : "off");
      row.appendChild(meta);
      listEl.appendChild(row);
    }
  }

  function pollDevices() {
    return getJson("/api/devices").then(function (reading) {
      renderDevices(CORE.devicesModel(reading), reading);
    });
  }

  /* ---------------- journal ---------------- */

  function renderJournal() {
    var listEl = $("journal");
    if (!journal || !listEl) return;
    var entries = journal.entries();
    while (listEl.firstChild) listEl.removeChild(listEl.firstChild);
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var row = document.createElement("div");
      row.className = "row";
      var t = document.createElement("span");
      t.className = "t";
      t.textContent = CORE.formatClock(e.at);
      row.appendChild(t);
      var x = document.createElement("span");
      x.className = "x " + e.tone;
      x.textContent = e.text;
      row.appendChild(x);
      if (e.count > 1) {
        var n = document.createElement("span");
        n.className = "n";
        n.textContent = "×" + e.count;
        row.appendChild(n);
      }
      listEl.appendChild(row);
    }
  }

  /* ---------------- E-STOP ---------------- */

  function wireEstop() {
    var btn = $("estop");
    // the button ships DISABLED in the HTML (audit #3): a page whose script
    // never loaded must not show a working-looking STOP; it becomes active
    // only here, once the handler is truly installed
    btn.disabled = false;
    btn.addEventListener("click", function () {
      // the e-stop never asks twice; it is disabled only while its own
      // request is in flight, and pressing an already-killed system is a
      // harmless re-stop
      btn.disabled = true;
      note(Date.now(), "kill", "E-STOP pressed — sending kill", "stop");
      postJson("/api/kill", { reason: "workspace console e-stop" }).then(function (result) {
        btn.disabled = false;
        // "confirmed" is a SCHEMA, not any HTTP 200 (audit #4): killed:true
        // with a usable epoch, and a degraded persistence stated as such —
        // then the next status poll re-verifies against /status itself
        var confirmation = CORE.killConfirmation(result);
        note(
          Date.now(),
          "kill",
          confirmation.text,
          confirmation.kind === "unconfirmed" ? "warn" : "stop",
        );
        pollStatus();
      });
    });
  }

  /* ---------------- boot ---------------- */

  function bootFailure() {
    // the module never loaded: nothing on this page is verified and nothing
    // works — say so in the static fail-closed banner instead of leaving
    // CONNECTING and a dead STOP button on screen (audit #3)
    var banner = $("banner");
    if (banner) banner.hidden = false;
    setText(
      "banner-text",
      "console failed to load its logic — nothing on this page is verified and the buttons cannot work; treat the system as killed and reload",
    );
    setText("killstate", "BOOT ERROR");
  }

  function statusLoop() {
    pollStatus().then(function () {
      setTimeout(statusLoop, STATUS_POLL_MS);
    });
  }
  function pendingLoop() {
    pollPending().then(function () {
      setTimeout(pendingLoop, STATUS_POLL_MS);
    });
  }
  function devicesLoop() {
    pollDevices().then(function () {
      setTimeout(devicesLoop, DEVICES_POLL_MS);
    });
  }

  import("./workspace-core.mjs")
    .then(function (mod) {
      CORE = mod;
      journal = CORE.createJournal(250);
      wireEstop();
      statusLoop();
      pendingLoop();
      devicesLoop();
      setInterval(tickCountdowns, TICK_MS);
      // a page revived from the BFCache or a long-hidden tab re-verifies
      // IMMEDIATELY: its painted state is history, not truth (audit #3)
      window.addEventListener("pageshow", function (event) {
        if (event.persisted) {
          lastStatusAt = null;
          pollStatus();
          pollPending();
        }
      });
      document.addEventListener("visibilitychange", function () {
        if (document.visibilityState === "visible") {
          pollStatus();
          pollPending();
        }
      });
    })
    .catch(function () {
      bootFailure();
    });
})();
