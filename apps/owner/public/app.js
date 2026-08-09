/* Owner app scaffold script — a separate file so the strict CSP the
   design requires (script-src 'self', no unsafe-inline) is achievable
   without rework; see DESIGN.md §4 and §6. */
(function () {
  // Static scaffold: tab highlighting off location.hash, nothing else.
  var tabs = document.getElementById("tabs").querySelectorAll("a");
  function sync() {
    var current = (location.hash || "#alert").slice(1);
    tabs.forEach(function (a) {
      a.classList.toggle("active", a.dataset.tab === current);
    });
  }
  window.addEventListener("hashchange", sync);
  sync();

  // Agent-supplied strings are TEXT, never markup (DESIGN.md §4). This
  // is the rule the scaffold demonstrates: agentId / tool / summary come
  // from agents and tool calls — attacker-influenced by definition — and
  // are ONLY ever assigned via textContent. innerHTML (or any
  // interpolation into markup) with these strings would be XSS on the
  // owner-app origin, right next to the device keys.
  var sample = {
    agent: "deploy-bot",
    tool: "github.merge_pr",
    action: "Merge pull request ownerswitchai/ownerswitch#7",
    window: "veto_3f9a21c04b7d",
  };
  Object.keys(sample).forEach(function (k) {
    var el = document.getElementById("kv-" + k);
    if (el) el.textContent = sample[k];
  });

  // Register the service-worker STUB so the scaffold exercises the shape.
  // The repository provides no supported install path; serving public/
  // manually may register this no-op worker, but no functional
  // OwnerSwitch app results (DESIGN.md §6). Guarded: file:// or ancient
  // browsers just skip it.
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("sw.js").catch(function () {
      /* scaffold: non-fatal */
    });
  }
})();
