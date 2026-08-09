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
