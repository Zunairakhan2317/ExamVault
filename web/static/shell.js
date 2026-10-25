/* App shell: collapsible sidebar (desktop) and slide-in drawer (mobile).
   External file because the CSP blocks inline scripts. */

/* Runs immediately (script is in <head>) so a collapsed sidebar never flashes open. */
(function () {
  try {
    if (localStorage.getItem("ev-sidebar") === "collapsed") {
      document.documentElement.classList.add("sb-collapsed");
    }
  } catch (e) { /* storage blocked: ignore */ }
})();

document.addEventListener("DOMContentLoaded", function () {
  var root = document.documentElement;
  var toggle = document.getElementById("sb-toggle");
  var backdrop = document.getElementById("sb-backdrop");
  var sidebar = document.getElementById("sidebar");
  if (!toggle || !sidebar) return;

  var desktop = window.matchMedia("(min-width: 992px)");

  function syncAria() {
    var open = desktop.matches ? !root.classList.contains("sb-collapsed") : root.classList.contains("sb-open");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  }
  function closeDrawer() { root.classList.remove("sb-open"); syncAria(); }

  toggle.addEventListener("click", function () {
    if (desktop.matches) {
      var collapsed = root.classList.toggle("sb-collapsed");
      try { localStorage.setItem("ev-sidebar", collapsed ? "collapsed" : "expanded"); } catch (e) {}
    } else {
      root.classList.toggle("sb-open");
    }
    syncAria();
  });

  if (backdrop) backdrop.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeDrawer(); });
  sidebar.addEventListener("click", function (e) {
    if (!desktop.matches && e.target.closest("a.sb-link")) closeDrawer();
  });
  desktop.addEventListener("change", function () { closeDrawer(); });
  syncAria();
});