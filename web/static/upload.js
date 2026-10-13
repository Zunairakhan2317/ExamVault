// Upload page helper (display and time conversion only; the server does hash, sign, encrypt, split, wrap).
// The datetime pickers give LOCAL time. We convert it to UTC here so the window the server stores and
// enforces (on its own UTC clock) is exactly the moment the examiner meant.
(function (root) {
  "use strict";

  // "2026-10-10T17:30" (local) -> "2026-10-10T12:30:00Z" when the browser is in UTC+5. "" if invalid.
  function toUtcIso(localValue) {
    if (!localValue) { return ""; }
    var d = new Date(localValue); // date-time text without an offset is read as local time
    return isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 19) + "Z";
  }

  function preview(utcIso) {
    return utcIso ? "UTC: " + utcIso.replace("T", " ").replace("Z", "") : "";
  }

  var api = { toUtcIso: toUtcIso, preview: preview };
  if (typeof module !== "undefined" && module.exports) { module.exports = api; return; }

  var doc = root.document;
  var form = doc && doc.getElementById("upload-form");
  if (!form) { return; }
  var panel = doc.getElementById("progress-steps");

  function sync(name) {
    var local = doc.getElementById(name);
    var utc = doc.getElementById(name + "_utc");
    var iso = toUtcIso(local.value);
    utc.value = iso;
    var note = doc.getElementById(name + "_preview");
    if (note) { note.textContent = preview(iso); }
  }

  ["window_start", "window_end"].forEach(function (name) {
    var input = doc.getElementById(name);
    if (!input) { return; }
    input.addEventListener("input", function () { sync(name); });
    input.addEventListener("change", function () { sync(name); });
    sync(name);
  });

  form.addEventListener("submit", function () {
    sync("window_start");
    sync("window_end");
    if (panel) { panel.classList.remove("d-none"); }
    var button = doc.getElementById("upload-button");
    if (button) { button.disabled = true; }
  });
})(typeof globalThis !== "undefined" ? globalThis : this);
