// Display-only countdown. The server clock decides everything; this just shows the time left.
(function () {
  var el = document.getElementById("countdown");
  if (!el) { return; }
  var status = el.dataset.status;
  var seconds = status === "before" ? parseInt(el.dataset.untilOpen, 10)
              : status === "open" ? parseInt(el.dataset.untilClose, 10) : 0;
  if (status === "closed" || isNaN(seconds)) { return; }
  function pad(n) { return (n < 10 ? "0" : "") + n; }
  function render(s) {
    el.textContent = pad(Math.floor(s / 3600)) + " : " + pad(Math.floor((s % 3600) / 60)) + " : " + pad(s % 60);
  }
  render(seconds);
  var timer = setInterval(function () {
    seconds -= 1;
    if (seconds <= 0) {
      clearInterval(timer);
      if (status === "before") {
        // Counting down to window open - reload to get fresh status
        window.location.reload();
      } else if (status === "open") {
        // Counting down to window close - show 00:00:00 and stop (avoid infinite refresh loop)
        render(0);
      }
      // status === "closed" case is handled by early return above
      return;
    }
    render(seconds);
  }, 1000);
})();
