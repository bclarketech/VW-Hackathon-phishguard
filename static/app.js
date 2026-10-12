// PhishGuard front-end: animates the score ring and fills a demo sample.

(function () {
  "use strict";

  // ---- Animate the conic-gradient score ring ----
  var ring = document.querySelector(".score-ring");
  if (ring) {
    var target = parseInt(ring.getAttribute("data-score"), 10) || 0;
    var start = null;
    var DURATION = 900;

    function step(ts) {
      if (start === null) start = ts;
      var p = Math.min((ts - start) / DURATION, 1);
      // ease-out
      var eased = 1 - Math.pow(1 - p, 3);
      var val = Math.round(eased * target);
      ring.style.setProperty("--pct", val);
      var numEl = ring.querySelector(".score-num");
      if (numEl) numEl.textContent = val;
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  // ---- Load a realistic phishing sample ----
  var sampleBtn = document.getElementById("sample-btn");
  if (sampleBtn) {
    sampleBtn.addEventListener("click", function () {
      var sender = document.getElementById("sender");
      var subject = document.getElementById("subject");
      var body = document.getElementById("body");

      if (sender) sender.value = 'Apple Support <verify@app1e-id-secure.com>';
      if (subject) subject.value = 'Urgent: Your Apple ID will be suspended within 24 hours';
      if (body) {
        body.value =
          "Dear Customer,\n\n" +
          "We detected unusual activity on your account and your Apple ID has been " +
          "limited. You must act now to avoid permanent suspension.\n\n" +
          "Please verify your identity and confirm your password within 24 hours by " +
          "clicking the link below:\n\n" +
          "http://192.168.1.55/secure/login.php?ref=verify\n" +
          "http://appleid.verify-account.secure.login.example.com/update\n\n" +
          "Failure to confirm your credit card details will result in your account " +
          "being terminated immediately.\n\n" +
          "Thank you,\nApple Security Team\n";
      }
      // Move focus to the submit button so users can just hit Analyze.
      var submit = document.querySelector(".btn-primary");
      if (submit) submit.focus();
    });
  }

  // ---- Optional: AJAX submit so the page doesn't fully reload ----
  var form = document.getElementById("analyze-form");
  if (form) {
    form.addEventListener("submit", function (e) {
      // Let the normal form POST work as a no-JS fallback; only intercept
      // when fetch is available.
      if (typeof fetch !== "function") return;
      e.preventDefault();

      var payload = {
        sender: (document.getElementById("sender") || {}).value || "",
        subject: (document.getElementById("subject") || {}).value || "",
        body: (document.getElementById("body") || {}).value || ""
      };

      fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data.error) { window.alert(data.error); return; }
          renderReport(data);
        })
        .catch(function () {
          // On any failure, fall back to a plain form submit.
          form.removeEventListener("submit", arguments.callee);
          form.submit();
        });
    });
  }

  function esc(s) {
    var d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }

  function renderReport(rep) {
    var existing = document.getElementById("report");
    if (existing) existing.remove();

    var verdict = (rep.verdict || "").replace(/_/g, " ");
    var counts = rep.counts || {};
    var findings = (rep.findings || []).map(function (f) {
      return (
        '<li class="finding finding-' + esc(f.severity) + '">' +
          '<span class="sev sev-' + esc(f.severity) + '">' + esc(f.severity) + '</span>' +
          '<div><strong>' + esc(f.title) + '</strong><p>' + esc(f.detail) + '</p></div>' +
        "</li>"
      );
    }).join("");

    var urls = (rep.urls || []).map(function (u) {
      return "<li><code>" + esc(u) + "</code></li>";
    }).join("");

    var hint = rep.verdict === "likely_phishing"
      ? "Multiple strong phishing signals found. Do not click links or reply."
      : rep.verdict === "suspicious"
        ? "Some warning signs present. Verify with the sender through a known channel."
        : "No major phishing signals detected — but always stay cautious.";

    var html =
      '<section class="report" id="report">' +
        '<div class="verdict verdict-' + esc(rep.verdict) + '">' +
          '<div class="score-ring" data-score="' + esc(rep.score) + '">' +
            '<span class="score-num">' + esc(rep.score) + '</span>' +
            '<span class="score-label">/ 100</span>' +
          "</div>" +
          '<div class="verdict-text"><h2>' + esc(verdict) + '</h2>' +
          '<p class="verdict-hint">' + esc(hint) + "</p></div>" +
        "</div>" +
        (urls ? '<div class="urls"><h3>🔗 Links found (' + (rep.urls || []).length + ")</h3><ul>" + urls + "</ul></div>" : "") +
        '<div class="findings"><h3>🔎 Findings (' + (rep.findings || []).length + ")</h3>" +
          (findings ? "<ul>" + findings + "</ul>" : '<p class="none">No suspicious indicators matched.</p>') +
        "</div>" +
      "</section>";

    var inputCard = document.querySelector(".input-card");
    if (inputCard && inputCard.parentNode) {
      inputCard.parentNode.insertAdjacentHTML("afterend", html);
    }

    // Re-run the ring animation on the freshly injected element.
    var ring = document.querySelector(".score-ring");
    if (ring) {
      var target = parseInt(ring.getAttribute("data-score"), 10) || 0;
      var start = null;
      (function animate(ts) {
        if (start === null) start = ts;
        var p = Math.min((ts - start) / 900, 1);
        var eased = 1 - Math.pow(1 - p, 3);
        var val = Math.round(eased * target);
        ring.style.setProperty("--pct", val);
        var numEl = ring.querySelector(".score-num");
        if (numEl) numEl.textContent = val;
        if (p < 1) requestAnimationFrame(animate);
      })(performance.now());
    }

    var rep2 = document.getElementById("report");
    if (rep2) rep2.scrollIntoView({ behavior: "smooth", block: "start" });
  }
})();
