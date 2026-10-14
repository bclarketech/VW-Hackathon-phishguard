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

  // ---- Clear: wipe fields explicitly ----
  // The form re-renders with the submitted values bound into value= attributes,
  // so a plain type="reset" would restore them instead of clearing. Handle it in JS.
  var clearBtn = document.getElementById("clear-btn");
  if (clearBtn) {
    clearBtn.addEventListener("click", function (e) {
      e.preventDefault();
      ["sender", "subject", "body"].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.value = "";
      });
      var f = document.getElementById("email-file");
      if (f) f.value = "";
      var rep = document.getElementById("report");
      if (rep) rep.remove();
      var s = document.getElementById("sender");
      if (s) s.focus();
    });
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

  // ---- Load an email file (.txt / .eml) ----
  var fileInput = document.getElementById("email-file");
  if (fileInput) {
    fileInput.addEventListener("change", function () {
      var file = this.files && this.files[0];
      if (!file) return;

      if (file.size > 50000) {
        window.alert("File is too large (" + file.size.toLocaleString() + " bytes). Please keep it under 50 KB.");
        fileInput.value = "";
        return;
      }

      var reader = new FileReader();
      reader.onload = function (e) {
        var text = String(e.target.result || "");
        var parsed = parseEmail(text);

        var senderEl = document.getElementById("sender");
        var subjectEl = document.getElementById("subject");
        var bodyEl = document.getElementById("body");
        if (senderEl) senderEl.value = parsed.sender;
        if (subjectEl) subjectEl.value = parsed.subject;
        if (bodyEl) bodyEl.value = parsed.body;

        // Auto-analyze right away so the user sees results immediately.
        var form = document.getElementById("analyze-form");
        if (form) form.submit();
      };
      reader.onerror = function () {
        window.alert("Could not read that file. Try saving the email as a .txt or .eml file first.");
      };
      reader.readAsText(file);
    });
  }

  // Split a raw email into sender / subject / body.
  // Handles RFC-822 style headers (blank line separates headers from body).
  function parseEmail(text) {
    var out = { sender: "", subject: "", body: text };
    var normalized = text.replace(/\r\n/g, "\n");

    // Only try header parsing if it actually looks like it has headers.
    var firstBlank = normalized.indexOf("\n\n");
    if (firstBlank === -1) return out;

    var headerBlock = normalized.slice(0, firstBlank);
    var bodyPart = normalized.slice(firstBlank + 2);

    // Must contain at least one recognizable header line to trust it.
    if (!/^(from|to|subject|date|message-id|received|return-path)\s*:/im.test(headerBlock)) {
      return out;
    }

    // Join continuation lines (headers wrapped over multiple lines).
    var headers = {};
    var currentKey = null;
    headerBlock.split("\n").forEach(function (line) {
      var m = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
      if (m) {
        currentKey = m[1].toLowerCase();
        headers[currentKey] = m[2].trim();
      } else if (currentKey && /^\s/.test(line)) {
        headers[currentKey] += " " + line.trim();
      }
    });

    // Light base64 / quoted-printable sniffing for encoded headers.
    function decodeHeader(v) {
      if (!v) return "";
      var b64 = v.match(/=\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?=/i);
      if (b64) {
        try { return decodeURIComponent(escape(window.atob(b64[1]))); } catch (err) { /* fall through */ }
      }
      var qp = v.match(/=\?UTF-8\?Q\?([^?]+)\?=/i);
      if (qp) {
        try {
          return decodeURIComponent(qp[1].replace(/_/g, " ").replace(/=([0-9A-F]{2})/gi, function (h, hex) {
            return "%" + hex;
          }));
        } catch (err) { /* fall through */ }
      }
      return v.replace(/=\n/g, ""); // basic quoted-printable soft line breaks in body-ish text
    }

    out.sender = decodeHeader(headers["from"] || "");
    out.subject = decodeHeader(headers["subject"] || "");
    out.body = bodyPart.trim() || text;
    return out;
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
