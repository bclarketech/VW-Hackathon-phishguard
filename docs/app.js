// PhishGuard (GitHub Pages edition): runs 100% in the browser via analyzer.js.
// No network calls — the email never leaves the device.

(function () {
  "use strict";

  var VERDICT_HINT = {
    likely_phishing: "Multiple strong phishing signals found. Do not click links or reply.",
    suspicious: "Some warning signs present. Verify with the sender through a known channel.",
    likely_safe: "No major phishing signals detected — but always stay cautious.",
  };

  function esc(s) {
    var d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }

  // ---- Animate the conic-gradient score ring ----
  function animateRing(score) {
    var ring = document.querySelector(".score-ring");
    if (!ring) return;
    var numEl = ring.querySelector(".ring-num");
    var start = null;
    var DURATION = 900;
    function step(ts) {
      if (start === null) start = ts;
      var p = Math.min((ts - start) / DURATION, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      var val = Math.round(eased * score);
      ring.style.setProperty("--pct", val);
      if (numEl) numEl.textContent = val;
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  // ---- Render a report into the fixed #report card ----
  function renderReport(rep) {
    var report = document.getElementById("report");
    if (!report) return;
    report.classList.remove("hidden");

    var ring = report.querySelector(".score-ring");
    if (ring) ring.setAttribute("data-verdict", rep.verdict);

    // Colour the ring + heading: CSS keys off .verdict-<verdict> on the card
    report.classList.remove("verdict-likely_safe", "verdict-suspicious", "verdict-likely_phishing");
    if (rep.verdict) report.classList.add("verdict-" + rep.verdict);

    var label = report.querySelector(".verdict-label");
    if (label) label.textContent = (rep.verdict || "").replace(/_/g, " ");
    var sub = report.querySelector(".verdict-sub");
    if (sub) sub.textContent = VERDICT_HINT[rep.verdict] || "";

    var counts = report.querySelector(".counts");
    if (counts) {
      var c = rep.counts || {};
      var parts = [];
      if (c.high) parts.push('<span class="chip chip-high">' + c.high + " high</span>");
      if (c.medium) parts.push('<span class="chip chip-medium">' + c.medium + " medium</span>");
      if (c.low) parts.push('<span class="chip chip-low">' + c.low + " low</span>");
      if (c.info) parts.push('<span class="chip chip-info">' + c.info + " info</span>");
      if (!parts.length) parts.push('<span class="chip chip-ok">no issues found</span>');
      counts.innerHTML = parts.join("");
    }

    var flist = report.querySelector(".findings");
    if (flist) {
      if (rep.findings && rep.findings.length) {
        flist.innerHTML = rep.findings.map(function (f) {
          return (
            '<li class="finding finding-' + esc(f.severity) + '">' +
              '<span class="sev sev-' + esc(f.severity) + '">' + esc(f.severity) + "</span>" +
              "<div><strong>" + esc(f.title) + "</strong><p>" + esc(f.detail) + "</p></div>" +
            "</li>"
          );
        }).join("");
      } else {
        flist.innerHTML = '<li class="none">No suspicious indicators matched.</li>';
      }
    }

    var urlBlock = report.querySelector(".urls-block");
    var ulist = report.querySelector(".urls");
    if (urlBlock && ulist) {
      if (rep.urls && rep.urls.length) {
        urlBlock.classList.remove("hidden");
        ulist.innerHTML = rep.urls.map(function (u) {
          return "<li><code>" + esc(u) + "</code></li>";
        }).join("");
      } else {
        urlBlock.classList.add("hidden");
      }
    }

    animateRing(rep.score);
    report.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ---- Split a raw email into sender / subject / body (client-side) ----
  function parseEmail(text) {
    var out = { sender: "", subject: "", body: text };
    var normalized = text.replace(/\r\n/g, "\n");
    var firstBlank = normalized.indexOf("\n\n");
    if (firstBlank === -1) return out;

    var headerBlock = normalized.slice(0, firstBlank);
    var bodyPart = normalized.slice(firstBlank + 2);
    if (!/^(from|to|subject|date|message-id|received|return-path)\s*:/im.test(headerBlock)) {
      return out;
    }

    var headers = {};
    var currentKey = null;
    headerBlock.split("\n").forEach(function (line) {
      var m = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
      if (m) { currentKey = m[1].toLowerCase(); headers[currentKey] = m[2].trim(); }
      else if (currentKey && /^\s/.test(line)) { headers[currentKey] += " " + line.trim(); }
    });

    function decodeHeader(v) {
      if (!v) return "";
      var b64 = v.match(/=\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?=/i);
      if (b64) { try { return decodeURIComponent(escape(window.atob(b64[1]))); } catch (e) {} }
      var qp = v.match(/=\?UTF-8\?Q\?([^?]+)\?=/i);
      if (qp) {
        try {
          return decodeURIComponent(qp[1].replace(/_/g, " ").replace(/=([0-9A-F]{2})/gi, function (h, hex) { return "%" + hex; }));
        } catch (e) {}
      }
      return v.replace(/=\n/g, "");
    }

    out.sender = decodeHeader(headers["from"] || "");
    out.subject = decodeHeader(headers["subject"] || "");
    out.body = bodyPart.trim() || text;
    return out;
  }

  // ---- Run the analysis locally (NO network) ----
  function runAnalysis() {
    var rep = window.PhishGuard.analyze({
      sender: (document.getElementById("sender") || {}).value || "",
      subject: (document.getElementById("subject") || {}).value || "",
      body: (document.getElementById("body") || {}).value || "",
    });
    renderReport(rep);
  }

  // ---- Wire up the form ----
  var form = document.getElementById("analyze-form");
  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      runAnalysis();
    });
  }

  // ---- Load a realistic phishing sample ----
  var sampleBtn = document.getElementById("sample-btn");
  if (sampleBtn) {
    sampleBtn.addEventListener("click", function () {
      var sender = document.getElementById("sender");
      var subject = document.getElementById("subject");
      var body = document.getElementById("body");
      if (sender) sender.value = "Apple Support <verify@app1e-id-secure.com>";
      if (subject) subject.value = "Urgent: Your Apple ID will be suspended within 24 hours";
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
      runAnalysis();
    });
  }

  // ---- Load an email file locally (read in-memory, never uploaded) ----
  var fileInput = document.getElementById("email-file");
  if (fileInput) {
    fileInput.addEventListener("change", function () {
      var file = this.files && this.files[0];
      if (!file) return;
      if (file.size > 50000) {
        window.alert("File is too large (" + file.size.toLocaleString() + " bytes). Keep it under 50 KB.");
        fileInput.value = "";
        return;
      }
      var reader = new FileReader();
      reader.onload = function (e) {
        var parsed = parseEmail(String(e.target.result || ""));
        var senderEl = document.getElementById("sender");
        var subjectEl = document.getElementById("subject");
        var bodyEl = document.getElementById("body");
        if (senderEl) senderEl.value = parsed.sender;
        if (subjectEl) subjectEl.value = parsed.subject;
        if (bodyEl) bodyEl.value = parsed.body;
        runAnalysis();
      };
      reader.onerror = function () {
        window.alert("Could not read that file. Try saving the email as a .txt or .eml file first.");
      };
      reader.readAsText(file);
    });
  }
})();
