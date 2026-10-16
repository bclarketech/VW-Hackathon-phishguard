/**
 * PhishGuard — browser-side phishing email analyzer.
 *
 * This is a faithful port of the Python engine (analyzer.py) so the whole app
 * can run as a static site on GitHub Pages. Everything executes in YOUR browser:
 * no server, no upload — the email you paste never leaves your device.
 * Citation: 
    *This project was inspired by AI assistants. 
    *The team used Hermes (by Nous Research)
    *To help draft and debug code, explain concepts, and write notes. 
 */

(function (global) {
  "use strict";

  // --- Heuristic rules (mirrors analyzer.py) -------------------------------

  var URGENT_PATTERNS = [
    [/\b(urgent|immediately|act now|within \d+ hours?)\b/i, "Urgency pressure"],
    [/\b(suspend(?:ed|sion)?|terminate|restrict(?:ed)?|closure)\b/i, "Threat of account action"],
    [/\b(verify|confirm|validate)\b.{0,40}\b(account|identity|details|information)\b/i, "Verification lure"],
    [/\b(failure|failed|unusual (?:login|sign[- ]?in|activity))\b/i, "Fake security alert"],
    [/\b(winner|congratulations|prize|lottery|inheritance|wire transfer)\b/i, "Advance-fee / prize bait"],
    [/\b(password|credential|ssn|social security|credit card|cvv)\b.{0,60}\b(enter|provide|update|confirm)\b/i,
      "Credential harvesting request"],
  ];

  var FINANCIAL_SENDERS = /(paypal|apple|microsoft|google|amazon|netflix|bank|coinbase|irs)\b/i;
  var DISPLAY_NAME_SPOOF = /^(.*?)<?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>?/;

  var LOOKALIKE_TOKENS = {
    "paypa1": "paypal", "paypai": "paypal", "micros*f": "microsoft",
    "app1e": "apple", "g00gle": "google", "arnazon": "amazon",
  };

  var FREE_MAIL_DOMAINS = {
    "gmail.com": 1, "yahoo.com": 1, "hotmail.com": 1, "outlook.com": 1,
    "aol.com": 1, "proton.me": 1, "protonmail.com": 1, "icloud.com": 1, "mail.com": 1,
  };

  var IDN_OR_PUNYCODE = /(xn--[a-z0-9]+|[Ѐ-ӿ؀-ۿ])/i;
  var IPV4_IN_URL = /https?:\/\/(\d{1,3}\.){3}\d{1,3}/i;
  var HEX_OR_NUMERIC_DOMAIN = /^(?:0x[0-9a-f]+|\d+)$/i;
  var URL_RE = /https?:\/\/[^\s<>"')]+/i;

  var SEVERITY_WEIGHT = { high: 25, medium: 12, low: 5, info: 0 };

  // --- Small helpers -------------------------------------------------------

  function isValidIPv4(host) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
    if (!m) return false;
    for (var i = 1; i <= 4; i++) {
      var n = Number(m[i]);
      if (n < 0 || n > 255 || String(n) !== String(Number(m[i]))) return false;
    }
    return true;
  }

  function domainOf(url) {
    try {
      var u = new URL(url);
      return (u.hostname || "").toLowerCase();
    } catch (e) {
      return "";
    }
  }

  function Report() {
    this.score = 0;
    this.verdict = "likely_safe";
    this.findings = [];
    this.urls = [];
  }
  Report.prototype.add = function (severity, title, detail) {
    this.findings.push({ severity: severity, title: title, detail: detail });
  };
  Report.prototype.counts = function () {
    var out = { high: 0, medium: 0, low: 0, info: 0 };
    for (var i = 0; i < this.findings.length; i++) {
      out[this.findings[i].severity] = (out[this.findings[i].severity] || 0) + 1;
    }
    return out;
  };

  // --- Checks --------------------------------------------------------------

  function checkUrls(report, urls) {
    report.urls = urls;
    if (!urls.length) return;

    for (var i = 0; i < urls.length; i++) {
      var url = urls[i];
      var host = domainOf(url);
      if (!host) continue;

      if (IPV4_IN_URL.test(url) && isValidIPv4(host)) {
        report.add("high", "URL uses a raw IP address",
          "'" + url + "' points at an IP literal instead of a domain — a common phishing tactic.");
      }
      if (IDN_OR_PUNYCODE.test(host)) {
        report.add("high", "Internationalised (punycode) domain",
          "'" + host + "' uses characters that can impersonate a legitimate brand.");
      }
      if (HEX_OR_NUMERIC_DOMAIN.test(host)) {
        report.add("medium", "Unusual host format",
          "'" + host + "' is a numeric/hex host rather than a normal domain name.");
      }

      var labels = host.split(".").filter(function (l) { return l; });
      if (labels.length >= 5) {
        report.add("medium", "Deeply nested subdomains",
          "'" + host + "' has " + labels.length + " labels — often used to hide the real domain.");
      }

      for (var bad in LOOKALIKE_TOKENS) {
        if (Object.prototype.hasOwnProperty.call(LOOKALIKE_TOKENS, bad)) {
          var brand = LOOKALIKE_TOKENS[bad];
          if (host.indexOf(bad) !== -1 && host.indexOf(brand) === -1) {
            report.add("high", "Brand lookalike domain",
              "'" + host + "' resembles '" + brand + "' but is not the real site.");
          }
        }
      }

      if (url.split("://").slice(1).join("://").indexOf("@") !== -1) {
        report.add("high", "Misleading '@' in URL",
          "'" + url + "' hides the true destination after the '@' symbol.");
      }
      if (url.toLowerCase().indexOf("http://") === 0) {
        report.add("low", "Unencrypted http:// link",
          "'" + url + "' is not using HTTPS.");
      }
    }
  }

  function checkSender(report, sender, hasContent) {
    sender = (sender || "").trim();
    if (!sender) {
      if (hasContent) {
        report.add("info", "No sender provided", "The From field was empty, so sender checks were skipped.");
      }
      return;
    }

    var m = DISPLAY_NAME_SPOOF.exec(sender);
    var display = m ? m[1].trim().replace(/^"|"$/g, "") : sender;
    var addr = (m ? m[2] : sender).toLowerCase();
    var domain = addr.indexOf("@") !== -1 ? addr.split("@").pop() : "";

    var brand = FINANCIAL_SENDERS.exec(display);
    if (brand && domain && !FINANCIAL_SENDERS.test(domain)) {
      report.add("high", "Display name / sender domain mismatch",
        "Claims to be '" + brand[1] + "' but sends from '" + domain + "'.");
    }
    if (Object.prototype.hasOwnProperty.call(FREE_MAIL_DOMAINS, domain)) {
      report.add("medium", "Free mail sender",
        "'" + domain + "' is a consumer mail provider — legitimate companies rarely send auth notices from it.");
    }
    for (var bad in LOOKALIKE_TOKENS) {
      if (Object.prototype.hasOwnProperty.call(LOOKALIKE_TOKENS, bad)) {
        var bn = LOOKALIKE_TOKENS[bad];
        if (domain.indexOf(bad) !== -1 && domain.indexOf(bn) === -1) {
          report.add("high", "Lookalike sender domain",
            "Sender domain '" + domain + "' spoofs '" + bn + "'.");
        }
      }
    }
  }

  function checkBody(report, subject, body) {
    var text = subject + "\n" + body;

    for (var i = 0; i < URGENT_PATTERNS.length; i++) {
      var m = URGENT_PATTERNS[i][0].exec(text);
      if (m) report.add("medium", URGENT_PATTERNS[i][1], 'Matched phrase: "' + m[0] + '"');
    }

    var linkRe = /href=["']([^"']+)["'][^>]*>([^<]{2,80})</gi;
    var lm;
    while ((lm = linkRe.exec(text)) !== null) {
      var href = lm[1], anchor = lm[2];
      if (href.indexOf("http") === 0 && anchor.trim()) {
        var ah = domainOf(anchor.trim()), hh = domainOf(href);
        if (ah && hh && ah !== hh) {
          report.add("high", "Link text does not match destination",
            "Shows '" + anchor.trim() + "' but actually goes to '" + hh + "'.");
        }
      }
    }

    if (/\b(enter|provide|update|submit)\b.{0,50}\b(password|credentials|ssn|card)\b/i.test(text)) {
      report.add("high", "Requests sensitive information",
        "The message asks you to submit a password, card, or SSN — never do this from an email link.");
    }
    if (/\b(dear (customer|member|user|subscriber)|dear customer)\b/i.test(text)) {
      report.add("low", "Generic greeting",
        "Uses 'Dear Customer/User' instead of your real name — a mass-mailing sign.");
    }
    if (/\.(exe|scr|zip|rar|js|vbs|iso|lnk)\b/i.test(text)) {
      report.add("medium", "Suspicious attachment type",
        "Mentions an executable or archive attachment (.exe/.zip/.js...), common in malware delivery.");
    }
  }

  // --- Main entry point ----------------------------------------------------

  function analyze(opts) {
    opts = opts || {};
    var subject = (opts.subject || "").trim();
    var body = (opts.body || "").trim();
    var sender = (opts.sender || "").trim();
    var raw = (opts.raw || "").trim();

    // If the user pasted a whole email, split headers from body.
    if (raw && !(subject || body || sender)) {
      var lines = raw.split(/\r\n|\n|\r/);
      var headerEnd = lines.length;
      for (var i = 0; i < lines.length; i++) {
        if (lines[i].trim() === "") { headerEnd = i; break; }
      }
      var headers = lines.slice(0, headerEnd);
      body = lines.slice(headerEnd + 1).join("\n");
      for (var h = 0; h < headers.length; h++) {
        var low = headers[h].toLowerCase();
        if (low.indexOf("from:") === 0) sender = headers[h].split(":").slice(1).join(":").trim();
        else if (low.indexOf("subject:") === 0) subject = headers[h].split(":").slice(1).join(":").trim();
      }
    }

    var report = new Report();

    var urlRe = /https?:\/\/[^\s<>"')]+/gi;
    var allText = raw + "\n" + body;
    // Dedupe while preserving order: .eml raw already contains the body,
    // and HTML parts repeat each link as href + visible text.
    var found = allText.match(urlRe) || [];
    var seen = {}, urls = [];
    for (var u = 0; u < found.length; u++) {
      if (!seen[found[u]]) { seen[found[u]] = true; urls.push(found[u]); }
    }
    checkUrls(report, urls);
    checkSender(report, sender, !!(subject || body || raw));
    checkBody(report, subject, body);

    var score = 0;
    for (var f = 0; f < report.findings.length; f++) {
      score += SEVERITY_WEIGHT[report.findings[f].severity] || 0;
    }
    report.score = Math.max(0, Math.min(100, score));

    if (report.score >= 60) report.verdict = "likely_phishing";
    else if (report.score >= 30) report.verdict = "suspicious";
    else report.verdict = "likely_safe";

    var order = { high: 0, medium: 1, low: 2, info: 3 };
    report.findings.sort(function (a, b) {
      return (order[a.severity] !== undefined ? order[a.severity] : 9) -
             (order[b.severity] !== undefined ? order[b.severity] : 9);
    });

    return {
      score: report.score,
      verdict: report.verdict,
      counts: report.counts(),
      findings: report.findings,
      urls: report.urls,
    };
  }

  // Expose for the page script.
  global.PhishGuard = { analyze: analyze };
})(typeof window !== "undefined" ? window : this);
