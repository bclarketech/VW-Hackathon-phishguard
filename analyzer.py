"""
PhishGuard — a lightweight phishing email analyzer.

Paste a suspicious email and get a risk score with explainable findings.

Design notes (important for the security write-up):
  * Nothing is written to disk or a database. Analysis is in-memory only.
  * The Flask debug toolbar is never enabled. Run under gunicorn in production.
  * Pure-Python heuristics; no external network calls at analysis time.

Citation: 
    *This project was inspired by AI assistants. 
    *The team used Hermes (by Nous Research)
    *To help draft and debug code, explain concepts, and write notes. 
    *All code was reviewed and tested by the team.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

__all__ = ["analyze", "Finding", "Report"]

# --------------------------------------------------------------------------- #
# Heuristic rules
# --------------------------------------------------------------------------- #

URGENT_PATTERNS: list[tuple[str, str]] = [
    (r"\b(urgent|immediately|act now|within \d+ hours?)\b", "Urgency pressure"),
    (r"\b(suspend(?:ed|sion)?|terminate|restrict(?:ed)?|closure)\b", "Threat of account action"),
    (r"\b(verify|confirm|validate)\b.{0,40}\b(account|identity|details|information)\b", "Verification lure"),
    (r"\b(failure|failed|unusual (?:login|sign[- ]?in|activity))\b", "Fake security alert"),
    (r"\b(winner|congratulations|prize|lottery|inheritance|wire transfer)\b", "Advance-fee / prize bait"),
    (r"\b(password|credential|ssn|social security|credit card|cvv)\b.{0,60}\b(enter|provide|update|confirm)\b",
     "Credential harvesting request"),
]

FINANCIAL_SENDERS = re.compile(r"(paypal|apple|microsoft|google|amazon|netflix|bank|coinbase|irs)\b", re.I)
DISPLAY_NAME_SPOOF = re.compile(r'^(?P<display>.*?)<?(?P<addr>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>?')

# Cheap homoglyph / lookalike map used to flag brand spoofing.
LOOKALIKE_TOKENS = {
    "paypa1": "paypal", "paypaI": "paypal", "micros*ft": "microsoft",
    "app1e": "apple", "g00gle": "google", "arnazon": "amazon",
}

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "proton.me", "protonmail.com", "icloud.com", "mail.com",
}

# Simple punycode / IDN detector.
IDN_OR_PUNYCODE = re.compile(r"(xn--[a-z0-9]+|[\u0400-\u04FF\u0600-\u06FF])", re.I)

# IPv4 literal embedded in a URL.
IPV4_IN_URL = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")

HEX_OR_NUMERIC_DOMAIN = re.compile(r"^(?:0x[0-9a-f]+|\d+)$")


@dataclass
class Finding:
    severity: str          # "high" | "medium" | "low" | "info"
    title: str
    detail: str

    def as_dict(self) -> dict:
        return {"severity": self.severity, "title": self.title, "detail": self.detail}


@dataclass
class Report:
    score: int = 0                     # 0..100
    verdict: str = "likely_safe"
    findings: list[Finding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    def add(self, severity: str, title: str, detail: str) -> None:
        self.findings.append(Finding(severity, title, detail))

    @property
    def counts(self) -> dict:
        out = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "counts": self.counts,
            "findings": [f.as_dict() for f in self.findings],
            "urls": self.urls,
        }


SEVERITY_WEIGHT = {"high": 25, "medium": 12, "low": 5, "info": 0}


def _extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s<>\")']+", text, re.I)


def _domain_of(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return ""
    return host.lower()


def _check_urls(report: Report, urls: list[str]) -> None:
    report.urls = urls
    if not urls:
        return

    for url in urls:
        host = _domain_of(url)
        if not host:
            continue

        # Raw IP as the host — classic malware / phishing host.
        if IPV4_IN_URL.search(url):
            try:
                ipaddress.ip_address(host)
                report.add("high", "URL uses a raw IP address",
                            f"'{url}' points at an IP literal instead of a domain — a common phishing tactic.")
            except ValueError:
                pass

        # Punycode / IDN can visually imitate a known brand.
        if IDN_OR_PUNYCODE.search(host):
            report.add("high", "Internationalised (punycode) domain",
                       f"'{host}' uses characters that can impersonate a legitimate brand.")

        # Bare hex / numeric hosts.
        if HEX_OR_NUMERIC_DOMAIN.match(host):
            report.add("medium", "Unusual host format",
                       f"'{host}' is a numeric/hex host rather than a normal domain name.")

        # Deep subdomain nesting (login.paypal.secure.verify.example.com).
        labels = [l for l in host.split(".") if l]
        if len(labels) >= 5:
            report.add("medium", "Deeply nested subdomains",
                       f"'{host}' has {len(labels)} labels — often used to hide the real domain.")

        # Lookalike brand tokens.
        for bad, brand in LOOKALIKE_TOKENS.items():
            if bad in host and brand not in host:
                report.add("high", "Brand lookalike domain",
                           f"'{host}' resembles '{brand}' but is not the real site.")

        # @ in URL confuses parsers (http://paypal.com@evil.com).
        if "@" in url.split("://", 1)[-1]:
            report.add("high", "Misleading '@' in URL",
                       f"'{url}' hides the true destination after the '@' symbol.")

        # http:// instead of https://.
        if url.lower().startswith("http://"):
            report.add("low", "Unencrypted http:// link",
                       f"'{url}' is not using HTTPS.")


def _check_sender(report: Report, sender: str, has_content: bool = True) -> None:
    sender = (sender or "").strip()
    if not sender:
        # Only worth mentioning if there's something else to analyze — an
        # entirely empty paste shouldn't produce a finding at all.
        if has_content:
            report.add("info", "No sender provided", "The From field was empty, so sender checks were skipped.")
        return

    m = DISPLAY_NAME_SPOOF.match(sender)
    display = m.group("display").strip().strip('"') if m else sender
    addr = m.group("addr").lower() if m else sender.lower()
    domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""

    # Brand in the display name but a totally different (or free) mail domain.
    brand = FINANCIAL_SENDERS.search(display)
    if brand and domain and FINANCIAL_SENDERS.search(domain) is None:
        report.add("high", "Display name / sender domain mismatch",
                   f"Claims to be '{brand.group(1).title()}' but sends from '{domain}'.")

    if domain in FREE_MAIL_DOMAINS:
        report.add("medium", "Free mail sender",
                   f"'{domain}' is a consumer mail provider — legitimate companies rarely send auth notices from it.")

    # Lookalike sender domain.
    for bad, brand_name in LOOKALIKE_TOKENS.items():
        if bad in domain and brand_name not in domain:
            report.add("high", "Lookalike sender domain",
                       f"Sender domain '{domain}' spoofs '{brand_name}'.")


def _check_body(report: Report, subject: str, body: str) -> None:
    text = f"{subject}\n{body}"

    for pattern, label in URGENT_PATTERNS:
        m = re.search(pattern, text, re.I)
        if m:
            report.add("medium", label, f"Matched phrase: \"{m.group(0)}\"")

    # Mismatched hyperlink text vs actual URL (only when raw HTML is pasted).
    for href, anchor in re.findall(r'href=["\']([^"\']+)["\'][^>]*>([^<]{2,80})<', text, re.I):
        if href.startswith("http") and anchor.strip():
            anchor_host = _domain_of(anchor.strip())
            href_host = _domain_of(href)
            if anchor_host and href_host and anchor_host != href_host:
                report.add("high", "Link text does not match destination",
                           f"Shows '{anchor.strip()}' but actually goes to '{href_host}'.")

    # Body asks for credentials with no legitimate context.
    if re.search(r"\b(enter|provide|update|submit)\b.{0,50}\b(password|credentials|ssn|card)\b", text, re.I):
        report.add("high", "Requests sensitive information",
                   "The message asks you to submit a password, card, or SSN — never do this from an email link.")

    # Generic greeting.
    if re.search(r"\b(dear (customer|member|user|subscriber)|dear customer)\b", text, re.I):
        report.add("low", "Generic greeting",
                   "Uses 'Dear Customer/User' instead of your real name — a mass-mailing sign.")

    # Unsolicited attachment.
    if re.search(r"\.(exe|scr|zip|rar|js|vbs|iso|lnk)\b", text, re.I):
        report.add("medium", "Suspicious attachment type",
                   "Mentions an executable or archive attachment (.exe/.zip/.js...), common in malware delivery.")


def analyze(subject: str = "", body: str = "", sender: str = "", raw: str = "") -> Report:
    """Run all heuristics and return an explainable risk report.

    Nothing passed in here is persisted anywhere.
    """
    report = Report()

    # If the user pasted the whole email, split headers from body cheaply.
    if raw and not (subject or body or sender):
        lines = raw.splitlines()
        header_end = 0
        for i, line in enumerate(lines):
            if line.strip() == "":
                header_end = i
                break
        headers = lines[:header_end]
        body = "\n".join(lines[header_end + 1:])
        for h in headers:
            low = h.lower()
            if low.startswith("from:"):
                sender = h.split(":", 1)[1].strip()
            elif low.startswith("subject:"):
                subject = h.split(":", 1)[1].strip()

    # Dedupe while preserving order: .eml raw already contains the body,
    # and HTML parts repeat each link as href + visible text.
    urls = list(dict.fromkeys(_extract_urls(f"{raw}\n{body}")))
    _check_urls(report, urls)
    _check_sender(report, sender, has_content=bool(subject or body or raw))
    _check_body(report, subject, body)

    score = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in report.findings)
    report.score = max(0, min(100, score))

    if report.score >= 60:
        report.verdict = "likely_phishing"
    elif report.score >= 30:
        report.verdict = "suspicious"
    else:
        report.verdict = "likely_safe"

    # Findings are shown worst-first for readability.
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    report.findings.sort(key=lambda f: order.get(f.severity, 9))
    return report
