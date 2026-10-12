"""Unit tests for the PhishGuard analyzer.

Run:  python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import analyze  # noqa: E402


PHISH_SUBJECT = "Urgent: your account will be suspended within 24 hours"
PHISH_SENDER = "Apple Support <verify@app1e-id-secure.com>"
PHISH_BODY = (
    "Dear Customer,\n\n"
    "We detected unusual activity on your account. You must act now to avoid "
    "permanent suspension. Please verify your identity and confirm your password "
    "within 24 hours:\n\n"
    "http://192.168.1.55/secure/login.php\n\n"
    "Provide your credit card details or your account will be terminated immediately.\n"
)

SAFE_SUBJECT = "Lunch plans for tomorrow?"
SAFE_SENDER = "Sam <sam@example.com>"
SAFE_BODY = "Hey, want to grab lunch around noon? Let me know what works for you."


class TestPhishDetection(unittest.TestCase):
    def test_obvious_phish_flagged(self):
        r = analyze(subject=PHISH_SUBJECT, body=PHISH_BODY, sender=PHISH_SENDER)
        self.assertEqual(r.verdict, "likely_phishing")
        self.assertGreaterEqual(r.score, 60)

    def test_safe_email_passes(self):
        r = analyze(subject=SAFE_SUBJECT, body=SAFE_BODY, sender=SAFE_SENDER)
        self.assertEqual(r.verdict, "likely_safe")
        self.assertLess(r.score, 30)

    def test_raw_ip_url_detected(self):
        r = analyze(body="Click http://192.168.1.55/login to verify")
        titles = [f.title for f in r.findings]
        self.assertTrue(any("raw IP" in t for t in titles))

    def test_lookalike_sender_detected(self):
        r = analyze(sender="PayPal <support@paypa1.com>", body="hello")
        titles = [f.title for f in r.findings]
        self.assertTrue(any("lookalike" in t.lower() for t in titles))

    def test_brand_mismatch_detected(self):
        r = analyze(sender="Netflix <billing@randomhost.net>", body="hi")
        titles = [f.title for f in r.findings]
        self.assertTrue(any("mismatch" in t.lower() for t in titles))

    def test_urgency_and_credential_language(self):
        r = analyze(subject="act now", body="verify your password immediately")
        titles = [f.title for f in r.findings]
        self.assertTrue(any("Urgency" in t for t in titles))

    def test_score_is_bounded(self):
        r = analyze(subject=PHISH_SUBJECT, body=PHISH_BODY * 5, sender=PHISH_SENDER, raw=PHISH_BODY)
        self.assertGreaterEqual(r.score, 0)
        self.assertLessEqual(r.score, 100)

    def test_finding_counts_consistent(self):
        r = analyze(subject=PHISH_SUBJECT, body=PHISH_BODY, sender=PHISH_SENDER)
        counts = r.counts
        self.assertEqual(sum(counts.values()), len(r.findings))

    def test_report_serializes(self):
        r = analyze(subject=PHISH_SUBJECT, body=PHISH_BODY, sender=PHISH_SENDER)
        d = r.as_dict()
        for key in ("score", "verdict", "counts", "findings", "urls"):
            self.assertIn(key, d)

    def test_empty_input_is_safe(self):
        r = analyze()
        self.assertEqual(r.findings, [])
        self.assertEqual(r.score, 0)
        self.assertEqual(r.verdict, "likely_safe")


if __name__ == "__main__":
    unittest.main()
