"""Tests for the /analyze route, including the email-file upload path."""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app  # noqa: E402


class AnalyzeRouteTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        app.config["TESTING"] = True

    def test_healthz(self):
        r = self.client.get("/healthz")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "ok")

    def test_index_renders(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"PhishGuard", r.data)

    def test_analyze_json(self):
        r = self.client.post("/analyze", json={
            "sender": "Apple Support <verify@app1e-id-secure.com>",
            "subject": "Urgent: your account will be suspended",
            "body": "Verify your password now http://192.168.1.55/login",
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["verdict"], "likely_phishing")
        self.assertGreaterEqual(data["score"], 60)

    def test_analyze_empty_is_400(self):
        r = self.client.post("/analyze", json={})
        self.assertEqual(r.status_code, 400)

    def test_analyze_form_post(self):
        r = self.client.post("/analyze", data={
            "subject": "hi", "body": "quick question about lunch",
        })
        self.assertEqual(r.status_code, 200)

    def test_raw_email_string_parses_headers(self):
        raw = (
            "From: PayPal <support@paypa1.com>\r\n"
            "Subject: Urgent verify your account\r\n\r\n"
            "Click http://192.168.1.55/login to avoid suspension\r\n"
        )
        r = self.client.post("/analyze", data={"raw": raw})
        self.assertEqual(r.status_code, 200)

    def test_uploaded_eml_file(self):
        eml = io.BytesIO(
            b"From: Apple Support <verify@app1e-id-secure.com>\r\n"
            b"Subject: Urgent: account will be suspended\r\n\r\n"
            b"Verify your password http://192.168.1.55/login or else\r\n"
        )
        r = self.client.post(
            "/analyze",
            data={"raw_file": (eml, "sample.eml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"verdict-", r.data)  # report rendered

    def test_oversized_rejected(self):
        big = "A" * 50001
        r = self.client.post("/analyze", json={"body": big})
        self.assertEqual(r.status_code, 413)


if __name__ == "__main__":
    unittest.main()
