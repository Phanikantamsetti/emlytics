import unittest
import os
from unittest.mock import patch

from app import PdfReader, analyze_email, analyze_input, web_app


class AnalyzeEmailTests(unittest.TestCase):
    def test_extracts_authentication_and_sender_metadata(self):
        result = analyze_email(
            "From: Security <alerts@example.com>\n"
            "To: analyst@example.net\n"
            "Cc: team@example.net\n"
            "Subject: Account notice\n"
            "Date: Mon, 02 Nov 2026 10:00:00 +0000\n"
            "Return-Path: <bounce@example.com>\n"
            "Message-ID: <message-123@example.com>\n"
            "Received: from sender.example by mx.example\n"
            "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n\n"
            "Review your account."
        )
        self.assertEqual(result["sender_domain"], "example.com")
        self.assertEqual(result["authentication"], {"spf": "pass", "dkim": "pass", "dmarc": "pass"})
        self.assertEqual(result["to"], "analyst@example.net")
        self.assertEqual(result["cc"], "team@example.net")
        self.assertEqual(result["date"], "Mon, 02 Nov 2026 10:00:00 +0000")
        self.assertEqual(result["return_path"], "<bounce@example.com>")
        self.assertEqual(result["message_id"], "<message-123@example.com>")
        self.assertEqual(result["received_hops"], ["from sender.example by mx.example"])
        self.assertEqual(result["received_hops_total"], 1)
        self.assertEqual(result["risk_score"], 0)

    def test_public_wsgi_api_analyzes_email_and_sets_security_headers(self):
        response = web_app.test_client().post(
            "/api/analyze",
            json={"email": "From: sender@example.test\n\nSample message."},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["sender_domain"], "example.test")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_public_demo_mode_is_explicitly_configured(self):
        with patch.dict(os.environ, {"EMLYTICS_PUBLIC_DEMO": "1"}):
            response = web_app.test_client().get("/api/config")
        self.assertEqual(response.json, {"public_demo": True})

    def test_public_analysis_discloses_hosted_processing(self):
        with patch.dict(os.environ, {"EMLYTICS_PUBLIC_DEMO": "1"}):
            result = analyze_input("domain", "example.test")
        self.assertIn("hosted server", result["body_summary"])

    def test_flags_reply_to_mismatch_and_failed_authentication(self):
        result = analyze_email(
            "From: help@bank.example\n"
            "Reply-To: collect@attacker.example\n"
            "Authentication-Results: mx.example; spf=fail; dkim=pass; dmarc=fail\n\n"
            "Please respond."
        )
        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("From and Reply-To domains differ", titles)
        self.assertIn("SPF reported fail", titles)
        self.assertIn("DMARC reported fail", titles)
        self.assertEqual(result["risk_level"], "high")

    def test_flags_cautious_sender_header_mismatches(self):
        result = analyze_email(
            'From: "Accounts secure.bank.example" <alerts@external.example>\n'
            "Return-Path: <bounce@mailer.example>\n"
            "Received: from sender.example by mx.example\n"
            "Received: from relay.example by mx.example\n\n"
            "Please review this message."
        )
        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("From and Return-Path domains differ", titles)
        self.assertIn("Display name claims a different domain", titles)
        self.assertIn("Repeated Received relay", titles)
        self.assertEqual(result["classification"]["phishing_score"], 15)
        self.assertEqual(result["classification"]["category"], "suspicious")
        self.assertTrue(all(finding["severity"] == "low" for finding in result["findings"]))

    def test_matching_sender_and_return_path_do_not_raise_header_mismatch(self):
        result = analyze_email(
            'From: "Example Support" <support@example.com>\n'
            "Return-Path: <bounce@example.com>\n"
            "Received: from relay.example by mx2.example\n"
            "Received: from sender.example by mx1.example\n\n"
            "Hello."
        )
        titles = {finding["title"] for finding in result["findings"]}
        self.assertNotIn("From and Return-Path domains differ", titles)
        self.assertNotIn("Display name claims a different domain", titles)
        self.assertNotIn("Repeated Received relay", titles)
        self.assertEqual(result["classification"]["phishing_score"], 0)

    def test_detects_suspicious_links_without_fetching_them(self):
        result = analyze_email(
            "From: sender@example.com\nSubject: Look here\nContent-Type: text/html; charset=utf-8\n\n"
            "<a href=\"http://192.0.2.10/login\">Sign in</a>"
        )
        self.assertEqual(len(result["links"]), 1)
        self.assertTrue(result["links"][0]["suspicious"])
        self.assertTrue(any("IP address" in item["title"] for item in result["findings"]))
        self.assertTrue(any("Unencrypted" in item["title"] for item in result["findings"]))

    def test_identifies_risky_attachment_by_name_without_opening(self):
        result = analyze_email(
            "From: sender@example.com\nSubject: Files\nMIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=part\n\n"
            "--part\nContent-Type: text/plain\n\nSee file.\n"
            "--part\nContent-Type: application/octet-stream\n"
            "Content-Disposition: attachment; filename=invoice.pdf.exe\n\nignored bytes\n"
            "--part--\n"
        )
        self.assertEqual(result["attachments"][0]["name"], "invoice.pdf.exe")
        self.assertTrue(result["attachments"][0]["risky"])
        self.assertTrue(any("risky attachment" in item["title"].lower() for item in result["findings"]))

    def test_summarizes_body_and_explains_phishing_classification(self):
        result = analyze_email(
            "From: help@bank.example\n"
            "Reply-To: collect@attacker.example\n"
            "Subject: Account notice\n"
            "Authentication-Results: mx.example; spf=fail; dkim=pass; dmarc=fail\n\n"
            "We held your login because unusual activity was found. "
            "Please verify your password immediately using the secure portal. "
            "Your reference number is 42."
        )
        self.assertIn("verify your password", result["body_summary"])
        self.assertEqual(result["classification"]["category"], "phishing")
        evidence_titles = {item["title"] for item in result["classification"]["evidence"]}
        self.assertIn("Sender and reply domains differ", evidence_titles)
        self.assertIn("Sensitive account action requested", evidence_titles)
        self.assertGreaterEqual(result["classification"]["phishing_score"], 30)

    def test_classifies_bulk_promotional_mail_with_supporting_cues(self):
        result = analyze_email(
            "From: deals@shop.example\n"
            "Subject: Special offer\n"
            "List-Unsubscribe: <mailto:leave@shop.example>\n"
            "Precedence: bulk\n\n"
            "Limited-time offer: enjoy a discount. Buy now!"
        )
        self.assertEqual(result["classification"]["category"], "spam")
        evidence_titles = {item["title"] for item in result["classification"]["evidence"]}
        self.assertIn("Bulk-mail unsubscribe header", evidence_titles)
        self.assertIn("Promotional wording", evidence_titles)

    def test_rejects_message_over_size_limit(self):
        with self.assertRaisesRegex(ValueError, "1 MB"):
            analyze_email("x" * 1_000_001)

    def test_analyzes_url_without_visiting_it(self):
        result = analyze_input("url", "http://192.0.2.10/login")
        self.assertEqual(result["document_type"], "url")
        self.assertEqual(result["links"][0]["host"], "192.0.2.10")
        self.assertTrue(any("Unencrypted" in item["title"] for item in result["findings"]))

    def test_analyzes_html_visible_text_and_links_without_scripts(self):
        result = analyze_input("html", "<script>urgent account suspended</script><p>Quarterly project update.</p><a href='https://example.test/info'>Read details</a>")
        self.assertEqual(result["document_type"], "html")
        self.assertIn("Quarterly project update", result["body_summary"])
        self.assertNotIn("urgent", result["body_summary"])
        self.assertEqual(result["links"][0]["host"], "example.test")

    def test_domain_input_checks_syntax_and_punycode_offline(self):
        result = analyze_input("domain", "xn--e1afmkfd.example")
        self.assertEqual(result["document_type"], "domain")
        self.assertEqual(result["classification"]["category"], "suspicious")
        self.assertIn("punycode", result["findings"][0]["title"].lower())
        self.assertIn("No DNS", result["body_summary"])

    def test_rejects_url_as_domain_input(self):
        with self.assertRaisesRegex(ValueError, "hostname only"):
            analyze_input("domain", "https://example.test/path")

    def test_rejects_invalid_or_oversized_pdf(self):
        with self.assertRaisesRegex(ValueError, "does not appear to be a PDF"):
            analyze_input("pdf", pdf_content=b"not a pdf")
        with self.assertRaisesRegex(ValueError, "5 MB"):
            analyze_input("pdf", pdf_content=b"%PDF-" + b"x" * 5_000_000)

    def test_extracts_pdf_text_and_link_annotations(self):
        class Reference:
            def __init__(self, value):
                self.value = value

            def get_object(self):
                return self.value

        class FakePage(dict):
            def extract_text(self):
                return "Please review the invoice and payment details."

        class FakeReader:
            def __init__(self, stream, strict):
                self.is_encrypted = False
                self.pages = [FakePage({"/Annots": [Reference({"/A": Reference({"/URI": "https://example.test/invoice"})})]})]
                self.metadata = type("Metadata", (), {"title": "Invoice sample"})()

        with patch("app.PdfReader", FakeReader):
            result = analyze_input("pdf", pdf_content=b"%PDF-1.4\\n%%EOF")
        self.assertEqual(result["document_type"], "pdf")
        self.assertEqual(result["pdf_metadata"]["pages"], 1)
        self.assertEqual(result["pdf_metadata"]["title"], "Invoice sample")
        self.assertEqual(result["links"][0]["host"], "example.test")
        self.assertIn("invoice", result["body_summary"].lower())

    @unittest.skipIf(PdfReader is not None, "This environment has the optional PDF dependency installed")
    def test_pdf_reports_missing_optional_dependency_cleanly(self):
        with self.assertRaisesRegex(ValueError, "requires pypdf"):
            analyze_input("pdf", pdf_content=b"%PDF-1.4\\n%%EOF")


if __name__ == "__main__":
    unittest.main()
