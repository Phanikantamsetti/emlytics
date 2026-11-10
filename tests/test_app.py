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
        with patch.dict(os.environ, {"EMLYTICS_PUBLIC_DEMO": "1"}, clear=True):
            response = web_app.test_client().get("/api/config")
        self.assertEqual(response.json, {
            "public_demo": True,
            "external_lookups_enabled": False,
            "providers": {"virustotal": False, "urlscan": False},
            "accounts_enabled": False,
            "ai_enabled": False,
        })

    def test_external_provider_configuration_is_reported_independently(self):
        with patch.dict(os.environ, {"EMLYTICS_VIRUSTOTAL_API_KEY": "secret"}, clear=True):
            response = web_app.test_client().get("/api/config")
        self.assertEqual(response.json["providers"], {"virustotal": True, "urlscan": False})
        self.assertNotIn("secret", response.get_data(as_text=True))

    def test_external_lookup_works_with_just_one_provider_key(self):
        def fake_provider_json(url, headers, payload=None):
            self.assertIn("virustotal.com", url)
            return {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 4, "undetected": 2},
            }}}

        with patch.dict(os.environ, {"EMLYTICS_VIRUSTOTAL_API_KEY": "test-key"}, clear=True), \
                patch("app._provider_json", side_effect=fake_provider_json):
            response = web_app.test_client().post(
                "/api/analyze-input",
                json={"kind": "url", "value": "https://example.test", "external_lookup": True},
            )
        self.assertEqual(response.status_code, 200)
        lookup = response.json["external_intelligence"][0]
        self.assertEqual(lookup["virustotal"]["status"], "found")
        self.assertEqual(lookup["urlscan"]["existing"]["status"], "not_configured")

    def test_domain_posture_is_only_requested_with_domain_scan_opt_in(self):
        with patch("app.scan_domain_posture", return_value={"status": "ok", "posture_score": 90}) as scan:
            response = web_app.test_client().post(
                "/api/analyze-input",
                json={"kind": "domain", "value": "example.test", "domain_scan": True},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["domain_posture"]["posture_score"], 90)
        scan.assert_called_once_with("example.test")

    def test_domain_posture_rejects_non_domain_inputs(self):
        response = web_app.test_client().post(
            "/api/analyze-input",
            json={"kind": "url", "value": "https://example.test", "domain_scan": True},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("only for domain input", response.json["error"])

    def test_domain_report_groups_evidence_and_explains_unchecked_threat_data(self):
        from app import _domain_report_categories

        categories = _domain_report_categories({
            "dns": {"status": "resolved", "addresses": ["203.0.113.7"], "records": {"NS": {"status": "found", "records": ["ns.example"]}}},
            "rdap": {"status": "found", "registered": "2020-01-01T00:00:00Z"},
            "https": {"status": "ok", "certificate": {"days_remaining": 200}, "security_headers": {}},
        })
        self.assertEqual([item["name"] for item in categories], [
            "Infrastructure", "Website security", "Email security", "Threat intelligence", "Domain trust",
        ])
        self.assertEqual(categories[3]["coverage"], "Not checked")
        self.assertIsNone(categories[3]["score"])
        self.assertTrue(any("not evidence of safety" in item.lower() for item in categories[3]["evidence"]))

    def test_url_intelligence_normalizes_and_flags_brand_lookalikes_without_visiting(self):
        response = web_app.test_client().post(
            "/api/url-intelligence",
            json={"url": "HTTPS://micros0ft.com/login?next=1"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["url"], "https://micros0ft.com/login?next=1")
        self.assertIn("microsoft", response.json["possible_brand_lookalikes"])
        self.assertFalse(response.json["visited"])

    def test_url_intelligence_rejects_malformed_port_and_credentials(self):
        client = web_app.test_client()
        invalid_port = client.post("/api/url-intelligence", json={"url": "https://example.com:bad/"})
        credential_url = client.post("/api/url-intelligence", json={"url": "https://user:pass@example.com/"})
        self.assertEqual(invalid_port.status_code, 400)
        self.assertEqual(credential_url.status_code, 400)

    def test_domain_comparison_requires_two_distinct_valid_domains(self):
        client = web_app.test_client()
        invalid = client.post("/api/compare-domains", json={"domains": ["example.com"]})
        same = client.post("/api/compare-domains", json={"domains": ["example.com", "example.com"]})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(same.status_code, 400)

    def test_email_analysis_includes_action_plan_and_extracted_indicators(self):
        result = analyze_email(
            "From: Security <alerts@example.com>\n"
            "Reply-To: verify@other.example\n"
            "Authentication-Results: mx.example; spf=fail; dkim=pass; dmarc=fail\n\n"
            "Verify your password immediately at https://login.example.test/account"
        )
        self.assertIn("recommended_actions", result)
        self.assertTrue(any("trusted channel" in item for item in result["recommended_actions"]))
        self.assertIn({"type": "url", "value": "https://login.example.test/account", "source": "Message link"}, result["indicators_of_compromise"])
        self.assertTrue(any(item["type"] == "domain" for item in result["indicators_of_compromise"]))

    def test_saved_email_report_excludes_raw_body_and_headers(self):
        from app import _saved_report_summary

        summary = _saved_report_summary({
            "document_type": "email",
            "sender_domain": "example.test",
            "subject": "private subject",
            "body_summary": "secret message text",
            "raw_email": "From: private@example.test",
            "risk_score": 30,
            "classification": {"label": "Suspicious — review", "evidence": []},
            "findings": [],
        })
        serialized = str(summary)
        self.assertNotIn("private subject", serialized)
        self.assertNotIn("secret message text", serialized)
        self.assertNotIn("raw_email", serialized)

    def test_saved_report_bounds_scores_from_untrusted_payload(self):
        from app import _saved_report_summary

        summary = _saved_report_summary({
            "document_type": "email",
            "risk_score": "999",
            "classification": {"phishing_score": True, "spam_score": -10},
        })
        self.assertIsNone(summary["score"])
        self.assertIsNone(summary["risk_score"])
        self.assertIsNone(summary["classification"]["phishing_score"])
        self.assertIsNone(summary["classification"]["spam_score"])
        email_summary = _saved_report_summary({
            "document_type": "email",
            "from": "private.sender@example.test",
        })
        self.assertEqual(email_summary["target"], "Unknown")

    def test_signup_sets_httponly_same_site_auth_cookies(self):
        session = {
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "expires_in": 3600,
        }
        with patch.dict(os.environ, {
            "EMLYTICS_SUPABASE_URL": "https://project.supabase.co",
            "EMLYTICS_SUPABASE_ANON_KEY": "public-anon-key",
        }, clear=True), patch("app._auth_request", return_value=session):
            response = web_app.test_client().post(
                "/api/auth/signup",
                json={"email": "analyst@example.test", "password": "long-password"},
            )
        self.assertEqual(response.status_code, 201)
        cookies = response.headers.getlist("Set-Cookie")
        self.assertEqual(len(cookies), 2)
        self.assertTrue(all("HttpOnly" in cookie and "SameSite=Lax" in cookie for cookie in cookies))

    def test_saved_report_route_forwards_session_and_stores_minimized_summary(self):
        client = web_app.test_client()
        client.set_cookie("emlytics_access", "test-access-token", path="/api")
        with patch.dict(os.environ, {
            "EMLYTICS_SUPABASE_URL": "https://project.supabase.co",
            "EMLYTICS_SUPABASE_ANON_KEY": "public-anon-key",
        }, clear=True), patch("app._supabase_request", return_value=[{"id": "saved-id"}]) as save:
            response = client.post("/api/saved-reports", json={
                "report": {
                    "document_type": "email",
                    "sender_domain": "example.test",
                    "body_summary": "private body",
                    "raw_email": "private source",
                    "risk_score": 20,
                },
            })
        self.assertEqual(response.status_code, 201)
        self.assertEqual(save.call_args.args[3], "test-access-token")
        serialized = str(save.call_args.args[2])
        self.assertNotIn("private body", serialized)
        self.assertNotIn("private source", serialized)

    def test_assistant_evidence_excludes_message_body(self):
        from app import _assistant_evidence

        evidence = _assistant_evidence({
            "sender_domain": "example.test",
            "body_summary": "secret message text",
            "raw_email": "private raw source",
            "findings": [{"title": "Suspicious link", "detail": "example.test link"}],
        })
        self.assertNotIn("body_summary", evidence)
        self.assertNotIn("raw_email", evidence)
        self.assertIn("findings", evidence)

    def test_account_endpoints_are_disabled_without_server_configuration(self):
        with patch.dict(os.environ, {}, clear=True):
            response = web_app.test_client().post("/api/auth/login", json={"email": "a@example.test", "password": "long-password"})
        self.assertEqual(response.status_code, 503)

    def test_domain_posture_score_explains_missing_security_headers(self):
        from app import _score_domain_posture

        posture = _score_domain_posture({
            "dns": {"status": "resolved"},
            "rdap": {"status": "found"},
            "https": {
                "status": "ok",
                "certificate": {"days_remaining": 200},
                "security_headers": {
                    "strict-transport-security": {"present": True},
                    "content-security-policy": {"present": False},
                    "x-content-type-options": {"present": False},
                    "x-frame-options": {"present": True},
                    "referrer-policy": {"present": True},
                },
            },
        })
        self.assertEqual(posture["posture_score"], 87)
        self.assertEqual([item["title"] for item in posture["score_factors"]], [
            "Missing content-security-policy",
            "Missing x-content-type-options",
        ])

    def test_domain_posture_parses_quoted_spf_and_scores_dmarc_policy(self):
        from app import _score_domain_posture

        posture = _score_domain_posture({
            "dns": {
                "status": "resolved",
                "records": {
                    "TXT": {"status": "found", "records": ['"v=spf1 include:mail.example -all"'], "dnssec_validated": True},
                    "DMARC": {"status": "found", "records": ['"v=DMARC1; p=none; rua=mailto:reports@example.test"'], "dnssec_validated": True},
                },
            },
            "rdap": {"status": "found"},
            "https": {
                "status": "ok",
                "certificate": {"days_remaining": 200},
                "security_headers": {
                    name: {"present": True}
                    for name in (
                        "strict-transport-security",
                        "content-security-policy",
                        "x-content-type-options",
                        "x-frame-options",
                        "referrer-policy",
                    )
                },
            },
        })

        self.assertEqual(posture["posture_score"], 95)
        self.assertEqual([item["title"] for item in posture["score_factors"]], ["DMARC is monitor-only"])
        self.assertEqual(posture["dnssec"]["status"], "validated")

    def test_domain_posture_flags_missing_and_duplicate_spf(self):
        from app import _score_domain_posture

        base = {
            "dns": {
                "status": "resolved",
                "records": {
                    "TXT": {"status": "none", "records": []},
                    "DMARC": {"status": "none", "records": []},
                },
            },
            "rdap": {"status": "found"},
            "https": {"status": "ok", "certificate": {"days_remaining": 200}, "security_headers": {
                name: {"present": True}
                for name in (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "referrer-policy",
                )
            }},
        }
        missing_spf = _score_domain_posture(base)
        self.assertEqual(
            [item["title"] for item in missing_spf["score_factors"]],
            ["SPF record not found", "DMARC record not found"],
        )

        base["dns"]["records"]["TXT"] = {
            "status": "found",
            "records": ["v=spf1 -all", '"v=spf1 include:mail.example -all"'],
        }
        duplicate_spf = _score_domain_posture(base)
        self.assertIn("Multiple SPF records found", [item["title"] for item in duplicate_spf["score_factors"]])

    def test_domain_scan_does_not_contact_services_when_public_ip_check_fails(self):
        from app import scan_domain_posture

        with patch("app._resolve_public_addresses", side_effect=ValueError("private address")), \
                patch("app._dns_record") as dns_lookup, patch("app._rdap_lookup") as rdap_lookup:
            result = scan_domain_posture("internal.example")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["https"]["status"], "not_checked")
        dns_lookup.assert_not_called()
        rdap_lookup.assert_not_called()

    def test_domain_scan_queries_caa_and_dmarc_records(self):
        from app import scan_domain_posture

        queried = []

        def fake_dns_record(host, record_type):
            queried.append((host, record_type))
            return {"status": "none", "records": [], "dnssec_validated": False}

        with patch("app._resolve_public_addresses", return_value=["8.8.8.8"]), \
                patch("app._dns_record", side_effect=fake_dns_record), \
                patch("app._rdap_lookup", return_value={"status": "not_found"}), \
                patch("app._inspect_public_https", return_value={"status": "ok", "security_headers": {}}):
            result = scan_domain_posture("example.test")

        self.assertIn(("example.test", "CAA"), queried)
        self.assertIn(("_dmarc.example.test", "TXT"), queried)
        self.assertIn("CAA", result["dns"]["records"])
        self.assertIn("DMARC", result["dns"]["records"])

    def test_external_lookup_requires_both_provider_keys(self):
        with patch.dict(os.environ, {}, clear=True):
            response = web_app.test_client().post(
                "/api/analyze-input",
                json={"kind": "url", "value": "https://example.test", "external_lookup": True},
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("at least one provider API key", response.json["error"])

    def test_external_lookup_summarizes_reports_and_submits_only_urls_publicly(self):
        def fake_provider_json(url, headers, payload=None):
            if "virustotal.com" in url:
                return {"data": {"attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 4, "undetected": 3},
                    "last_analysis_results": {
                        "ExampleAV": {"category": "malicious", "result": "Phishing"},
                        "SampleAV": {"category": "suspicious", "result": "Suspicious URL"},
                    },
                    "reputation": -5,
                    "last_analysis_date": 1_700_000_000,
                }}}
            if url.endswith("/api/v1/scan/"):
                return {"uuid": "scan-123", "result": "https://urlscan.io/result/scan-123/", "visibility": "public"}
            return {"total": 1, "results": [{
                "task": {"url": "https://example.test/login", "time": "2026-01-02T03:04:05.000Z"},
                "result": "https://urlscan.io/result/scan-existing/",
                "verdicts": {"overall": {"malicious": True, "score": 100, "categories": ["Phishing"], "brands": ["Example Bank"]}},
            }]}

        with patch.dict(os.environ, {
            "EMLYTICS_VIRUSTOTAL_API_KEY": "test-vt-key",
            "EMLYTICS_URLSCAN_API_KEY": "test-urlscan-key",
        }, clear=True), patch("app._provider_json", side_effect=fake_provider_json):
            response = web_app.test_client().post(
                "/api/analyze",
                json={
                    "email": "From: sender@example.test\n\nVisit https://example.test/login",
                    "external_lookup": True,
                    "urlscan_submit": True,
                },
            )

        self.assertEqual(response.status_code, 200)
        lookups = response.json["external_intelligence"]
        self.assertEqual([item["type"] for item in lookups], ["url", "domain"])
        self.assertEqual(lookups[0]["virustotal"]["malicious"], 2)
        self.assertIn("3 of 10 engines flagged", lookups[0]["virustotal"]["brief"])
        self.assertEqual(lookups[0]["virustotal"]["detections"][0]["engine"], "ExampleAV")
        self.assertIn("1 of 1 returned report", lookups[0]["urlscan"]["existing"]["brief"])
        self.assertIn("Phishing", lookups[0]["urlscan"]["existing"]["brief"])
        self.assertEqual(lookups[0]["urlscan"]["submission"]["visibility"], "public")
        self.assertNotIn("submission", lookups[1]["urlscan"])

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
