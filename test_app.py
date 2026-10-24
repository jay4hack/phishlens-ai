"""
Unit and integration tests for PhishLens AI.
Tests URL parsing, heuristics, input validation, malformed inputs, and report generation.
"""

import unittest
from security_engine import (
    extract_urls,
    analyze_url_heuristics,
    validate_input,
    format_text_report,
    MAX_TEXT_LENGTH,
    MAX_IMAGE_SIZE_BYTES
)


class TestPhishLensAI(unittest.TestCase):

    # -------------------------------------------------------------
    # 1. URL Extraction Tests
    # -------------------------------------------------------------
    def test_extract_urls_single_and_multiple(self):
        text = "Check this link https://example.com/test and also http://192.168.1.1/admin."
        urls = extract_urls(text)
        self.assertIn("https://example.com/test", urls)
        self.assertIn("http://192.168.1.1/admin", urls)
        self.assertEqual(len(urls), 2)

    def test_extract_urls_punctuation_trimming(self):
        # Trailing period, comma, or exclamation should be cleanly stripped
        text = "Visit http://secure-portal.com/login! Or maybe https://test.org/path."
        urls = extract_urls(text)
        self.assertEqual(urls, ["http://secure-portal.com/login", "https://test.org/path"])

    def test_extract_urls_empty_and_none(self):
        self.assertEqual(extract_urls(""), [])
        self.assertEqual(extract_urls(None), [])
        self.assertEqual(extract_urls("No links here in this regular email text."), [])

    # -------------------------------------------------------------
    # 2. URL Heuristics & Pattern Detection Tests
    # -------------------------------------------------------------
    def test_ip_address_host_detection(self):
        result = analyze_url_heuristics("http://192.168.0.1/paypal/login")
        self.assertTrue(result["is_suspicious"])
        findings_str = " ".join(result["findings"])
        self.assertIn("Direct IP Host", findings_str)
        self.assertIn("Insecure Protocol", findings_str)

    def test_subdomain_stacking(self):
        result = analyze_url_heuristics("https://login.verify.account.update.fakebank.com/secure")
        self.assertTrue(result["is_suspicious"])
        findings_str = " ".join(result["findings"])
        self.assertIn("Excessive Subdomains", findings_str)

    def test_authority_delimiter_spoofing(self):
        result = analyze_url_heuristics("https://google.com@attacker-controlled-site.com/auth")
        self.assertTrue(result["is_suspicious"])
        findings_str = " ".join(result["findings"])
        self.assertIn("Deceptive Delimiter", findings_str)

    def test_suspicious_generic_tld(self):
        result = analyze_url_heuristics("https://account-security-notice.xyz/signin")
        self.assertTrue(result["is_suspicious"])
        findings_str = " ".join(result["findings"])
        self.assertIn("Suspicious TLD", findings_str)

    def test_misleading_brand_in_subdomain(self):
        result = analyze_url_heuristics("https://paypal.com.account-verification-node.net/webapps/login")
        self.assertTrue(result["is_suspicious"])
        findings_str = " ".join(result["findings"])
        self.assertIn("Brand Keyword in Subdomain", findings_str)

    def test_legitimate_clean_url(self):
        result = analyze_url_heuristics("https://www.google.com/search?q=cybersecurity")
        # Standard HTTPS with standard brand root domain should not raise suspicious flag
        self.assertFalse(result["is_suspicious"])
        self.assertEqual(result["findings"], [])

    def test_malformed_url_handling(self):
        # Extremely distorted URL strings should not crash the function
        result = analyze_url_heuristics("http://")
        self.assertIsInstance(result, dict)
        self.assertIn("findings", result)

    # -------------------------------------------------------------
    # 3. Input Validation & Size Limit Tests
    # -------------------------------------------------------------
    def test_validate_input_empty(self):
        val = validate_input("", None)
        self.assertFalse(val["is_valid"])
        self.assertIn("No content provided", val["errors"][0])

    def test_validate_input_valid_text(self):
        val = validate_input("Hello, please inspect this email.", None)
        self.assertTrue(val["is_valid"])
        self.assertEqual(val["errors"], [])

    def test_validate_input_text_too_long(self):
        huge_text = "A" * (MAX_TEXT_LENGTH + 500)
        val = validate_input(huge_text, None)
        self.assertFalse(val["is_valid"])
        self.assertTrue(any("exceeds maximum limit" in err for err in val["errors"]))

    def test_validate_input_image_oversized(self):
        oversized_bytes = b"0" * (MAX_IMAGE_SIZE_BYTES + 1024)
        val = validate_input(None, image_bytes=oversized_bytes, mime_type="image/png")
        self.assertFalse(val["is_valid"])
        self.assertTrue(any("5MB file-size limit" in err for err in val["errors"]))

    def test_validate_input_image_invalid_type(self):
        valid_bytes = b"sample_bytes"
        val = validate_input(None, image_bytes=valid_bytes, mime_type="application/pdf")
        self.assertFalse(val["is_valid"])
        self.assertTrue(any("Unsupported image type" in err for err in val["errors"]))

    # -------------------------------------------------------------
    # 4. Structured Report Generation Tests
    # -------------------------------------------------------------
    def test_format_text_report_structure(self):
        report = format_text_report(
            timestamp="2026-10-24 12:00:00",
            model="gemma-4-26b-a4b-it",
            risk_level="HIGH",
            summary="Suspicious credential harvesting lure detected.",
            warning_signs=["Direct IP host used", "Urgency language detected"],
            recommended_actions=["Do not enter credentials", "Report to security team"],
            technical_indicators=["IP 192.168.1.1 in URL", "Keywords: 'verify', 'account'"],
            url_findings=[{"url": "http://192.168.1.1/login", "findings": ["Direct IP Host"]}],
            input_preview="URGENT: Verify your account immediately."
        )
        # Verify key mandatory sections are present
        self.assertIn("PHISHLENS AI — CYBERSECURITY TRIAGE REPORT", report)
        self.assertIn("RISK ASSESSMENT:", report)
        self.assertIn("HIGH", report)
        self.assertIn("EVIDENCE & WARNING SIGNS:", report)
        self.assertIn("Direct IP host used", report)
        self.assertIn("RECOMMENDED DEFENSIVE ACTIONS:", report)
        self.assertIn("LIMITATIONS & TRANSPARENCY NOTICE:", report)
    # -------------------------------------------------------------
    # 5. Retry Logic & Transient 503/500 Error Detection Tests
    # -------------------------------------------------------------
    def test_transient_error_detection(self):
        from app import is_transient_error
        from unittest.mock import MagicMock

        # Simulated 503 error object
        err_503 = Exception("503 UNAVAILABLE: The model is currently experiencing high demand. Please try again later.")
        self.assertTrue(is_transient_error(err_503))

        # Simulated 500 internal server error
        err_500 = Exception("500 Internal Server Error encountered")
        self.assertTrue(is_transient_error(err_500))

        # Object with code attribute
        mock_err = MagicMock()
        mock_err.code = 503
        self.assertTrue(is_transient_error(mock_err))

        # Client-side 400 or 404 should NOT be flagged as transient retryable
        err_404 = Exception("404 NotFound: Model 'invalid-model' was not found")
        self.assertFalse(is_transient_error(err_404))

    def test_query_gemma_retry_exhaustion_message(self):
        from app import query_gemma_model
        from unittest.mock import patch, MagicMock

        # Mock client to raise 503 UNAVAILABLE every time
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = Exception("503 UNAVAILABLE: The model is overloaded")

        with patch("google.genai.Client", return_value=mock_client):
            status_updates = []
            res = query_gemma_model(
                api_key="mock_key",
                model_name="gemma-4-26b-a4b-it",
                text_input="Sample text",
                max_retries=2,
                initial_delay=0.01,
                status_callback=lambda msg: status_updates.append(msg)
            )
            # Ensure retries happened and status callbacks fired
            self.assertEqual(len(status_updates), 2)
            self.assertIn("error", res)
            self.assertIn("503", res["error"])
            self.assertIn("temporarily unavailable", res["error"])


if __name__ == "__main__":
    unittest.main()
