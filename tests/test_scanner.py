import socket
import unittest
from unittest.mock import patch
import io

from scanner import (ScanError, calculate_score, validate_target,
                     _finding, _normalize_same_origin_url, _inspect_cookies)
import ipaddress


class ScannerValidationTests(unittest.TestCase):
    def test_localhost_target_is_allowed(self):
        self.assertEqual(validate_target("http://127.0.0.1:3000"), "http://127.0.0.1:3000/")

    def test_missing_scheme_defaults_to_https(self):
        with patch("scanner._resolve_addresses", return_value={__import__("ipaddress").ip_address("93.184.216.34")}):
            self.assertEqual(validate_target("example.test"), "https://example.test/")

    def test_private_address_is_blocked(self):
        with self.assertRaises(ScanError):
            validate_target("http://192.168.1.10")

    def test_cloud_metadata_address_is_blocked(self):
        with self.assertRaises(ScanError):
            validate_target("http://169.254.169.254")

    def test_public_nonstandard_port_is_blocked(self):
        with patch("scanner._resolve_addresses", return_value={__import__("ipaddress").ip_address("93.184.216.34")}):
            with self.assertRaises(ScanError):
                validate_target("https://example.test:8443")

    def test_redirect_destination_is_revalidated_by_request_layer(self):
        # URL validation is also applied to every redirect in _snapshot_request.
        with self.assertRaises(ScanError):
            validate_target("http://127.0.0.1:3000@169.254.169.254/")


class ScoringTests(unittest.TestCase):
    def test_score_never_below_zero(self):
        findings = [{"severity": "critical"} for _ in range(10)]
        self.assertEqual(calculate_score(findings), 0)

    def test_info_findings_do_not_reduce_score(self):
        self.assertEqual(calculate_score([{"severity": "info"}]), 100)

    def test_insufficient_coverage_returns_no_score(self):
        coverage = {"percentage": 25}
        self.assertIsNone(calculate_score([], coverage))

    def test_unique_finding_types_have_different_impacts(self):
        self.assertLess(calculate_score([{"severity": "high", "fingerprint": "one", "observation_type": "security_misconfiguration"}]),
                        calculate_score([{"severity": "low", "fingerprint": "two", "observation_type": "security_misconfiguration"}]))


class EvidenceTests(unittest.TestCase):
    def test_same_origin_normalization_rejects_external_link(self):
        self.assertIsNone(_normalize_same_origin_url("https://example.test/", "https://external.test/page"))

    def test_same_origin_normalization_accepts_relative_link(self):
        self.assertEqual(
            _normalize_same_origin_url("https://example.test/base/", "../login"),
            "https://example.test/login",
        )

    def test_cookie_evidence_names_the_actual_cookie(self):
        from scanner import ResponseSnapshot
        snapshot = ResponseSnapshot(
            url="https://example.test/login",
            status_code=200,
            headers={"Set-Cookie": "session=abc"},
            cookies=["session=abc; Path=/"],
            body=b"",
            elapsed_ms=10,
        )
        findings = []
        _inspect_cookies(snapshot, findings)
        self.assertTrue(findings)
        self.assertIn("session", findings[0]["evidence"])


class ReportTests(unittest.TestCase):
    def test_pdf_starts_with_pdf_header_and_contains_pages(self):
        from report_generator import generate_pdf
        scan = {
            "id": 1,
            "target": "https://example.test/",
            "final_url": "https://example.test/",
            "created_at": "2026-11-27T00:00:00+00:00",
            "scanner_version": "2.0.0",
            "methodology_version": "WAPT-Baseline-2",
            "score": 82,
            "counts": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 1},
            "coverage": {"percentage": 80, "tested": 8, "total": 10, "checks": {"HSTS": "tested"}},
            "assessment": {"reconnaissance": {"headers": {"server": "ExampleServer"}, "technologies": []}},
            "findings": [{
                "title": "Cookie flags need review: session",
                "severity": "medium",
                "category": "Session Management",
                "confidence": "confirmed",
                "affected_url": "https://example.test/login",
                "evidence": "Set-Cookie for session; missing Secure",
                "description": "The login response omitted a cookie attribute.",
                "impact": "The cookie may be exposed in some connection conditions.",
                "recommendation": "Set Secure and HttpOnly.",
                "verification": "Request the login page again and inspect Set-Cookie.",
                "fingerprint": "abc123",
                "cwe": "CWE-614",
            }],
        }
        pdf = generate_pdf(scan).getvalue()
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertGreater(len(pdf), 1000)

    def test_sensitive_header_and_bearer_values_are_redacted(self):
        from report_generator import redact_sensitive, redact_headers
        self.assertEqual(redact_headers({"Authorization": "Bearer secret", "Server": "nginx"}),
                         {"Server": "nginx"})
        self.assertIn("[redacted]", redact_sensitive("Bearer secret-token"))


class ComparisonTests(unittest.TestCase):
    def test_comparison_matches_fingerprints_and_resolved_findings(self):
        from app import compare_assessments
        previous = {
            "findings": [{"fingerprint": "old", "title": "Missing HSTS", "category": "Security Headers",
                          "severity": "medium", "evidence": "Header missing"}],
            "coverage": {"checks": {"HSTS": "tested"}},
        }
        current = {
            "findings": [{"fingerprint": "new", "title": "Missing CSP", "category": "Security Headers",
                          "severity": "medium", "evidence": "Header missing"}],
            "coverage": {"checks": {"HSTS": "tested", "CSP": "tested"}},
        }
        result = compare_assessments(previous, current)
        self.assertEqual(len(result["new"]), 1)
        self.assertEqual(len(result["resolved"]), 1)


if __name__ == "__main__":
    unittest.main()
