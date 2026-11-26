import socket
import unittest
from unittest.mock import patch

from scanner import ScanError, calculate_score, validate_target


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


if __name__ == "__main__":
    unittest.main()
