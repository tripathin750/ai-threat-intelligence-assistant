import unittest

from backend.fetch_cves import VulnerabilityValidationError, normalize_cve


class NormalizeCveTests(unittest.TestCase):
    def test_uses_newest_cvss_version_and_normalizes_values(self) -> None:
        record = normalize_cve(
            {
                "id": "cve-2026-12345",
                "descriptions": [{"lang": "en", "value": "  Example\n vulnerability.  "}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "type": "Primary",
                            "cvssData": {"baseScore": 8.1, "baseSeverity": "high"},
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "type": "Primary",
                            "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"},
                        }
                    ],
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "cwe-79"}]}],
                "published": "2026-08-20T12:00:00.000Z",
                "lastModified": "2026-08-21T12:00:00.000Z",
            }
        )

        self.assertEqual(record["cve_id"], "CVE-2026-12345")
        self.assertEqual(record["description"], "Example vulnerability.")
        self.assertEqual(record["cvss_score"], 8.1)
        self.assertEqual(record["severity"], "HIGH")
        self.assertEqual(record["cwe_id"], "CWE-79")
        self.assertEqual(record["published_date"].tzinfo is not None, True)

    def test_missing_optional_nvd_fields_are_normalized_safely(self) -> None:
        record = normalize_cve({"id": "CVE-2026-12346"})

        self.assertEqual(record["description"], "No description available.")
        self.assertIsNone(record["cvss_score"])
        self.assertIsNone(record["severity"])
        self.assertIsNone(record["cwe_id"])

    def test_invalid_cve_id_is_rejected(self) -> None:
        with self.assertRaises(VulnerabilityValidationError):
            normalize_cve({"id": "not-a-cve"})

    def test_malformed_optional_fields_do_not_crash_normalization(self) -> None:
        record = normalize_cve(
            {
                "id": "CVE-2026-12348",
                "descriptions": "not a list",
                "metrics": "not an object",
                "weaknesses": ["not an object"],
                "published": "not a date",
            }
        )

        self.assertEqual(record["description"], "No description available.")
        self.assertIsNone(record["cvss_score"])
        self.assertIsNone(record["cwe_id"])
        self.assertIsNone(record["published_date"])

    def test_out_of_range_cvss_score_is_rejected(self) -> None:
        with self.assertRaises(VulnerabilityValidationError):
            normalize_cve(
                {
                    "id": "CVE-2026-12347",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 12.5,
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                }
            )


if __name__ == "__main__":
    unittest.main()
