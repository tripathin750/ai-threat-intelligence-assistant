import unittest
from datetime import datetime

from pydantic import ValidationError

from backend.schemas import SyncResultSchema, VulnerabilitySchema


class VulnerabilitySchemaTests(unittest.TestCase):
    def test_validates_and_normalizes_a_vulnerability(self) -> None:
        vulnerability = VulnerabilitySchema(
            cve_id="cve-2026-12345",
            description="  Remote code execution  ",
            cvss_score=9.8,
            severity="critical",
            cwe_id="cwe-79",
            published_date="2026-08-20T12:00:00Z",
        )

        self.assertEqual(vulnerability.cve_id, "CVE-2026-12345")
        self.assertEqual(vulnerability.description, "Remote code execution")
        self.assertEqual(vulnerability.severity, "CRITICAL")
        self.assertEqual(vulnerability.cwe_id, "CWE-79")
        self.assertIsInstance(vulnerability.published_date, datetime)

    def test_rejects_an_invalid_cvss_value(self) -> None:
        with self.assertRaises(ValidationError):
            VulnerabilitySchema(
                cve_id="CVE-2026-12345",
                description="Example",
                cvss_score="hello",
            )

    def test_rejects_unexpected_fields_and_invalid_severity(self) -> None:
        with self.assertRaises(ValidationError):
            VulnerabilitySchema(
                cve_id="CVE-2026-12345",
                description="Example",
                severity="URGENT",
                internal_note="must never be exposed",
            )

    def test_validates_sync_response_counts(self) -> None:
        result = SyncResultSchema(
            fetched=5, validated=4, skipped=1, created=2, updated=2
        )
        self.assertEqual(result.validated, 4)


if __name__ == "__main__":
    unittest.main()
