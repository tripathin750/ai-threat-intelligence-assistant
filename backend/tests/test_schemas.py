import unittest
from datetime import datetime

from pydantic import ValidationError

from backend.schemas import (
    KevEntrySchema,
    SyncResultSchema,
    VulnerabilitySchema,
    VulnerabilityWithKevSchema,
)


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


class KevEntrySchemaTests(unittest.TestCase):
    def _kev_kwargs(self, **overrides: object) -> dict:
        defaults: dict[str, object] = {
            "cve_id": "cve-2026-70001",
            "vendor_project": "ExampleCorp",
            "product": "Example Product",
            "vulnerability_name": "Example Vulnerability",
            "date_added": "2026-08-01",
            "short_description": "An example vulnerability.",
            "required_action": "Apply the vendor patch.",
            "due_date": "2026-08-22",
            "known_ransomware_use": "Unknown",
        }
        defaults.update(overrides)
        return defaults

    def test_validates_and_normalizes_a_kev_entry(self) -> None:
        entry = KevEntrySchema(**self._kev_kwargs())
        self.assertEqual(entry.cve_id, "CVE-2026-70001")

    def test_rejects_a_ransomware_value_outside_the_known_enum(self) -> None:
        with self.assertRaises(ValidationError):
            KevEntrySchema(**self._kev_kwargs(known_ransomware_use="Maybe"))


class VulnerabilityWithKevSchemaTests(unittest.TestCase):
    def test_kev_is_optional_and_defaults_to_none(self) -> None:
        vulnerability = VulnerabilityWithKevSchema(cve_id="CVE-2026-12345", description="Example")
        self.assertIsNone(vulnerability.kev)

    def test_accepts_a_nested_kev_entry(self) -> None:
        vulnerability = VulnerabilityWithKevSchema(
            cve_id="CVE-2026-12345",
            description="Example",
            kev={
                "cve_id": "CVE-2026-12345",
                "vendor_project": "ExampleCorp",
                "product": "Example Product",
                "vulnerability_name": "Example Vulnerability",
                "date_added": "2026-08-01",
                "short_description": "An example vulnerability.",
                "required_action": "Apply the vendor patch.",
                "due_date": "2026-08-22",
                "known_ransomware_use": "Known",
            },
        )
        self.assertIsNotNone(vulnerability.kev)
        self.assertEqual(vulnerability.kev.known_ransomware_use, "Known")


if __name__ == "__main__":
    unittest.main()
