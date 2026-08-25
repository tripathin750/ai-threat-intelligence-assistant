import unittest

from backend.fetch_kev import KevValidationError, normalize_kev_entry


def _raw_entry(**overrides: object) -> dict:
    defaults: dict[str, object] = {
        "cveID": "cve-2026-21962",
        "vendorProject": "Oracle",
        "product": "HTTP Server",
        "vulnerabilityName": "Oracle HTTP Server Improper Access Control Vulnerability",
        "dateAdded": "2026-08-24",
        "shortDescription": "An improper access control vulnerability.",
        "requiredAction": "Apply mitigations per vendor instructions.",
        "dueDate": "2026-08-27",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "https://example.com/advisory",
    }
    defaults.update(overrides)
    return defaults


class NormalizeKevEntryTests(unittest.TestCase):
    def test_normalizes_a_valid_entry(self) -> None:
        record = normalize_kev_entry(_raw_entry())

        self.assertEqual(record["cve_id"], "CVE-2026-21962")
        self.assertEqual(record["vendor_project"], "Oracle")
        self.assertEqual(record["known_ransomware_use"], "Unknown")
        self.assertEqual(record["date_added"].isoformat(), "2026-08-24")
        self.assertEqual(record["due_date"].isoformat(), "2026-08-27")

    def test_missing_notes_is_normalized_to_none(self) -> None:
        raw = _raw_entry()
        del raw["notes"]
        record = normalize_kev_entry(raw)
        self.assertIsNone(record["notes"])

    def test_invalid_cve_id_is_rejected(self) -> None:
        with self.assertRaises(KevValidationError):
            normalize_kev_entry(_raw_entry(cveID="not-a-cve"))

    def test_invalid_ransomware_value_is_rejected(self) -> None:
        # CISA's own feed only ever emits "Known" or "Unknown" - anything
        # else signals an upstream format change that must not be
        # silently miscategorized.
        with self.assertRaises(KevValidationError):
            normalize_kev_entry(_raw_entry(knownRansomwareCampaignUse="Maybe"))

    def test_missing_required_field_is_rejected(self) -> None:
        raw = _raw_entry()
        del raw["dueDate"]
        with self.assertRaises(KevValidationError):
            normalize_kev_entry(raw)

    def test_non_object_entry_is_rejected(self) -> None:
        with self.assertRaises(KevValidationError):
            normalize_kev_entry("not a dict")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
