"""Tests use an isolated in-memory SQLite database and mocked LLM/NVD calls,
so they run offline and never call a real LLM provider, the real NVD API, or
touch the real dev/prod database.
"""

from datetime import date
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.models import KevEntry, Vulnerability
from backend.services import intelligence_service, triage_service
from backend.services.ai_service import AnalysisResult


def _analysis_result(**overrides: object) -> AnalysisResult:
    defaults: dict[str, object] = {
        "summary": "s", "impact": "i", "affected_component": "a",
        "risk": "HIGH", "confidence": 0.8, "evidence": ["e"],
    }
    defaults.update(overrides)
    return AnalysisResult(**defaults)


def _kev_entry(cve_id: str) -> KevEntry:
    return KevEntry(
        cve_id=cve_id,
        vendor_project="ExampleCorp",
        product="Example Product",
        vulnerability_name="Example Vulnerability",
        date_added=date(2026, 8, 1),
        short_description="An example vulnerability.",
        required_action="Apply the vendor patch.",
        due_date=date(2026, 8, 22),
        known_ransomware_use="Unknown",
    )


class TriageBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()
        self._generate_analysis_patch = patch.object(
            intelligence_service, "generate_analysis", return_value=_analysis_result()
        )
        self._generate_analysis_patch.start()
        # Default to "EPSS has no scores for this batch" so tests that don't
        # care about EPSS ranking stay offline; individual tests override
        # this with their own patch.object(...) to exercise EPSS ordering.
        self._epss_patch = patch.object(triage_service, "fetch_epss_scores", return_value={})
        self._epss_patch.start()

    def tearDown(self) -> None:
        self._epss_patch.stop()
        self._generate_analysis_patch.stop()
        self.db.close()
        self.engine.dispose()

    def test_kev_confirmed_exploitation_outranks_higher_cvss_non_kev(self) -> None:
        self.db.add_all([
            Vulnerability(
                cve_id="CVE-2026-90001", description="A high severity issue.",
                cvss_score=8.1, severity="HIGH", source="NVD",
            ),
            Vulnerability(
                cve_id="CVE-2026-90002", description="A critical severity issue.",
                cvss_score=9.8, severity="CRITICAL", source="NVD",
            ),
            _kev_entry("CVE-2026-90001"),
        ])
        self.db.commit()

        result = triage_service.triage_batch(self.db, ["CVE-2026-90002", "CVE-2026-90001"])

        self.assertEqual([row.cve_id for row in result.rows], ["CVE-2026-90001", "CVE-2026-90002"])
        self.assertEqual(result.rows[0].urgency, "IMMEDIATE")
        self.assertTrue(result.rows[0].kev)
        self.assertEqual(result.rows[1].urgency, "CRITICAL")

    def test_unknown_cve_is_marked_not_found_without_failing_the_rest_of_the_batch(self) -> None:
        self.db.add(Vulnerability(
            cve_id="CVE-2026-90003", description="A known local issue.",
            cvss_score=5.0, severity="MEDIUM", source="NVD",
        ))
        self.db.commit()

        with patch.object(triage_service, "fetch_cve_by_id", return_value=None):
            result = triage_service.triage_batch(self.db, ["CVE-2026-90003", "CVE-2026-90099"])

        self.assertEqual(result.not_found, 1)
        by_id = {row.cve_id: row for row in result.rows}
        self.assertTrue(by_id["CVE-2026-90003"].found)
        self.assertFalse(by_id["CVE-2026-90099"].found)
        self.assertEqual(by_id["CVE-2026-90099"].urgency, "NOT_FOUND")

    def test_malformed_id_is_marked_not_found_without_a_network_call(self) -> None:
        with patch.object(triage_service, "fetch_cve_by_id") as mock_fetch:
            result = triage_service.triage_batch(self.db, ["not-a-cve-id"])

        mock_fetch.assert_not_called()
        self.assertEqual(result.rows[0].found, False)
        self.assertEqual(result.rows[0].note, "Not a valid CVE ID.")

    def test_duplicate_ids_are_deduplicated(self) -> None:
        self.db.add(Vulnerability(
            cve_id="CVE-2026-90004", description="An issue.",
            cvss_score=4.0, severity="MEDIUM", source="NVD",
        ))
        self.db.commit()

        result = triage_service.triage_batch(
            self.db, ["cve-2026-90004", "CVE-2026-90004", " CVE-2026-90004 "]
        )

        self.assertEqual(result.requested, 1)
        self.assertEqual(len(result.rows), 1)

    def test_epss_breaks_ties_within_the_same_urgency_tier(self) -> None:
        self.db.add_all([
            Vulnerability(
                cve_id="CVE-2026-90006", description="A high severity issue, low predicted exploitation.",
                cvss_score=8.5, severity="HIGH", source="NVD",
            ),
            Vulnerability(
                cve_id="CVE-2026-90007", description="A high severity issue, high predicted exploitation.",
                cvss_score=8.1, severity="HIGH", source="NVD",
            ),
        ])
        self.db.commit()
        self._epss_patch.stop()
        with patch.object(
            triage_service, "fetch_epss_scores",
            return_value={"CVE-2026-90006": 0.02, "CVE-2026-90007": 0.87},
        ):
            result = triage_service.triage_batch(self.db, ["CVE-2026-90006", "CVE-2026-90007"])
        self._epss_patch.start()

        # Both rows are the same urgency tier (HIGH) and CVE-2026-90006 has
        # the higher CVSS score, but CVE-2026-90007's far higher predicted
        # exploitation probability must still put it first.
        self.assertEqual([row.cve_id for row in result.rows], ["CVE-2026-90007", "CVE-2026-90006"])

    def test_an_epss_lookup_failure_does_not_fail_the_batch(self) -> None:
        self.db.add(Vulnerability(
            cve_id="CVE-2026-90008", description="An issue.",
            cvss_score=6.0, severity="MEDIUM", source="NVD",
        ))
        self.db.commit()
        self._epss_patch.stop()
        with patch.object(triage_service, "fetch_epss_scores", side_effect=triage_service.EpssRequestError("down")):
            result = triage_service.triage_batch(self.db, ["CVE-2026-90008"])
        self._epss_patch.start()

        self.assertTrue(result.rows[0].found)
        self.assertIsNone(result.rows[0].epss_score)

    def test_batch_is_capped_at_max_batch_size(self) -> None:
        ids = [f"CVE-2026-9{i:04d}" for i in range(triage_service.MAX_BATCH_SIZE + 10)]

        with patch.object(triage_service, "fetch_cve_by_id", return_value=None):
            result = triage_service.triage_batch(self.db, ids)

        self.assertEqual(result.requested, triage_service.MAX_BATCH_SIZE)

    def test_a_new_cve_not_yet_local_is_fetched_from_nvd_and_persisted(self) -> None:
        nvd_payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-90005",
                        "descriptions": [{"lang": "en", "value": "A newly disclosed issue."}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                            ]
                        },
                    }
                }
            ]
        }
        with patch.object(triage_service, "fetch_cve_by_id", return_value=nvd_payload):
            result = triage_service.triage_batch(self.db, ["CVE-2026-90005"])

        self.assertTrue(result.rows[0].found)
        self.assertEqual(result.rows[0].severity, "HIGH")
        self.assertIsNotNone(self.db.get(Vulnerability, "CVE-2026-90005"))


if __name__ == "__main__":
    unittest.main()
