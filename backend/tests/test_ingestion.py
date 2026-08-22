"""Ingestion tests use an isolated in-memory SQLite database and a mocked
NVD client, so they run offline and never touch the real dev/prod database.
"""

import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.models import SyncState, Vulnerability
from backend.services import ingestion_service


def _nvd_payload(*cves: dict) -> dict:
    return {
        "totalResults": len(cves),
        "vulnerabilities": [{"cve": cve} for cve in cves],
    }


def _cve(cve_id: str, description: str = "Example vulnerability.", score: float = 7.5) -> dict:
    return {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {
            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}]
        },
        "published": "2026-08-01T00:00:00.000Z",
        "lastModified": "2026-08-02T00:00:00.000Z",
    }


class IngestionServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        # A private in-memory database per test — isolated from the app's
        # configured engine and from every other test in this suite.
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self) -> None:
        self.db.close()
        self.engine.dispose()

    def test_first_sync_creates_records_and_stores_sync_state(self) -> None:
        with patch.object(
            ingestion_service,
            "fetch_modified_cves",
            return_value=_nvd_payload(_cve("CVE-2026-50001"), _cve("CVE-2026-50002")),
        ):
            result = ingestion_service.synchronize_nvd(self.db, limit=100)

        self.assertEqual((result.created, result.updated, result.skipped), (2, 0, 0))
        self.assertEqual(self.db.query(Vulnerability).count(), 2)
        state = self.db.get(SyncState, "NVD")
        self.assertIsNotNone(state)
        self.assertEqual(state.updated_records, 2)

    def test_rerunning_sync_updates_instead_of_duplicating(self) -> None:
        with patch.object(
            ingestion_service, "fetch_modified_cves", return_value=_nvd_payload(_cve("CVE-2026-50003"))
        ):
            ingestion_service.synchronize_nvd(self.db, limit=100)

        # Same CVE ID returned again, with a changed description (as if NVD
        # re-enriched the record) — this must update, not duplicate.
        with patch.object(
            ingestion_service,
            "fetch_modified_cves",
            return_value=_nvd_payload(_cve("CVE-2026-50003", description="Updated NVD description.")),
        ):
            result = ingestion_service.synchronize_nvd(self.db, limit=100)

        self.assertEqual((result.created, result.updated), (0, 1))
        self.assertEqual(self.db.query(Vulnerability).count(), 1)
        stored = self.db.get(Vulnerability, "CVE-2026-50003")
        self.assertEqual(stored.description, "Updated NVD description.")

    def test_malformed_records_are_skipped_not_fatal(self) -> None:
        malformed = {"id": "CVE-2026-INVALID-ID"}  # fails the CVE_ID_PATTERN
        with patch.object(
            ingestion_service,
            "fetch_modified_cves",
            return_value=_nvd_payload(_cve("CVE-2026-50004"), malformed),
        ):
            result = ingestion_service.synchronize_nvd(self.db, limit=100)

        self.assertEqual(result.created, 1)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(self.db.query(Vulnerability).count(), 1)

    def test_second_sync_uses_previous_successful_timestamp(self) -> None:
        with patch.object(
            ingestion_service, "fetch_modified_cves", return_value=_nvd_payload(_cve("CVE-2026-50005"))
        ) as mocked_fetch:
            ingestion_service.synchronize_nvd(self.db, limit=50)
            first_call_arg = mocked_fetch.call_args.args[0]
            self.assertIsNone(first_call_arg)  # no prior sync state yet

        with patch.object(
            ingestion_service, "fetch_modified_cves", return_value=_nvd_payload()
        ) as mocked_fetch:
            ingestion_service.synchronize_nvd(self.db, limit=50)
            second_call_arg = mocked_fetch.call_args.args[0]
            self.assertIsNotNone(second_call_arg)  # now passes the stored timestamp


if __name__ == "__main__":
    unittest.main()
