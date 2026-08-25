"""Tests use an isolated in-memory SQLite database and a mocked CISA KEV
client, so they run offline and never touch the real dev/prod database or
the real CISA feed.
"""

import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.models import KevEntry, SyncState
from backend.services import kev_service


def _kev_payload(*entries: dict) -> dict:
    return {"catalogVersion": "test", "count": len(entries), "vulnerabilities": list(entries)}


def _entry(cve_id: str, **overrides: object) -> dict:
    defaults: dict[str, object] = {
        "cveID": cve_id,
        "vendorProject": "ExampleCorp",
        "product": "Example Product",
        "vulnerabilityName": "Example Vulnerability",
        "dateAdded": "2026-08-01",
        "shortDescription": "An example vulnerability.",
        "requiredAction": "Apply the vendor patch.",
        "dueDate": "2026-08-22",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
    }
    defaults.update(overrides)
    return defaults


class KevServiceTests(unittest.TestCase):
    def setUp(self) -> None:
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

    def test_first_sync_creates_entries_and_stores_sync_state(self) -> None:
        with patch.object(
            kev_service, "fetch_kev_catalog",
            return_value=_kev_payload(_entry("CVE-2026-70001"), _entry("CVE-2026-70002")),
        ):
            result = kev_service.synchronize_kev(self.db)

        self.assertEqual((result.created, result.updated, result.skipped), (2, 0, 0))
        self.assertEqual(self.db.query(KevEntry).count(), 2)
        state = self.db.get(SyncState, kev_service.KEV_SOURCE)
        self.assertIsNotNone(state)
        self.assertEqual(state.updated_records, 2)

    def test_rerunning_sync_updates_instead_of_duplicating(self) -> None:
        with patch.object(
            kev_service, "fetch_kev_catalog", return_value=_kev_payload(_entry("CVE-2026-70003"))
        ):
            kev_service.synchronize_kev(self.db)

        # CISA re-publishes the same CVE with an updated due date.
        with patch.object(
            kev_service, "fetch_kev_catalog",
            return_value=_kev_payload(_entry("CVE-2026-70003", dueDate="2026-09-01")),
        ):
            result = kev_service.synchronize_kev(self.db)

        self.assertEqual((result.created, result.updated), (0, 1))
        self.assertEqual(self.db.query(KevEntry).count(), 1)
        stored = self.db.get(KevEntry, "CVE-2026-70003")
        self.assertEqual(stored.due_date.isoformat(), "2026-09-01")

    def test_malformed_entries_are_skipped_not_fatal(self) -> None:
        malformed = {"cveID": "not-a-cve"}
        with patch.object(
            kev_service, "fetch_kev_catalog",
            return_value=_kev_payload(_entry("CVE-2026-70004"), malformed),
        ):
            result = kev_service.synchronize_kev(self.db)

        self.assertEqual(result.created, 1)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(self.db.query(KevEntry).count(), 1)


if __name__ == "__main__":
    unittest.main()
