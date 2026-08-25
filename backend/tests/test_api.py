"""End-to-end API tests against an isolated, throwaway SQLite database.

DATABASE_URL is overridden *before* any `backend.*` module is imported, since
backend/config.py and backend/database.py build the settings object and the
SQLAlchemy engine once, at import time. This keeps these tests from ever
touching the real development database file.
"""

import os
import tempfile
import unittest
from pathlib import Path

_TMP_DB = Path(tempfile.gettempdir()) / "threat_intelligence_test_api.db"
_TMP_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"
os.environ.setdefault("ENABLE_SCHEDULER", "false")
# Force the deterministic analyser regardless of the developer's local
# backend/.env - test_full_intelligence_pipeline_end_to_end below asserts
# on that analyser's exact output shape, and this suite must stay offline
# and reproducible even when a real GEMINI_API_KEY is configured for
# everyday use of the app.
os.environ["ENABLE_LLM_ANALYSIS"] = "false"

from fastapi.testclient import TestClient  # noqa: E402

from backend.database import SessionLocal, engine  # noqa: E402
from backend.main import app, settings  # noqa: E402
from backend.models import Vulnerability  # noqa: E402


def _seed_vulnerability(**overrides: object) -> None:
    defaults: dict[str, object] = {
        "cve_id": "CVE-2026-60001",
        "description": "A remote command injection vulnerability in the web application.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "cwe_id": "CWE-77",
        "source": "NVD",
    }
    defaults.update(overrides)
    db = SessionLocal()
    try:
        if db.get(Vulnerability, defaults["cve_id"]) is None:
            db.add(Vulnerability(**defaults))
            db.commit()
    finally:
        db.close()


class ApiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # `with TestClient(app)` runs the app's lifespan (init_db + ATT&CK
        # catalogue seeding), same as a real startup.
        cls.client = TestClient(app)
        cls.client.__enter__()
        _seed_vulnerability()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.__exit__(None, None, None)
        # Windows keeps an exclusive file lock while any pooled SQLite
        # connection is open; dispose the engine first or the unlink below
        # raises PermissionError even though the app has "closed" its sessions.
        engine.dispose()
        _TMP_DB.unlink(missing_ok=True)

    def test_health_and_about(self) -> None:
        self.assertEqual(self.client.get("/health").status_code, 200)
        about = self.client.get("/about").json()
        self.assertEqual(about["intelligence_policy"], "NVD is authoritative; analysis and ATT&CK mappings are advisory.")

    def test_security_headers_present_on_every_response(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("X-Request-ID", response.headers)

    def test_search_omits_a_legacy_row_that_fails_current_validation_instead_of_500ing(self) -> None:
        """Regression test: a pre-existing row with a CVE ID that predates the
        stricter CVE_ID_PATTERN (e.g. a hand-inserted 'CVE-TEST-001' row from
        an early manual exercise) must not crash the whole search response."""
        db = SessionLocal()
        try:
            if db.get(Vulnerability, "CVE-TEST-001") is None:
                db.add(
                    Vulnerability(
                        cve_id="CVE-TEST-001",
                        description="Legacy row predating strict CVE ID validation.",
                        cvss_score=9.8,
                        severity="CRITICAL",
                        source="NVD",
                    )
                )
                db.commit()
        finally:
            db.close()

        response = self.client.get("/cves", params={"q": "Legacy row"})
        self.assertEqual(response.status_code, 200)
        ids = {item["cve_id"] for item in response.json()["items"]}
        self.assertNotIn("CVE-TEST-001", ids)

    def test_search_filters_by_severity_and_min_cvss(self) -> None:
        page = self.client.get("/cves", params={"severity": "critical", "min_cvss": 9}).json()
        self.assertGreaterEqual(page["total"], 1)
        self.assertTrue(all(item["severity"] == "CRITICAL" for item in page["items"]))

    def test_search_rejects_a_limit_above_the_server_side_cap(self) -> None:
        response = self.client.get("/cves", params={"limit": 500})
        self.assertEqual(response.status_code, 422)

    def test_get_cve_by_id_and_404_for_unknown(self) -> None:
        found = self.client.get("/cves/CVE-2026-60001")
        self.assertEqual(found.status_code, 200)
        self.assertEqual(found.json()["cve_id"], "CVE-2026-60001")

        missing = self.client.get("/cves/CVE-1999-99999")
        self.assertEqual(missing.status_code, 404)

    def test_get_cve_rejects_a_malformed_id_before_touching_the_database(self) -> None:
        response = self.client.get("/cves/DROP TABLE vulnerabilities")
        self.assertEqual(response.status_code, 422)

    def test_full_intelligence_pipeline_end_to_end(self) -> None:
        """Regression test for the stale-relationship-cache bug fixed in
        services/intelligence_service.py: the very first analyze call for a
        CVE with no prior analysis must succeed, not 500."""
        response = self.client.post("/intelligence/CVE-2026-60001/analyze")
        self.assertEqual(response.status_code, 200)
        body = response.json()

        self.assertIn("CVE-2026-60001", body["analysis"]["summary"])
        self.assertEqual(body["analysis"]["risk"], "CRITICAL")
        technique_ids = {mapping["technique"]["technique_id"] for mapping in body["attack_mappings"]}
        self.assertIn("T1190", technique_ids)
        self.assertIn("T1059", technique_ids)
        self.assertTrue(body["mitigations"]["immediate_action"])
        self.assertIn("advisory", body["disclaimer"])

        # A second, non-refreshing GET must return the persisted record.
        persisted = self.client.get("/intelligence/CVE-2026-60001").json()
        self.assertEqual(persisted["analysis"]["generated_at"], body["analysis"]["generated_at"])

    def test_attack_technique_catalog_is_searchable(self) -> None:
        results = self.client.get("/attack/techniques", params={"q": "T1190"}).json()
        self.assertTrue(any(item["technique_id"] == "T1190" for item in results))

    def test_api_key_enforced_when_configured(self) -> None:
        original = settings.api_key
        object.__setattr__(settings, "api_key", "test-secret-key")
        try:
            unauthenticated = self.client.get("/cves")
            self.assertEqual(unauthenticated.status_code, 401)

            authenticated = self.client.get("/cves", headers={"X-API-Key": "test-secret-key"})
            self.assertEqual(authenticated.status_code, 200)

            wrong_key = self.client.get("/cves", headers={"X-API-Key": "not-it"})
            self.assertEqual(wrong_key.status_code, 401)
        finally:
            object.__setattr__(settings, "api_key", original)

    def test_zz_rate_limit_returns_429_once_the_window_is_exceeded(self) -> None:
        # Named to run last (unittest executes test_* methods alphabetically
        # within a class): this test deliberately exhausts the per-client
        # rate-limit window, which would otherwise cause every test that
        # runs after it in this shared TestClient/app instance to also see
        # 429s until the 60-second sliding window clears.
        #
        # RateLimitMiddleware also captures requests_per_minute once, at app
        # construction time (main.py's add_middleware call) — it isn't a
        # live read of `settings`, so this drives the real configured limit
        # rather than monkeypatching it.
        limit = settings.rate_limit_per_minute
        statuses = [self.client.get("/about").status_code for _ in range(limit + 5)]
        self.assertIn(429, statuses)


if __name__ == "__main__":
    unittest.main()
