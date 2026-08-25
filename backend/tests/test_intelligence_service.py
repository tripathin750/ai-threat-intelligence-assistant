"""Tests use an isolated in-memory SQLite database and a mocked
generate_analysis(), so they run offline and never call a real LLM
provider or touch the real dev/prod database.
"""

import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.models import MitigationRecommendation, Vulnerability, VulnerabilityAttackMapping
from backend.services import intelligence_service
from backend.services.ai_service import AnalysisResult


def _analysis_result(**overrides: object) -> AnalysisResult:
    defaults: dict[str, object] = {
        "summary": "s", "impact": "i", "affected_component": "a",
        "risk": "HIGH", "confidence": 0.8, "evidence": ["e"],
    }
    defaults.update(overrides)
    return AnalysisResult(**defaults)


class GenerateIntelligenceTests(unittest.TestCase):
    def setUp(self) -> None:
        # A private in-memory database per test - isolated from the app's
        # configured engine and from every other test in this suite.
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()
        self.vulnerability = Vulnerability(
            cve_id="CVE-2026-80001",
            description="A remote command injection vulnerability in the web application.",
            cvss_score=9.8,
            severity="CRITICAL",
            source="NVD",
        )
        self.db.add(self.vulnerability)
        self.db.commit()

    def tearDown(self) -> None:
        self.db.close()
        self.engine.dispose()

    def _mappings(self) -> list[VulnerabilityAttackMapping]:
        return (
            self.db.query(VulnerabilityAttackMapping)
            .filter(VulnerabilityAttackMapping.cve_id == "CVE-2026-80001")
            .all()
        )

    def _mitigation(self) -> MitigationRecommendation:
        return (
            self.db.query(MitigationRecommendation)
            .filter(MitigationRecommendation.cve_id == "CVE-2026-80001")
            .one()
        )

    def test_deterministic_path_uses_the_keyword_matcher_and_rule_based_mitigations(self) -> None:
        # The description contains genuine keyword signals for T1190 and
        # T1059 (see test_services.py's equivalent direct test) - the
        # deterministic path must still find them exactly as before.
        with patch.object(
            intelligence_service, "generate_analysis", return_value=_analysis_result(model="evidence-based-rules-v1")
        ):
            intelligence_service._generate_intelligence(self.db, self.vulnerability)

        technique_ids = {m.technique_id for m in self._mappings()}
        self.assertEqual(technique_ids, {"T1190", "T1059"})
        mitigation = self._mitigation()
        self.assertEqual(mitigation.source, "evidence-based-rules-v1")
        self.assertIn(
            "Confirm whether each asset runs an affected product and version before making a remediation decision.",
            mitigation.recommendations,
        )

    def test_llm_path_uses_its_own_technique_selections_and_mitigations(self) -> None:
        llm_result = _analysis_result(
            model="gemini:gemini-3.5-flash-lite",
            attack_techniques=[("T1078", "Description implies default credential use.")],
            mitigations=["Rotate the affected credential immediately.", "Enforce MFA on the exposed endpoint."],
        )
        with patch.object(intelligence_service, "generate_analysis", return_value=llm_result):
            intelligence_service._generate_intelligence(self.db, self.vulnerability)

        technique_ids = {m.technique_id for m in self._mappings()}
        # T1078 came from the LLM, not the keyword matcher - and the keyword
        # matcher's own T1190/T1059 matches must NOT also appear, since the
        # LLM path ran and its selections are authoritative.
        self.assertEqual(technique_ids, {"T1078"})
        mitigation = self._mitigation()
        self.assertEqual(mitigation.source, "gemini:gemini-3.5-flash-lite")
        self.assertEqual(
            mitigation.recommendations,
            ["Rotate the affected credential immediately.", "Enforce MFA on the exposed endpoint."],
        )

    def test_llm_path_with_no_techniques_does_not_fall_back_to_the_keyword_matcher(self) -> None:
        # The description would match T1190/T1059 by keyword, but the LLM
        # ran and confidently found nothing - that answer must be respected,
        # not silently overridden by the keyword matcher.
        llm_result = _analysis_result(
            model="gemini:gemini-3.5-flash-lite",
            attack_techniques=[],
            mitigations=["Apply the vendor-supplied patch for this component."],
        )
        with patch.object(intelligence_service, "generate_analysis", return_value=llm_result):
            intelligence_service._generate_intelligence(self.db, self.vulnerability)

        self.assertEqual(self._mappings(), [])

    def test_a_hallucinated_technique_id_outside_the_catalogue_is_dropped(self) -> None:
        llm_result = _analysis_result(
            model="gemini:gemini-3.5-flash-lite",
            attack_techniques=[
                ("T1078", "A real, cataloged technique."),
                ("T9999", "Not a real technique in our catalogue."),
            ],
            mitigations=["Rotate the affected credential immediately."],
        )
        with patch.object(intelligence_service, "generate_analysis", return_value=llm_result):
            intelligence_service._generate_intelligence(self.db, self.vulnerability)

        technique_ids = {m.technique_id for m in self._mappings()}
        self.assertEqual(technique_ids, {"T1078"})


if __name__ == "__main__":
    unittest.main()
