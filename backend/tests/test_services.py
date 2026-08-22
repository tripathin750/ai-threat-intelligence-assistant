import unittest

from backend.schemas import VulnerabilitySchema
from backend.services.ai_service import analyse_vulnerability
from backend.services.attack_service import infer_attack_techniques
from backend.services.mitigation_service import recommend_mitigations


def _vulnerability(**overrides: object) -> VulnerabilitySchema:
    defaults: dict[str, object] = {
        "cve_id": "CVE-2026-40000",
        "description": "Example vulnerability description.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "cwe_id": "CWE-79",
    }
    defaults.update(overrides)
    return VulnerabilitySchema(**defaults)


class AnalyseVulnerabilityTests(unittest.TestCase):
    def test_evidence_is_grounded_only_in_supplied_nvd_fields(self) -> None:
        vulnerability = _vulnerability(description="Remote code execution in the widget parser.")
        result = analyse_vulnerability(vulnerability)

        self.assertIn(vulnerability.cve_id, result.summary)
        self.assertIn("Remote code execution in the widget parser.", result.evidence[0])
        self.assertIn("9.8", result.evidence[1])
        self.assertIn("CWE-79", result.evidence[2])
        self.assertEqual(result.risk, "CRITICAL")

    def test_missing_cvss_and_cwe_are_reported_as_absent_not_guessed(self) -> None:
        vulnerability = _vulnerability(cvss_score=None, severity=None, cwe_id=None)
        result = analyse_vulnerability(vulnerability)

        self.assertIn("did not provide a CVSS", result.evidence[1])
        self.assertIn("did not provide a CWE", result.evidence[2])
        self.assertEqual(result.risk, "UNKNOWN")
        # Lower confidence when the record is missing enrichment fields.
        self.assertLess(result.confidence, 0.9)


class InferAttackTechniquesTests(unittest.TestCase):
    def test_matches_multiple_independent_signals(self) -> None:
        vulnerability = _vulnerability(
            description=(
                "A remote command injection vulnerability in the web application "
                "allows arbitrary command execution."
            )
        )
        inferred = {item.technique_id for item in infer_attack_techniques(vulnerability)}
        self.assertEqual(inferred, {"T1190", "T1059"})

    def test_no_mapping_without_a_concrete_signal(self) -> None:
        vulnerability = _vulnerability(description="A cross-site scripting vulnerability was found.")
        self.assertEqual(infer_attack_techniques(vulnerability), [])

    def test_rationale_explicitly_labels_the_mapping_as_inferred(self) -> None:
        vulnerability = _vulnerability(description="An SMB remote service vulnerability.")
        inferred = infer_attack_techniques(vulnerability)
        self.assertTrue(inferred)
        self.assertIn("not an official MITRE ATT&CK mapping", inferred[0].rationale)


class RecommendMitigationsTests(unittest.TestCase):
    def test_high_severity_gets_an_urgent_immediate_action(self) -> None:
        vulnerability = _vulnerability(severity="CRITICAL")
        result = recommend_mitigations(vulnerability, technique_ids=[])
        self.assertIn("Prioritise", result.immediate_action)

    def test_low_severity_gets_a_measured_immediate_action(self) -> None:
        vulnerability = _vulnerability(severity="LOW")
        result = recommend_mitigations(vulnerability, technique_ids=[])
        self.assertNotIn("Prioritise", result.immediate_action)

    def test_technique_specific_recommendation_is_appended_without_duplicating(self) -> None:
        vulnerability = _vulnerability(severity="HIGH")
        result = recommend_mitigations(vulnerability, technique_ids=["T1190", "T1190"])
        matches = [item for item in result.recommendations if "Internet exposure" in item]
        self.assertEqual(len(matches), 1)

    def test_unknown_technique_id_is_ignored_rather_than_crashing(self) -> None:
        vulnerability = _vulnerability(severity="HIGH")
        result = recommend_mitigations(vulnerability, technique_ids=["T9999"])
        self.assertEqual(len(result.recommendations), 3)  # only the baseline recommendations


if __name__ == "__main__":
    unittest.main()
