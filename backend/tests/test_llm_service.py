"""Tests mock requests.post directly (no network, no real Gemini API key), so
this suite runs fully offline and never depends on GEMINI_API_KEY being set
in the environment.
"""

from dataclasses import replace
import json
import unittest
from unittest.mock import MagicMock, patch

import requests

from backend.schemas import VulnerabilitySchema
from backend.services import llm_service
from backend.services.llm_service import LLMAnalysisError, analyse_with_llm, generate_analysis


def _vulnerability(**overrides: object) -> VulnerabilitySchema:
    defaults: dict[str, object] = {
        "cve_id": "CVE-2026-90001",
        "description": "Example vulnerability description.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "cwe_id": "CWE-79",
    }
    defaults.update(overrides)
    return VulnerabilitySchema(**defaults)


def _enabled_settings():
    return replace(llm_service.settings, gemini_api_key="test-key", enable_llm_analysis=True)


def _fake_gemini_response(text: str, status_code: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": text}]}}]
    }
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(f"{status_code} error")
    else:
        response.raise_for_status.return_value = None
    return response


VALID_MODEL_JSON = json.dumps(
    {
        "summary": "Concise, evidence-grounded summary.",
        "impact": "Rated CRITICAL; confirm with the vendor advisory.",
        "affected_component": "Not identified from the normalized NVD fields.",
        "risk": "CRITICAL",
        "confidence": 0.85,
        "evidence": ["NVD description: Example vulnerability description."],
        "attack_techniques": [{"technique_id": "T1059", "rationale": "Description mentions command execution."}],
        "mitigations": ["Validate and sanitize the affected input before use."],
    }
)


class AnalyseWithLLMTests(unittest.TestCase):
    def test_maps_a_valid_response_to_an_analysis_result(self) -> None:
        with patch.object(llm_service, "settings", _enabled_settings()):
            with patch.object(
                llm_service.requests, "post", return_value=_fake_gemini_response(VALID_MODEL_JSON)
            ):
                result = analyse_with_llm(_vulnerability())

        self.assertEqual(result.risk, "CRITICAL")
        self.assertEqual(result.confidence, 0.85)
        self.assertTrue(result.model.startswith("gemini:"))
        self.assertEqual(result.attack_techniques, [("T1059", "Description mentions command execution.")])
        self.assertEqual(result.mitigations, ["Validate and sanitize the affected input before use."])

    def test_raises_when_mitigations_is_missing_or_empty(self) -> None:
        # LLMAnalysisOutputSchema requires at least one mitigation - a
        # response that omits the field (or sends an empty list) must be
        # rejected the same way any other schema violation is.
        missing = json.loads(VALID_MODEL_JSON)
        del missing["mitigations"]
        with patch.object(llm_service, "settings", _enabled_settings()):
            with patch.object(
                llm_service.requests, "post", return_value=_fake_gemini_response(json.dumps(missing))
            ):
                with self.assertRaises(LLMAnalysisError):
                    analyse_with_llm(_vulnerability())

    def test_raises_when_the_response_is_not_valid_json(self) -> None:
        with patch.object(llm_service, "settings", _enabled_settings()):
            with patch.object(
                llm_service.requests, "post", return_value=_fake_gemini_response("not json")
            ):
                with self.assertRaises(LLMAnalysisError):
                    analyse_with_llm(_vulnerability())

    def test_raises_when_the_response_does_not_match_the_schema(self) -> None:
        malformed = json.dumps({"summary": "s"})  # missing every other required field
        with patch.object(llm_service, "settings", _enabled_settings()):
            with patch.object(
                llm_service.requests, "post", return_value=_fake_gemini_response(malformed)
            ):
                with self.assertRaises(LLMAnalysisError):
                    analyse_with_llm(_vulnerability())

    def test_raises_on_an_http_error(self) -> None:
        with patch.object(llm_service, "settings", _enabled_settings()):
            with patch.object(
                llm_service.requests, "post", return_value=_fake_gemini_response("", status_code=429)
            ):
                with self.assertRaises(LLMAnalysisError):
                    analyse_with_llm(_vulnerability())

    def test_raises_on_a_network_error(self) -> None:
        with patch.object(llm_service, "settings", _enabled_settings()):
            with patch.object(
                llm_service.requests, "post", side_effect=requests.ConnectionError("no route")
            ):
                with self.assertRaises(LLMAnalysisError):
                    analyse_with_llm(_vulnerability())

    def test_raises_on_an_unexpected_response_shape(self) -> None:
        with patch.object(llm_service, "settings", _enabled_settings()):
            fake = MagicMock()
            fake.raise_for_status.return_value = None
            fake.json.return_value = {"candidates": []}  # no content at all
            with patch.object(llm_service.requests, "post", return_value=fake):
                with self.assertRaises(LLMAnalysisError):
                    analyse_with_llm(_vulnerability())


class GenerateAnalysisTests(unittest.TestCase):
    def test_uses_the_deterministic_analyser_when_no_api_key_is_configured(self) -> None:
        disabled = replace(llm_service.settings, gemini_api_key=None)
        with patch.object(llm_service, "settings", disabled):
            with patch.object(llm_service, "analyse_with_llm") as mocked_llm:
                result = generate_analysis(_vulnerability())

        mocked_llm.assert_not_called()
        self.assertEqual(result.model, "evidence-based-rules-v1")

    def test_uses_the_deterministic_analyser_when_disabled_even_with_a_key(self) -> None:
        disabled = replace(llm_service.settings, gemini_api_key="test-key", enable_llm_analysis=False)
        with patch.object(llm_service, "settings", disabled):
            with patch.object(llm_service, "analyse_with_llm") as mocked_llm:
                result = generate_analysis(_vulnerability())

        mocked_llm.assert_not_called()
        self.assertEqual(result.model, "evidence-based-rules-v1")

    def test_falls_back_and_labels_the_result_when_the_llm_call_fails(self) -> None:
        with patch.object(llm_service, "settings", _enabled_settings()):
            with patch.object(llm_service, "analyse_with_llm", side_effect=LLMAnalysisError("boom")):
                result = generate_analysis(_vulnerability())

        self.assertEqual(result.model, "evidence-based-rules-v1-fallback")
        self.assertEqual(result.risk, "CRITICAL")  # deterministic analyser still ran

    def test_falls_back_on_a_completely_unexpected_exception_too(self) -> None:
        with patch.object(llm_service, "settings", _enabled_settings()):
            with patch.object(llm_service, "analyse_with_llm", side_effect=RuntimeError("unexpected")):
                result = generate_analysis(_vulnerability())

        self.assertEqual(result.model, "evidence-based-rules-v1-fallback")

    def test_uses_the_llm_result_when_the_call_succeeds(self) -> None:
        expected = llm_service.AnalysisResult(
            summary="s", impact="i", affected_component="a",
            risk="HIGH", confidence=0.7, evidence=["e"], model="gemini:gemini-3.5-flash-lite",
        )
        with patch.object(llm_service, "settings", _enabled_settings()):
            with patch.object(llm_service, "analyse_with_llm", return_value=expected):
                result = generate_analysis(_vulnerability())

        self.assertIs(result, expected)


if __name__ == "__main__":
    unittest.main()
