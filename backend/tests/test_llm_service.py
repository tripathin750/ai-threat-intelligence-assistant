"""Tests use a fake Anthropic client (no network, no real API key) and patch
the module's `settings` snapshot directly, so this suite runs fully offline
and never depends on ANTHROPIC_API_KEY being set in the environment.
"""

from dataclasses import replace
import unittest
from unittest.mock import MagicMock, patch

import anthropic
import httpx2

from backend.schemas import LLMAnalysisOutputSchema, VulnerabilitySchema
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
    return replace(llm_service.settings, anthropic_api_key="sk-test-key", enable_llm_analysis=True)


def _fake_response(parsed_output: object | None) -> MagicMock:
    response = MagicMock()
    response.parsed_output = parsed_output
    return response


class AnalyseWithLLMTests(unittest.TestCase):
    def test_maps_a_valid_response_to_an_analysis_result(self) -> None:
        parsed = LLMAnalysisOutputSchema(
            summary="Concise, evidence-grounded summary.",
            impact="Rated CRITICAL; confirm with the vendor advisory.",
            affected_component="Not identified from the normalized NVD fields.",
            risk="CRITICAL",
            confidence=0.85,
            evidence=["NVD description: Example vulnerability description."],
        )
        with patch.object(llm_service, "settings", _enabled_settings()):
            fake_client = MagicMock()
            fake_client.messages.parse.return_value = _fake_response(parsed)
            with patch.object(llm_service, "_client", return_value=fake_client):
                result = analyse_with_llm(_vulnerability())

        self.assertEqual(result.summary, parsed.summary)
        self.assertEqual(result.risk, "CRITICAL")
        self.assertEqual(result.confidence, 0.85)
        self.assertTrue(result.model.startswith("anthropic:"))

    def test_raises_when_the_response_does_not_match_the_schema(self) -> None:
        with patch.object(llm_service, "settings", _enabled_settings()):
            fake_client = MagicMock()
            fake_client.messages.parse.return_value = _fake_response(None)
            with patch.object(llm_service, "_client", return_value=fake_client):
                with self.assertRaises(LLMAnalysisError):
                    analyse_with_llm(_vulnerability())

    def test_wraps_anthropic_api_errors(self) -> None:
        request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
        with patch.object(llm_service, "settings", _enabled_settings()):
            fake_client = MagicMock()
            fake_client.messages.parse.side_effect = anthropic.APIConnectionError(request=request)
            with patch.object(llm_service, "_client", return_value=fake_client):
                with self.assertRaises(LLMAnalysisError):
                    analyse_with_llm(_vulnerability())


class GenerateAnalysisTests(unittest.TestCase):
    def test_uses_the_deterministic_analyser_when_no_api_key_is_configured(self) -> None:
        disabled = replace(llm_service.settings, anthropic_api_key=None)
        with patch.object(llm_service, "settings", disabled):
            with patch.object(llm_service, "analyse_with_llm") as mocked_llm:
                result = generate_analysis(_vulnerability())

        mocked_llm.assert_not_called()
        self.assertEqual(result.model, "evidence-based-rules-v1")

    def test_uses_the_deterministic_analyser_when_disabled_even_with_a_key(self) -> None:
        disabled = replace(llm_service.settings, anthropic_api_key="sk-test-key", enable_llm_analysis=False)
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
            risk="HIGH", confidence=0.7, evidence=["e"], model="anthropic:claude-opus-5",
        )
        with patch.object(llm_service, "settings", _enabled_settings()):
            with patch.object(llm_service, "analyse_with_llm", return_value=expected):
                result = generate_analysis(_vulnerability())

        self.assertIs(result, expected)


if __name__ == "__main__":
    unittest.main()
