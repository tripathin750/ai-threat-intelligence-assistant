"""Claude-backed vulnerability analysis - the LLM half of the evidence-based
seam described in services/prompts.py.

This module is the only place that calls out to Anthropic. It is designed to
fail closed: any provider error, missing key, or output that does not match
LLMAnalysisOutputSchema falls back to the deterministic rules-based analyser
in ai_service.py rather than ever breaking the /intelligence endpoint or
returning an unvalidated shape to a client.
"""

from dataclasses import replace
import logging

import anthropic

from ..config import settings
from ..schemas import LLMAnalysisOutputSchema, VulnerabilitySchema
from .ai_service import AnalysisResult, analyse_vulnerability
from .prompts import SYSTEM_PROMPT, build_user_prompt


logger = logging.getLogger(__name__)

# Bounded on purpose: the JSON contract is a handful of short strings plus a
# small evidence list, never a long free-form essay. See the skill guidance
# this was built against - don't lowball max_tokens, but a classification-
# shaped structured output doesn't need the general-purpose 16000 default.
MAX_OUTPUT_TOKENS = 4096


class LLMAnalysisError(RuntimeError):
    """Raised when the configured LLM cannot produce a valid analysis.

    Callers should catch this (generate_analysis() already does) and fall
    back to the deterministic analyser - never let a provider outage or a
    malformed response break vulnerability intelligence generation.
    """


def _client() -> anthropic.Anthropic:
    # A thin wrapper (rather than a module-level client) so tests can patch
    # this single seam instead of mocking the whole anthropic package.
    return anthropic.Anthropic(api_key=settings.anthropic_api_key)


def analyse_with_llm(vulnerability: VulnerabilitySchema) -> AnalysisResult:
    """Ask Claude to analyze one CVE and return a validated AnalysisResult.

    Raises LLMAnalysisError on any provider failure or schema mismatch.
    Never called with unset settings.anthropic_api_key - generate_analysis()
    guards that.
    """
    try:
        response = _client().messages.parse(
            model=settings.llm_model,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_user_prompt(vulnerability)}],
            output_format=LLMAnalysisOutputSchema,
        )
    except anthropic.APIError as exc:
        raise LLMAnalysisError(f"Anthropic API call failed: {exc}") from exc

    parsed = response.parsed_output
    if parsed is None:
        raise LLMAnalysisError("Model response did not match the required JSON schema.")

    return AnalysisResult(
        summary=parsed.summary,
        impact=parsed.impact,
        affected_component=parsed.affected_component,
        risk=parsed.risk,
        confidence=parsed.confidence,
        evidence=parsed.evidence,
        model=f"anthropic:{settings.llm_model}",
    )


def generate_analysis(vulnerability: VulnerabilitySchema) -> AnalysisResult:
    """Prefer the configured Claude model; fall back to the deterministic,
    evidence-based-rules analyser whenever the LLM path isn't usable.

    This is the single entry point intelligence_service.py should call - it
    keeps /intelligence available even with no API key configured, a
    provider outage, or an unparseable response, mirroring the "skip and
    log, don't crash" discipline this project already applies to untrusted
    NVD data.
    """
    if not (settings.enable_llm_analysis and settings.anthropic_api_key):
        return analyse_vulnerability(vulnerability)

    try:
        return analyse_with_llm(vulnerability)
    except LLMAnalysisError:
        logger.warning(
            "LLM analysis failed for %s; falling back to the deterministic analyser.",
            vulnerability.cve_id,
            exc_info=True,
        )
    except Exception:
        # Defense in depth: an unexpected failure mode here (e.g. an SDK
        # change this code hasn't been updated for) must still degrade to
        # the deterministic analyser rather than 500 the whole endpoint.
        logger.exception(
            "Unexpected error calling the LLM provider for %s; falling back to the deterministic analyser.",
            vulnerability.cve_id,
        )
    fallback = analyse_vulnerability(vulnerability)
    # Keep the model name honest: this result did NOT come from the LLM.
    return replace(fallback, model=f"{fallback.model}-fallback")
