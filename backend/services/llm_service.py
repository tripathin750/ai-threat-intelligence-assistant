"""Groq-backed vulnerability analysis - the LLM half of the evidence-based
seam described in services/prompts.py.

Groq was chosen over a metered-credit provider because its free developer
tier has no credit system and no per-token charge - just rate limits - so
this can run indefinitely at zero cost (see README's "AI-generated
analysis" section for the reasoning and the rejected alternatives).

This module is the only place that calls out to Groq. It is designed to
fail closed: any request error, rate limit, or response that does not match
LLMAnalysisOutputSchema falls back to the deterministic rules-based analyser
in ai_service.py rather than ever breaking the /intelligence endpoint or
returning an unvalidated shape to a client.
"""

from dataclasses import replace
import logging

from pydantic import ValidationError
import requests

from ..config import settings
from ..schemas import LLMAnalysisOutputSchema, VulnerabilitySchema
from .ai_service import AnalysisResult, analyse_vulnerability
from .prompts import SYSTEM_PROMPT, build_user_prompt


logger = logging.getLogger(__name__)

GROQ_CHAT_COMPLETIONS_URL = "https://api.groq.com/openai/v1/chat/completions"
REQUEST_TIMEOUT_SECONDS = 30
# Bounded on purpose: the JSON contract is a handful of short strings plus a
# small evidence list, never a long free-form essay.
MAX_OUTPUT_TOKENS = 1024


class LLMAnalysisError(RuntimeError):
    """Raised when Groq cannot produce a valid analysis.

    Callers should catch this (generate_analysis() already does) and fall
    back to the deterministic analyser - never let a provider outage, rate
    limit, or malformed response break vulnerability intelligence
    generation.
    """


def analyse_with_llm(vulnerability: VulnerabilitySchema) -> AnalysisResult:
    """Ask Groq to analyze one CVE and return a validated AnalysisResult.

    Raises LLMAnalysisError on any request failure or schema mismatch.
    Never called with unset settings.groq_api_key - generate_analysis()
    guards that.
    """
    try:
        response = requests.post(
            GROQ_CHAT_COMPLETIONS_URL,
            headers={"Authorization": f"Bearer {settings.groq_api_key}"},
            json={
                "model": settings.groq_model,
                "max_tokens": MAX_OUTPUT_TOKENS,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_user_prompt(vulnerability)},
                ],
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise LLMAnalysisError(f"Groq API call failed: {exc}") from exc
    except ValueError as exc:
        raise LLMAnalysisError("Groq returned a non-JSON response.") from exc

    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMAnalysisError(f"Unexpected Groq response shape: {payload!r}") from exc

    try:
        parsed = LLMAnalysisOutputSchema.model_validate_json(content)
    except ValidationError as exc:
        raise LLMAnalysisError(f"Model response did not match the required JSON schema: {exc}") from exc

    return AnalysisResult(
        summary=parsed.summary,
        impact=parsed.impact,
        affected_component=parsed.affected_component,
        risk=parsed.risk,
        confidence=parsed.confidence,
        evidence=parsed.evidence,
        model=f"groq:{settings.groq_model}",
    )


def generate_analysis(vulnerability: VulnerabilitySchema) -> AnalysisResult:
    """Prefer Groq; fall back to the deterministic, evidence-based-rules
    analyser whenever the LLM path isn't usable.

    This is the single entry point intelligence_service.py should call - it
    keeps /intelligence available with no API key configured, a provider
    outage, a rate limit, or an unparseable response, mirroring the "skip
    and log, don't crash" discipline this project already applies to
    untrusted NVD data.
    """
    if not (settings.enable_llm_analysis and settings.groq_api_key):
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
        # Defense in depth: an unexpected failure mode here (e.g. an API
        # change this code hasn't been updated for) must still degrade to
        # the deterministic analyser rather than 500 the whole endpoint.
        logger.exception(
            "Unexpected error calling Groq for %s; falling back to the deterministic analyser.",
            vulnerability.cve_id,
        )
    fallback = analyse_vulnerability(vulnerability)
    # Keep the model name honest: this result did NOT come from the LLM.
    return replace(fallback, model=f"{fallback.model}-fallback")
