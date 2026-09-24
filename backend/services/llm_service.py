"""Gemini-backed vulnerability analysis - the LLM half of the evidence-based
seam described in services/prompts.py.

Google's Gemini API (Flash / Flash-Lite models) was chosen for its free
tier: no credit card, and limits are per-minute/per-day rate limits rather
than a metered credit pool that runs out after a handful of requests (see
README's "AI-generated analysis" section for the fuller reasoning, and why
Anthropic and Hugging Face were ruled out first).

This module is the only place that calls out to Gemini. It is designed to
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

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
# Structured-output requests (responseSchema) appear to take noticeably
# longer than plain text generation, and Render's free tier throttles CPU,
# so 30s wasn't enough headroom - a real request timed out in production
# with no other error. 55s stays under a plausible ~60s outer proxy limit.
REQUEST_TIMEOUT_SECONDS = 55
# Bounded on purpose: a real summary/impact paragraph, a handful of evidence
# citations, up to 5 mitigations, and a few attack-technique rationales -
# still never a long free-form essay, but more than the original 1024 now
# that the contract carries mitigations and attack_techniques too.
MAX_OUTPUT_TOKENS = 2048

# A hand-written subset of LLMAnalysisOutputSchema's shape, using only the
# JSON Schema keywords Gemini's structured-output mode documents support
# (type, properties, required, items). Pydantic's own model_json_schema()
# emits keywords (e.g. $defs, additionalProperties) outside that subset, so
# it is not reused directly here - this schema only shapes the model's
# output; LLMAnalysisOutputSchema below is still what actually validates it.
_GEMINI_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "impact": {"type": "string"},
        "affected_component": {"type": "string"},
        "risk": {"type": "string"},
        "confidence": {"type": "number"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "attack_techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["technique_id", "rationale"],
            },
        },
        "mitigations": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "summary", "impact", "affected_component", "risk", "confidence",
        "evidence", "attack_techniques", "mitigations",
    ],
}


class LLMAnalysisError(RuntimeError):
    """Raised when Gemini cannot produce a valid analysis.

    Callers should catch this (generate_analysis() already does) and fall
    back to the deterministic analyser - never let a provider outage, rate
    limit, or malformed response break vulnerability intelligence
    generation.
    """


def call_gemini_json(
    system_prompt: str,
    user_prompt: str,
    response_schema: dict,
    max_output_tokens: int = MAX_OUTPUT_TOKENS,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
) -> str:
    """POST one structured-output request to Gemini and return the raw JSON text.

    The single place that speaks Gemini's generateContent protocol, shared by
    every LLM feature (CVE analysis here, CWE fault trees in
    services/fault_tree_service.py). Callers still validate the returned text
    against their own Pydantic schema - this only guarantees "a JSON string
    came back", never that it has the right shape.

    Raises LLMAnalysisError on any request failure or unexpected response.

    The API key travels in the ``x-goog-api-key`` header, never the URL: a
    ``?key=`` query parameter ends up inside every ``requests`` exception
    message (which embeds the URL), and those messages are logged - so any
    Gemini 429/503 would have written the key into the deployment's logs.
    Error messages below deliberately carry only the exception type and HTTP
    status, never the exception text, as a second line of defence.
    """
    try:
        response = requests.post(
            f"{GEMINI_API_BASE}/{settings.gemini_model}:generateContent",
            headers={"x-goog-api-key": settings.gemini_api_key},
            json={
                "systemInstruction": {"parts": [{"text": system_prompt}]},
                "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "responseSchema": response_schema,
                    "maxOutputTokens": max_output_tokens,
                },
            },
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        detail = f"{type(exc).__name__}" + (f" (HTTP {status})" if status else "")
        # `from None`: the chained exception's text/URL must not reach the logs either.
        raise LLMAnalysisError(f"Gemini API call failed: {detail}") from None
    except ValueError as exc:
        raise LLMAnalysisError("Gemini returned a non-JSON response.") from exc

    try:
        return payload["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMAnalysisError(f"Unexpected Gemini response shape: {payload!r}") from exc


def analyse_with_llm(vulnerability: VulnerabilitySchema) -> AnalysisResult:
    """Ask Gemini to analyze one CVE and return a validated AnalysisResult.

    Raises LLMAnalysisError on any request failure or schema mismatch.
    Never called with unset settings.gemini_api_key - generate_analysis()
    guards that.
    """
    content = call_gemini_json(SYSTEM_PROMPT, build_user_prompt(vulnerability), _GEMINI_RESPONSE_SCHEMA)

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
        model=f"gemini:{settings.gemini_model}",
        attack_techniques=[(item.technique_id, item.rationale) for item in parsed.attack_techniques],
        mitigations=parsed.mitigations,
    )


def generate_analysis(vulnerability: VulnerabilitySchema) -> AnalysisResult:
    """Prefer Gemini; fall back to the deterministic, evidence-based-rules
    analyser whenever the LLM path isn't usable.

    This is the single entry point intelligence_service.py should call - it
    keeps /intelligence available with no API key configured, a provider
    outage, a rate limit, or an unparseable response, mirroring the "skip
    and log, don't crash" discipline this project already applies to
    untrusted NVD data.
    """
    if not (settings.enable_llm_analysis and settings.gemini_api_key):
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
            "Unexpected error calling Gemini for %s; falling back to the deterministic analyser.",
            vulnerability.cve_id,
        )
    fallback = analyse_vulnerability(vulnerability)
    # Keep the model name honest: this result did NOT come from the LLM.
    return replace(fallback, model=f"{fallback.model}-fallback")
