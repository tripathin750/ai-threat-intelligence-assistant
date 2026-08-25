# Decision Flow: `llm_service.generate_analysis()`

How the app chooses between a real Gemini call and the deterministic analyser, and why a failure at any point degrades safely instead of breaking the request. This project runs at zero cost by default — the two gates at the top are what keep it that way until a developer deliberately opts in.

```mermaid
flowchart TD
    Start(["generate_analysis(vulnerability)"]) --> GateKey{"GEMINI_API_KEY set?"}
    GateKey -- "no" --> Deterministic
    GateKey -- "yes" --> GateEnable{"ENABLE_LLM_ANALYSIS=true?"}
    GateEnable -- "no" --> Deterministic
    GateEnable -- "yes" --> Call["analyse_with_llm(vulnerability)\nPOST generateContent, responseSchema,\n~55s timeout"]

    Call --> Ok{"200 OK\nwithin timeout?"}
    Ok -- "no (timeout / rate limit /\nnetwork / non-2xx)" --> LogWarn["log warning + traceback"]
    Ok -- "yes" --> Parse{"response text is valid JSON\nmatching LLMAnalysisOutputSchema?"}
    Parse -- "no" --> LogWarn
    Parse -- "yes" --> Success["AnalysisResult\nmodel = \"gemini:&lt;model&gt;\"\nattack_techniques + mitigations from Gemini"]

    LogWarn --> Deterministic["analyse_vulnerability(vulnerability)\n(services/ai_service.py)\nmodel = \"evidence-based-rules-v1\""]
    Deterministic --> WasAttempt{"was this reached\nafter a real LLM attempt?"}
    WasAttempt -- "yes" --> Labelled["relabel model as\n\"evidence-based-rules-v1-fallback\"\n(so the DB shows an attempt happened)"]
    WasAttempt -- "no (gates closed)" --> Plain["model stays\n\"evidence-based-rules-v1\""]

    Success --> Return(["return AnalysisResult"])
    Labelled --> Return
    Plain --> Return
```

**The `model` field is the only signal downstream code needs.** `intelligence_service.py` never asks "did Gemini run?" directly — it checks whether `AnalysisResult.model` starts with `"gemini:"`. That one string tells it whether to trust the LLM's own `attack_techniques`/`mitigations` or fall back to the separate keyword-matching (`attack_service.py`) and rule-based (`mitigation_service.py`) services, and it's also what makes a genuinely-attempted-but-failed call visibly different in the data (`…-fallback` suffix) from a call that was never attempted at all.

**An empty `attack_techniques` list from Gemini is a real answer, not a gap.** The prompt explicitly instructs the model to return no mappings rather than force one — the same "no signal, no mapping" discipline the keyword matcher already followed — so `intelligence_service.py` must not paper over a confident "nothing matches" with a keyword-based guess.

**Every exit from this flow is designed to be non-fatal.** A Gemini outage, a rate limit, a malformed response, or simply no key configured all land on the same deterministic path that has run since before any LLM integration existed — `/intelligence` never 500s because of this optional layer.
