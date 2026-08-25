# System Architecture

The end-to-end data pipeline, from external source to user interface.

```mermaid
flowchart TB
    NVD["NVD CVE API 2.0\n(external, live)"]
    Gemini["Google Gemini API\n(external, optional, free tier)"]

    subgraph Backend["FastAPI backend (backend/)"]
        direction TB
        Ingest["Ingestion Service\nfetch → normalize → validate → upsert\n(services/ingestion_service.py, fetch_cves.py)"]
        Sched["Scheduler (optional)\nservices/scheduler.py"]
        DB[("PostgreSQL / SQLite\nmodels.py")]
        LLM["LLM Analyser (optional)\nservices/llm_service.py\ngenerate_analysis()"]
        AI["Deterministic Analyser\nservices/ai_service.py\n(always-available fallback)"]
        ATT["ATT&CK Inference\nservices/attack_service.py\n(keyword fallback)"]
        MIT["Mitigation Engine\nservices/mitigation_service.py\n(rule-based fallback)"]
        Intel["Intelligence Service\nservices/intelligence_service.py\n(orchestrates + chooses LLM vs. fallback)"]
        API["FastAPI routes\nmain.py"]
        Sec["Security middleware\nrate limit · API key · headers\nsecurity.py"]
    end

    Dash["Dashboard\n(frontend/, static, served at /dashboard/)"]
    Client(["Browser / API client"])

    NVD -->|"HTTPS GET, paginated"| Ingest
    Sched -->|"on interval"| Ingest
    Ingest -->|"upsert"| DB
    DB --> Intel
    Intel -->|"ENABLE_LLM_ANALYSIS=true\n+ GEMINI_API_KEY set"| LLM
    LLM -->|"HTTPS, structured JSON"| Gemini
    LLM -.->|"on any failure: timeout,\nrate limit, bad schema"| AI
    Intel -->|"no key / disabled / LLM failed"| AI
    LLM -->|"attack_techniques + mitigations\n(when it ran)"| Intel
    AI --> Intel
    Intel -->|"only when LLM did not run"| ATT
    Intel -->|"only when LLM did not run"| MIT
    ATT --> Intel
    MIT --> Intel
    Intel --> API
    DB --> API
    Sec -.->|"wraps every route"| API
    API -->|"JSON"| Dash
    API -->|"JSON"| Client
    Dash --> Client
```

**Design principle carried through every layer:** NVD is the sole authoritative source of vulnerability facts. Everything generated inside the Backend box (LLM Analyser, Deterministic Analyser, ATT&CK Inference, Mitigation Engine) is advisory, evidence-labelled, and never overwrites or contradicts what NVD reported — see `IntelligenceResponseSchema.disclaimer` in [../backend/schemas.py](../backend/schemas.py).

**Two analysers, one contract:** `intelligence_service.py` always calls `llm_service.generate_analysis()`, which itself decides whether to call Gemini or go straight to the deterministic analyser (see [llm-decision-flow.md](llm-decision-flow.md)). Either way it returns the same `AnalysisResult` shape, so the rest of the pipeline — persistence, schema validation, the API response — never needs to know which one ran. This project is free by default (no LLM call, no external cost); Gemini is an opt-in upgrade gated by two independent settings, never silently enabled by one stray env var.
