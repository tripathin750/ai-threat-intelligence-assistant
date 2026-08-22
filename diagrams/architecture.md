# System Architecture

The end-to-end data pipeline, from external source to user interface.

```mermaid
flowchart TB
    NVD["NVD CVE API 2.0\n(external, live)"]

    subgraph Backend["FastAPI backend (backend/)"]
        direction TB
        Ingest["Ingestion Service\nfetch → normalize → validate → upsert\n(services/ingestion_service.py, fetch_cves.py)"]
        Sched["Scheduler (optional)\nservices/scheduler.py"]
        DB[("PostgreSQL / SQLite\nmodels.py")]
        AI["AI Analysis\nservices/ai_service.py"]
        ATT["ATT&CK Inference\nservices/attack_service.py"]
        MIT["Mitigation Engine\nservices/mitigation_service.py"]
        Intel["Intelligence Service\nservices/intelligence_service.py"]
        API["FastAPI routes\nmain.py"]
        Sec["Security middleware\nrate limit · API key · headers\nsecurity.py"]
    end

    Dash["Dashboard\n(frontend/, static, served at /dashboard/)"]
    Client(["Browser / API client"])

    NVD -->|"HTTPS GET, paginated"| Ingest
    Sched -->|"on interval"| Ingest
    Ingest -->|"upsert"| DB
    DB --> Intel
    Intel --> AI
    Intel --> ATT
    Intel --> MIT
    AI --> Intel
    ATT --> Intel
    MIT --> Intel
    Intel --> API
    DB --> API
    Sec -.->|"wraps every route"| API
    API -->|"JSON"| Dash
    API -->|"JSON"| Client
    Dash --> Client
```

**Design principle carried through every layer:** NVD is the sole authoritative source of vulnerability facts. Everything generated inside the Backend box (AI Analysis, ATT&CK Inference, Mitigation Engine) is advisory, evidence-labelled, and never overwrites or contradicts what NVD reported — see `IntelligenceResponseSchema.disclaimer` in [../backend/schemas.py](../backend/schemas.py).
