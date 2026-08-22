# Database Schema (Entity-Relationship Diagram)

Generated from the live SQLAlchemy models ([../backend/models.py](../backend/models.py)); matches [../database/schema.sql](../database/schema.sql).

```mermaid
erDiagram
    VULNERABILITY {
        string cve_id PK
        text description
        float cvss_score
        string severity
        string cwe_id
        datetime published_date
        datetime last_modified
        string source
    }

    ATTACK_TECHNIQUE {
        string technique_id PK
        string name
        text description
        json tactics
        string external_url
    }

    INTELLIGENCE_ANALYSIS {
        int id PK
        string cve_id FK
        text summary
        text impact
        text affected_component
        string risk
        float confidence
        json evidence
        string model
        datetime generated_at
    }

    MITIGATION_RECOMMENDATION {
        int id PK
        string cve_id FK
        text immediate_action
        text short_term
        text long_term
        json recommendations
        string source
        datetime generated_at
    }

    VULNERABILITY_ATTACK_MAPPING {
        int id PK
        string cve_id FK
        string technique_id FK
        string mapping_type "inferred | official"
        float confidence
        text rationale
        datetime created_at
    }

    SYNC_STATE {
        string source PK
        datetime last_successful_sync
        datetime last_attempted_sync
        int updated_records
    }

    VULNERABILITY ||--o| INTELLIGENCE_ANALYSIS : "has one (unique cve_id)"
    VULNERABILITY ||--o| MITIGATION_RECOMMENDATION : "has one (unique cve_id)"
    VULNERABILITY ||--o{ VULNERABILITY_ATTACK_MAPPING : "has many"
    ATTACK_TECHNIQUE ||--o{ VULNERABILITY_ATTACK_MAPPING : "mapped by"
```

**Notes:**
- `INTELLIGENCE_ANALYSIS.cve_id` and `MITIGATION_RECOMMENDATION.cve_id` are each `UNIQUE` — a true one-to-one relationship enforced at the database level, not just assumed by the ORM (see [docs/Day21.md](../docs/Day21.md)).
- `VULNERABILITY_ATTACK_MAPPING` has a composite `UNIQUE(cve_id, technique_id)` constraint, preventing the same technique from being mapped twice to one CVE.
- All three child tables cascade-delete (`ondelete="CASCADE"`) when their parent `Vulnerability` row is removed — no orphaned advisory records can exist.
- `SYNC_STATE` has no foreign key to `Vulnerability` — it tracks ingestion progress per source (`"NVD"`), independent of any specific CVE.
