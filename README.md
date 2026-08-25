# AI-Based Threat Intelligence Assistant

An evidence-grounded vulnerability intelligence pipeline: it ingests CVEs from the National Vulnerability Database (NVD), normalizes and validates every record, stores them persistently, and layers advisory analysis, MITRE ATT&CK technique inference, and mitigation recommendations on top — all clearly labelled as advisory, with NVD remaining the authoritative source of vulnerability facts.

```
NVD API
   │
   ▼
Ingestion Service  (fetch → normalize → validate → upsert)
   │
   ▼
PostgreSQL / SQLite
   │
   ├──► AI Analysis        (evidence-grounded summary, impact, risk)
   ├──► ATT&CK Inference    (signal-matched, explicitly labelled "inferred")
   └──► Mitigation Engine   (severity + technique-aware recommendations)
   │
   ▼
FastAPI  (/cves, /intelligence/{cve_id}, /attack/techniques, ...)
   │
   ▼
Static dashboard (/dashboard/)
```

## Why "advisory, not authoritative"

Every AI-generated summary and every ATT&CK mapping in this project is produced from data already present in the stored NVD record — never invented — and is returned with an explicit `disclaimer` field and evidence list. Vulnerability facts (CVE ID, CVSS score, CWE) always come directly from NVD; the analysis layer explains and contextualizes that data, it does not replace it.

## Project layout

```
backend/
├── main.py                    FastAPI app: routes, middleware, lifespan
├── config.py                  Environment-driven settings (backend/.env)
├── database.py                SQLAlchemy engine/session/Base
├── models.py                  ORM models (Vulnerability, AttackTechnique, ...)
├── schemas.py                 Pydantic request/response schemas
├── fetch_cves.py              NVD client + extraction/normalization
├── security.py                Rate limiting + optional API-key auth
├── logging_config.py          Secret-free structured logging
├── data/attack_catalog.py     Curated ATT&CK technique + mitigation catalogue
├── services/
│   ├── ingestion_service.py   synchronize_nvd(): fetch → validate → upsert
│   ├── ai_service.py          Evidence-grounded analysis (deterministic)
│   ├── attack_service.py      ATT&CK catalogue seeding + signal-based inference
│   ├── mitigation_service.py  Severity/technique-aware mitigation guidance
│   ├── intelligence_service.py Combines the three into one persisted view
│   ├── scheduler.py           Optional background NVD sync thread
│   └── prompts.py             Unused-but-tested LLM prompt template (see docs/Day19.md)
└── tests/                     test_api.py (full API + auth + rate limit),
                                test_ingestion.py (upsert/duplicate handling, mocked NVD),
                                test_services.py, test_prompts.py, test_schemas.py, test_fetch_cves.py

frontend/                      Static dashboard served at /dashboard/
docs/                          Day-by-day learning log (Day01–Day30)
diagrams/                      Architecture, ER, and sequence diagrams (Mermaid)
dissertation/                  Consolidated implementation & evaluation report
database/                      Reference SQL schema
```

## ⚠️ One-time setup on this machine: a stray `DATABASE_URL` environment variable

Before running anything, know this: a **system-level Windows environment variable** named `DATABASE_URL` currently exists on this machine and **overrides `backend/.env`** (`config.py` reads whatever's already in the process environment first). Until it's removed, the app connects to whatever that system variable says — not to `backend/.env` — no matter what you edit in the file.

**Check what it's currently set to:**

```powershell
[Environment]::GetEnvironmentVariable("DATABASE_URL", "User")
[Environment]::GetEnvironmentVariable("DATABASE_URL", "Machine")
```

**Remove it** (then open a *new* terminal for the change to take effect):

```powershell
[Environment]::SetEnvironmentVariable("DATABASE_URL", $null, "User")
[Environment]::SetEnvironmentVariable("DATABASE_URL", $null, "Machine")   # only if the Machine check above printed something; needs an admin terminal
```

Once that's done, `backend/.env` (see below) becomes the single source of truth. Until then, every `uvicorn` run below uses whatever the system variable points at — verify with `echo $env:DATABASE_URL` in a fresh PowerShell window if anything looks unexpected.

## Running it locally — quick start (SQLite, zero setup)

> **On Windows PowerShell**: run each line below separately (press Enter after each), or join them with `;` — PowerShell doesn't understand bash's `&&`.

Install dependencies once from `backend/`:
```bash
cd backend
pip install -r requirements.txt
```

Then run the server **from the project root** (not from inside `backend/`) — `backend/main.py` uses relative imports (`from .config import settings`), so it only works when imported as part of the `backend` package:
```bash
cd ..
python -m uvicorn backend.main:app --reload
```

> Running `python -m uvicorn main:app --reload` from inside `backend/` fails with `ImportError: attempted relative import with no known parent package` — always reference it as `backend.main:app` from the project root instead.

With no `DATABASE_URL` anywhere (system variable removed, no `backend/.env`), `config.py` defaults to a local SQLite file (`backend/threat_intelligence.db`) — the API and dashboard work immediately, nothing to install or configure.

Then open:
- API docs: http://127.0.0.1:8000/docs
- Dashboard: http://127.0.0.1:8000/dashboard/

Try it end to end:
```bash
curl -X POST "http://127.0.0.1:8000/cves/sync?limit=20"   # ingest 20 real CVEs from NVD
curl "http://127.0.0.1:8000/cves?limit=5"                 # see them
```
...or just open the dashboard and click **Sync latest NVD CVEs**, then click any CVE card.

## Running it with PostgreSQL (the project's real, dedicated database)

This project's `backend/.env` is already configured to point at a **local PostgreSQL 18** database dedicated to this project (`threat_intelligence`, matching the very first Day 10 setup) — not the earlier-discovered Neon cloud instance, which turned out to also hold an unrelated app's tables and was never meant for this project.

1. Make sure PostgreSQL is running locally (Windows Services → `postgresql-x64-18`, or via pgAdmin) and the `threat_intelligence` database exists:
   ```powershell
   & "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -c "CREATE DATABASE threat_intelligence;"
   ```
   (skip if it already exists — it does on this machine).
2. Remove the stray system-level `DATABASE_URL` variable (see the section above) — otherwise it silently wins over `backend/.env`.
3. Open a **new** terminal, then run from the **project root** (see the note above about why `backend.main:app`, not `main:app`):
   ```bash
   python -m uvicorn backend.main:app --reload
   ```
4. Confirm it's really using PostgreSQL, not the SQLite fallback:
   ```bash
   curl http://127.0.0.1:8000/health
   ```
   and check the terminal log for `psycopg`/`postgresql` in any connection errors — a clean `{"status":"ok"}` with no `backend/threat_intelligence.db` file being created confirms Postgres is in use.

`backend/.env`'s current value (already verified working):
```
DATABASE_URL=postgresql+psycopg://postgres:mustang@localhost:5432/threat_intelligence
```
Change the password/host/db name there if your local setup differs.

## Key endpoints

| Endpoint | Purpose |
|---|---|
| `POST /cves/sync?limit=100` | Ingest new/changed CVEs from NVD (incremental) |
| `GET /cves?severity=&min_cvss=&q=&limit=&offset=` | Search/filter/paginate stored CVEs |
| `GET /cves/{cve_id}` | Fetch one stored CVE |
| `POST /intelligence/{cve_id}/analyze` | Generate/refresh the full intelligence view |
| `GET /intelligence/{cve_id}` | Read the persisted intelligence view |
| `GET /attack/techniques?q=` | Search the ATT&CK technique catalogue |
| `GET /health` | Liveness check (verifies DB connectivity) |

Set `API_KEY` in `backend/.env` to require an `X-API-Key` header on the endpoints above; unset, they're open (suitable for local development only). If set, the dashboard has an "API key" field (top-right) to supply it — stored in that browser tab's `sessionStorage` only, cleared when the tab closes.

## Configuration reference (`backend/.env`)

```
DATABASE_URL=postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/threat_intelligence
API_KEY=                       # optional; when set, required as X-API-Key
NVD_API_KEY=                   # optional; raises NVD's rate limit
ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
ALLOWED_HOSTS=*
RATE_LIMIT_PER_MINUTE=120
ENABLE_SCHEDULER=false
SYNC_INTERVAL_MINUTES=60
GEMINI_API_KEY=                 # optional; see "AI-generated analysis" below
GEMINI_MODEL=gemini-3.5-flash-lite
ENABLE_LLM_ANALYSIS=false       # must be explicitly "true" (as well as a key set) to use Gemini
```

`.env` files are gitignored — never commit real credentials.

### AI-generated analysis (optional, and free)

This project runs at **zero cost**: Render's free plan, Neon's free Postgres tier, and the public NVD API are all free. By default, every CVE's "AI-assisted summary," risk rating, and evidence list come from a deterministic, rules-based analyser (`backend/services/ai_service.py`, model name `evidence-based-rules-v1`) that reflows the NVD-supplied fields into readable text and invents nothing — no API key, no bill.

Setting `GEMINI_API_KEY` (and `ENABLE_LLM_ANALYSIS=true`) switches CVE analysis over to a real LLM call via [Google's Gemini API](https://aistudio.google.com/app/apikey) (`backend/services/llm_service.py`), using the schema-constrained prompt already defined in `backend/services/prompts.py`. Gemini's Flash / Flash-Lite models were chosen deliberately: Google AI Studio's free tier needs no credit card and is governed by per-minute/per-day rate limits rather than a metered credit pool, so it stays genuinely free — unlike Anthropic and OpenAI (paid per token with no ongoing free tier) or Hugging Face's own "free" tier (a $0.10/month credit pool that most modern chat models exhaust in a handful of requests, per HF's own pricing docs). `GEMINI_MODEL` defaults to `gemini-3.5-flash-lite`; Google's model catalogue shifts over time, so check [ai.google.dev/gemini-api/docs/models](https://ai.google.dev/gemini-api/docs/models) for current IDs.

Both switches (`GEMINI_API_KEY` set **and** `ENABLE_LLM_ANALYSIS=true`) are required before any Gemini call happens — leaving either at its default keeps the deterministic analyser in charge. Whenever Gemini *is* enabled, the model's JSON response is still validated with Pydantic (`LLMAnalysisOutputSchema`) before it's stored, exactly like inbound NVD data — a malformed response, a rate limit, or a network error falls back to the deterministic analyser automatically (recorded as `evidence-based-rules-v1-fallback` in the `model` field) rather than breaking `/intelligence`.

**Before any non-local deployment**, set `ALLOWED_HOSTS` explicitly to your real hostname(s) (e.g. `ALLOWED_HOSTS=api.example.com`) — the `*` default disables `TrustedHostMiddleware` entirely and is meant for local development only (see `docs/Day29.md`).

## Testing

```bash
cd ..   # project root
python -m unittest discover -s backend/tests -v
```

## Documentation

- [`docs/`](docs/) — the full Day 1–30 build log: theory, implementation notes, testing evidence, and reflection for every part of the system, from CTI/MITRE ATT&CK fundamentals through the complete pipeline and its evaluation.
- [`diagrams/`](diagrams/) — architecture, database ER, request-sequence, and LLM-fallback-decision diagrams (Mermaid; render natively on GitHub).
- [`dissertation/Implementation_and_Evaluation.md`](dissertation/Implementation_and_Evaluation.md) — a consolidated report synthesizing the full build into one dissertation-ready chapter, including real measured evaluation results.

## Author

Nitesh Tripathi
