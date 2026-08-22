"""FastAPI entrypoint for the AI Threat Intelligence Assistant MVP."""

from contextlib import asynccontextmanager
import logging
from pathlib import Path
from typing import AsyncGenerator

from fastapi import Depends, FastAPI, HTTPException, Path as ApiPath, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from sqlalchemy import or_, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .config import settings
from .database import SessionLocal, get_db, init_db
from .fetch_cves import NVDRequestError, VulnerabilityValidationError, fetch_latest_cves, normalize_cve
from .logging_config import configure_logging
from .models import AttackTechnique, Vulnerability
from .schemas import (
    AttackTechniqueSchema,
    IntelligenceResponseSchema,
    SyncResultSchema,
    VulnerabilityPageSchema,
    VulnerabilitySchema,
)
from .security import RateLimitMiddleware, SecurityHeadersMiddleware, verify_api_key
from .services.attack_service import seed_attack_catalog
from .services.ingestion_service import synchronize_nvd
from .services.intelligence_service import build_intelligence
from .services.scheduler import NvdSyncScheduler


configure_logging()
logger = logging.getLogger(__name__)
FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
CVE_ID_PATTERN = r"^CVE-\d{4}-\d{4,}$"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    init_db()
    db = SessionLocal()
    try:
        seed_attack_catalog(db)
    finally:
        db.close()
    scheduler = NvdSyncScheduler(settings.sync_interval_minutes) if settings.enable_scheduler else None
    if scheduler:
        scheduler.start()
        logger.info("NVD scheduler enabled; interval_minutes=%s", settings.sync_interval_minutes)
    yield
    if scheduler:
        scheduler.stop()


app = FastAPI(
    title="AI Threat Intelligence Assistant",
    description=(
        "Evidence-grounded CVE ingestion, ATT&CK inference, and mitigation guidance. "
        "AI-assisted conclusions are advisory, not authoritative vulnerability facts."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
)
if settings.allowed_hosts != ("*",):
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.rate_limit_per_minute)
app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(SQLAlchemyError)
async def database_exception_handler(_: Request, exc: SQLAlchemyError) -> JSONResponse:
    logger.exception("database request failed", exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "A database operation could not be completed."},
    )


@app.get("/")
def home() -> dict[str, str]:
    return {"message": "Welcome to the AI Threat Intelligence Assistant", "dashboard": "/dashboard/"}


@app.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "ok"}


@app.get("/about")
def about() -> dict[str, str]:
    return {
        "project": "AI Threat Intelligence Assistant",
        "author": "Nitesh Tripathi",
        "intelligence_policy": "NVD is authoritative; analysis and ATT&CK mappings are advisory.",
    }


@app.get("/cves/live", response_model=list[VulnerabilitySchema], dependencies=[Depends(verify_api_key)])
def get_live_cves(limit: int = Query(default=5, ge=1, le=100)) -> list[dict[str, object]]:
    """Preview recent NVD CVEs without writing to the local database."""
    try:
        payload = fetch_latest_cves(limit)
        return _extract_valid_records(payload)[0]
    except NVDRequestError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="NVD is unavailable.") from exc


@app.post("/cves/sync", response_model=SyncResultSchema, dependencies=[Depends(verify_api_key)])
def sync_cves(
    limit: int = Query(default=100, ge=1, le=2000), db: Session = Depends(get_db)
) -> SyncResultSchema:
    """Incrementally fetch, validate and upsert NVD records."""
    try:
        return synchronize_nvd(db, limit=limit)
    except NVDRequestError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="NVD is unavailable.") from exc


@app.get("/cves", response_model=VulnerabilityPageSchema, dependencies=[Depends(verify_api_key)])
def search_cves(
    severity: str | None = Query(default=None, max_length=20),
    min_cvss: float | None = Query(default=None, ge=0, le=10),
    q: str | None = Query(default=None, min_length=2, max_length=100),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> VulnerabilityPageSchema:
    """Search local CVEs with database-side filtering and offset pagination."""
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity.strip().upper())
    if min_cvss is not None:
        query = query.filter(Vulnerability.cvss_score >= min_cvss)
    if q:
        # Parameterized SQLAlchemy expressions prevent user text becoming SQL.
        term = f"%{q.strip()}%"
        query = query.filter(or_(Vulnerability.cve_id.ilike(term), Vulnerability.description.ilike(term)))
    total = query.count()
    items = (
        query.order_by(Vulnerability.last_modified.desc(), Vulnerability.cve_id.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return VulnerabilityPageSchema(
        items=_validate_stored_records(items),
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get("/cves/{cve_id}", response_model=VulnerabilitySchema, dependencies=[Depends(verify_api_key)])
def get_cve(
    cve_id: str = ApiPath(pattern=CVE_ID_PATTERN), db: Session = Depends(get_db)
) -> VulnerabilitySchema:
    vulnerability = _get_vulnerability_or_404(db, cve_id)
    return VulnerabilitySchema.model_validate(vulnerability)


@app.get("/vulnerabilities", response_model=list[VulnerabilitySchema], dependencies=[Depends(verify_api_key)])
def list_vulnerabilities(
    limit: int = Query(default=20, ge=1, le=100),
    severity: str | None = Query(default=None, max_length=20),
    db: Session = Depends(get_db),
) -> list[VulnerabilitySchema]:
    """Backward-compatible alias for the original local vulnerability list."""
    page = search_cves(severity=severity, min_cvss=None, q=None, limit=limit, offset=0, db=db)
    return page.items


@app.get("/vulnerabilities/{cve_id}", response_model=VulnerabilitySchema, dependencies=[Depends(verify_api_key)])
def get_vulnerability(
    cve_id: str = ApiPath(pattern=CVE_ID_PATTERN), db: Session = Depends(get_db)
) -> VulnerabilitySchema:
    return get_cve(cve_id=cve_id, db=db)


@app.get("/attack/techniques", response_model=list[AttackTechniqueSchema], dependencies=[Depends(verify_api_key)])
def list_attack_techniques(
    q: str | None = Query(default=None, min_length=2, max_length=100),
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[AttackTechniqueSchema]:
    query = db.query(AttackTechnique)
    if q:
        query = query.filter(
            or_(AttackTechnique.technique_id.ilike(f"%{q}%"), AttackTechnique.name.ilike(f"%{q}%"))
        )
    return [
        AttackTechniqueSchema.model_validate(item)
        for item in query.order_by(AttackTechnique.technique_id).limit(limit)
    ]


@app.post(
    "/intelligence/{cve_id}/analyze",
    response_model=IntelligenceResponseSchema,
    dependencies=[Depends(verify_api_key)],
)
def analyse_cve(
    cve_id: str = ApiPath(pattern=CVE_ID_PATTERN),
    refresh: bool = Query(default=True),
    db: Session = Depends(get_db),
) -> IntelligenceResponseSchema:
    """Create or refresh persisted, evidence-labelled intelligence for a CVE."""
    return build_intelligence(db, _get_vulnerability_or_404(db, cve_id), refresh=refresh)


@app.get(
    "/intelligence/{cve_id}",
    response_model=IntelligenceResponseSchema,
    dependencies=[Depends(verify_api_key)],
)
def get_intelligence(
    cve_id: str = ApiPath(pattern=CVE_ID_PATTERN),
    refresh: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> IntelligenceResponseSchema:
    """Return the persisted intelligence view, creating one for a new CVE if needed."""
    return build_intelligence(db, _get_vulnerability_or_404(db, cve_id), refresh=refresh)


def _validate_stored_records(items: list[Vulnerability]) -> list[VulnerabilitySchema]:
    """Validate stored rows the same way inbound NVD data is validated.

    A row already in the database is not automatically trustworthy forever:
    the validation schema itself can tighten over time (e.g. the stricter
    CVE_ID_PATTERN added after this project's very first manually-inserted
    test row), and a single non-conforming legacy row must never turn a
    search response into a 500 for every other, valid record alongside it.
    This mirrors the "skip and log, don't crash" discipline already applied
    to inbound NVD records in _extract_valid_records().
    """
    validated: list[VulnerabilitySchema] = []
    for item in items:
        try:
            validated.append(VulnerabilitySchema.model_validate(item))
        except ValidationError:
            logger.warning("stored record %s failed response validation; omitted from results", item.cve_id)
    return validated


def _get_vulnerability_or_404(db: Session, cve_id: str) -> Vulnerability:
    vulnerability = db.get(Vulnerability, cve_id.upper())
    if vulnerability is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found.")
    return vulnerability


def _extract_valid_records(payload: dict[str, object]) -> tuple[list[dict[str, object]], int]:
    """Discard malformed remote entries so they never reach a response or database."""
    records: list[dict[str, object]] = []
    skipped = 0
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return records, skipped
    for item in vulnerabilities:
        if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
            skipped += 1
            continue
        try:
            records.append(normalize_cve(item["cve"]))
        except VulnerabilityValidationError:
            skipped += 1
    return records, skipped


app.mount("/dashboard", StaticFiles(directory=FRONTEND_DIR, html=True), name="dashboard")
