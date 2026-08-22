# AI-Based Threat Intelligence Assistant
# Day 14 – CVE Search, Filtering & Pagination

**Date:** 29 July 2026

---

# Objective

The objective of today's session was to turn the local vulnerability store into a usable search API: path parameters, query-parameter filtering, database-side pagination, and indexing — implemented as `GET /cves` and `GET /cves/{cve_id}` in [backend/main.py](../backend/main.py).

---

# Topics Studied

## Path Parameters vs Query Parameters

A **path parameter** identifies a specific resource and is part of the URL structure:

```
GET /cves/{cve_id}          → GET /cves/CVE-2026-12345
```

A **query parameter** modifies or filters a collection and is optional:

```
GET /cves?severity=CRITICAL&min_cvss=9&limit=20&offset=0
```

In FastAPI, path parameters are declared with `Path(...)` and query parameters with `Query(...)`. The project validates both:

```python
CVE_ID_PATTERN = r"^CVE-\d{4}-\d{4,}$"

@app.get("/cves/{cve_id}", response_model=VulnerabilitySchema)
def get_cve(cve_id: str = ApiPath(pattern=CVE_ID_PATTERN), db: Session = Depends(get_db)):
    ...
```

A malformed `cve_id` (e.g. `/cves/DROP TABLE`) is rejected by FastAPI/Pydantic before the route body even runs — it never reaches a SQL query.

## The Search Endpoint

```python
@app.get("/cves", response_model=VulnerabilityPageSchema)
def search_cves(
    severity: str | None = Query(default=None, max_length=20),
    min_cvss: float | None = Query(default=None, ge=0, le=10),
    q: str | None = Query(default=None, min_length=2, max_length=100),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> VulnerabilityPageSchema:
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity.strip().upper())
    if min_cvss is not None:
        query = query.filter(Vulnerability.cvss_score >= min_cvss)
    if q:
        term = f"%{q.strip()}%"
        query = query.filter(or_(Vulnerability.cve_id.ilike(term), Vulnerability.description.ilike(term)))
    total = query.count()
    items = query.order_by(Vulnerability.last_modified.desc(), Vulnerability.cve_id.asc()) \
        .offset(offset).limit(limit).all()
    return VulnerabilityPageSchema(items=..., total=total, limit=limit, offset=offset)
```

Supports exactly the shapes from the brief:

```
GET /cves
GET /cves/{cve_id}
GET /cves?severity=CRITICAL
GET /cves?min_cvss=9
GET /cves?limit=20&offset=0
GET /cves?q=fabrik          (free-text search over cve_id/description)
```

## Why Filtering Must Happen in the Database, Not in Python

A wrong approach would fetch every row and filter with a Python list comprehension. That means:

- Every filter query still pays the cost of loading the *entire* table into memory.
- It doesn't scale — the NVD alone has 300,000+ CVEs.
- The database's own indexes are never used.

Instead, `query.filter(...)` builds a SQL `WHERE` clause that PostgreSQL/SQLite evaluates directly, only returning matching rows, and only *after* the `LIMIT`/`OFFSET` is applied.

## Parameterized Queries, Not String Concatenation

Every filter above is built with SQLAlchemy's expression API (`Vulnerability.severity == ...`, `.ilike(...)`), which always parameterizes values. The user-supplied `q` term is never spliced into a raw SQL string — this is what prevents SQL injection through the search box, and it happens automatically as a consequence of using the ORM correctly rather than as a manual escaping step.

## Offset Pagination

```python
.offset(offset).limit(limit)
```

`VulnerabilityPageSchema` returns `items`, `total`, `limit`, and `offset` together so a client can compute whether more pages exist (`offset + limit < total`) without a second request. `limit` is capped at 100 (`Query(..., le=100)`) — a client cannot force the server to return the entire table in one call, matching the Day 13 principle of never processing unbounded external — or internal — data in one response.

## Database Indexing

```python
cve_id = Column(String(30), primary_key=True, index=True)   # primary key is indexed automatically
severity = Column(String(20), index=True)
```

A database index lets PostgreSQL locate matching rows via a lookup structure (similar to a book's index) instead of scanning every row (`O(log n)` vs `O(n)`). `severity` is indexed because it's the most common filter (`WHERE severity = 'CRITICAL'`) — without the index, that query degrades to a full table scan as the table grows.

## Deterministic Ordering

Results are ordered by `last_modified DESC, cve_id ASC`. Pagination without a deterministic `ORDER BY` is a real bug: two consecutive `LIMIT/OFFSET` calls can return overlapping or missing rows if the underlying order isn't stable, especially if rows are being upserted concurrently by the ingestion service.

## Backward-Compatible Aliases

`GET /vulnerabilities` and `GET /vulnerabilities/{cve_id}` remain as thin wrappers around `search_cves`/`get_cve` so any earlier client code from Days 5–10 keeps working while `/cves` becomes the primary, documented interface.

---

# Architecture

```
Frontend / client
      │
      ▼  GET /cves?severity=CRITICAL&limit=20&offset=0
   FastAPI  (validates query params via Pydantic/Query())
      │
      ▼
SQLAlchemy query (filter → count → order_by → offset → limit)
      │
      ▼
PostgreSQL / SQLite (uses the severity/cve_id indexes)
      │
      ▼
VulnerabilityPageSchema  →  JSON response
```

---

# Practical Activities / Testing Performed

Ran the search API live against records ingested from the real NVD API (SQLite backend):

```
GET /cves?limit=5
→ 200 OK, 5 items returned, total=25, ordered by last_modified desc

GET /cves?q=XSS&limit=1
→ 200 OK, 1 match (CVE-2026-77027, CWE-79)

GET /cves/CVE-1999-00001   (non-existent CVE, valid pattern)
→ 404 Not Found

GET /cves/DROP TABLE        (invalid path pattern)
→ 422 Unprocessable Entity — rejected before reaching the database
```

- Confirmed `severity`/`min_cvss`/`q` filters compose correctly (combinable in one request).
- Confirmed pagination metadata (`total`, `limit`, `offset`) is returned alongside `items`.
- Confirmed the backward-compatible `/vulnerabilities` alias delegates to the same filtered/paginated query.

---

# Key Learnings

- Path parameters identify one resource; query parameters filter a collection.
- Filtering, counting, and pagination should all happen in the database — never in application code after loading everything.
- SQLAlchemy's expression API parameterizes values automatically, which is what actually prevents SQL injection (not manual string escaping).
- An index turns `WHERE severity = 'CRITICAL'` from a full table scan into a fast lookup; add indexes on columns you actually filter or sort by.
- Pagination needs a deterministic `ORDER BY` to be correct, not just fast.
- Bounding `limit` server-side (`le=100`) is a small but real defense against a client trying to dump the whole table in one call.

---

# Security Considerations

- **Input validation at the boundary**: `cve_id` path pattern and all `Query(...)` constraints reject malformed input via FastAPI/Pydantic before any database code runs.
- **No SQL injection surface**: filters are built exclusively with SQLAlchemy's parameterized expression API; the free-text `q` parameter is never concatenated into SQL.
- **Bounded responses**: `limit` is capped at 100 both to protect the server and to stop a client from exfiltrating the entire dataset in a single unauthenticated-looking call (the endpoint additionally sits behind the optional `X-API-Key` dependency and the global rate limiter).
- **Response schema, not raw ORM objects**: `VulnerabilitySchema`'s `extra="forbid"` config guarantees the API can never leak a column added to the `Vulnerability` model later without a deliberate schema update.

---

# Reflection

Today's session is what makes the previous nine days' ingestion pipeline actually useful to a human or a frontend: the data was already being collected and stored correctly, but there was no efficient way to ask for a subset of it. Pushing filtering, counting, and ordering down into the database — rather than doing any of it in Python — is the difference between an API that stays fast at 25 rows and one that stays fast at 300,000.

---

# Next Steps

- Add explicit error handling/HTTP status mapping for NVD and database failures (Day 15).
- Automate ingestion on an interval instead of manual `POST /cves/sync` calls (Day 16).
- Build the combined `/intelligence/{cve_id}` view on top of this search layer (Day 27).

---

# 🎯 End-of-Day Challenge — With Answers

**1. Difference between path and query parameters?**
✅ A path parameter identifies a specific resource (`/cves/{cve_id}`); a query parameter filters or modifies a collection request (`/cves?severity=CRITICAL`) and is optional.

**2. Why do we paginate?**
✅ To bound response size and memory/network cost regardless of how large the underlying table grows — a client should never be able to force the server to return every row in one call.

**3. Why should filtering happen in the database?**
✅ The database can use indexes and only transfer matching rows; filtering in application code after loading everything scales linearly with total table size instead of with the number of matches.

**4. What is a database index?**
✅ A structure the database maintains alongside a table so it can find rows matching a condition (or in a given order) without scanning every row — at the cost of extra storage and slightly slower writes.

**5. Why shouldn't the frontend retrieve every CVE?**
✅ It would be slow, memory-heavy on both ends, and defeats the purpose of server-side filtering; the frontend should ask for exactly the page/filter it needs via `/cves`.

---

# 🎤 Interview Questions

**Q1. How does this endpoint prevent SQL injection through the search box?**
By building every filter with SQLAlchemy's expression API (`.filter(Vulnerability.description.ilike(term))`), which parameterizes the value at the driver level. The user's text is passed as a bound parameter, never interpolated into a SQL string, so it cannot change the query's structure.

**Q2. Why is `ORDER BY` important for correct pagination, not just consistent-looking output?**
Without a deterministic order, the database is free to return rows in a different order on each call (especially as data changes between requests). Two sequential `LIMIT/OFFSET` calls could then return overlapping or skipped rows — a genuine correctness bug, not just a cosmetic one.

**Q3. What would you change if this table grew from 25 to 30 million rows?**
Offset pagination degrades on very large tables because the database still has to count past `offset` rows. At that scale you'd move to keyset/cursor pagination (`WHERE (last_modified, cve_id) < (last_seen_last_modified, last_seen_cve_id)`), which uses the index directly instead of skipping rows.

---

# ⚡ 5-Minute Revision

- Path parameter → identifies one resource.
- Query parameter → filters/modifies a collection.
- `Query(..., le=100)` → server-side bound, not just documentation.
- Filtering/pagination belongs in SQL, not Python.
- SQLAlchemy expression filters are parameterized → no SQL injection.
- Index → fast lookup on a filtered/sorted column.
- Deterministic `ORDER BY` → pagination correctness, not just style.
