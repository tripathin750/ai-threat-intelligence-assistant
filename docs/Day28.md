# AI-Based Threat Intelligence Assistant
# Day 28 – Frontend Dashboard

**Date:** 12 August 2026

---

# Objective

Build a working interface over the API: search/filter, a CVE list, and an intelligence detail panel — [frontend/index.html](../frontend/index.html), [frontend/app.js](../frontend/app.js), [frontend/styles.css](../frontend/styles.css), served by FastAPI itself at `/dashboard/`.

A note on scope: this implementation uses plain HTML/CSS/vanilla JavaScript rather than React. That's a deliberate choice worth stating explicitly rather than silently diverging from the original plan — see the rationale below — not an unfinished step toward a React app.

---

# Topics Studied

## Why Vanilla JS Instead of React Here

- **No build step.** `app.mount("/dashboard", StaticFiles(directory=FRONTEND_DIR, html=True))` (`main.py`) serves the three files directly — there's no `npm install`/bundler dependency for anyone running this project to get the dashboard working, which matters for a project meant to be easy to check out and run end-to-end.
- **The UI's actual complexity doesn't need component state management.** There are exactly two pieces of client state (the search/pagination params and which CVE is selected) — a single `state` object and direct DOM updates (Day 28's `app.js`) cover this without the overhead a component framework would add for a UI this size.
- **It keeps the "what does this page actually do" fully readable in ~125 lines of one file** — valuable for a dissertation artifact meant to be read and reviewed, not just run.

This tradeoff would flip for a larger UI (more views, more shared component state, more interactive complexity) — noted honestly as a scope decision, not a limitation being hidden.

## Serving Static Files From FastAPI Itself

```python
app.mount("/dashboard", StaticFiles(directory=FRONTEND_DIR, html=True), name="dashboard")
```

One process serves both the API and the dashboard — appropriate for this project's size, and it means the whole system (API + UI) starts with a single `uvicorn` command, no separate frontend dev server required to actually use it.

## Search/Filter/Pagination Driven Entirely by the Day 14 API

```javascript
function paramsForSearch() {
  const params = new URLSearchParams({ limit: state.limit, offset: state.offset });
  const q = $("search-input").value.trim();
  const severity = $("severity-select").value;
  const score = $("cvss-input").value;
  if (q.length >= 2) params.set("q", q);
  if (severity) params.set("severity", severity);
  if (score) params.set("min_cvss", score);
  return params;
}

async function loadCves() {
  const page = await api(`/cves?${paramsForSearch()}`);
  ...
  $("previous-button").disabled = state.offset === 0;
  $("next-button").disabled = state.offset + state.limit >= page.total;
}
```

The dashboard does no client-side filtering or pagination math beyond what `total`/`limit`/`offset` already provide — it's a thin client over the same search API documented on Day 14, not a second implementation of search logic.

## Rendering the Combined Intelligence View

```javascript
async function loadIntelligence(cveId) {
  const intelligence = await api(`/intelligence/${encodeURIComponent(cveId)}`);
  renderIntelligence(intelligence);
}

function renderIntelligence(data) {
  $("analysis-summary").textContent = data.analysis.summary;
  ...
  if (!data.attack_mappings.length) {
    note.textContent = "No ATT&CK technique was inferred from a sufficiently specific NVD description signal.";
  }
  for (const mapping of data.attack_mappings) { ... item.append(title, rationale); }
  ...
}
```

Notice the dashboard explicitly renders the *empty* ATT&CK mappings case with a clear explanation, rather than showing a blank section that could read as a loading failure — carrying the Day 24 principle ("zero mappings is a valid, honest outcome") through to the UI, not just the API.

## `textContent`, Not `innerHTML`

Every place a value from the API is rendered — `description.textContent = cve.description`, `title.textContent = ...` — uses `textContent`, never `innerHTML`. Since CVE descriptions come from an external, not-fully-trusted source (Day 11's trust boundary again), rendering them as plain text rather than parsed HTML means a description containing `<script>` or other markup is displayed as literal text, not executed — the dashboard's actual XSS defense, achieved by using the right DOM API rather than any explicit sanitization step.

## `encodeURIComponent` on Path Segments

```javascript
api(`/intelligence/${encodeURIComponent(cveId)}`)
```

Even though `cveId` values only ever come from the app's own rendered CVE list (not raw user typing) in the current UI, encoding it before interpolating into a URL path is a correct, cheap habit that prevents a malformed or unexpected CVE ID from corrupting the request's path structure.

## Explicit Loading/Error/Empty States

```javascript
setStatus(page.total ? "Select a CVE to inspect its intelligence." : "No local CVEs yet. Sync recent NVD data to begin.");
...
} catch (error) { setStatus(error.message, true); }
```

A single `#status` element carries all three states (loading, informative, error), styled distinctly (`.status.error`) — the dashboard never fails silently, and the error message shown is the same `detail` string the backend's error-handling layer (Day 15) deliberately keeps safe and generic.

---

# Practical Activities / Testing Performed

- Verified `GET /dashboard/` returns `200` and serves `index.html`.
- Manually exercised the full user flow against the live app: sync → search/filter by severity and minimum CVSS → select a CVE → view generated intelligence (summary, ATT&CK mappings or the explicit "none inferred" message, mitigations, evidence) → paginate.
- Confirmed the "no ATT&CK mapping" and "no CVSS score" states both render clear, honest messaging rather than blank or misleading UI.

---

# Key Learnings

- A framework isn't required to build a clean, maintainable UI — it's a tradeoff against a UI's actual state-management complexity, and this dashboard's complexity doesn't cross that threshold.
- `textContent` over `innerHTML` is a simple, effective, and often-overlooked default defense against reflecting untrusted API data as executable markup.
- A UI's honesty about "nothing was found here" (empty ATT&CK mappings, missing CVSS) matters as much as the backend's honesty about the same thing — the principle has to survive all the way to what a human actually reads.
- Serving the frontend from the same process as the API is a legitimate simplicity choice for a project at this scale.

---

# Security Considerations

- **XSS**: mitigated by consistent `textContent` usage rather than `innerHTML`, for every piece of API-sourced data rendered.
- **CORS**: the dashboard is same-origin with the API (served from `/dashboard/` by the same FastAPI app), so it doesn't rely on the configured `ALLOWED_ORIGINS` CORS policy at all in normal use — that policy exists for a separately-hosted frontend or external client.
- **No credentials handled client-side**: the dashboard makes unauthenticated requests in local development (no `API_KEY` configured by default); if `API_KEY` is set for a deployment, the current dashboard would need a mechanism to supply `X-API-Key` — a noted gap, not a currently exercised path, worth flagging for anyone deploying with an API key enabled.

---

# Reflection

Watching the actual data — a real NVD-sourced CVE, a generated summary, an inferred (or honestly absent) ATT&CK mapping, and mitigation guidance — render in a browser is what made the whole ten-plus-day pipeline feel real rather than abstract. Keeping the frontend simple meant almost no time was spent fighting tooling, and all of it went into making sure the UI told the truth about what the backend actually knew.

---

# Next Steps

- Formal security review pass across the whole application, frontend included (Day 29).
- Note the `API_KEY` + dashboard gap above as a concrete follow-up if the project is deployed with authentication enabled.

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why does this dashboard use vanilla JavaScript instead of React?**
✅ The UI's actual state-management needs (search params, selected CVE) are small enough not to need a component framework, and avoiding a build step keeps the project easy to check out and run as a single `uvicorn` command — a deliberate scope decision, not an oversight.

**2. What's the dashboard's actual XSS defense, and why does it work without an explicit sanitization step?**
✅ Every API-sourced value is assigned via `element.textContent`, which the browser always renders as literal text — never parsed as HTML/JS — regardless of what the CVE description or any other field contains.

**3. Why does the UI explicitly render "No ATT&CK technique was inferred..." instead of just showing an empty section?**
✅ To carry through the Day 24 principle that a deliberate, honest "nothing here" is different from a bug or a loading failure — the UI states which one it is instead of leaving the viewer to guess.

---

# 🎤 Interview Questions

**Q1. If a CVE description contained `<img src=x onerror=alert(1)>`, what would actually happen in this dashboard?**
It would be displayed as the literal text `<img src=x onerror=alert(1)>` inside the description `<p>` element, because `description.textContent = cve.description` never parses the string as markup — no script would execute.

**Q2. What would you need to add to this dashboard to support a deployment with `API_KEY` enabled?**
A way to supply an API key (e.g. a settings/login step storing it in memory, not `localStorage` for anything sensitive) and include it as `X-API-Key` on every `fetch` call in `api()` — currently the dashboard assumes the open, no-auth local-development configuration.

---

# ⚡ 5-Minute Revision

- Vanilla JS chosen deliberately: small state surface, no build step, single-process deployment.
- Thin client over the Day 14 search API — no reimplemented filtering/pagination logic.
- `textContent`, never `innerHTML` → the actual XSS defense.
- Empty/absent states rendered explicitly and honestly, not left blank.
- Same-origin with the API → CORS policy isn't exercised by the dashboard itself.
