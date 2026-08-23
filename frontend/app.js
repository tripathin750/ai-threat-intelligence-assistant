const state = { limit: 12, offset: 0, total: 0, selectedId: null };
const $ = (id) => document.getElementById(id);

// Only relevant when the deployment sets API_KEY (backend/.env) and every
// route starts requiring X-API-Key. Kept in sessionStorage (this tab only,
// cleared when the tab closes) rather than localStorage — deliberately not
// persisted long-term, since it's a bearer credential.
const API_KEY_STORAGE_KEY = "ti_api_key";

function setStatus(message, isError = false) {
  const element = $("status");
  element.textContent = message;
  element.classList.toggle("error", isError);
}

function getStoredApiKey() {
  try {
    return sessionStorage.getItem(API_KEY_STORAGE_KEY) || "";
  } catch {
    return ""; // sessionStorage can be unavailable (e.g. some private-browsing modes)
  }
}

function initApiKeyField() {
  const input = $("api-key-input");
  const stored = getStoredApiKey();
  if (stored) input.value = stored;
  input.addEventListener("change", () => {
    try {
      if (input.value) sessionStorage.setItem(API_KEY_STORAGE_KEY, input.value);
      else sessionStorage.removeItem(API_KEY_STORAGE_KEY);
    } catch {
      // sessionStorage unavailable — the key still works for this page load via the input's own value.
    }
  });
}

async function api(path, options = {}) {
  const apiKey = getStoredApiKey();
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (apiKey) headers["X-API-Key"] = apiKey;
  const response = await fetch(path, { headers, ...options });
  if (response.status === 401) {
    throw new Error("Invalid or missing API key. Enter it in the \"API key\" field above.");
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

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
  setStatus("Loading local CVEs…");
  try {
    const page = await api(`/cves?${paramsForSearch()}`);
    state.total = page.total;
    renderCves(page.items);
    $("result-count").textContent = `${page.total} result${page.total === 1 ? "" : "s"}`;
    $("previous-button").disabled = state.offset === 0;
    $("next-button").disabled = state.offset + state.limit >= page.total;
    setStatus(page.total ? "Select a CVE to inspect its intelligence." : "No local CVEs yet. Sync recent NVD data to begin.");
  } catch (error) {
    setStatus(error.message, true);
  }
}

function renderCves(items) {
  const list = $("cve-list");
  list.replaceChildren();
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "empty-list";
    empty.textContent = "No vulnerabilities match this search.";
    list.append(empty);
    return;
  }
  for (const cve of items) {
    const button = document.createElement("button");
    button.className = `cve-card${state.selectedId === cve.cve_id ? " selected" : ""}`;
    button.type = "button";
    button.addEventListener("click", () => loadIntelligence(cve.cve_id));
    const top = document.createElement("div"); top.className = "cve-card-top";
    const id = document.createElement("span"); id.className = "cve-id"; id.textContent = cve.cve_id;
    const severity = document.createElement("span"); severity.className = `badge badge-${cve.severity || "neutral"}`; severity.textContent = cve.severity || "UNSCORED";
    top.append(id, severity);
    const description = document.createElement("p"); description.className = "description"; description.textContent = cve.description;
    button.append(top, description); list.append(button);
  }
}

async function loadIntelligence(cveId) {
  state.selectedId = cveId;
  $("selected-cve").textContent = cveId;
  setStatus(`Generating evidence-grounded intelligence for ${cveId}…`);
  try {
    const intelligence = await api(`/intelligence/${encodeURIComponent(cveId)}`);
    renderIntelligence(intelligence);
    setStatus("Intelligence record ready.");
    loadCves();
  } catch (error) {
    setStatus(error.message, true);
  }
}

// Splits the (single-string) generated summary into standalone sentences so
// it renders as bullet points rather than one dense paragraph. Purely
// presentational — the underlying data is still one evidence-grounded string.
function splitIntoPoints(text) {
  return text
    .split(/(?<=[.!?])\s+(?=[A-Z(])/)
    .map((sentence) => sentence.trim())
    .filter(Boolean);
}

function renderIntelligence(data) {
  $("intelligence-empty").hidden = true;
  $("intelligence-content").hidden = false;
  const summary = $("analysis-summary"); summary.replaceChildren();
  for (const point of splitIntoPoints(data.analysis.summary)) {
    const item = document.createElement("li"); item.textContent = point; summary.append(item);
  }
  $("analysis-impact").textContent = data.analysis.impact;
  $("analysis-risk").textContent = `Risk: ${data.analysis.risk}`;
  $("analysis-risk").className = `badge badge-${data.analysis.risk}`;
  $("analysis-confidence").textContent = `Confidence: ${Math.round(data.analysis.confidence * 100)}%`;
  const attacks = $("attack-list"); attacks.replaceChildren();
  if (!data.attack_mappings.length) {
    const note = document.createElement("p"); note.className = "secondary-text"; note.textContent = "No ATT&CK technique was inferred from a sufficiently specific NVD description signal."; attacks.append(note);
  }
  for (const mapping of data.attack_mappings) {
    const item = document.createElement("div"); item.className = "attack-item";
    const title = document.createElement("strong"); title.textContent = `${mapping.technique.technique_id} — ${mapping.technique.name}`;
    const rationale = document.createElement("p"); rationale.textContent = mapping.rationale;
    item.append(title, rationale); attacks.append(item);
  }
  $("immediate-action").textContent = data.mitigations.immediate_action;
  const mitigations = $("mitigation-list"); mitigations.replaceChildren();
  for (const recommendation of data.mitigations.recommendations) { const item = document.createElement("li"); item.textContent = recommendation; mitigations.append(item); }
  const evidence = $("evidence-list"); evidence.replaceChildren();
  for (const entry of data.analysis.evidence) { const item = document.createElement("li"); item.textContent = entry; evidence.append(item); }
}

async function syncCves() {
  const button = $("sync-button"); button.disabled = true; setStatus("Synchronizing recent NVD CVEs…");
  try {
    const result = await api("/cves/sync?limit=2000", { method: "POST" });
    state.offset = 0;
    setStatus(`Sync complete: ${result.created} created, ${result.updated} updated, ${result.skipped} skipped.`);
    await loadCves();
  } catch (error) { setStatus(error.message, true); }
  finally { button.disabled = false; }
}

// Decorative digital-rain background for the Matrix theme. Skipped entirely
// under prefers-reduced-motion, and cheap enough (one fillRect + column of
// glyphs, ~16fps) not to compete with the actual dashboard for CPU.
function initMatrixRain() {
  const canvas = $("matrix-rain");
  if (!canvas || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const ctx = canvas.getContext("2d");
  const glyphs = "アイウエオカキクケコサシスセソタチツテト0123456789";
  const fontSize = 15;
  let columns = [];

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    const count = Math.floor(canvas.width / fontSize);
    columns = Array.from({ length: count }, () => Math.floor(Math.random() * -50));
  }
  resize();
  window.addEventListener("resize", resize);

  ctx.font = `${fontSize}px "JetBrains Mono", monospace`;
  setInterval(() => {
    ctx.fillStyle = "rgba(1, 6, 3, 0.15)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#39ff14";
    columns.forEach((y, i) => {
      ctx.fillText(glyphs[Math.floor(Math.random() * glyphs.length)], i * fontSize, y * fontSize);
      columns[i] = y * fontSize > canvas.height && Math.random() > 0.975 ? 0 : y + 1;
    });
  }, 60);
}

$("search-button").addEventListener("click", () => { state.offset = 0; loadCves(); });
$("search-input").addEventListener("keydown", (event) => { if (event.key === "Enter") { state.offset = 0; loadCves(); } });
$("sync-button").addEventListener("click", syncCves);
$("previous-button").addEventListener("click", () => { state.offset = Math.max(0, state.offset - state.limit); loadCves(); });
$("next-button").addEventListener("click", () => { state.offset += state.limit; loadCves(); });
initApiKeyField();
initMatrixRain();
loadCves();
