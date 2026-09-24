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
    const badges = document.createElement("span"); badges.className = "cve-badges";
    const severity = document.createElement("span"); severity.className = `badge badge-${cve.severity || "neutral"}`; severity.textContent = cve.severity || "UNSCORED";
    badges.append(severity);
    if (cve.kev) {
      const kevBadge = document.createElement("span");
      kevBadge.className = "badge badge-kev";
      kevBadge.textContent = "KNOWN EXPLOITED";
      badges.append(kevBadge);
    }
    top.append(id, badges);
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
    loadImpactSummary();
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

function renderKevSection(kev) {
  const section = $("kev-section");
  section.hidden = !kev;
  if (!kev) return;
  $("kev-vendor-product").textContent = `${kev.vendor_project} — ${kev.product}`;
  $("kev-date-added").textContent = kev.date_added;
  $("kev-due-date").textContent = kev.due_date;
  $("kev-required-action").textContent = kev.required_action;
  const ransomware = $("kev-ransomware");
  ransomware.textContent = kev.known_ransomware_use === "Known" ? "Ransomware use: Known" : "Ransomware use: Unknown";
  ransomware.className = `badge ${kev.known_ransomware_use === "Known" ? "badge-CRITICAL" : "badge-neutral"}`;
}

// Fault tree (per CWE). Everything in the tree is LLM- or MITRE-derived text,
// so it is rendered with textContent only - never innerHTML.
function renderFaultTreeNode(nodesById, nodeId) {
  const node = nodesById.get(nodeId);
  const item = document.createElement("li");
  const box = document.createElement("span");
  box.className = `ft-node${node.gate === "NONE" ? " ft-leaf" : ""}`;
  if (node.gate !== "NONE") {
    const gate = document.createElement("span");
    gate.className = `ft-gate ft-gate-${node.gate}`;
    gate.textContent = node.gate;
    box.append(gate);
  }
  const label = document.createElement("span");
  label.textContent = node.label;
  box.append(label);
  item.append(box);
  if (node.children.length) {
    const list = document.createElement("ul");
    for (const childId of node.children) list.append(renderFaultTreeNode(nodesById, childId));
    item.append(list);
  }
  return item;
}

// ---- Fault-tree diagram (SVG) --------------------------------------------
// Standard FTA notation: rectangle = event, circle = basic event (leaf),
// AND / OR gate symbols between an event and its inputs. Built with
// createElementNS + textContent only - labels are LLM/MITRE-derived.
const SVG_NS = "http://www.w3.org/2000/svg";
const FT = { slot: 200, boxW: 180, boxH: 76, gateH: 36, gateW: 24, gapTop: 16, gapBus: 14, gapBottom: 16, margin: 24 };
FT.pitch = FT.boxH + FT.gapTop + FT.gateH + FT.gapBus + FT.gapBottom;

function svgEl(name, attrs = {}, text) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value);
  if (text !== undefined) el.textContent = text;
  return el;
}

function wrapLabel(text, maxChars, maxLines) {
  const lines = []; let line = "";
  for (const word of text.split(/\s+/)) {
    if (word.length > maxChars) { // very long token: hard-split
      if (line) { lines.push(line); line = ""; }
      lines.push(word.slice(0, maxChars - 1) + "…"); continue;
    }
    if ((line + " " + word).trim().length > maxChars) { lines.push(line); line = word; }
    else line = (line + " " + word).trim();
  }
  if (line) lines.push(line);
  if (lines.length > maxLines) { lines.length = maxLines; lines[maxLines - 1] = lines[maxLines - 1].replace(/.?$/, "…"); }
  return lines;
}

function drawGateSymbol(gate, cx, top) {
  const { gateH: H, gateW: W } = FT;
  const shape = gate === "AND"
    ? `M ${-W} ${H} V ${W} A ${W} ${W} 0 0 1 ${W} ${W} V ${H} Z`
    : gate === "INHIBIT"
      ? `M ${-W * 0.6} 0 L ${W * 0.6} 0 L ${W} ${H / 2} L ${W * 0.6} ${H} L ${-W * 0.6} ${H} L ${-W} ${H / 2} Z`
      : `M ${-W} ${H} Q 0 ${H - 12} ${W} ${H} Q ${W * 0.95} ${H * 0.35} 0 0 Q ${-W * 0.95} ${H * 0.35} ${-W} ${H} Z`;
  const group = svgEl("g", { transform: `translate(${cx} ${top})`, class: `ft-svg-gate ft-svg-gate-${gate}` });
  group.append(svgEl("path", { d: shape }), svgEl("text", { x: 0, y: gate === "INHIBIT" ? H * 0.58 : H * 0.62, "text-anchor": "middle" }, gate === "INHIBIT" ? "INH" : gate));
  return group;
}

function renderFaultTreeDiagram(tree) {
  const nodesById = new Map(tree.nodes.map((node) => [node.id, node]));
  const pos = new Map(); let leafIndex = 0; let maxDepth = 0;
  (function place(id, depth) {
    const node = nodesById.get(id); maxDepth = Math.max(maxDepth, depth);
    if (!node.children.length) pos.set(id, { x: FT.margin + FT.slot * leafIndex++ + FT.slot / 2, depth });
    else {
      node.children.forEach((childId) => place(childId, depth + 1));
      const xs = node.children.map((childId) => pos.get(childId).x);
      pos.set(id, { x: (Math.min(...xs) + Math.max(...xs)) / 2, depth });
    }
  })(tree.root_id, 0);

  const width = Math.max(FT.margin * 2 + FT.slot * leafIndex, 900);
  const legendH = 74;
  // Wide enough that the legend line is never clipped on narrow trees.
  const height = FT.margin * 2 + FT.pitch * maxDepth + FT.boxH + legendH;
  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, width, height, role: "img", class: "ft-svg", "aria-label": "Fault tree diagram; a text outline follows" });
  const lines = svgEl("g", { class: "ft-svg-lines" }); const shapes = svgEl("g");
  svg.append(lines, shapes);
  const yOf = (depth) => FT.margin + depth * FT.pitch;

  for (const node of tree.nodes) {
    const { x, depth } = pos.get(node.id); const y = yOf(depth);
    const isLeaf = !node.children.length;
    const group = svgEl("g", { class: isLeaf ? "ft-svg-basic" : "ft-svg-event" });
    group.append(svgEl("title", {}, node.reason ? `${node.label}

Why: ${node.reason}` : node.label));
    if (isLeaf) {
      group.append(svgEl("circle", { cx: x, cy: y + 11, r: 11 }));
      group.append(svgEl("rect", { x: x - FT.boxW / 2, y: y + 26, width: FT.boxW, height: FT.boxH - 26, rx: 4 }));
    } else {
      group.append(svgEl("rect", { x: x - FT.boxW / 2, y, width: FT.boxW, height: FT.boxH, rx: 4 }));
    }
    const textTop = isLeaf ? y + 26 : y;
    const room = FT.boxH - (isLeaf ? 26 : 0);
    const wrapped = wrapLabel(node.label, 26, Math.floor((room - 8) / 13));
    const text = svgEl("text", { x, y: textTop + (room - wrapped.length * 13) / 2 + 10, "text-anchor": "middle" });
    wrapped.forEach((line, i) => text.append(svgEl("tspan", { x, dy: i === 0 ? 0 : 13 }, line)));
    group.append(text);
    shapes.append(group);

    if (!isLeaf) {
      const gateTop = y + FT.boxH + FT.gapTop;
      lines.append(svgEl("line", { x1: x, y1: y + FT.boxH, x2: x, y2: gateTop }));
      shapes.append(drawGateSymbol(node.gate, x, gateTop));
      if (node.gate === "INHIBIT" && node.condition) {
        // Conditioning event: an ellipse beside the gate, joined to it by a horizontal line.
        const cy = gateTop + FT.gateH / 2; const cx = x + FT.gateW + 8 + 68;
        lines.append(svgEl("line", { x1: x + FT.gateW, y1: cy, x2: cx - 68, y2: cy }));
        const cond = svgEl("g", { class: "ft-svg-cond" });
        cond.append(svgEl("title", {}, `Condition: ${node.condition}`), svgEl("ellipse", { cx, cy, rx: 68, ry: 24 }));
        const condLines = wrapLabel(node.condition, 20, 3);
        const condText = svgEl("text", { x: cx, y: cy - (condLines.length - 1) * 5.5 + 3, "text-anchor": "middle" });
        condLines.forEach((line, i) => condText.append(svgEl("tspan", { x: cx, dy: i === 0 ? 0 : 11 }, line)));
        cond.append(condText);
        shapes.append(cond);
      }
      const busY = gateTop + FT.gateH + FT.gapBus;
      const xs = node.children.map((childId) => pos.get(childId).x);
      lines.append(svgEl("line", { x1: x, y1: gateTop + FT.gateH, x2: x, y2: busY }));
      lines.append(svgEl("line", { x1: Math.min(...xs, x), y1: busY, x2: Math.max(...xs, x), y2: busY }));
      for (const childX of xs) lines.append(svgEl("line", { x1: childX, y1: busY, x2: childX, y2: yOf(depth + 1) }));
    }
  }

  const ly = height - legendH + 14; const legend = svgEl("g", { class: "ft-svg-legend" });
  const legendEvent = svgEl("g", { class: "ft-svg-event" }); legendEvent.append(svgEl("rect", { x: FT.margin, y: ly - 10, width: 26, height: 16, rx: 3 }));
  const legendBasic = svgEl("g", { class: "ft-svg-basic" }); legendBasic.append(svgEl("circle", { cx: FT.margin + 120, cy: ly - 2, r: 8 }));
  legend.append(legendEvent, svgEl("text", { x: FT.margin + 34, y: ly + 3 }, "Event"), legendBasic,
    svgEl("text", { x: FT.margin + 136, y: ly + 3 }, "Basic event"),
    svgEl("text", { x: FT.margin + 250, y: ly + 3 }, "AND = all inputs required    OR = any one input suffices"),
    svgEl("text", { x: FT.margin, y: ly + 24 }, "INH (INHIBIT) = the single input causes the event only if the dashed oval condition also holds"));
  svg.append(legend);
  return svg;
}

function renderFaultTreeReasons(tree) {
  const list = $("faulttree-reasons"); list.replaceChildren();
  const nodesById = new Map(tree.nodes.map((node) => [node.id, node]));
  (function walk(id) {
    const node = nodesById.get(id);
    if (node.reason || node.condition) {
      const item = document.createElement("li");
      const head = document.createElement("strong");
      head.textContent = `${node.gate === "NONE" ? "Basic event" : node.gate}: ${node.label}`;
      item.append(head);
      if (node.condition) { const cond = document.createElement("div"); cond.className = "ft-reason-cond"; cond.textContent = `Condition: ${node.condition}`; item.append(cond); }
      if (node.reason) { const why = document.createElement("div"); why.className = "secondary-text"; why.textContent = node.reason; item.append(why); }
      list.append(item);
    }
    node.children.forEach(walk);
  })(tree.root_id);
  $("faulttree-reasoning").hidden = !list.children.length;
}

function resetFaultTree(cweId) {
  const section = $("faulttree-section");
  section.hidden = !cweId;
  section.dataset.cwe = cweId || "";
  $("faulttree-cwe").textContent = cweId ? `(${cweId})` : "";
  $("faulttree-diagram").replaceChildren();
  $("faulttree-reasons").replaceChildren();
  $("faulttree-result").hidden = true;
  $("faulttree-refresh").hidden = true;
  $("faulttree-button").hidden = false;
  $("faulttree-button").disabled = false;
  $("faulttree-status").textContent = "";
}

function showFaultTree(result) {
  const nodesById = new Map(result.tree.nodes.map((node) => [node.id, node]));
  $("faulttree-tree").replaceChildren(renderFaultTreeNode(nodesById, result.tree.root_id));
  $("faulttree-diagram").replaceChildren(renderFaultTreeDiagram(result.tree));
  renderFaultTreeReasons(result.tree);
  $("faulttree-source").textContent = `Source: ${result.source}`;
  $("faulttree-disclaimer").textContent = `${result.cwe_name}. ${result.disclaimer}`;
  $("faulttree-result").hidden = false;
  $("faulttree-button").hidden = true;
  $("faulttree-refresh").hidden = false;
}

// Gemini is slow on the free tier, so the server answers at once with a
// template tree (upgrading: true) and swaps in Gemini's tree in the background.
// Show the quick tree now, then poll the same URL until the upgrade lands.
const FAULT_TREE_POLL_MS = 6000;
const FAULT_TREE_MAX_POLLS = 30; // ~3 minutes; the server-side attempt gives up before that
let faultTreeRun = 0; // newest load wins; older polling loops stop themselves

async function loadFaultTree(refresh = false) {
  const cweId = $("faulttree-section").dataset.cwe;
  if (!cweId) return;
  const button = $("faulttree-button"); const again = $("faulttree-refresh");
  const run = ++faultTreeRun;
  const stillCurrent = () => run === faultTreeRun && $("faulttree-section").dataset.cwe === cweId;
  button.disabled = true; again.disabled = true;
  $("faulttree-status").textContent = `Building fault tree for ${cweId}…`;
  try {
    const path = `/cwe/${encodeURIComponent(cweId)}/fault-tree`;
    let result = await api(`${path}${refresh ? "?refresh=true" : ""}`);
    for (let poll = 0; stillCurrent(); poll++) {
      showFaultTree(result);
      if (!result.upgrading || poll >= FAULT_TREE_MAX_POLLS) {
        $("faulttree-status").textContent = result.upgrading ? "Gemini is still working; press Regenerate later to check." : "";
        break;
      }
      $("faulttree-status").textContent = "Showing the quick template tree. Gemini is drafting a fuller one; it will replace this automatically…";
      button.disabled = false; again.disabled = false;
      await new Promise((resolve) => setTimeout(resolve, FAULT_TREE_POLL_MS));
      if (!stillCurrent()) return;
      result = await api(path);
    }
  } catch (error) {
    if (stillCurrent()) $("faulttree-status").textContent = error.message;
  } finally {
    button.disabled = false; again.disabled = false;
  }
}

function renderIntelligence(data) {
  $("intelligence-empty").hidden = true;
  $("intelligence-content").hidden = false;
  renderKevSection(data.cve.kev);
  resetFaultTree(data.cve.cwe_id);
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
    loadImpactSummary();
  } catch (error) { setStatus(error.message, true); }
  finally { button.disabled = false; }
}

async function syncKev() {
  const button = $("sync-kev-button"); button.disabled = true; setStatus("Synchronizing CISA Known Exploited Vulnerabilities…");
  try {
    const result = await api("/kev/sync", { method: "POST" });
    setStatus(`CISA KEV sync complete: ${result.created} created, ${result.updated} updated, ${result.skipped} skipped.`);
    await loadCves();
    loadImpactSummary();
    if (state.selectedId) await loadIntelligence(state.selectedId);
  } catch (error) { setStatus(error.message, true); }
  finally { button.disabled = false; }
}

// --- Cost & Time Impact ---------------------------------------------------
// A transparent estimate, not a vendor claim: the counts come from the
// backend (GET /impact/summary), but the time-per-CVE and hourly-cost
// assumptions are editable by the viewer and applied entirely client-side,
// so the figure always matches numbers a reader chose, never a fabricated
// per-organization claim this project has no way to actually know.
const impactState = { analyzedCves: 0 };

async function loadImpactSummary() {
  try {
    const summary = await api("/impact/summary");
    $("impact-total").textContent = summary.total_cves;
    $("impact-analyzed").textContent = summary.analyzed_cves;
    $("impact-kev").textContent = summary.kev_matches;
    $("impact-methodology-count").textContent = summary.analyzed_cves;
    impactState.analyzedCves = summary.analyzed_cves;
    recomputeImpact();
  } catch {
    // Non-critical — the rest of the dashboard still works without this panel.
  }
}

function recomputeImpact() {
  const minutes = Math.max(0, Number($("impact-minutes-input").value) || 0);
  const rate = Math.max(0, Number($("impact-rate-input").value) || 0);
  const hours = (impactState.analyzedCves * minutes) / 60;
  $("impact-hours").textContent = hours.toLocaleString(undefined, { maximumFractionDigits: 1 });
  $("impact-cost").textContent = `£${(hours * rate).toLocaleString(undefined, { maximumFractionDigits: 0 })}`;
}

// --- Bulk Triage --------------------------------------------------------
// Turns a pasted batch of CVE IDs (a scanner export, an overnight alert
// queue) into a ranked SOC worklist via POST /triage/batch, instead of an
// analyst opening the single-CVE view once per ID. See
// backend/services/triage_service.py for the ranking rules.
const triageState = { lastResults: [] };
const URGENCY_LABEL = {
  IMMEDIATE: "IMMEDIATE — KNOWN EXPLOITED",
  CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW",
  UNKNOWN: "UNSCORED", NOT_FOUND: "NOT FOUND",
};

function parseTriageIds(raw) {
  const matches = raw.toUpperCase().match(/CVE-\d{4}-\d{4,}/g) || [];
  return [...new Set(matches)];
}

async function runTriage() {
  const ids = parseTriageIds($("triage-input").value);
  const status = $("triage-status");
  const runButton = $("triage-run-button");
  if (!ids.length) { status.textContent = "Paste at least one CVE ID."; return; }
  const capped = ids.slice(0, 50);
  if (ids.length > 50) status.textContent = `Only the first 50 of ${ids.length} IDs were submitted.`;
  else status.textContent = `Triaging ${capped.length} CVE${capped.length === 1 ? "" : "s"}…`;

  runButton.disabled = true;
  try {
    const result = await api("/triage/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cve_ids: capped }),
    });
    triageState.lastResults = result.results;
    renderTriageResults(result);
    $("triage-export-button").disabled = result.results.length === 0;
    status.textContent = `${result.requested - result.not_found} found, ${result.not_found} not found. Ranked by urgency.`;
  } catch (error) {
    status.textContent = error.message;
  } finally {
    runButton.disabled = false;
  }
}

function renderTriageResults(result) {
  const container = $("triage-results");
  container.replaceChildren();
  if (!result.results.length) return;

  const table = document.createElement("table");
  table.className = "triage-table";
  const thead = document.createElement("thead");
  thead.innerHTML = "<tr><th>Urgency</th><th>CVE</th><th title=\"FIRST.org EPSS: predicted probability of exploitation in the next 30 days\">EPSS</th><th>ATT&CK</th><th>Immediate action</th><th></th></tr>";
  table.append(thead);
  const tbody = document.createElement("tbody");

  for (const row of result.results) {
    const tr = document.createElement("tr");
    tr.className = row.found ? "" : "triage-row-not-found";

    const urgencyCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge badge-${row.urgency === "IMMEDIATE" ? "kev" : row.urgency}`;
    badge.textContent = URGENCY_LABEL[row.urgency] || row.urgency;
    urgencyCell.append(badge);

    const cveCell = document.createElement("td");
    if (row.found) {
      const link = document.createElement("button");
      link.type = "button";
      link.className = "triage-cve-link";
      link.textContent = row.cve_id;
      link.addEventListener("click", () => loadIntelligence(row.cve_id));
      cveCell.append(link);
    } else {
      cveCell.textContent = row.cve_id;
      const note = document.createElement("span");
      note.className = "secondary-text";
      note.textContent = ` — ${row.note || "unavailable"}`;
      cveCell.append(note);
    }

    const epssCell = document.createElement("td");
    epssCell.textContent = typeof row.epss_score === "number" ? `${(row.epss_score * 100).toFixed(1)}%` : "—";

    const attackCell = document.createElement("td");
    attackCell.textContent = row.top_technique || "—";

    const actionCell = document.createElement("td");
    actionCell.textContent = row.immediate_action || "—";

    const copyCell = document.createElement("td");
    if (row.found) {
      const copyButton = document.createElement("button");
      copyButton.type = "button";
      copyButton.className = "button button-secondary triage-copy-button";
      copyButton.textContent = "Copy note";
      copyButton.addEventListener("click", () => copyTriageNote(row, copyButton));
      copyCell.append(copyButton);
    }

    tr.append(urgencyCell, cveCell, epssCell, attackCell, actionCell, copyCell);
    tbody.append(tr);
  }
  table.append(tbody);
  container.append(table);
}

// A clean, ticket-ready plain-text block — paste straight into Jira,
// ServiceNow, or an incident note without reformatting.
function formatTriageNote(row) {
  const lines = [
    `CVE: ${row.cve_id}`,
    `Urgency: ${URGENCY_LABEL[row.urgency] || row.urgency}`,
    `Severity: ${row.severity || "Unscored"}${row.cvss_score ? ` (CVSS ${row.cvss_score})` : ""}`,
    `CISA KEV (confirmed exploited): ${row.kev ? "YES" : "No"}`,
    `EPSS (predicted 30-day exploitation probability): ${typeof row.epss_score === "number" ? `${(row.epss_score * 100).toFixed(1)}%` : "Unavailable"}`,
    `ATT&CK technique: ${row.top_technique || "None inferred"}`,
    `Immediate action: ${row.immediate_action || "See full intelligence record."}`,
  ];
  if (row.summary) lines.push("", "Summary:", row.summary);
  return lines.join("\n");
}

async function copyTriageNote(row, button) {
  const text = formatTriageNote(row);
  try {
    await navigator.clipboard.writeText(text);
    const original = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = original; }, 1500);
  } catch {
    $("triage-status").textContent = "Clipboard unavailable in this browser.";
  }
}

function exportTriageCsv() {
  if (!triageState.lastResults.length) return;
  const header = ["cve_id", "urgency", "severity", "cvss_score", "epss_score", "kev", "top_technique", "immediate_action", "found"];
  const escape = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
  const rows = triageState.lastResults.map((row) => header.map((key) => escape(row[key])).join(","));
  const csv = [header.join(","), ...rows].join("\r\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `cve-triage-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
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
$("sync-kev-button").addEventListener("click", syncKev);
$("faulttree-button").addEventListener("click", () => loadFaultTree(false));
$("faulttree-refresh").addEventListener("click", () => loadFaultTree(true));
$("faulttree-zoom").addEventListener("click", () => {
  const actual = $("faulttree-diagram").classList.toggle("ft-actual-size");
  $("faulttree-zoom").textContent = actual ? "Fit to panel" : "Actual size";
});
$("triage-toggle-button").addEventListener("click", () => {
  const panel = $("triage-panel");
  panel.hidden = !panel.hidden;
  $("triage-toggle-button").setAttribute("aria-expanded", String(!panel.hidden));
});
$("triage-run-button").addEventListener("click", runTriage);
$("triage-export-button").addEventListener("click", exportTriageCsv);
$("impact-minutes-input").addEventListener("input", recomputeImpact);
$("impact-rate-input").addEventListener("input", recomputeImpact);
$("previous-button").addEventListener("click", () => { state.offset = Math.max(0, state.offset - state.limit); loadCves(); });
$("next-button").addEventListener("click", () => { state.offset += state.limit; loadCves(); });
initApiKeyField();
initGlitchTitle();
initMatrixRain();
loadCves();
loadImpactSummary();


// Title effect: the heading "decrypts" from random matrix glyphs on load and
// re-scrambles briefly every few seconds. The real text stays the accessible
// name (aria-label); the scrambled frames are decoration only.
function initGlitchTitle() {
  const title = $("site-title");
  if (!title) return;
  const finalText = title.dataset.text;
  title.setAttribute("aria-label", finalText);
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const glyphs = "01ABCDEF<>/|{}[]#$%&*+=";  // single-width only: wide glyphs would reflow the title
  const textNode = document.createElement("span");
  const cursor = document.createElement("span");
  cursor.className = "cursor"; cursor.textContent = " ";
  title.replaceChildren(textNode, cursor);
  let timer = null;
  function decode(duration = 1100) {
    clearInterval(timer);
    const start = performance.now();
    timer = setInterval(() => {
      const progress = Math.min(1, (performance.now() - start) / duration);
      const settled = Math.floor(progress * finalText.length);
      let out = "";
      for (let i = 0; i < finalText.length; i++) {
        out += i < settled || finalText[i] === " " ? finalText[i] : glyphs[Math.floor(Math.random() * glyphs.length)];
      }
      textNode.textContent = out;
      title.dataset.text = out;
      if (progress === 1) { clearInterval(timer); title.dataset.text = finalText; textNode.textContent = finalText; }
    }, 40);
  }
  decode(1400);
  setInterval(() => decode(500), 9000);
}
