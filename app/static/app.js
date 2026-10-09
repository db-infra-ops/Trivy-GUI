"use strict";

const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const SEV_LABEL = { CRITICAL: "Kritisch", HIGH: "Hoch", MEDIUM: "Mittel", LOW: "Niedrig", UNKNOWN: "Unbekannt" };
const KIND_LABEL = { vuln: "Schwachstelle", secret: "Secret", misconfig: "Fehlkonfiguration", license: "Lizenz" };
const STATUS_LABEL = { queued: "Wartet", running: "Läuft", done: "Fertig", failed: "Fehler", cancelled: "Abgebrochen" };
const TYPE_LABEL = { image: "Image", repo: "Repository" };
const ACTIVE = new Set(["queued", "running"]);

const state = {
  scans: [],
  current: null,      // { scan, findings, log }
  filter: null,
  sort: { key: "severity", dir: 1 },
  pollTimer: null,
};

// ---------------------------------------------------------------------------
// Helfer
// ---------------------------------------------------------------------------

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

async function api(path, options = {}) {
  const headers = options.body ? { "Content-Type": "application/json" } : {};
  const res = await fetch(path, { ...options, headers });
  let data = null;
  try { data = await res.json(); } catch { /* leerer Body */ }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

function safeUrl(url) {
  return /^https?:\/\//i.test(url || "") ? url : null;
}

function fmtDate(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });
}

function fmtDuration(a, b) {
  if (!a) return "";
  const ms = (b ? new Date(b) : new Date()) - new Date(a);
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${s % 60} s`;
}

function sevPill(sev, text) {
  return el("span", { class: `pill sev-${SEV.includes(sev) ? sev : "UNKNOWN"}`, title: SEV_LABEL[sev] || sev }, text);
}

function countPills(counts) {
  if (!counts) return [];
  return SEV.filter((s) => counts[s]).map((s) => sevPill(s, counts[s]));
}

function defaultFilter() {
  return { sev: new Set(SEV), q: "", kind: "", target: "", fixedOnly: false };
}

// ---------------------------------------------------------------------------
// Formular
// ---------------------------------------------------------------------------

function initForm() {
  const sevBox = $("#sev-checks");
  for (const s of SEV) {
    sevBox.append(el("label", {},
      el("input", { type: "checkbox", name: "severity", value: s, checked: s !== "UNKNOWN" }),
      " ", SEV_LABEL[s]));
  }

  for (const radio of document.querySelectorAll('input[name="type"]')) {
    radio.addEventListener("change", updateTypeUi);
  }

  $("#scan-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const form = ev.currentTarget;
    const errBox = $("#form-error");
    errBox.hidden = true;

    const payload = {
      type: form.querySelector('input[name="type"]:checked').value,
      target: $("#target").value.trim(),
      severities: [...form.querySelectorAll('input[name="severity"]:checked')].map((i) => i.value),
      scanners: [...form.querySelectorAll('input[name="scanner"]:checked')].map((i) => i.value),
      ignoreUnfixed: $("#ignore-unfixed").checked,
    };
    if (!payload.target) {
      errBox.textContent = "Bitte ein Ziel angeben.";
      errBox.hidden = false;
      return;
    }

    const btn = $("#submit-btn");
    btn.disabled = true;
    try {
      const { scan } = await startScan(payload);
      location.hash = `#/scan/${scan.id}`;
    } catch (e) {
      errBox.textContent = e.message;
      errBox.hidden = false;
    } finally {
      btn.disabled = false;
    }
  });
}

async function startScan(payload) {
  const res = await api("/api/scans", { method: "POST", body: JSON.stringify(payload) });
  await refreshList();
  return res;
}

function updateTypeUi() {
  const type = document.querySelector('input[name="type"]:checked').value;
  const input = $("#target");
  if (type === "image") {
    $("#target-label").textContent = "Image";
    input.placeholder = "z. B. nginx:latest";
    input.setAttribute("list", "images");
  } else {
    $("#target-label").textContent = "Repository-URL";
    input.placeholder = "https://github.com/org/repo";
    input.removeAttribute("list");
  }
  updateImageHint();
}

let dockerAvailable = null;
let imageCount = 0;

function updateImageHint() {
  const type = document.querySelector('input[name="type"]:checked').value;
  const hint = $("#target-hint");
  if (type === "repo") {
    hint.textContent = "Öffentliche Repositories über HTTPS.";
  } else if (dockerAvailable === false) {
    hint.textContent = "Docker-Socket nicht verfügbar – es werden Images direkt aus der Registry geladen.";
  } else if (dockerAvailable) {
    hint.textContent = `${imageCount} lokale Images verfügbar (Vorschläge beim Tippen).`;
  } else {
    hint.textContent = "";
  }
}

async function loadImages() {
  try {
    const { available, images } = await api("/api/images");
    dockerAvailable = available;
    imageCount = images.length;
    const list = $("#images");
    list.replaceChildren(...images.map((i) => el("option", { value: i.name })));
  } catch {
    dockerAvailable = false;
  }
  updateImageHint();
}

async function loadInfo() {
  try {
    const info = await api("/api/info");
    const parts = [];
    parts.push(info.version ? `Trivy ${info.version}` : "Trivy-Version unbekannt");
    parts.push(info.dbUpdatedAt ? `DB vom ${fmtDate(info.dbUpdatedAt)}` : "DB noch nicht geladen");
    parts.push(info.docker ? "Docker verbunden" : "ohne Docker-Socket");
    $("#info").textContent = parts.join(" · ");
  } catch (e) {
    $("#info").textContent = `Server nicht erreichbar: ${e.message}`;
  }
}

// ---------------------------------------------------------------------------
// Verlauf
// ---------------------------------------------------------------------------

async function refreshList() {
  const { scans } = await api("/api/scans");
  state.scans = scans;
  renderHistory();
}

function renderHistory() {
  const currentId = state.current && state.current.scan.id;
  const ul = $("#history");
  $("#history-count").textContent = state.scans.length ? `${state.scans.length} Scans` : "";
  if (!state.scans.length) {
    ul.replaceChildren(el("li", { class: "muted small" }, "Noch keine Scans."));
    return;
  }
  ul.replaceChildren(...state.scans.map((s) => el("li", {},
    el("a", { href: `#/scan/${s.id}`, class: s.id === currentId ? "active" : null },
      el("div", { class: "h-target" }, s.target),
      el("div", { class: "h-meta" },
        el("span", { class: `badge ${s.status}` }, STATUS_LABEL[s.status] || s.status),
        el("span", { class: "muted small" }, `${TYPE_LABEL[s.type] || s.type} · ${fmtDate(s.created)}`),
        s.status === "done" && s.total === 0 ? el("span", { class: "small fixed" }, "keine Funde") : null,
        countPills(s.counts),
      ),
    ),
  )));
}

// ---------------------------------------------------------------------------
// Detailansicht
// ---------------------------------------------------------------------------

function renderEmpty() {
  $("#detail").replaceChildren(el("div", { class: "card empty" },
    el("h2", {}, "Kein Scan ausgewählt"),
    el("p", { class: "muted" }, "Starten Sie links einen neuen Scan oder wählen Sie einen aus dem Verlauf."),
  ));
}

async function loadDetail(id) {
  try {
    const data = await api(`/api/scans/${id}`);
    const switched = !state.current || state.current.scan.id !== id;
    const statusChanged = !switched && state.current.scan.status !== data.scan.status;
    state.current = data;
    if (switched) {
      state.filter = defaultFilter();
      state.sort = { key: "severity", dir: 1 };
    }
    if (switched || statusChanged || ACTIVE.has(data.scan.status)) renderDetail();
    renderHistory();
  } catch (e) {
    state.current = null;
    $("#detail").replaceChildren(el("div", { class: "card empty" },
      el("h2", {}, "Scan nicht gefunden"), el("p", { class: "muted" }, e.message)));
  }
}

function renderDetail() {
  const { scan, log } = state.current;
  const opts = scan.options || {};
  const info = scan.info || {};

  const actions = el("div", { class: "actions" },
    ACTIVE.has(scan.status)
      ? el("button", { class: "btn", onclick: () => cancelCurrent() }, "Abbrechen")
      : el("button", { class: "btn", onclick: () => rescanCurrent() }, "Erneut scannen"),
    scan.status === "done" ? el("a", { class: "btn", href: `/api/scans/${scan.id}/raw` }, "JSON") : null,
    scan.status === "done" ? el("button", { class: "btn", onclick: exportCsv }, "CSV") : null,
    el("button", { class: "btn danger", onclick: () => deleteCurrent() }, "Löschen"),
  );

  const head = el("div", { class: "card" },
    el("div", { class: "detail-head" },
      el("div", {},
        el("h1", {}, scan.target),
        el("div", { class: "meta-line muted small" },
          el("span", { class: `badge ${scan.status}` }, STATUS_LABEL[scan.status] || scan.status),
          el("span", {}, `${TYPE_LABEL[scan.type] || scan.type}`),
          el("span", {}, `Gestartet: ${fmtDate(scan.created)}`),
          scan.started ? el("span", {}, `Dauer: ${fmtDuration(scan.started, scan.finished)}`) : null,
          info.os ? el("span", {}, `OS: ${info.os}${info.eosl ? " (End of Life!)" : ""}`) : null,
        ),
        el("div", { class: "meta-line muted small" },
          el("span", {}, `Scanner: ${(opts.scanners || []).map((s) => KIND_LABEL[s] || s).join(", ")}`),
          el("span", {}, `Schweregrade: ${(opts.severities || []).map((s) => SEV_LABEL[s]).join(", ")}`),
          opts.ignoreUnfixed ? el("span", {}, "nur mit Fix") : null,
        ),
      ),
      actions,
    ),
  );

  const body = [];
  if (ACTIVE.has(scan.status)) {
    body.push(el("div", { class: "card" },
      el("div", {}, el("span", { class: "spinner" }), " ",
        scan.status === "queued" ? "Wartet auf freien Slot …" : "Scan läuft … (beim ersten Scan wird die Schwachstellen-Datenbank geladen)"),
      log ? el("pre", { class: "log mono" }, log) : null,
    ));
  } else if (scan.status === "failed" || scan.status === "cancelled") {
    body.push(el("div", { class: "card" },
      el("h2", {}, scan.status === "failed" ? "Scan fehlgeschlagen" : "Scan abgebrochen"),
      scan.error ? el("pre", { class: "log mono" }, scan.error) : null,
      !scan.error && log ? el("pre", { class: "log mono" }, log) : null,
    ));
  } else {
    body.push(el("div", { id: "results" }));
  }

  $("#detail").replaceChildren(head, ...body);
  if (scan.status === "done") renderResults();
}

function renderResults() {
  const findings = state.current.findings || [];
  const box = $("#results");
  if (!findings.length) {
    box.replaceChildren(el("div", { class: "card empty" },
      el("h2", { class: "fixed" }, "Keine Funde"),
      el("p", { class: "muted" }, "Trivy hat mit den gewählten Einstellungen nichts gefunden."),
    ));
    return;
  }

  const f = state.filter;
  const counts = Object.fromEntries(SEV.map((s) => [s, 0]));
  for (const x of findings) counts[SEV.includes(x.severity) ? x.severity : "UNKNOWN"]++;

  const summary = el("div", { class: "summary" }, SEV.map((s) =>
    el("button", {
      class: `sev-card c-${s}${f.sev.has(s) ? "" : " off"}`,
      title: "Filter umschalten",
      onclick: () => { f.sev.has(s) ? f.sev.delete(s) : f.sev.add(s); renderResults(); },
    }, el("span", { class: "n" }, counts[s]), el("span", { class: "muted small" }, SEV_LABEL[s])),
  ));

  const kinds = [...new Set(findings.map((x) => x.kind))];
  const targets = [...new Set(findings.map((x) => x.target))].sort();

  const search = el("input", { type: "search", placeholder: "Suchen (CVE, Paket, Titel …)", value: f.q });
  search.addEventListener("input", () => { f.q = search.value; renderTable(); });

  const kindSel = el("select", { "aria-label": "Art" },
    el("option", { value: "" }, "Alle Arten"),
    kinds.map((k) => el("option", { value: k, selected: f.kind === k }, KIND_LABEL[k] || k)));
  kindSel.addEventListener("change", () => { f.kind = kindSel.value; renderTable(); });

  const targetSel = el("select", { "aria-label": "Ziel" },
    el("option", { value: "" }, `Alle Ziele (${targets.length})`),
    targets.map((t) => el("option", { value: t, selected: f.target === t }, t)));
  targetSel.addEventListener("change", () => { f.target = targetSel.value; renderTable(); });

  const fixedCb = el("input", { type: "checkbox", checked: f.fixedOnly });
  fixedCb.addEventListener("change", () => { f.fixedOnly = fixedCb.checked; renderTable(); });

  const filters = el("div", { class: "filters" },
    search, kindSel, targets.length > 1 ? targetSel : null,
    el("label", { class: "check-line small" }, fixedCb, " nur mit Fix"),
    el("span", { id: "result-count", class: "muted small" }),
  );

  box.replaceChildren(summary, filters, el("div", { class: "table-wrap", id: "table-wrap" }));
  renderTable();
}

const COLUMNS = [
  { key: "severity", label: "Schweregrad" },
  { key: "id", label: "ID" },
  { key: "pkg", label: "Paket" },
  { key: "installed", label: "Installiert" },
  { key: "fixed", label: "Behoben in" },
  { key: "title", label: "Titel" },
  { key: "target", label: "Ziel" },
];

function filteredFindings() {
  const f = state.filter;
  const q = f.q.trim().toLowerCase();
  const rows = (state.current.findings || []).filter((x) =>
    f.sev.has(SEV.includes(x.severity) ? x.severity : "UNKNOWN") &&
    (!f.kind || x.kind === f.kind) &&
    (!f.target || x.target === f.target) &&
    (!f.fixedOnly || x.fixed) &&
    (!q || [x.id, x.pkg, x.title, x.installed, x.fixed, x.target].some((v) => (v || "").toLowerCase().includes(q))));

  const { key, dir } = state.sort;
  const sevRank = (s) => { const i = SEV.indexOf(s); return i < 0 ? SEV.length : i; };
  rows.sort((a, b) => {
    const r = key === "severity"
      ? sevRank(a.severity) - sevRank(b.severity) || a.id.localeCompare(b.id, "de", { numeric: true })
      : (a[key] || "").localeCompare(b[key] || "", "de", { numeric: true });
    return r * dir;
  });
  return rows;
}

function renderTable() {
  const rows = filteredFindings();
  const total = (state.current.findings || []).length;
  $("#result-count").textContent = `${rows.length} von ${total}`;

  const thead = el("thead", {}, el("tr", {}, COLUMNS.map((c) =>
    el("th", {
      class: state.sort.key === c.key ? `sorted${state.sort.dir < 0 ? " desc" : ""}` : null,
      onclick: () => {
        state.sort = { key: c.key, dir: state.sort.key === c.key ? -state.sort.dir : 1 };
        renderTable();
      },
    }, c.label))));

  const tbody = el("tbody");
  const frag = document.createDocumentFragment();
  for (const x of rows) {
    const url = safeUrl(x.url);
    frag.append(el("tr", {},
      el("td", { class: "nowrap" }, sevPill(x.severity, SEV_LABEL[x.severity] || x.severity)),
      el("td", { class: "nowrap mono" },
        url ? el("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, x.id) : x.id,
        x.kind !== "vuln" ? el("div", { class: "muted small" }, KIND_LABEL[x.kind]) : null),
      el("td", { class: "mono" }, x.pkg),
      el("td", { class: "mono nowrap" }, x.installed),
      el("td", { class: x.kind === "vuln" ? "mono nowrap fixed" : "small" }, x.fixed || (x.kind === "vuln" ? el("span", { class: "muted" }, x.status || "–") : "")),
      el("td", { class: "title" }, x.title),
      el("td", { class: "small muted" }, x.target),
    ));
  }
  tbody.append(frag);
  if (!rows.length) {
    tbody.append(el("tr", {}, el("td", { colspan: COLUMNS.length, class: "muted" }, "Keine Funde für diesen Filter.")));
  }
  $("#table-wrap").replaceChildren(el("table", {}, thead, tbody));
}

function exportCsv() {
  const rows = filteredFindings();
  const cols = ["severity", "kind", "id", "pkg", "installed", "fixed", "status", "title", "target", "url"];
  const esc = (v) => {
    let s = String(v ?? "");
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // Formel-Injection in Excel verhindern
    return `"${s.replace(/"/g, '""')}"`;
  };
  const csv = [cols.join(";"), ...rows.map((r) => cols.map((c) => esc(r[c])).join(";"))].join("\r\n");
  const blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8" });
  const a = el("a", { href: URL.createObjectURL(blob), download: `trivy-${state.current.scan.id.slice(0, 8)}.csv` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ---------------------------------------------------------------------------
// Aktionen
// ---------------------------------------------------------------------------

async function cancelCurrent() {
  const { scan } = state.current;
  try {
    await api(`/api/scans/${scan.id}/cancel`, { method: "POST", body: "{}" });
    await loadDetail(scan.id);
    await refreshList();
  } catch (e) { alert(e.message); }
}

async function rescanCurrent() {
  const { scan } = state.current;
  try {
    const res = await startScan({ type: scan.type, target: scan.target, ...scan.options });
    location.hash = `#/scan/${res.scan.id}`;
  } catch (e) { alert(e.message); }
}

async function deleteCurrent() {
  const { scan } = state.current;
  if (!confirm(`Scan von „${scan.target}“ wirklich löschen?`)) return;
  try {
    await api(`/api/scans/${scan.id}`, { method: "DELETE" });
    state.current = null;
    location.hash = "";
    await refreshList();
    renderEmpty();
  } catch (e) { alert(e.message); }
}

// ---------------------------------------------------------------------------
// Routing & Polling
// ---------------------------------------------------------------------------

function route() {
  const m = location.hash.match(/^#\/scan\/([0-9a-f]{32})$/);
  if (m) loadDetail(m[1]);
  else { state.current = null; renderEmpty(); renderHistory(); }
}

function schedulePoll() {
  clearTimeout(state.pollTimer);
  const busy = state.scans.some((s) => ACTIVE.has(s.status));
  state.pollTimer = setTimeout(poll, busy ? 2000 : 15000);
}

async function poll() {
  try {
    await refreshList();
    const cur = state.current && state.current.scan;
    if (cur) {
      const fresh = state.scans.find((s) => s.id === cur.id);
      if (fresh && (ACTIVE.has(cur.status) || fresh.status !== cur.status)) await loadDetail(cur.id);
    }
  } catch { /* naechster Versuch */ }
  schedulePoll();
}

initForm();
updateTypeUi();
window.addEventListener("hashchange", route);
loadInfo();
loadImages();
refreshList().catch(() => {}).finally(() => { route(); schedulePoll(); });
