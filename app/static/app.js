"use strict";

const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const ACTIVE = new Set(["queued", "running"]);

// ---------------------------------------------------------------------------
// Uebersetzungen
// ---------------------------------------------------------------------------

const I18N = {
  de: {
    locale: "de-DE",
    "sev.CRITICAL": "Kritisch", "sev.HIGH": "Hoch", "sev.MEDIUM": "Mittel", "sev.LOW": "Niedrig", "sev.UNKNOWN": "Unbekannt",
    "kind.vuln": "Schwachstelle", "kind.secret": "Secret", "kind.misconfig": "Fehlkonfiguration", "kind.license": "Lizenz",
    "kinds.vuln": "Schwachstellen", "kinds.secret": "Secrets", "kinds.misconfig": "Fehlkonfigurationen", "kinds.license": "Lizenzen",
    "status.queued": "Wartet", "status.running": "Läuft", "status.done": "Fertig", "status.failed": "Fehler", "status.cancelled": "Abgebrochen",
    "type.image": "Image", "type.repo": "Repository",
    "type.image.long": "Container-Image", "type.repo.long": "Git-Repository",

    "info.version": "Trivy {v}", "info.noVersion": "Trivy-Version unbekannt",
    "info.db": "DB vom {d}", "info.noDb": "DB noch nicht geladen",
    "info.docker": "Docker verbunden", "info.noDocker": "ohne Docker-Socket",
    "info.unreachable": "Server nicht erreichbar: {e}",

    "form.title": "Neuer Scan", "form.type": "Scan-Typ",
    "form.target.image": "Image", "form.target.repo": "Repository-URL",
    "form.placeholder.image": "z. B. nginx:latest", "form.placeholder.repo": "https://github.com/org/repo",
    "form.hint.repo": "Öffentliche Repositories über HTTPS.",
    "form.hint.noDocker": "Docker-Socket nicht verfügbar – es werden Images direkt aus der Registry geladen.",
    "form.hint.images": "{n} lokale Images verfügbar (Vorschläge beim Tippen).",
    "form.severities": "Schweregrade", "form.scanners": "Scanner",
    "form.ignoreUnfixed": "Nur Schwachstellen mit verfügbarem Fix",
    "form.submit": "Scan starten", "form.noTarget": "Bitte ein Ziel angeben.",

    "history.title": "Verlauf", "history.count": "{n} Scans", "history.empty": "Noch keine Scans.",
    "history.clean": "keine Funde",

    "empty.title": "Kein Scan ausgewählt",
    "empty.text": "Starten Sie links einen neuen Scan oder wählen Sie einen aus dem Verlauf.",
    "notFound.title": "Scan nicht gefunden",

    "btn.cancel": "Abbrechen", "btn.rescan": "Erneut scannen", "btn.delete": "Löschen",
    "detail.started": "Gestartet: {d}", "detail.duration": "Dauer: {d}", "detail.os": "OS: {os}",
    "detail.eol": " (End of Life!)", "detail.scanners": "Scanner: {s}", "detail.severities": "Schweregrade: {s}",
    "detail.fixedOnly": "nur mit Fix",
    "detail.queued": "Wartet auf freien Slot …",
    "detail.running": "Scan läuft … (beim ersten Scan wird die Schwachstellen-Datenbank geladen)",
    "detail.failed": "Scan fehlgeschlagen", "detail.cancelled": "Scan abgebrochen",
    "detail.clean.title": "Keine Funde", "detail.clean.text": "Trivy hat mit den gewählten Einstellungen nichts gefunden.",
    "confirm.delete": "Scan von „{t}“ wirklich löschen?",

    "filter.toggle": "Filter umschalten", "filter.search": "Suchen (CVE, Paket, Titel …)",
    "filter.allKinds": "Alle Arten", "filter.allTargets": "Alle Ziele ({n})", "filter.fixedOnly": "nur mit Fix",
    "filter.count": "{a} von {b}", "filter.none": "Keine Funde für diesen Filter.",
    "filter.kind": "Art", "filter.target": "Ziel",

    "col.severity": "Schweregrad", "col.id": "ID", "col.pkg": "Paket", "col.installed": "Installiert",
    "col.fixed": "Behoben in", "col.title": "Titel", "col.target": "Ziel",
    "line": "Zeile {n}",

    "err.invalid_type": "Unbekannter Scan-Typ.",
    "err.invalid_image": "Ungültiger Image-Name (Beispiel: nginx:1.27 oder ghcr.io/org/app:tag).",
    "err.invalid_repo": "Ungültige Repository-URL (nur https://…, z. B. https://github.com/org/repo).",
    "err.no_severity": "Mindestens einen Schweregrad auswählen.",
    "err.no_scanner": "Mindestens einen Scanner auswählen.",
    "err.bad_content_type": "Ungültiger Content-Type.", "err.too_large": "Anfrage zu groß.",
    "err.bad_request": "Ungültige Anfrage.", "err.not_found": "Nicht gefunden.",
    "err.forbidden_origin": "Anfrage von fremder Origin abgelehnt.",
    "err.start_failed": "Trivy konnte nicht gestartet werden: {e}",
    "err.result_unreadable": "Ergebnis nicht lesbar: {e}",
    "err.interrupted": "Durch Neustart des Servers unterbrochen.",
  },
  en: {
    locale: "en-GB",
    "sev.CRITICAL": "Critical", "sev.HIGH": "High", "sev.MEDIUM": "Medium", "sev.LOW": "Low", "sev.UNKNOWN": "Unknown",
    "kind.vuln": "Vulnerability", "kind.secret": "Secret", "kind.misconfig": "Misconfiguration", "kind.license": "License",
    "kinds.vuln": "Vulnerabilities", "kinds.secret": "Secrets", "kinds.misconfig": "Misconfigurations", "kinds.license": "Licenses",
    "status.queued": "Queued", "status.running": "Running", "status.done": "Done", "status.failed": "Failed", "status.cancelled": "Cancelled",
    "type.image": "Image", "type.repo": "Repository",
    "type.image.long": "Container image", "type.repo.long": "Git repository",

    "info.version": "Trivy {v}", "info.noVersion": "Trivy version unknown",
    "info.db": "DB from {d}", "info.noDb": "DB not loaded yet",
    "info.docker": "Docker connected", "info.noDocker": "no Docker socket",
    "info.unreachable": "Server unreachable: {e}",

    "form.title": "New scan", "form.type": "Scan type",
    "form.target.image": "Image", "form.target.repo": "Repository URL",
    "form.placeholder.image": "e.g. nginx:latest", "form.placeholder.repo": "https://github.com/org/repo",
    "form.hint.repo": "Public repositories via HTTPS.",
    "form.hint.noDocker": "Docker socket not available – images are pulled directly from the registry.",
    "form.hint.images": "{n} local images available (suggested while typing).",
    "form.severities": "Severities", "form.scanners": "Scanners",
    "form.ignoreUnfixed": "Only vulnerabilities with an available fix",
    "form.submit": "Start scan", "form.noTarget": "Please enter a target.",

    "history.title": "History", "history.count": "{n} scans", "history.empty": "No scans yet.",
    "history.clean": "no findings",

    "empty.title": "No scan selected",
    "empty.text": "Start a new scan on the left or pick one from the history.",
    "notFound.title": "Scan not found",

    "btn.cancel": "Cancel", "btn.rescan": "Rescan", "btn.delete": "Delete",
    "detail.started": "Started: {d}", "detail.duration": "Duration: {d}", "detail.os": "OS: {os}",
    "detail.eol": " (end of life!)", "detail.scanners": "Scanners: {s}", "detail.severities": "Severities: {s}",
    "detail.fixedOnly": "fixed only",
    "detail.queued": "Waiting for a free slot …",
    "detail.running": "Scan running … (the vulnerability database is downloaded on the first scan)",
    "detail.failed": "Scan failed", "detail.cancelled": "Scan cancelled",
    "detail.clean.title": "No findings", "detail.clean.text": "Trivy found nothing with the selected settings.",
    "confirm.delete": "Really delete the scan of “{t}”?",

    "filter.toggle": "Toggle filter", "filter.search": "Search (CVE, package, title …)",
    "filter.allKinds": "All types", "filter.allTargets": "All targets ({n})", "filter.fixedOnly": "fixed only",
    "filter.count": "{a} of {b}", "filter.none": "No findings for this filter.",
    "filter.kind": "Type", "filter.target": "Target",

    "col.severity": "Severity", "col.id": "ID", "col.pkg": "Package", "col.installed": "Installed",
    "col.fixed": "Fixed in", "col.title": "Title", "col.target": "Target",
    "line": "Line {n}",

    "err.invalid_type": "Unknown scan type.",
    "err.invalid_image": "Invalid image name (example: nginx:1.27 or ghcr.io/org/app:tag).",
    "err.invalid_repo": "Invalid repository URL (https://… only, e.g. https://github.com/org/repo).",
    "err.no_severity": "Select at least one severity.",
    "err.no_scanner": "Select at least one scanner.",
    "err.bad_content_type": "Invalid Content-Type.", "err.too_large": "Request too large.",
    "err.bad_request": "Invalid request.", "err.not_found": "Not found.",
    "err.forbidden_origin": "Cross-origin request rejected.",
    "err.start_failed": "Trivy could not be started: {e}",
    "err.result_unreadable": "Result could not be read: {e}",
    "err.interrupted": "Interrupted by server restart.",
  },
};

function detectLang() {
  try {
    const saved = localStorage.getItem("trivy-gui-lang");
    if (saved && I18N[saved]) return saved;
  } catch { /* Speicher nicht verfuegbar */ }
  return (navigator.language || "").toLowerCase().startsWith("de") ? "de" : "en";
}

let lang = detectLang();

function t(key, vars = {}) {
  const s = I18N[lang][key] ?? I18N.en[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (_, k) => (k in vars ? vars[k] : `{${k}}`));
}

function errorText(code, fallback) {
  return code && I18N[lang][`err.${code}`] ? t(`err.${code}`, { e: fallback || "" }) : fallback;
}

function setLang(next) {
  if (!I18N[next] || next === lang) return;
  lang = next;
  try { localStorage.setItem("trivy-gui-lang", lang); } catch { /* egal */ }
  applyStaticTexts();
  updateTypeUi();
  renderInfo();
  renderHistory();
  if (state.current) renderDetail(); else if (!location.hash) renderEmpty();
}

function applyStaticTexts() {
  document.documentElement.lang = lang;
  for (const node of document.querySelectorAll("[data-i18n]")) node.textContent = t(node.dataset.i18n);
  for (const node of document.querySelectorAll("[data-i18n-aria]")) node.setAttribute("aria-label", t(node.dataset.i18nAria));
  for (const btn of document.querySelectorAll(".lang-switch button")) {
    btn.setAttribute("aria-pressed", String(btn.dataset.lang === lang));
  }
}

// ---------------------------------------------------------------------------
// Zustand & Helfer
// ---------------------------------------------------------------------------

const state = {
  scans: [],
  current: null,      // { scan, findings, log }
  filter: null,
  sort: { key: "severity", dir: 1 },
  pollTimer: null,
  info: null,
  infoError: null,
  dockerAvailable: null,
  imageCount: 0,
};

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
  if (!res.ok) throw new Error(errorText(data && data.code, (data && data.error) || `HTTP ${res.status}`));
  return data;
}

function safeUrl(url) {
  return /^https?:\/\//i.test(url || "") ? url : null;
}

function fmtDate(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString(t("locale"), { dateStyle: "short", timeStyle: "short" });
}

function fmtDuration(a, b) {
  if (!a) return "";
  const ms = (b ? new Date(b) : new Date()) - new Date(a);
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${s % 60} s`;
}

const sevLabel = (s) => t(`sev.${SEV.includes(s) ? s : "UNKNOWN"}`);

function sevPill(sev, text) {
  return el("span", { class: `pill sev-${SEV.includes(sev) ? sev : "UNKNOWN"}`, title: sevLabel(sev) }, text);
}

function countPills(counts) {
  if (!counts) return [];
  return SEV.filter((s) => counts[s]).map((s) => sevPill(s, counts[s]));
}

function defaultFilter() {
  return { sev: new Set(SEV), q: "", kind: "", target: "", fixedOnly: false };
}

function installedText(x) {
  return x.kind === "secret" && x.line ? t("line", { n: x.line }) : x.installed;
}

// ---------------------------------------------------------------------------
// Formular
// ---------------------------------------------------------------------------

function selectedType() {
  return document.querySelector('input[name="type"]:checked').value;
}

function initForm() {
  const sevBox = $("#sev-checks");
  for (const s of SEV) {
    sevBox.append(el("label", {},
      el("input", { type: "checkbox", name: "severity", value: s, checked: s !== "UNKNOWN" }),
      " ", el("span", { "data-i18n": `sev.${s}` })));
  }

  for (const radio of document.querySelectorAll('input[name="type"]')) {
    radio.addEventListener("change", updateTypeUi);
  }
  for (const btn of document.querySelectorAll(".lang-switch button")) {
    btn.addEventListener("click", () => setLang(btn.dataset.lang));
  }

  $("#scan-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const form = ev.currentTarget;
    const errBox = $("#form-error");
    errBox.hidden = true;

    const payload = {
      type: selectedType(),
      target: $("#target").value.trim(),
      severities: [...form.querySelectorAll('input[name="severity"]:checked')].map((i) => i.value),
      scanners: [...form.querySelectorAll('input[name="scanner"]:checked')].map((i) => i.value),
      ignoreUnfixed: $("#ignore-unfixed").checked,
    };
    if (!payload.target) {
      errBox.textContent = t("form.noTarget");
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
  const type = selectedType();
  const input = $("#target");
  $("#target-label").textContent = t(`form.target.${type}`);
  input.placeholder = t(`form.placeholder.${type}`);
  if (type === "image") input.setAttribute("list", "images");
  else input.removeAttribute("list");
  updateImageHint();
}

function updateImageHint() {
  const hint = $("#target-hint");
  if (selectedType() === "repo") hint.textContent = t("form.hint.repo");
  else if (state.dockerAvailable === false) hint.textContent = t("form.hint.noDocker");
  else if (state.dockerAvailable) hint.textContent = t("form.hint.images", { n: state.imageCount });
  else hint.textContent = "";
}

async function loadImages() {
  try {
    const { available, images } = await api("/api/images");
    state.dockerAvailable = available;
    state.imageCount = images.length;
    $("#images").replaceChildren(...images.map((i) => el("option", { value: i.name })));
  } catch {
    state.dockerAvailable = false;
  }
  updateImageHint();
}

async function loadInfo() {
  try {
    state.info = await api("/api/info");
    state.infoError = null;
  } catch (e) {
    state.infoError = e.message;
  }
  renderInfo();
}

function renderInfo() {
  const box = $("#info");
  if (state.infoError) { box.textContent = t("info.unreachable", { e: state.infoError }); return; }
  const info = state.info;
  if (!info) return;
  box.textContent = [
    info.version ? t("info.version", { v: info.version }) : t("info.noVersion"),
    info.dbUpdatedAt ? t("info.db", { d: fmtDate(info.dbUpdatedAt) }) : t("info.noDb"),
    info.docker ? t("info.docker") : t("info.noDocker"),
  ].join(" · ");
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
  $("#history-count").textContent = state.scans.length ? t("history.count", { n: state.scans.length }) : "";
  if (!state.scans.length) {
    ul.replaceChildren(el("li", { class: "muted small" }, t("history.empty")));
    return;
  }
  ul.replaceChildren(...state.scans.map((s) => el("li", {},
    el("a", { href: `#/scan/${s.id}`, class: s.id === currentId ? "active" : null },
      el("div", { class: "h-target" }, s.target),
      el("div", { class: "h-meta" },
        el("span", { class: `badge ${s.status}` }, t(`status.${s.status}`)),
        el("span", { class: "muted small" }, `${t(`type.${s.type}`)} · ${fmtDate(s.created)}`),
        s.status === "done" && s.total === 0 ? el("span", { class: "small fixed" }, t("history.clean")) : null,
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
    el("h2", {}, t("empty.title")),
    el("p", { class: "muted" }, t("empty.text")),
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
      el("h2", {}, t("notFound.title")), el("p", { class: "muted" }, e.message)));
  }
}

function renderDetail() {
  const { scan, log } = state.current;
  const opts = scan.options || {};
  const info = scan.info || {};
  const error = scan.error ? errorText(scan.errorCode, scan.error) : null;

  const actions = el("div", { class: "actions" },
    ACTIVE.has(scan.status)
      ? el("button", { class: "btn", onclick: () => cancelCurrent() }, t("btn.cancel"))
      : el("button", { class: "btn", onclick: () => rescanCurrent() }, t("btn.rescan")),
    scan.status === "done" ? el("a", { class: "btn", href: `/api/scans/${scan.id}/raw` }, "JSON") : null,
    scan.status === "done" ? el("button", { class: "btn", onclick: exportCsv }, "CSV") : null,
    el("button", { class: "btn danger", onclick: () => deleteCurrent() }, t("btn.delete")),
  );

  const head = el("div", { class: "card" },
    el("div", { class: "detail-head" },
      el("div", {},
        el("h1", {}, scan.target),
        el("div", { class: "meta-line muted small" },
          el("span", { class: `badge ${scan.status}` }, t(`status.${scan.status}`)),
          el("span", {}, t(`type.${scan.type}`)),
          el("span", {}, t("detail.started", { d: fmtDate(scan.created) })),
          scan.started ? el("span", {}, t("detail.duration", { d: fmtDuration(scan.started, scan.finished) })) : null,
          info.os ? el("span", {}, t("detail.os", { os: info.os }) + (info.eosl ? t("detail.eol") : "")) : null,
        ),
        el("div", { class: "meta-line muted small" },
          el("span", {}, t("detail.scanners", { s: (opts.scanners || []).map((s) => t(`kinds.${s}`)).join(", ") })),
          el("span", {}, t("detail.severities", { s: (opts.severities || []).map(sevLabel).join(", ") })),
          opts.ignoreUnfixed ? el("span", {}, t("detail.fixedOnly")) : null,
        ),
      ),
      actions,
    ),
  );

  const body = [];
  if (ACTIVE.has(scan.status)) {
    body.push(el("div", { class: "card" },
      el("div", {}, el("span", { class: "spinner" }), " ", t(`detail.${scan.status}`)),
      log ? el("pre", { class: "log mono" }, log) : null,
    ));
  } else if (scan.status === "failed" || scan.status === "cancelled") {
    body.push(el("div", { class: "card" },
      el("h2", {}, t(`detail.${scan.status}`)),
      error ? el("pre", { class: "log mono" }, error) : null,
      !error && log ? el("pre", { class: "log mono" }, log) : null,
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
      el("h2", { class: "fixed" }, t("detail.clean.title")),
      el("p", { class: "muted" }, t("detail.clean.text")),
    ));
    return;
  }

  const f = state.filter;
  const counts = Object.fromEntries(SEV.map((s) => [s, 0]));
  for (const x of findings) counts[SEV.includes(x.severity) ? x.severity : "UNKNOWN"]++;

  const summary = el("div", { class: "summary" }, SEV.map((s) =>
    el("button", {
      class: `sev-card c-${s}${f.sev.has(s) ? "" : " off"}`,
      title: t("filter.toggle"),
      onclick: () => { f.sev.has(s) ? f.sev.delete(s) : f.sev.add(s); renderResults(); },
    }, el("span", { class: "n" }, counts[s]), el("span", { class: "muted small" }, sevLabel(s))),
  ));

  const kinds = [...new Set(findings.map((x) => x.kind))];
  const targets = [...new Set(findings.map((x) => x.target))].sort();

  const search = el("input", { type: "search", placeholder: t("filter.search"), value: f.q });
  search.addEventListener("input", () => { f.q = search.value; renderTable(); });

  const kindSel = el("select", { "aria-label": t("filter.kind") },
    el("option", { value: "" }, t("filter.allKinds")),
    kinds.map((k) => el("option", { value: k, selected: f.kind === k }, t(`kind.${k}`))));
  kindSel.addEventListener("change", () => { f.kind = kindSel.value; renderTable(); });

  const targetSel = el("select", { "aria-label": t("filter.target") },
    el("option", { value: "" }, t("filter.allTargets", { n: targets.length })),
    targets.map((x) => el("option", { value: x, selected: f.target === x }, x)));
  targetSel.addEventListener("change", () => { f.target = targetSel.value; renderTable(); });

  const fixedCb = el("input", { type: "checkbox", checked: f.fixedOnly });
  fixedCb.addEventListener("change", () => { f.fixedOnly = fixedCb.checked; renderTable(); });

  const filters = el("div", { class: "filters" },
    search, kindSel, targets.length > 1 ? targetSel : null,
    el("label", { class: "check-line small" }, fixedCb, " ", t("filter.fixedOnly")),
    el("span", { id: "result-count", class: "muted small" }),
  );

  box.replaceChildren(summary, filters, el("div", { class: "table-wrap", id: "table-wrap" }));
  renderTable();
}

const COLUMNS = ["severity", "id", "pkg", "installed", "fixed", "title", "target"];

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
      ? sevRank(a.severity) - sevRank(b.severity) || a.id.localeCompare(b.id, undefined, { numeric: true })
      : (a[key] || "").localeCompare(b[key] || "", undefined, { numeric: true });
    return r * dir;
  });
  return rows;
}

function renderTable() {
  const rows = filteredFindings();
  const total = (state.current.findings || []).length;
  $("#result-count").textContent = t("filter.count", { a: rows.length, b: total });

  const thead = el("thead", {}, el("tr", {}, COLUMNS.map((key) =>
    el("th", {
      class: state.sort.key === key ? `sorted${state.sort.dir < 0 ? " desc" : ""}` : null,
      onclick: () => {
        state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : 1 };
        renderTable();
      },
    }, t(`col.${key}`)))));

  const tbody = el("tbody");
  const frag = document.createDocumentFragment();
  for (const x of rows) {
    const url = safeUrl(x.url);
    frag.append(el("tr", {},
      el("td", { class: "nowrap" }, sevPill(x.severity, sevLabel(x.severity))),
      el("td", { class: "nowrap mono" },
        url ? el("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, x.id) : x.id,
        x.kind !== "vuln" ? el("div", { class: "muted small" }, t(`kind.${x.kind}`)) : null),
      el("td", { class: "mono" }, x.pkg),
      el("td", { class: "mono nowrap" }, installedText(x)),
      el("td", { class: x.kind === "vuln" ? "mono nowrap fixed" : "small" }, x.fixed || (x.kind === "vuln" ? el("span", { class: "muted" }, x.status || "–") : "")),
      el("td", { class: "title" }, x.title),
      el("td", { class: "small muted" }, x.target),
    ));
  }
  tbody.append(frag);
  if (!rows.length) {
    tbody.append(el("tr", {}, el("td", { colspan: COLUMNS.length, class: "muted" }, t("filter.none"))));
  }
  $("#table-wrap").replaceChildren(el("table", {}, thead, tbody));
}

function exportCsv() {
  const rows = filteredFindings().map((r) => ({ ...r, installed: installedText(r) }));
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
  if (!confirm(t("confirm.delete", { t: scan.target }))) return;
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
applyStaticTexts();
updateTypeUi();
window.addEventListener("hashchange", route);
loadInfo();
loadImages();
refreshList().catch(() => {}).finally(() => { route(); schedulePoll(); });
