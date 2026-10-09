"use strict";

const I18N = {
  de: {
    title: "Anmelden",
    subtitle: "Bitte melden Sie sich an, um Trivy GUI zu verwenden.",
    user: "Benutzername",
    password: "Passwort",
    submit: "Anmelden",
    missing: "Bitte Benutzername und Passwort eingeben.",
    invalid_login: "Benutzername oder Passwort ist falsch.",
    too_many_attempts: "Zu viele Fehlversuche. Bitte in einigen Minuten erneut versuchen.",
    error: "Anmeldung fehlgeschlagen: {e}",
  },
  en: {
    title: "Sign in",
    subtitle: "Please sign in to use Trivy GUI.",
    user: "Username",
    password: "Password",
    submit: "Sign in",
    missing: "Please enter username and password.",
    invalid_login: "Invalid username or password.",
    too_many_attempts: "Too many failed attempts. Please try again in a few minutes.",
    error: "Sign-in failed: {e}",
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
const t = (key, vars = {}) => (I18N[lang][key] || key).replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? "");

function applyTexts() {
  document.documentElement.lang = lang;
  for (const node of document.querySelectorAll("[data-i18n]")) node.textContent = t(node.dataset.i18n);
  for (const btn of document.querySelectorAll(".lang-switch button")) {
    btn.setAttribute("aria-pressed", String(btn.dataset.lang === lang));
  }
}

function showError(text) {
  const box = document.getElementById("login-error");
  box.textContent = text;
  box.hidden = !text;
}

for (const btn of document.querySelectorAll(".lang-switch button")) {
  btn.addEventListener("click", () => {
    lang = btn.dataset.lang;
    try { localStorage.setItem("trivy-gui-lang", lang); } catch { /* egal */ }
    applyTexts();
    showError("");
  });
}

document.getElementById("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const user = document.getElementById("user").value.trim();
  const password = document.getElementById("password").value;
  if (!user || !password) { showError(t("missing")); return; }

  const btn = document.getElementById("login-btn");
  btn.disabled = true;
  showError("");
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user, password }),
    });
    if (res.ok) { location.replace("/"); return; }
    let data = null;
    try { data = await res.json(); } catch { /* leer */ }
    const code = data && data.code;
    showError(I18N[lang][code] ? t(code) : t("error", { e: (data && data.error) || `HTTP ${res.status}` }));
    document.getElementById("password").value = "";
    document.getElementById("password").focus();
  } catch (e) {
    showError(t("error", { e: e.message }));
  } finally {
    btn.disabled = false;
  }
});

applyTexts();

// Bereits angemeldet (z. B. Cookie vorhanden) oder Anmeldung deaktiviert -> direkt zur App.
fetch("/api/session")
  .then((r) => r.json())
  .then((s) => { if (!s.authRequired || s.authenticated) location.replace("/"); })
  .catch(() => {});

document.getElementById("user").focus();
