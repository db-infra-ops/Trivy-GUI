# Trivy GUI

[English](README.md) | **Deutsch**

[![Docker image](https://github.com/db-infra-ops/Trivy-GUI/actions/workflows/docker.yml/badge.svg)](https://github.com/db-infra-ops/Trivy-GUI/actions/workflows/docker.yml)

Schlanke Weboberfläche für [Trivy](https://github.com/aquasecurity/trivy), läuft komplett in einem Docker-Container.

- Container-Images (lokal oder aus einer Registry) und Git-Repositories scannen
- Schwachstellen, Secrets, Fehlkonfigurationen und Lizenzen
- Ergebnisübersicht nach Schweregrad, Volltextsuche, Filter (Art, Ziel, „nur mit Fix“), sortierbare Tabelle
- Scan-Verlauf, erneut scannen, Abbrechen, Löschen
- „Nur Schwachstellen mit verfügbarem Fix“ ist standardmäßig aktiv (wie `--ignore-unfixed`)
- Export als Trivy-JSON, CSV (Excel-tauglich) oder eigenständiger HTML-Bericht (druckbar / als PDF speicherbar, enthält die aktuell gefilterten Funde)
- Oberfläche auf Deutsch und Englisch (Umschalter in der Kopfzeile, wird im Browser gespeichert)
- Optionale Login-Seite mit Sitzungs-Cookie und Schutz vor Passwort-Raten
- Fertiges Multi-Arch-Image (amd64/arm64) in der GitHub Container Registry
- Keine Abhängigkeiten außer Trivy und Python 3 (nur Standardbibliothek)

## Start

Mit dem fertigen Image (empfohlen):

```bash
docker compose up -d
```

Oder ohne Compose:

```bash
docker run -d --name trivy-gui -p 127.0.0.1:8080:8080 -v /var/run/docker.sock:/var/run/docker.sock:ro -v trivy-gui-data:/data -v trivy-cache:/cache ghcr.io/db-infra-ops/trivy-gui:latest
```

Selbst bauen: `docker compose up -d --build`

Danach <http://localhost:8080> öffnen.

Der erste Scan dauert länger, weil Trivy zuerst die Schwachstellen-Datenbank lädt. Die Datenbank liegt im Volume `trivy-cache` und wird anschließend nur noch aktualisiert.

## Konfiguration (Umgebungsvariablen in `docker-compose.yml`)

| Variable | Standard | Bedeutung |
|---|---|---|
| `MAX_PARALLEL_SCANS` | `1` | Gleichzeitige Scans (Trivy sperrt den Cache, daher 1 empfohlen) |
| `SCAN_TIMEOUT` | `15m` | Timeout pro Scan |
| `AUTH_PASSWORD` | leer | Aktiviert die Login-Seite (siehe [Anmeldung](#anmeldung)) |
| `AUTH_USER` | `admin` | Benutzername für die Anmeldung |
| `SESSION_HOURS` | `8` | Wie lange eine Anmeldung gültig bleibt |
| `COOKIE_SECURE` | `auto` | `Secure`-Flag des Sitzungs-Cookies: `auto` (gesetzt, wenn der Proxy `X-Forwarded-Proto: https` sendet), `true`, `false` |
| `TRIVY_USERNAME` / `TRIVY_PASSWORD` | leer | Zugangsdaten für private Registries |
| `PORT` | `8080` | Port im Container |

Private Registries lassen sich alternativ nutzen, indem man die Docker-Konfiguration einbindet:
`- ~/.docker/config.json:/root/.docker/config.json:ro`

## Anmeldung

Sobald `AUTH_PASSWORD` gesetzt ist, zeigt die GUI eine Login-Seite (Deutsch/Englisch) und in der Kopfzeile einen
*Abmelden*-Button.

- Sitzungs-Cookie: zufälliges Token, `HttpOnly`, `SameSite=Strict`, gültig für `SESSION_HOURS`. Hinter einem
  HTTPS-Reverse-Proxy wird es automatisch als `Secure` markiert (`COOKIE_SECURE=auto`).
- Schutz vor Passwort-Raten: Jeder Fehlversuch wird um eine Sekunde verzögert; nach 20 Fehlversuchen in 5 Minuten
  wird die Anmeldung vorübergehend gesperrt (bestehende Sitzungen laufen weiter).
- Sitzungen liegen im Arbeitsspeicher: Nach einem Neustart des Containers ist eine erneute Anmeldung nötig.
- Skripte können die API weiterhin mit HTTP-Basic-Auth aufrufen, z. B. `curl -u admin:<passwort> http://host:8080/api/scans`.
  Dafür gilt derselbe Schutz vor Passwort-Raten.
- Ist `AUTH_USER` ohne `AUTH_PASSWORD` gesetzt, startet der Container nicht.

## Sicherheit

**Trivy-Version pinnen.** Im März 2026 gab es einen Supply-Chain-Angriff auf Trivy:
Das Release v0.69.4 sowie die Docker-Hub-Images `aquasec/trivy:0.69.5` und `0.69.6` waren kompromittiert
(CVE-2026-33634, GHSA-69fq-xp46-6x23). Dieses Projekt pinnt Trivy `0.74.0` daher per Tag **und** Digest und verwendet nie `latest`.

- Vor einem Update die [offiziellen Releases](https://github.com/aquasecurity/trivy/releases) und Advisories prüfen.
- Bevorzugt Releases verwenden, die mindestens zwei Wochen alt sind.
- Beim Build spielt `apk upgrade` Sicherheitsupdates der Alpine-Pakete über das Basisimage. Schwachstellen im Trivy-Binary selbst lassen sich nur durch eine neuere Trivy-Version beheben.
- Für ein Update den Digest der neuen Version ermitteln und `TRIVY_VERSION` und `TRIVY_DIGEST` im `Dockerfile` gemeinsam ändern:
  ```bash
  docker buildx imagetools inspect aquasec/trivy:<version>
  ```

**Docker-Socket.** Für lokale Images wird `/var/run/docker.sock` eingebunden. Wer Zugriff auf den Socket hat, hat faktisch
Root-Rechte auf dem Host, und `:ro` ändert daran nichts. Deshalb:

- Die GUI ist standardmäßig nur auf `127.0.0.1` erreichbar.
- Bei Freigabe im Netzwerk unbedingt `AUTH_USER`/`AUTH_PASSWORD` setzen und am besten einen Reverse-Proxy mit HTTPS vorschalten.
- Wird nur aus Registries gescannt, kann die Socket-Zeile entfallen.

Die App selbst ruft Trivy ohne Shell auf, validiert Image-Namen und URLs streng, liefert Inhalte mit einer strikten CSP aus,
prüft bei schreibenden Anfragen die Origin (CSRF) und übernimmt keine Secret-Inhalte („Match“) in die Oberfläche.

## Docker-Image & CI

Der GitHub-Actions-Workflow [`.github/workflows/docker.yml`](.github/workflows/docker.yml) baut das Image für
`linux/amd64` und `linux/arm64` und veröffentlicht es unter `ghcr.io/db-infra-ops/trivy-gui`:

| Auslöser | Tags |
|---|---|
| Push auf `main` | `latest`, `sha-<commit>` |
| Git-Tag `v1.2.3` | `1.2.3`, `1.2`, `sha-<commit>` |
| Pull Request | nur bauen, nichts wird veröffentlicht |

Vor der Veröffentlichung startet ein Smoke-Test den gebauten Container und führt echte Scans aus (lokales Image über den Docker-Socket und ein Registry-Image).
Jedes Image enthält ein SBOM und Build-Provenance. Alle Actions sind per Commit-SHA gepinnt,
Dependabot hält sie aktuell.

## Deployment-Beispiel (hinter einem Reverse-Proxy)

Beispiel für den Betrieb auf einem Server hinter einem externen Reverse-Proxy wie
[Nginx Proxy Manager](https://nginxproxymanager.com/) (NPM), mit fester Image-Version und Passwortschutz.

`docker-compose.yml` auf dem Server:

```yaml
services:
  trivy-gui:
    image: ghcr.io/db-infra-ops/trivy-gui:0.5.3   # Version pinnen, nicht latest
    restart: unless-stopped
    ports:
      - "8080:8080"   # besser: nur an eine interne IP binden, z. B. "10.0.0.5:8080:8080"
    environment:
      # Zugangsdaten kommen aus Variablen, damit kein Passwort in dieser Datei steht:
      #   Portainer:      Stacks -> Environment variables -> TRIVY_GUI_PASSWORD (optional TRIVY_GUI_USER) anlegen
      #   docker compose: Datei .env neben dieser Datei anlegen mit:
      #                     TRIVY_GUI_USER=admin
      #                     TRIVY_GUI_PASSWORD=hier-ein-langes-zufaelliges-passwort
      AUTH_USER: ${TRIVY_GUI_USER:-admin}
      AUTH_PASSWORD: ${TRIVY_GUI_PASSWORD:?TRIVY_GUI_PASSWORD ist nicht gesetzt}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro   # optional, nur für lokale Images
      - trivy-gui-data:/data
      - trivy-cache:/cache

volumes:
  trivy-gui-data:
  trivy-cache:
```

`TRIVY_GUI_PASSWORD` (optional `TRIVY_GUI_USER`, Standard `admin`) in Portainer als Stack-Umgebungsvariable oder in einer `.env`-Datei neben der Compose-Datei setzen und starten. Ohne Passwort startet der Stack nicht:

```bash
docker compose up -d
```

**Proxy Host in NPM:**

| Feld | Wert |
|---|---|
| Domain Names | `trivy.example.com` |
| Scheme | `http` |
| Forward Hostname / IP | IP des Docker-Hosts, auf dem Trivy GUI läuft |
| Forward Port | `8080` |
| Block Common Exploits | an |
| SSL | Let's-Encrypt-Zertifikat anfordern, *Force SSL* und *HTTP/2* aktivieren |

Hinweise:

- **`trusted_proxies` ist nicht nötig.** Die App wertet keine `X-Forwarded-*`-Header aus (keine IP-basierten Regeln,
  keine absoluten Weiterleitungen). Einzige Voraussetzung: Der Proxy muss den originalen `Host`-Header durchreichen,
  weil schreibende Anfragen dagegen geprüft werden (CSRF-Schutz). NPM macht das standardmäßig. Im Container-Log
  steht die IP des Proxys statt der des Clients.
- **Zugriff auf den Port einschränken.** Von Docker veröffentlichte Ports umgehen Host-Firewalls wie `ufw`. Den Port
  an eine interne IP binden (siehe oben) oder in der iptables-Kette `DOCKER-USER` nur den NPM-Host zulassen.
- **NPM auf demselben Docker-Host:** Beide Container in ein gemeinsames Docker-Netzwerk hängen und als Ziel
  `trivy-gui` / `8080` eintragen. Dann kann der Abschnitt `ports:` komplett entfallen.
- Scans laufen im Hintergrund, lange Scans laufen daher nicht in Proxy-Timeouts.

**Update:** Image-Tag ändern (z. B. `0.5.3` → `0.6.0`), dann `docker compose pull && docker compose up -d`.
Scan-Verlauf und Trivy-Datenbank bleiben in den Volumes erhalten.

## Aufbau

```
.github/workflows/    CI: Docker-Image bauen & veröffentlichen
Dockerfile            Basis aquasec/trivy + python3
docker-compose.yml
app/server.py         HTTP-Server + Job-Queue (Python-Standardbibliothek)
app/static/           Oberfläche (HTML/CSS/JS, keine externen Abhängigkeiten)
```

Daten: Volume `trivy-gui-data` (`/data/scans/<id>/meta.json`, `result.json`, `trivy.log`).

### API

| Methode | Pfad | |
|---|---|---|
| GET | `/api/info` | Trivy-Version, DB-Stand, Docker-Status |
| GET | `/api/images` | Lokale Docker-Images |
| GET | `/api/scans` | Verlauf |
| POST | `/api/scans` | Scan starten: `{"type":"image","target":"nginx:latest","severities":["CRITICAL","HIGH"],"scanners":["vuln"],"ignoreUnfixed":false}` |
| GET | `/api/scans/<id>` | Status + normalisierte Funde |
| GET | `/api/scans/<id>/raw` | Original-Trivy-JSON |
| POST | `/api/scans/<id>/cancel` | Abbrechen |
| DELETE | `/api/scans/<id>` | Löschen |

## Lokale Entwicklung ohne Docker

```bash
TRIVY_BIN=/pfad/zu/trivy DATA_DIR=./data PORT=8080 python3 app/server.py
```

## Lizenz

[Apache License 2.0](LICENSE)
