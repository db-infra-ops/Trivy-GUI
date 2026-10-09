# Trivy GUI

Schlanke Weboberfläche für [Trivy](https://github.com/aquasecurity/trivy), läuft komplett in einem Docker-Container.

- Container-Images (lokal oder aus einer Registry) und Git-Repositories scannen
- Schwachstellen, Secrets, Fehlkonfigurationen und Lizenzen
- Ergebnisübersicht nach Schweregrad, Volltextsuche, Filter (Art, Ziel, „nur mit Fix“), sortierbare Tabelle
- Scan-Verlauf, erneut scannen, Abbrechen, Löschen
- Export als Trivy-JSON oder CSV (Excel-tauglich)
- Keine Abhängigkeiten außer Trivy und Python 3 (nur Standardbibliothek)

## Start

```bash
docker compose up -d --build
```

Danach <http://localhost:8080> öffnen.

Der erste Scan dauert länger, weil Trivy zuerst die Schwachstellen-Datenbank lädt. Die Datenbank liegt im Volume `trivy-cache` und wird anschließend nur noch aktualisiert.

## Konfiguration (Umgebungsvariablen in `docker-compose.yml`)

| Variable | Standard | Bedeutung |
|---|---|---|
| `MAX_PARALLEL_SCANS` | `1` | Gleichzeitige Scans (Trivy sperrt den Cache, daher 1 empfohlen) |
| `SCAN_TIMEOUT` | `15m` | Timeout pro Scan |
| `AUTH_USER` / `AUTH_PASSWORD` | leer | Aktiviert HTTP-Basic-Auth |
| `TRIVY_USERNAME` / `TRIVY_PASSWORD` | leer | Zugangsdaten für private Registries |
| `PORT` | `8080` | Port im Container |

Private Registries lassen sich alternativ nutzen, indem man die Docker-Konfiguration einbindet:
`- ~/.docker/config.json:/root/.docker/config.json:ro`

## Sicherheit

**Trivy-Version pinnen.** Im März 2026 gab es einen Supply-Chain-Angriff auf Trivy:
Das Release v0.69.4 sowie die Docker-Hub-Images `aquasec/trivy:0.69.5` und `0.69.6` waren kompromittiert
(CVE-2026-33634, GHSA-69fq-xp46-6x23). Dieses Projekt pinnt daher `0.69.3` und verwendet nie `latest`.

- Vor einem Update die [offiziellen Releases](https://github.com/aquasecurity/trivy/releases) und Advisories prüfen.
- Noch sicherer: das Basis-Image per Digest pinnen:
  ```bash
  docker pull aquasec/trivy:0.69.3
  docker inspect --format "{{index .RepoDigests 0}}" aquasec/trivy:0.69.3
  ```
  Den Digest dann im `Dockerfile` eintragen: `FROM aquasec/trivy:0.69.3@sha256:...`

**Docker-Socket.** Für lokale Images wird `/var/run/docker.sock` eingebunden. Wer Zugriff auf den Socket hat, hat faktisch
Root-Rechte auf dem Host, und `:ro` ändert daran nichts. Deshalb:

- Die GUI ist standardmäßig nur auf `127.0.0.1` erreichbar.
- Bei Freigabe im Netzwerk unbedingt `AUTH_USER`/`AUTH_PASSWORD` setzen und am besten einen Reverse-Proxy mit HTTPS vorschalten.
- Wird nur aus Registries gescannt, kann die Socket-Zeile entfallen.

Die App selbst ruft Trivy ohne Shell auf, validiert Image-Namen und URLs streng, liefert Inhalte mit einer strikten CSP aus,
prüft bei schreibenden Anfragen die Origin (CSRF) und übernimmt keine Secret-Inhalte („Match“) in die Oberfläche.

## Aufbau

```
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
