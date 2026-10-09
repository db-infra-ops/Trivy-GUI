# Trivy GUI

**English** | [Deutsch](README_DE.md)

[![Docker image](https://github.com/db-infra-ops/Trivy-GUI/actions/workflows/docker.yml/badge.svg)](https://github.com/db-infra-ops/Trivy-GUI/actions/workflows/docker.yml)

Lightweight web interface for [Trivy](https://github.com/aquasecurity/trivy) that runs entirely inside a single Docker container.

- Scan container images (local or from a registry) and Git repositories
- Vulnerabilities, secrets, misconfigurations and licenses
- Results overview by severity, full-text search, filters (type, target, "fixed only"), sortable table
- Scan history: rescan, cancel, delete
- Export as Trivy JSON or CSV (Excel-friendly)
- User interface in English and German (switch in the header, remembered per browser)
- Prebuilt multi-arch image (amd64/arm64) on GitHub Container Registry
- No dependencies besides Trivy and Python 3 (standard library only)

## Getting started

With the prebuilt image (recommended):

```bash
docker compose up -d
```

Or without Compose:

```bash
docker run -d --name trivy-gui -p 127.0.0.1:8080:8080 -v /var/run/docker.sock:/var/run/docker.sock:ro -v trivy-gui-data:/data -v trivy-cache:/cache ghcr.io/db-infra-ops/trivy-gui:latest
```

To build the image yourself: `docker compose up -d --build`

Then open <http://localhost:8080>.

The first scan takes longer because Trivy has to download its vulnerability database first. The database is stored in the `trivy-cache` volume and is only updated afterwards.

## Configuration (environment variables in `docker-compose.yml`)

| Variable | Default | Description |
|---|---|---|
| `MAX_PARALLEL_SCANS` | `1` | Concurrent scans (Trivy locks its cache, so 1 is recommended) |
| `SCAN_TIMEOUT` | `15m` | Timeout per scan |
| `AUTH_USER` / `AUTH_PASSWORD` | empty | Enables HTTP Basic Auth |
| `TRIVY_USERNAME` / `TRIVY_PASSWORD` | empty | Credentials for private registries |
| `PORT` | `8080` | Port inside the container |

Alternatively, private registries can be used by mounting your Docker config:
`- ~/.docker/config.json:/root/.docker/config.json:ro`

## Security

**Pin the Trivy version.** In March 2026 Trivy was hit by a supply-chain attack:
release v0.69.4 as well as the Docker Hub images `aquasec/trivy:0.69.5` and `0.69.6` were compromised
(CVE-2026-33634, GHSA-69fq-xp46-6x23). This project therefore pins `0.69.3` and never uses `latest`.

- Check the [official releases](https://github.com/aquasecurity/trivy/releases) and advisories before upgrading.
- Even safer: pin the base image by digest:
  ```bash
  docker pull aquasec/trivy:0.69.3
  docker inspect --format "{{index .RepoDigests 0}}" aquasec/trivy:0.69.3
  ```
  Then put the digest into the `Dockerfile`: `FROM aquasec/trivy:0.69.3@sha256:...`

**Docker socket.** `/var/run/docker.sock` is mounted to scan local images. Anyone with access to the socket effectively has
root on the host, and `:ro` does not change that. Therefore:

- By default the GUI is only reachable on `127.0.0.1`.
- If you expose it on your network, always set `AUTH_USER`/`AUTH_PASSWORD`, ideally behind a reverse proxy with HTTPS.
- If you only scan registry images, you can remove the socket mount.

The app itself calls Trivy without a shell, strictly validates image names and URLs, serves content with a strict CSP,
checks the origin of write requests (CSRF) and never shows secret contents ("Match") in the UI.

## Docker image & CI

The GitHub Actions workflow [`.github/workflows/docker.yml`](.github/workflows/docker.yml) builds the image for
`linux/amd64` and `linux/arm64` and publishes it to `ghcr.io/db-infra-ops/trivy-gui`:

| Trigger | Tags |
|---|---|
| Push to `main` | `latest`, `sha-<commit>` |
| Git tag `v1.2.3` | `1.2.3`, `1.2`, `sha-<commit>` |
| Pull request | build only, nothing is pushed |

Every image ships with an SBOM and build provenance. All actions are pinned to commit SHAs;
Dependabot keeps them up to date.

## Structure

```
.github/workflows/    CI: build & publish the Docker image
Dockerfile            Base aquasec/trivy + python3
docker-compose.yml
app/server.py         HTTP server + job queue (Python standard library)
app/static/           UI (HTML/CSS/JS, no external dependencies)
```

Data: volume `trivy-gui-data` (`/data/scans/<id>/meta.json`, `result.json`, `trivy.log`).

### API

| Method | Path | |
|---|---|---|
| GET | `/api/info` | Trivy version, DB state, Docker status |
| GET | `/api/images` | Local Docker images |
| GET | `/api/scans` | History |
| POST | `/api/scans` | Start a scan: `{"type":"image","target":"nginx:latest","severities":["CRITICAL","HIGH"],"scanners":["vuln"],"ignoreUnfixed":false}` |
| GET | `/api/scans/<id>` | Status + normalized findings |
| GET | `/api/scans/<id>/raw` | Original Trivy JSON |
| POST | `/api/scans/<id>/cancel` | Cancel |
| DELETE | `/api/scans/<id>` | Delete |

## Local development without Docker

```bash
TRIVY_BIN=/path/to/trivy DATA_DIR=./data PORT=8080 python3 app/server.py
```

## License

[Apache License 2.0](LICENSE)
