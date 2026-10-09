#!/usr/bin/env python3
"""Trivy GUI - kleiner Webserver rund um die Trivy-CLI.

Nutzt ausschliesslich die Python-Standardbibliothek. Scans laufen als
Hintergrund-Jobs; Ergebnisse werden als JSON unter DATA_DIR/scans/<id>/ abgelegt.
"""
import base64
import hmac
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

TRIVY_BIN = os.environ.get("TRIVY_BIN", "trivy")
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
STATIC_DIR = Path(__file__).resolve().parent / "static"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
DOCKER_SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
MAX_PARALLEL = max(1, int(os.environ.get("MAX_PARALLEL_SCANS", "1")))
SCAN_TIMEOUT = os.environ.get("SCAN_TIMEOUT", "15m")
AUTH_USER = os.environ.get("AUTH_USER", "")
AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", "")

SCANS_DIR = DATA_DIR / "scans"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SCANNERS = ["vuln", "secret", "misconfig", "license"]
TYPES = ["image", "repo"]
ACTIVE = ("queued", "running")

# Ziele werden nach "--" uebergeben und zusaetzlich streng validiert,
# damit nichts als Trivy-Option interpretiert werden kann.
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
REPO_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%-]+)+/?$")
ID_RE = re.compile(r"^[0-9a-f]{32}$")

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}

_lock = threading.Lock()
_procs = {}
_executor = ThreadPoolExecutor(max_workers=MAX_PARALLEL)
_info_cache = {"at": 0.0, "data": None}


class ApiError(ValueError):
    """Fehler mit maschinenlesbarem Code; die Oberflaeche uebersetzt anhand des Codes."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------------------------------------------------------
# Ablage
# --------------------------------------------------------------------------

def scan_dir(sid):
    return SCANS_DIR / sid


def read_meta(sid):
    with open(scan_dir(sid) / "meta.json", encoding="utf-8") as f:
        return json.load(f)


def write_meta(meta):
    path = scan_dir(meta["id"]) / "meta.json"
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def update_meta(sid, **changes):
    with _lock:
        meta = read_meta(sid)
        meta.update(changes)
        write_meta(meta)
        return meta


def list_scans():
    scans = []
    if not SCANS_DIR.is_dir():
        return scans
    for d in SCANS_DIR.iterdir():
        if d.is_dir() and ID_RE.match(d.name) and (d / "meta.json").is_file():
            try:
                scans.append(read_meta(d.name))
            except (OSError, ValueError):
                continue
    scans.sort(key=lambda m: m.get("created", ""), reverse=True)
    return scans


def tail(path, max_bytes=4000):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


# --------------------------------------------------------------------------
# Trivy-Report normalisieren
# --------------------------------------------------------------------------

def normalize(report):
    findings = []
    for res in report.get("Results") or []:
        target = res.get("Target", "")
        rtype = res.get("Type", "")
        for v in res.get("Vulnerabilities") or []:
            findings.append({
                "kind": "vuln",
                "id": v.get("VulnerabilityID", ""),
                "severity": v.get("Severity", "UNKNOWN"),
                "pkg": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion", ""),
                "status": v.get("Status", ""),
                "title": v.get("Title") or (v.get("Description") or "")[:200],
                "url": v.get("PrimaryURL", ""),
                "target": target,
                "type": rtype,
            })
        for m in res.get("Misconfigurations") or []:
            findings.append({
                "kind": "misconfig",
                "id": m.get("AVDID") or m.get("ID", ""),
                "severity": m.get("Severity", "UNKNOWN"),
                "pkg": "",
                "installed": "",
                "fixed": m.get("Resolution", ""),
                "status": m.get("Status", ""),
                "title": m.get("Title", "") + (" - " + m["Message"] if m.get("Message") else ""),
                "url": m.get("PrimaryURL", ""),
                "target": target,
                "type": rtype,
            })
        for s in res.get("Secrets") or []:
            # "Match" enthaelt Teile des Secrets und wird bewusst nicht uebernommen.
            line = s.get("StartLine")
            findings.append({
                "kind": "secret",
                "id": s.get("RuleID", ""),
                "severity": s.get("Severity", "UNKNOWN"),
                "pkg": s.get("Category", ""),
                "installed": "",
                "line": line,
                "fixed": "",
                "status": "",
                "title": s.get("Title", ""),
                "url": "",
                "target": target,
                "type": rtype,
            })
        for lic in res.get("Licenses") or []:
            findings.append({
                "kind": "license",
                "id": lic.get("Name", ""),
                "severity": lic.get("Severity", "UNKNOWN"),
                "pkg": lic.get("PkgName", ""),
                "installed": "",
                "fixed": "",
                "status": lic.get("Category", ""),
                "title": f"{lic.get('Name', '')} ({lic.get('Category', '')})",
                "url": lic.get("Link", ""),
                "target": lic.get("FilePath") or target,
                "type": rtype,
            })
    return findings


def report_info(report):
    md = report.get("Metadata") or {}
    os_info = md.get("OS") or {}
    return {
        "artifact": report.get("ArtifactName", ""),
        "os": " ".join(x for x in (os_info.get("Family"), os_info.get("Name")) if x),
        "eosl": bool(os_info.get("EOSL")),
        "imageId": md.get("ImageID", ""),
        "trivyVersion": (report.get("Trivy") or {}).get("Version", ""),
    }


# --------------------------------------------------------------------------
# Scan-Ausfuehrung
# --------------------------------------------------------------------------

def run_scan(sid):
    with _lock:
        meta = read_meta(sid)
        if meta["status"] != "queued":
            return
        meta.update(status="running", started=now())
        write_meta(meta)

    d = scan_dir(sid)
    opts = meta["options"]
    result_path = d / "result.json"
    cmd = [
        TRIVY_BIN, meta["type"],
        "--format", "json",
        "--output", str(result_path),
        "--no-progress",
        "--timeout", SCAN_TIMEOUT,
        "--scanners", ",".join(opts["scanners"]),
        "--severity", ",".join(opts["severities"]),
    ]
    if opts.get("ignoreUnfixed"):
        cmd.append("--ignore-unfixed")
    cmd += ["--", meta["target"]]

    try:
        with open(d / "trivy.log", "wb") as log:
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            with _lock:
                _procs[sid] = proc
            rc = proc.wait()
    except OSError as e:
        update_meta(sid, status="failed", finished=now(), errorCode="start_failed", error=str(e))
        return
    finally:
        with _lock:
            _procs.pop(sid, None)

    with _lock:
        meta = read_meta(sid)
        if meta["status"] == "cancelled":
            meta["finished"] = now()
            write_meta(meta)
            return

    if rc != 0 or not result_path.is_file():
        update_meta(sid, status="failed", finished=now(),
                    error=tail(d / "trivy.log") or f"Trivy exited with code {rc}")
        return

    try:
        with open(result_path, encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, ValueError) as e:
        update_meta(sid, status="failed", finished=now(), errorCode="result_unreadable", error=str(e))
        return

    findings = normalize(report)
    counts = {s: 0 for s in SEVERITIES}
    for fd in findings:
        counts[fd["severity"] if fd["severity"] in counts else "UNKNOWN"] += 1
    update_meta(sid, status="done", finished=now(), counts=counts,
                total=len(findings), info=report_info(report))


def create_scan(payload):
    scan_type = payload.get("type")
    target = str(payload.get("target", "")).strip()
    if scan_type not in TYPES:
        raise ApiError("invalid_type", "Unknown scan type.")
    if scan_type == "image" and not IMAGE_RE.match(target):
        raise ApiError("invalid_image", "Invalid image name.")
    if scan_type == "repo" and not REPO_RE.match(target):
        raise ApiError("invalid_repo", "Invalid repository URL (https only).")

    severities = [s for s in SEVERITIES if s in (payload.get("severities") or [])]
    scanners = [s for s in SCANNERS if s in (payload.get("scanners") or [])]
    if not severities:
        raise ApiError("no_severity", "Select at least one severity.")
    if not scanners:
        raise ApiError("no_scanner", "Select at least one scanner.")

    sid = uuid.uuid4().hex
    scan_dir(sid).mkdir(parents=True)
    meta = {
        "id": sid,
        "type": scan_type,
        "target": target,
        "options": {
            "severities": severities,
            "scanners": scanners,
            "ignoreUnfixed": bool(payload.get("ignoreUnfixed")),
        },
        "status": "queued",
        "created": now(),
        "started": None,
        "finished": None,
        "error": None,
        "errorCode": None,
        "counts": None,
        "total": None,
        "info": None,
    }
    with _lock:
        write_meta(meta)
    _executor.submit(run_scan, sid)
    return meta


def cancel_scan(sid):
    with _lock:
        meta = read_meta(sid)
        if meta["status"] not in ACTIVE:
            return meta
        meta.update(status="cancelled", finished=now())
        write_meta(meta)
        proc = _procs.get(sid)
    if proc:
        proc.terminate()
    return meta


def recover_interrupted():
    for meta in list_scans():
        if meta.get("status") in ACTIVE:
            meta.update(status="failed", finished=now(), errorCode="interrupted", error="Interrupted by server restart.")
            write_meta(meta)


# --------------------------------------------------------------------------
# Docker / Trivy Infos
# --------------------------------------------------------------------------

class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=5)
        self._path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(self._path)
        self.sock = sock


def docker_images():
    if not hasattr(socket, "AF_UNIX") or not os.path.exists(DOCKER_SOCK):
        return None
    conn = UnixHTTPConnection(DOCKER_SOCK)
    try:
        conn.request("GET", "/images/json")
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        data = json.loads(resp.read())
    except (OSError, ValueError, http.client.HTTPException):
        return None
    finally:
        conn.close()
    images = []
    for img in data:
        for tag in img.get("RepoTags") or []:
            if tag and tag != "<none>:<none>":
                images.append({"name": tag, "size": img.get("Size", 0), "created": img.get("Created", 0)})
    images.sort(key=lambda i: i["name"])
    return images


def trivy_info():
    if _info_cache["data"] and time.time() - _info_cache["at"] < 60:
        return _info_cache["data"]
    info = {"version": None, "dbUpdatedAt": None}
    try:
        out = subprocess.run([TRIVY_BIN, "version", "--format", "json"],
                             capture_output=True, timeout=15, stdin=subprocess.DEVNULL)
        data = json.loads(out.stdout or b"{}")
        info["version"] = data.get("Version")
        info["dbUpdatedAt"] = (data.get("VulnerabilityDB") or {}).get("UpdatedAt")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    _info_cache.update(at=time.time(), data=info)
    return info


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "TrivyGUI"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Polling-Anfragen nicht ins Log schreiben.
        if self.command == "GET" and self.path.startswith("/api/"):
            return
        super().log_message(fmt, *args)

    # -- Hilfsfunktionen ---------------------------------------------------

    def _security_headers(self):
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                         "script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")

    def send_json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status, message, code=None):
        self.send_json(status, {"error": message, "code": code})

    def send_file(self, path, ctype, download_name=None):
        try:
            data = path.read_bytes()
        except OSError:
            self.send_error_json(HTTPStatus.NOT_FOUND, "Not found.", "not_found")
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if download_name:
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
            self.send_header("Cache-Control", "no-store")
        else:
            self.send_header("Cache-Control", "no-cache")
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self):
        if not AUTH_USER:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            user, _, password = base64.b64decode(header[6:]).decode("utf-8").partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        ok_user = hmac.compare_digest(user.encode(), AUTH_USER.encode())
        ok_pass = hmac.compare_digest(password.encode(), AUTH_PASSWORD.encode())
        return ok_user and ok_pass

    def _check_auth(self):
        if self._authorized():
            return True
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="Trivy GUI", charset="UTF-8"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _same_origin(self):
        """Schutz vor CSRF: schreibende Anfragen nur von derselben Origin."""
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc != self.headers.get("Host", ""):
            return False
        return True

    def _read_json(self):
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ApiError("bad_content_type", "Content-Type must be application/json.")
        length = int(self.headers.get("Content-Length") or 0)
        if length > 64 * 1024:
            raise ApiError("too_large", "Request too large.")
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            raise ApiError("bad_request", "Invalid request.")
        return payload

    def _scan_route(self):
        """Zerlegt /api/scans/<id>[/<action>] -> (id, action) oder (None, None)."""
        parts = urlparse(self.path).path.strip("/").split("/")
        if len(parts) in (3, 4) and parts[:2] == ["api", "scans"] and ID_RE.match(parts[2]):
            if (scan_dir(parts[2]) / "meta.json").is_file():
                return parts[2], (parts[3] if len(parts) == 4 else None)
        return None, None

    # -- Routen ---------------------------------------------------------------

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            self.send_json(HTTPStatus.OK, {"ok": True})
            return
        if not self._check_auth():
            return

        if path in STATIC_FILES:
            name, ctype = STATIC_FILES[path]
            self.send_file(STATIC_DIR / name, ctype)
        elif path == "/api/info":
            info = trivy_info()
            info["docker"] = docker_images() is not None
            self.send_json(HTTPStatus.OK, info)
        elif path == "/api/images":
            images = docker_images()
            self.send_json(HTTPStatus.OK, {"available": images is not None, "images": images or []})
        elif path == "/api/scans":
            self.send_json(HTTPStatus.OK, {"scans": list_scans()})
        else:
            sid, action = self._scan_route()
            if not sid:
                self.send_error_json(HTTPStatus.NOT_FOUND, "Not found.", "not_found")
            elif action is None:
                self._get_scan(sid)
            elif action == "raw":
                safe = re.sub(r"[^A-Za-z0-9._-]+", "_", read_meta(sid)["target"])[:80]
                self.send_file(scan_dir(sid) / "result.json", "application/json",
                               download_name=f"trivy-{safe}-{sid[:8]}.json")
            else:
                self.send_error_json(HTTPStatus.NOT_FOUND, "Not found.", "not_found")

    def _get_scan(self, sid):
        meta = read_meta(sid)
        resp = {"scan": meta, "findings": None, "log": None}
        if meta["status"] == "done":
            try:
                with open(scan_dir(sid) / "result.json", encoding="utf-8") as f:
                    resp["findings"] = normalize(json.load(f))
            except (OSError, ValueError):
                resp["findings"] = []
        else:
            resp["log"] = tail(scan_dir(sid) / "trivy.log")
        self.send_json(HTTPStatus.OK, resp)

    def do_POST(self):
        if not self._check_auth():
            return
        if not self._same_origin():
            self.send_error_json(HTTPStatus.FORBIDDEN, "Cross-origin request rejected.", "forbidden_origin")
            return
        path = urlparse(self.path).path
        if path == "/api/scans":
            try:
                meta = create_scan(self._read_json())
            except ApiError as e:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(e), e.code)
                return
            self.send_json(HTTPStatus.CREATED, {"scan": meta})
            return
        sid, action = self._scan_route()
        if sid and action == "cancel":
            self.send_json(HTTPStatus.OK, {"scan": cancel_scan(sid)})
        else:
            self.send_error_json(HTTPStatus.NOT_FOUND, "Not found.", "not_found")

    def do_DELETE(self):
        if not self._check_auth():
            return
        if not self._same_origin():
            self.send_error_json(HTTPStatus.FORBIDDEN, "Cross-origin request rejected.", "forbidden_origin")
            return
        sid, action = self._scan_route()
        if not sid or action is not None:
            self.send_error_json(HTTPStatus.NOT_FOUND, "Not found.", "not_found")
            return
        cancel_scan(sid)
        proc = _procs.get(sid)
        if proc:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(scan_dir(sid), ignore_errors=True)
        self.send_json(HTTPStatus.OK, {"deleted": sid})


def main():
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    recover_interrupted()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    if AUTH_USER and not AUTH_PASSWORD:
        print("WARNUNG: AUTH_USER gesetzt, aber AUTH_PASSWORD leer.", flush=True)
    print(f"Trivy GUI laeuft auf http://{HOST}:{PORT} (parallele Scans: {MAX_PARALLEL})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
