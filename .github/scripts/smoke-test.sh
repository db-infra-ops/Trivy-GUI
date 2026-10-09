#!/usr/bin/env bash
# Smoke-Test: startet das gebaute Image und fuehrt echte Scans ueber die API aus.
#  1. lokales Image ueber den Docker-Socket (das Image selbst)
#  2. Image direkt aus der Registry
set -euo pipefail

IMAGE="${1:?Aufruf: smoke-test.sh <image>}"
NAME=trivy-gui-smoke
BASE=http://127.0.0.1:8080

cleanup() {
  echo "::group::Container-Log"
  docker logs "$NAME" 2>&1 || true
  echo "::endgroup::"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "$NAME" -p 127.0.0.1:8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  curl -fsS "$BASE/api/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$BASE/api/health" >/dev/null

echo "Info:   $(curl -fsS "$BASE/api/info")"
echo "Images: $(curl -fsS "$BASE/api/images" | jq -c '{available, count: (.images | length)}')"
[ "$(curl -fsS "$BASE/api/images" | jq -r .available)" = "true" ] || { echo "Docker-Socket nicht erreichbar"; exit 1; }

start_scan() {
  curl -fsS -X POST -H 'Content-Type: application/json' \
    -d "{\"type\":\"image\",\"target\":\"$1\",\"severities\":[\"CRITICAL\",\"HIGH\",\"MEDIUM\",\"LOW\",\"UNKNOWN\"],\"scanners\":[\"vuln\",\"secret\",\"misconfig\",\"license\"],\"ignoreUnfixed\":true}" \
    "$BASE/api/scans" | jq -r .scan.id
}

wait_scan() {
  local id=$1 target=$2 status
  for _ in $(seq 1 120); do
    status=$(curl -fsS "$BASE/api/scans/$id" | jq -r .scan.status)
    case "$status" in
      done)
        echo "OK  $target: $(curl -fsS "$BASE/api/scans/$id" | jq -c '{total: .scan.total, counts: .scan.counts, os: .scan.info.os}')"
        return 0 ;;
      failed|cancelled)
        echo "FEHLER $target ($status):"
        curl -fsS "$BASE/api/scans/$id" | jq -r '.scan.error // .log'
        return 1 ;;
    esac
    sleep 5
  done
  echo "TIMEOUT $target"
  return 1
}

LOCAL_ID=$(start_scan "$IMAGE")
REMOTE_ID=$(start_scan "alpine:3.20")
wait_scan "$LOCAL_ID" "$IMAGE (lokal)"
wait_scan "$REMOTE_ID" "alpine:3.20 (Registry)"

# Raw-Export muss gueltiges Trivy-JSON liefern
curl -fsS "$BASE/api/scans/$LOCAL_ID/raw" | jq -e '.SchemaVersion == 2' >/dev/null

# Bericht ueber die Funde im eigenen Image (nur mit verfuegbarem Fix)
REPORT=$(curl -fsS "$BASE/api/scans/$LOCAL_ID" | jq -r '
  (.findings | map(select(.kind != "license"))) as $f
  | (.findings | map(select(.kind == "license"))) as $lic
  | "### Schwachstellen im Image (nur mit Fix)\n",
    "| Ziel | Typ | Kritisch | Hoch | Mittel | Niedrig | Unbekannt |",
    "|---|---|---|---|---|---|---|",
    ($f | group_by(.target)[] | . as $g
      | "| `\($g[0].target)` | \($g[0].type) | \([$g[] | select(.severity=="CRITICAL")] | length) | \([$g[] | select(.severity=="HIGH")] | length) | \([$g[] | select(.severity=="MEDIUM")] | length) | \([$g[] | select(.severity=="LOW")] | length) | \([$g[] | select(.severity=="UNKNOWN")] | length) |"),
    "\nLizenz-Funde (keine Schwachstellen): \($lic | length), davon Hoch/Kritisch: \([$lic[] | select(.severity=="HIGH" or .severity=="CRITICAL")] | length)\n",
    "#### Kritisch und Hoch\n",
    "| Schweregrad | ID | Paket | Installiert | Behoben in | Ziel |",
    "|---|---|---|---|---|---|",
    ($f | map(select(.severity=="CRITICAL" or .severity=="HIGH")) | sort_by(.severity, .pkg, .id)[]
      | "| \(.severity) | \(.id) | \(.pkg) | \(.installed) | \(.fixed) | `\(.target)` |")')
echo "$REPORT"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then echo "$REPORT" >> "$GITHUB_STEP_SUMMARY"; fi

echo "Smoke-Test erfolgreich."
