# Trivy-Version bewusst per Tag UND Digest pinnen, niemals "latest".
# Hintergrund: Im Maerz 2026 wurden v0.69.4 (Binary) sowie die Docker-Hub-Tags
# 0.69.5 und 0.69.6 kompromittiert. Siehe README, Abschnitt "Sicherheit".
# Beim Update beide Werte gemeinsam aendern:
#   docker buildx imagetools inspect aquasec/trivy:<version>
ARG TRIVY_VERSION=0.74.0
ARG TRIVY_DIGEST=sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969
FROM aquasec/trivy:${TRIVY_VERSION}@${TRIVY_DIGEST}

RUN apk add --no-cache python3

WORKDIR /app
COPY app/ /app/

ENV DATA_DIR=/data \
    TRIVY_CACHE_DIR=/cache \
    PORT=8080 \
    PYTHONUNBUFFERED=1

VOLUME ["/data", "/cache"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["python3", "/app/server.py"]
