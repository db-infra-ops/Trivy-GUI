# Trivy-Version bewusst fest pinnen, niemals "latest".
# Hintergrund: Im Maerz 2026 wurden v0.69.4 (Binary) sowie die Docker-Hub-Tags
# 0.69.5 und 0.69.6 kompromittiert. Siehe README, Abschnitt "Sicherheit".
ARG TRIVY_VERSION=0.69.3
FROM aquasec/trivy:${TRIVY_VERSION}

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
