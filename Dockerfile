# syntax=docker/dockerfile:1

# Base image pinned by digest (Debian 13 slim). Dependabot proposes digest updates.
FROM python:3.12-slim-trixie@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2 AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
# --require-hashes: every wheel must match the lock file, or the build fails.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt \
 && /opt/venv/bin/pip uninstall -y pip


FROM python:3.12-slim-trixie@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2 AS runtime

LABEL org.opencontainers.image.title="shieldpipe" \
      org.opencontainers.image.description="Incident API delivered through a DevSecOps pipeline" \
      org.opencontainers.image.source="https://github.com/Barkatzineddine/shieldpipe" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SHIELDPIPE_DATABASE_URL="sqlite:////app/data/shieldpipe.db"

# No package manager left for an attacker, and a dedicated unprivileged user.
RUN python -m pip uninstall -y pip \
 && groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin app \
 && mkdir -p /app/data \
 && chown app:app /app/data

COPY --from=build /opt/venv /opt/venv
WORKDIR /app
# Code is owned by root and read-only for the app user.
COPY app ./app

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status != 200)"]

CMD ["uvicorn", "app.main:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--no-server-header", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
