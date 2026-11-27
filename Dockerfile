# syntax=docker/dockerfile:1
#
# passkey-vault server image.
#
#   docker build -t passkey-vault .
#   docker build -t passkey-vault --build-arg LOCK=requirements-db.lock .   # with PostgreSQL/MongoDB drivers
#
# Dependencies are installed from hash-pinned lock files, wheels only (nothing is built or executed at
# install time). The server runs as an unprivileged user and only writes to /data.

ARG PYTHON_IMAGE=python:3.15-slim-trixie@sha256:63bb298d2b7b88f176f51b5189f54ce6535c997682ea70885d2132f5d473a8a5

FROM ${PYTHON_IMAGE} AS deps
ARG LOCK=requirements.lock
COPY deploy/${LOCK} /tmp/requirements.lock
RUN python -m venv /venv \
 && /venv/bin/pip install --no-cache-dir --disable-pip-version-check --no-input \
      --require-hashes --no-deps --only-binary :all: -r /tmp/requirements.lock

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="passkey-vault" \
      org.opencontainers.image.description="Release one secret to one command, only after a passkey approval." \
      org.opencontainers.image.licenses="MIT"

RUN useradd --system --uid 10001 --user-group --home-dir /nonexistent --shell /usr/sbin/nologin passkey-vault \
 && install -d -o passkey-vault -g passkey-vault -m 0700 /data

COPY --from=deps /venv /venv
COPY packages/server/src /app/src

ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER passkey-vault
WORKDIR /data
VOLUME ["/data"]
# 8740: approver door (put an HTTPS reverse proxy in front). 8741: requester door (publish to loopback only).
EXPOSE 8740 8741

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8740/', timeout=2)"]

ENTRYPOINT ["/venv/bin/python", "-m", "passkey_vault", "--bind", "0.0.0.0", "--data-dir", "/data"]
CMD ["--origin", "http://localhost:8740"]
