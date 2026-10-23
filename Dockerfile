FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY skillguard ./skillguard
RUN /opt/venv/bin/python -m pip install --no-cache-dir --retries 5 --timeout 60 .

FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="SkillGuard" \
      org.opencontainers.image.description="Read-only security auditor for AI agent skills and MCP bundles" \
      org.opencontainers.image.source="https://github.com/Tayane225/SkillGuard" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="1.0.0"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp \
    HOME=/home/skillguard

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 skillguard \
    && useradd --uid 10001 --gid skillguard --create-home \
        --home-dir /home/skillguard --shell /usr/sbin/nologin skillguard

COPY --from=builder /opt/venv /opt/venv

WORKDIR /workspace
USER skillguard
STOPSIGNAL SIGTERM

ENTRYPOINT ["skillguard"]
CMD ["mcp"]
