# Base image for every Python service in the M1 stack.
#
# All 14+ Python services (mock OIDC, auth gateway, MCP gateway, six mock
# APIs, six MCP servers) share the same dependency surface — so one image
# is built once and each service entry is selected via the compose
# `command:` (factory + port). Grafana ships in its own upstream image.
#
# Healthchecks use the stdlib `urllib.request` so the image stays free of
# curl/wget dependencies.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install only what the runtime needs. dev extras are NOT included in the
# image — tests run on the host.
COPY pyproject.toml README.md ./
RUN pip install --upgrade pip && \
    pip install \
        "fastapi>=0.110" \
        "uvicorn[standard]>=0.27" \
        "fastmcp>=0.2" \
        "pyseto>=1.7" \
        "pyjwt[crypto]>=2.8" \
        "httpx>=0.27" \
        "pydantic>=2.6" \
        "pyyaml>=6.0" \
        "opentelemetry-sdk>=1.24" \
        "opentelemetry-exporter-otlp>=1.24" \
        "opentelemetry-instrumentation-fastapi>=0.45b0" \
        "opentelemetry-instrumentation-httpx>=0.45b0"

COPY gateways ./gateways
COPY mcp_servers ./mcp_servers
COPY mock_apis ./mock_apis
COPY config ./config

# Default port; overridden per service in docker-compose.
ENV SERVICE_PORT=8000
EXPOSE 8000
