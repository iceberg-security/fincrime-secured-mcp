"""Structural tests for the docker-compose stack (US-011 + US-024).

These tests do NOT spin up Docker — they parse ``docker-compose.yml`` and
``Dockerfile`` and assert that the stack is wired consistently with each
service's ``build_default_app()`` env-var contract. Catches drift between
the compose file and the production entry points before ``docker compose up``
fails on a missing env var.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT / "docker-compose.yml"
DOCKERFILE = ROOT / "Dockerfile"
MAKEFILE = ROOT / "Makefile"
README = ROOT / "README.md"


# Six MCP server names — must match the directory names under mcp_servers/.
MCP_SERVERS = ("customer_data", "transactions", "kyc", "sanctions", "osint", "case_actions")

# (mock_service_name, mock_port, mcp_service_name, mcp_port) per server.
SERVER_TOPOLOGY: tuple[tuple[str, int, str, int], ...] = (
    ("customer-data-mock", 8001, "customer-data-mcp", 8002),
    ("transactions-mock", 8003, "transactions-mcp", 8004),
    ("kyc-mock", 8005, "kyc-mcp", 8006),
    ("sanctions-mock", 8007, "sanctions-mcp", 8008),
    ("osint-mock", 8009, "osint-mcp", 8010),
    ("case-actions-mock", 8011, "case-actions-mcp", 8012),
)


def _server_name_for(compose_name: str) -> str:
    """'customer-data-mcp' -> 'customer_data', etc."""
    return compose_name.replace("-mcp", "").replace("-mock", "").replace("-", "_")


REQUIRED_SERVICES = {
    "mock-oidc",
    "auth-gateway",
    "mcp-gateway",
    "grafana",
} | {row[0] for row in SERVER_TOPOLOGY} | {row[2] for row in SERVER_TOPOLOGY}


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    raw = COMPOSE_FILE.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    assert isinstance(data, dict), "compose file must parse to a mapping"
    return data


@pytest.fixture(scope="module")
def services(compose: dict[str, Any]) -> dict[str, dict[str, Any]]:
    svc = compose.get("services")
    assert isinstance(svc, dict), "compose file must declare a services map"
    return svc


# --------------------------------------------------------------------------- #
# Service inventory                                                           #
# --------------------------------------------------------------------------- #


def test_compose_file_exists() -> None:
    assert COMPOSE_FILE.exists(), "docker-compose.yml must exist at the repo root"


def test_dockerfile_exists() -> None:
    assert DOCKERFILE.exists(), "Dockerfile must exist at the repo root"


def test_all_required_services_declared(services: dict[str, dict[str, Any]]) -> None:
    assert REQUIRED_SERVICES.issubset(services.keys()), (
        f"missing services: {REQUIRED_SERVICES - services.keys()}"
    )


def test_every_service_has_healthcheck(services: dict[str, dict[str, Any]]) -> None:
    for name in REQUIRED_SERVICES:
        svc = services[name]
        hc = svc.get("healthcheck")
        assert isinstance(hc, dict), f"{name} missing healthcheck"
        assert "test" in hc, f"{name} healthcheck missing 'test'"


def test_healthcheck_budget_is_under_15_seconds(services: dict[str, dict[str, Any]]) -> None:
    """interval * retries + start_period must be <= 15s per US-011 AC."""
    for name in REQUIRED_SERVICES:
        hc = services[name]["healthcheck"]
        interval = _parse_duration(hc.get("interval", "30s"))
        retries = int(hc.get("retries", 3))
        start = _parse_duration(hc.get("start_period", "0s"))
        budget = interval * retries + start
        assert budget <= 15.0, (
            f"{name} healthcheck budget {budget}s exceeds 15s "
            f"(interval={interval}, retries={retries}, start_period={start})"
        )


def _parse_duration(raw: object) -> float:
    if isinstance(raw, (int, float)):
        return float(raw)
    assert isinstance(raw, str), f"expected duration string, got {raw!r}"
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|s|m|h)?", raw.strip())
    assert match, f"unrecognized duration: {raw!r}"
    value = float(match.group(1))
    unit = match.group(2) or "s"
    return value * {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}[unit]


# --------------------------------------------------------------------------- #
# Service-specific wiring                                                     #
# --------------------------------------------------------------------------- #


def test_mock_oidc_command_uses_factory(services: dict[str, dict[str, Any]]) -> None:
    cmd = _command_str(services["mock-oidc"])
    assert "mock_apis.mock_oidc.main:build_default_app" in cmd
    assert "--factory" in cmd


def test_auth_gateway_env_matches_build_default_app(
    services: dict[str, dict[str, Any]],
) -> None:
    """Every env var that gateways/auth/main.py:build_default_app reads must be present."""
    env = services["auth-gateway"].get("environment", {})
    assert isinstance(env, dict)
    expected = {
        "OIDC_JWKS_URL",
        "OIDC_AUDIENCE",
        "PASETO_PRIVATE_KEY_PATH",
        "PASETO_PUBLIC_KEY_PATH",
        "RBAC_CONFIG_PATH",
    }
    missing = expected - env.keys()
    assert not missing, f"auth-gateway missing env vars: {missing}"
    # The auth gateway must reach the mock IdP by its compose hostname.
    assert env["OIDC_JWKS_URL"].startswith("http://mock-oidc"), (
        "auth-gateway OIDC_JWKS_URL must point at the in-network mock-oidc service"
    )
    assert services["auth-gateway"]["depends_on"]["mock-oidc"]["condition"] == "service_healthy"


def test_mcp_gateway_env_matches_build_default_app(
    services: dict[str, dict[str, Any]],
) -> None:
    env = services["mcp-gateway"].get("environment", {})
    assert isinstance(env, dict)
    # One of the two downstream-URL shapes must be set. The 14-service stack
    # uses the JSON map; the M0 single-server stack used the legacy single URL.
    has_single = "MCP_GATEWAY_DOWNSTREAM_URL" in env
    has_map = "MCP_GATEWAY_DOWNSTREAM_URLS" in env
    assert has_single or has_map, (
        "mcp-gateway must declare MCP_GATEWAY_DOWNSTREAM_URL or "
        "MCP_GATEWAY_DOWNSTREAM_URLS"
    )
    expected = {
        "MCP_GATEWAY_SERVICE_PRIVATE_KEY",
        "MCP_GATEWAY_INBOUND_PUBLIC_KEY",
    }
    missing = expected - env.keys()
    assert not missing, f"mcp-gateway missing env vars: {missing}"
    # SQLite audit by default per PRD.
    assert env.get("AUDIT_BACKEND", "sqlite") == "sqlite"
    assert env["AUDIT_DB_PATH"].startswith("/")


def test_mcp_gateway_downstream_urls_map_covers_every_mcp_server(
    services: dict[str, dict[str, Any]],
) -> None:
    """The JSON map must point each MCP server name at its in-network MCP container."""
    env = services["mcp-gateway"].get("environment", {})
    raw = env.get("MCP_GATEWAY_DOWNSTREAM_URLS")
    if raw is None:
        pytest.skip("compose uses the single-URL shape, not the map")
    assert isinstance(raw, str)
    parsed = json.loads(raw)
    assert isinstance(parsed, dict)
    # Every MCP server must have an entry and the value must reference the
    # right in-network hostname.
    expected_topology = {row[2]: row[3] for row in SERVER_TOPOLOGY}
    for mcp_compose_name, mcp_port in expected_topology.items():
        server_name = _server_name_for(mcp_compose_name)
        assert server_name in parsed, (
            f"MCP_GATEWAY_DOWNSTREAM_URLS missing entry for '{server_name}'"
        )
        url = parsed[server_name]
        assert mcp_compose_name in url, (
            f"{server_name} downstream URL must point at {mcp_compose_name}; got {url!r}"
        )
        assert f":{mcp_port}" in url, (
            f"{server_name} downstream URL must include port {mcp_port}; got {url!r}"
        )


@pytest.mark.parametrize(
    "mock_name, mock_port, mcp_name, mcp_port", SERVER_TOPOLOGY
)
def test_mcp_server_env_matches_build_default_app(
    services: dict[str, dict[str, Any]],
    mock_name: str,
    mock_port: int,
    mcp_name: str,
    mcp_port: int,
) -> None:
    """Each MCP server must declare its PASETO public key + the mock's URL."""
    env = services[mcp_name].get("environment", {})
    assert isinstance(env, dict)
    server_name = _server_name_for(mcp_name)
    pub_key_var = f"{server_name.upper()}_MCP_PUBLIC_KEY"
    api_url_var = f"{server_name.upper()}_API_URL"
    assert pub_key_var in env, f"{mcp_name} missing env {pub_key_var}"
    assert api_url_var in env, f"{mcp_name} missing env {api_url_var}"
    assert env[api_url_var].startswith(f"http://{mock_name}"), (
        f"{mcp_name} {api_url_var} must point at the in-network mock ({mock_name})"
    )
    assert f":{mock_port}" in env[api_url_var]
    # Each MCP server must depend on its own mock.
    deps = services[mcp_name].get("depends_on", {})
    assert mock_name in deps, f"{mcp_name} must depend on {mock_name}"


def test_paseto_keypair_consistency(services: dict[str, dict[str, Any]]) -> None:
    """The auth gateway's PASETO PUBLIC key MUST equal the MCP gateway's INBOUND
    PUBLIC key — they're the two halves of the same user-token verification."""
    auth_pub = services["auth-gateway"]["environment"]["PASETO_PUBLIC_KEY_PATH"]
    mcp_inbound = services["mcp-gateway"]["environment"]["MCP_GATEWAY_INBOUND_PUBLIC_KEY"]
    assert auth_pub == mcp_inbound, (
        "auth gateway's PASETO public key must match the MCP gateway's "
        f"inbound public key (auth={auth_pub!r}, mcp={mcp_inbound!r})"
    )


@pytest.mark.parametrize(
    "mcp_name", [row[2] for row in SERVER_TOPOLOGY]
)
def test_service_paseto_keypair_consistency(
    services: dict[str, dict[str, Any]], mcp_name: str
) -> None:
    """Every MCP server's PUBLIC key must be the public half of the MCP
    gateway's service-to-service PRIVATE key — same keypair, two sides."""
    mcp_priv = services["mcp-gateway"]["environment"]["MCP_GATEWAY_SERVICE_PRIVATE_KEY"]
    server_name = _server_name_for(mcp_name)
    pub_var = f"{server_name.upper()}_MCP_PUBLIC_KEY"
    server_pub = services[mcp_name]["environment"][pub_var]
    assert mcp_priv.replace("private", "public") == server_pub, (
        f"{mcp_name} keypair mismatch: mcp_priv={mcp_priv!r}, "
        f"server_pub={server_pub!r}"
    )


def test_compose_uses_named_volume_for_audit(
    compose: dict[str, Any], services: dict[str, dict[str, Any]]
) -> None:
    volumes = compose.get("volumes", {})
    assert "audit_data" in volumes, "named volume 'audit_data' must be declared"
    mcp_volumes = services["mcp-gateway"].get("volumes", [])
    assert any("audit_data:" in str(v) for v in mcp_volumes), (
        "mcp-gateway must mount the audit_data volume"
    )


def test_dependency_order_respects_data_flow(services: dict[str, dict[str, Any]]) -> None:
    """auth-gateway depends on mock-oidc; each MCP server depends on its
    matching mock; mcp-gateway depends on auth-gateway + every MCP server."""
    auth_deps = services["auth-gateway"]["depends_on"]
    assert "mock-oidc" in auth_deps
    mcp_deps = services["mcp-gateway"]["depends_on"]
    assert "auth-gateway" in mcp_deps
    for mock_name, _, mcp_name, _ in SERVER_TOPOLOGY:
        assert mock_name in services[mcp_name]["depends_on"], (
            f"{mcp_name} must depend on its mock {mock_name}"
        )
        assert mcp_name in mcp_deps, (
            f"mcp-gateway must depend on {mcp_name} so the JSON URL map "
            "can resolve at first request"
        )


def test_required_ports_published(services: dict[str, dict[str, Any]]) -> None:
    """Each service publishes its port on the host so the smoke-test curl chain works."""
    expected: dict[str, int] = {
        "mock-oidc": 9000,
        "auth-gateway": 8080,
        "mcp-gateway": 8000,
        "grafana": 3000,
    }
    for mock_name, mock_port, mcp_name, mcp_port in SERVER_TOPOLOGY:
        expected[mock_name] = mock_port
        expected[mcp_name] = mcp_port
    for name, port in expected.items():
        ports = services[name].get("ports", [])
        assert any(f"{port}:" in str(p) for p in ports), (
            f"{name} must publish port {port}; got {ports}"
        )


# --------------------------------------------------------------------------- #
# Dockerfile                                                                  #
# --------------------------------------------------------------------------- #


def test_dockerfile_targets_python_3_11() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert re.search(r"FROM\s+python:3\.11", text), (
        "Dockerfile must use python:3.11 (matches pyproject requires-python)"
    )


def test_dockerfile_installs_runtime_deps() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    for pkg in ("fastapi", "uvicorn", "fastmcp", "pyseto", "pyjwt", "httpx", "pyyaml"):
        assert pkg in text, f"Dockerfile missing runtime dep: {pkg}"


def test_dockerfile_copies_runtime_source() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    for src in ("gateways", "mcp_servers", "mock_apis", "config"):
        assert f"COPY {src}" in text, f"Dockerfile missing COPY for {src}"


# --------------------------------------------------------------------------- #
# Makefile + README integration                                               #
# --------------------------------------------------------------------------- #


def test_makefile_declares_compose_targets() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    for target in ("compose-up:", "compose-down:", "compose-ps:", "gen-keys:"):
        assert target in text, f"Makefile missing target: {target.rstrip(':')}"
    # US-024 AC: load-fixtures is no longer a placeholder.
    assert "load-fixtures:" in text
    assert "scripts/load_fixtures.py" in text, (
        "load-fixtures target must invoke the persona-seeding script"
    )


def test_load_fixtures_script_exists() -> None:
    script = ROOT / "scripts" / "load_fixtures.py"
    assert script.exists(), "scripts/load_fixtures.py must exist (US-024)"
    text = script.read_text(encoding="utf-8")
    # All six scenarios must be represented (cross-mock consistency contract).
    for scenario in ("clean", "mule", "sanctions_hit", "ato", "structuring", "synthetic_id"):
        assert scenario in text, f"load_fixtures.py missing scenario '{scenario}'"


def test_readme_quickstart_lists_compose_commands() -> None:
    text = README.read_text(encoding="utf-8")
    assert "make compose-up" in text
    assert "make gen-keys" in text
    assert "make load-fixtures" in text, (
        "README quickstart must mention make load-fixtures (US-024)"
    )
    # Smoke chain mentioned in the quickstart.
    assert "/login?email=alice@example.com" in text
    assert "/mcp/customer_data" in text


def test_readme_documents_cold_start_benchmark() -> None:
    text = README.read_text(encoding="utf-8")
    assert "Cold-start benchmark" in text, (
        "README must include a Cold-start benchmark section (US-024 AC)"
    )
    # The methodology must mention the <30s gate and how to reproduce.
    assert "30" in text


# --------------------------------------------------------------------------- #
# Full-stack inventory (US-024)                                               #
# --------------------------------------------------------------------------- #


def test_compose_declares_all_six_mock_apis(services: dict[str, dict[str, Any]]) -> None:
    for mock_name, _, _, _ in SERVER_TOPOLOGY:
        assert mock_name in services, f"compose missing mock API: {mock_name}"


def test_compose_declares_all_six_mcp_servers(services: dict[str, dict[str, Any]]) -> None:
    for _, _, mcp_name, _ in SERVER_TOPOLOGY:
        assert mcp_name in services, f"compose missing MCP server: {mcp_name}"


def test_compose_has_at_least_14_services(services: dict[str, dict[str, Any]]) -> None:
    """US-024 AC: 'all 14 services' — mock OIDC, auth gw, MCP gw, 6 mocks, 6 MCP servers."""
    assert len(services) >= 14, (
        f"compose has {len(services)} services; AC requires >= 14"
    )


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _command_str(service: dict[str, Any]) -> str:
    cmd = service.get("command")
    if isinstance(cmd, list):
        return " ".join(str(p) for p in cmd)
    assert isinstance(cmd, str)
    return cmd
