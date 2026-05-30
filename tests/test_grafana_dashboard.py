"""Structural tests for the Grafana dashboard + provisioning (US-023).

These tests do NOT spin up Grafana — they parse the dashboard JSON and the
provisioning YAML, and assert the four PRD-mandated panels exist with queries
that reference the ``audit_events`` table for BOTH SQLite and ClickHouse.
Catches drift between dashboard panels and the audit schema before an
operator opens Grafana and finds 'no data' panels.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
GRAFANA = ROOT / "config" / "grafana"
DASHBOARD_PATH = GRAFANA / "dashboards" / "fraud-copilot.json"
PROVISIONING_DATASOURCES = GRAFANA / "provisioning" / "datasources" / "audit.yaml"
PROVISIONING_DASHBOARDS = GRAFANA / "provisioning" / "dashboards" / "dashboards.yaml"
COMPOSE_FILE = ROOT / "docker-compose.yml"


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def dashboard() -> dict[str, Any]:
    raw = DASHBOARD_PATH.read_text(encoding="utf-8")
    data = json.loads(raw)
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def panels(dashboard: dict[str, Any]) -> list[dict[str, Any]]:
    p = dashboard.get("panels")
    assert isinstance(p, list)
    return p


@pytest.fixture(scope="module")
def datasources_yaml() -> dict[str, Any]:
    data = yaml.safe_load(PROVISIONING_DATASOURCES.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def dashboards_yaml() -> dict[str, Any]:
    data = yaml.safe_load(PROVISIONING_DASHBOARDS.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    data = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


# --------------------------------------------------------------------------- #
# Dashboard JSON structure                                                    #
# --------------------------------------------------------------------------- #


def test_dashboard_file_exists() -> None:
    assert DASHBOARD_PATH.exists(), (
        "config/grafana/dashboards/fraud-copilot.json must exist per US-023 AC"
    )


def test_dashboard_is_valid_json() -> None:
    json.loads(DASHBOARD_PATH.read_text(encoding="utf-8"))


def test_dashboard_uid_is_stable(dashboard: dict[str, Any]) -> None:
    """A stable uid lets provisioning re-import without duplicating the dashboard."""
    assert dashboard.get("uid") == "fraud-copilot-audit"


def test_dashboard_title(dashboard: dict[str, Any]) -> None:
    title = dashboard.get("title", "")
    assert "Fraud Copilot" in title


def test_dashboard_has_four_panels(panels: list[dict[str, Any]]) -> None:
    """PRD §6.3 / US-023 names exactly four panels."""
    assert len(panels) == 4, f"expected 4 panels, got {len(panels)}"


# --------------------------------------------------------------------------- #
# Per-panel acceptance                                                        #
# --------------------------------------------------------------------------- #


REQUIRED_PANELS = {
    "Tool calls per user (last 24h)",
    "Latency p50 / p95 by tool (ms)",
    "Denied requests by role (stacked)",
    "Audit volume per day",
}


def _panel_titles(panels: list[dict[str, Any]]) -> set[str]:
    return {p.get("title", "") for p in panels}


def test_all_required_panels_present(panels: list[dict[str, Any]]) -> None:
    titles = _panel_titles(panels)
    missing = REQUIRED_PANELS - titles
    assert not missing, f"missing panels: {missing}"


def _panel_by_title(panels: list[dict[str, Any]], title: str) -> dict[str, Any]:
    for p in panels:
        if p.get("title") == title:
            return p
    raise AssertionError(f"panel not found: {title}")


def _targets(panel: dict[str, Any]) -> list[dict[str, Any]]:
    targets = panel.get("targets")
    assert isinstance(targets, list) and targets, (
        f"panel {panel.get('title')!r} must declare at least one target"
    )
    return targets


def _sql_for_dialect(panel: dict[str, Any], ds_type: str) -> str:
    for t in _targets(panel):
        ds = t.get("datasource") or {}
        if ds.get("type") == ds_type:
            sql = t.get("rawSql", "")
            assert isinstance(sql, str) and sql, (
                f"target on {panel.get('title')!r} for {ds_type} missing rawSql"
            )
            return sql
    raise AssertionError(
        f"panel {panel.get('title')!r} has no target for datasource type {ds_type!r}"
    )


def test_every_panel_has_exactly_one_sqlite_target(panels: list[dict[str, Any]]) -> None:
    """Each panel must have EXACTLY ONE target — the SQLite one.

    The dashboard previously carried a second ClickHouse target per panel for
    the AUDIT_BACKEND=clickhouse path. But Grafana evaluates every target on a
    panel, and on the default SQLite stack the ClickHouse target errors (no CH
    client). A bar chart that receives that error frame fails x-field
    resolution with "Configured x field not found" (see grafana/grafana#96821).
    Hiding the target did not stop it. So the dashboard is SQLite-only: one
    target per panel, no dead frame to break the charts. The ClickHouse
    datasource + plugin stay provisioned (tests below) for operators who wire
    up their own CH panels."""
    for p in panels:
        types = [(t.get("datasource") or {}).get("type") for t in _targets(p)]
        assert types == ["frser-sqlite-datasource"], (
            f"panel {p.get('title')!r} must have exactly one SQLite target "
            f"(got {types}); a second/dead target breaks bar-chart x-field "
            "resolution"
        )


def test_every_query_references_audit_events_table(panels: list[dict[str, Any]]) -> None:
    """Every panel reads from audit_events — drift between dashboard and audit
    schema is the most likely cause of 'no data' panels."""
    for p in panels:
        for t in _targets(p):
            sql = t.get("rawSql", "")
            assert "audit_events" in sql, (
                f"panel {p.get('title')!r} target rawSql doesn't reference audit_events"
            )


def test_every_sqlite_target_sets_querytype_and_rawquerytext(
    panels: list[dict[str, Any]],
) -> None:
    """The frser-sqlite-datasource plugin reads ``rawQueryText`` + ``queryType``
    (NOT the Grafana-native ``rawSql`` field). A SQLite target missing these
    sends an empty query to the plugin → silent 'no data' panel. This is the
    exact regression that left three of four panels blank in the field."""
    for p in panels:
        for t in _targets(p):
            if (t.get("datasource") or {}).get("type") != "frser-sqlite-datasource":
                continue
            assert t.get("rawQueryText"), (
                f"panel {p.get('title')!r} SQLite target missing rawQueryText "
                "(frser plugin won't see rawSql)"
            )
            assert t.get("queryType") in ("table", "time series"), (
                f"panel {p.get('title')!r} SQLite target queryType must be "
                f"'table' or 'time series' (got {t.get('queryType')!r})"
            )
            # rawQueryText and rawSql must agree so the plugin and the
            # schema-drift test above can't disagree on what's executed.
            assert t.get("rawQueryText") == t.get("rawSql"), (
                f"panel {p.get('title')!r} SQLite target rawQueryText != rawSql"
            )


# Per-AC panel queries:


def test_tool_calls_per_user_panel_groups_by_sub(panels: list[dict[str, Any]]) -> None:
    panel = _panel_by_title(panels, "Tool calls per user (last 24h)")
    sql = _sql_for_dialect(panel, "frser-sqlite-datasource").lower()
    assert "group by sub" in sql, "SQLite target must GROUP BY sub"
    assert "count(" in sql, "SQLite target must use COUNT"


def test_latency_panel_computes_p50_and_p95_by_tool(panels: list[dict[str, Any]]) -> None:
    panel = _panel_by_title(panels, "Latency p50 / p95 by tool (ms)")
    sqlite_sql = _sql_for_dialect(panel, "frser-sqlite-datasource").lower()
    assert "p50" in sqlite_sql and "p95" in sqlite_sql, (
        "SQLite latency query must compute p50 and p95"
    )
    assert "latency_ms" in sqlite_sql
    assert "tool" in sqlite_sql, "grouped by tool"


def test_denied_requests_panel_filters_status_denied_and_groups_by_role(
    panels: list[dict[str, Any]],
) -> None:
    panel = _panel_by_title(panels, "Denied requests by role (stacked)")
    sql = _sql_for_dialect(panel, "frser-sqlite-datasource").lower()
    assert "status = 'denied'" in sql
    assert "group by role" in sql, "must group by role per US-023 AC"
    # Stacked bar — must surface deny_reason for stack segments.
    assert "deny_reason" in sql


def test_denied_requests_panel_is_stacked(panels: list[dict[str, Any]]) -> None:
    panel = _panel_by_title(panels, "Denied requests by role (stacked)")
    options = panel.get("options", {})
    assert options.get("stacking") == "normal", (
        "denied-requests-by-role panel must be a stacked bar chart per US-023 AC"
    )


def test_audit_volume_panel_buckets_by_day(panels: list[dict[str, Any]]) -> None:
    panel = _panel_by_title(panels, "Audit volume per day")
    sqlite_sql = _sql_for_dialect(panel, "frser-sqlite-datasource").lower()
    # SQLite: date(ts) collapses to day.
    assert "date(ts)" in sqlite_sql
    # The panel renders a chart (not a table) because its panel *type* is
    # "timeseries". The frser-sqlite-datasource plugin (v4.0.6) does NOT honour
    # format=time_series for a 2-column daily aggregate — it crashes with "can
    # not convert to wide series, expected long format series input". Instead
    # the SQLite target uses format=table and DESIGNATES the time column via the
    # plugin's `timeColumns` field, emitting an RFC3339 string the plugin parses
    # as a timestamp (per the plugin docs: Unix-seconds OR RFC3339, never
    # epoch-millis). ClickHouse's native plugin has no such limitation and keeps
    # format=time_series.
    assert panel.get("type") == "timeseries", (
        "audit-volume-per-day must be a timeseries panel so it renders a chart"
    )
    sqlite_target = next(
        t for t in _targets(panel)
        if (t.get("datasource") or {}).get("type") == "frser-sqlite-datasource"
    )
    assert sqlite_target.get("format") == "table", (
        "SQLite target must use format=table (format=time_series crashes the "
        "frser plugin's long->wide conversion on a 2-column daily aggregate)"
    )
    # frser needs the time column explicitly designated, else the panel errors
    # "Data is missing a time field".
    assert "time" in (sqlite_target.get("timeColumns") or []), (
        "SQLite target must list its time column in timeColumns so the "
        "timeseries panel can find a time axis"
    )
    # RFC3339 text time column (NOT epoch-millis — the plugin rejects ms).
    assert "t00:00:00z" in sqlite_sql, (
        "SQLite time column must be an RFC3339 string "
        "(date(ts) || 'T00:00:00Z'), which frser parses as a timestamp"
    )


# --------------------------------------------------------------------------- #
# Provisioning configs                                                        #
# --------------------------------------------------------------------------- #


def test_dashboards_provider_points_at_grafana_dashboards_dir(
    dashboards_yaml: dict[str, Any],
) -> None:
    providers = dashboards_yaml.get("providers", [])
    assert isinstance(providers, list) and providers
    paths = {p.get("options", {}).get("path") for p in providers}
    assert "/etc/grafana/dashboards" in paths, (
        "dashboards provider must read from /etc/grafana/dashboards"
    )


def test_datasources_yaml_declares_both_backends(datasources_yaml: dict[str, Any]) -> None:
    sources = datasources_yaml.get("datasources", [])
    assert isinstance(sources, list)
    types = {s.get("type") for s in sources}
    assert "frser-sqlite-datasource" in types, (
        "SQLite datasource must be provisioned (the default)"
    )
    assert "grafana-clickhouse-datasource" in types, (
        "ClickHouse datasource must be provisioned (AUDIT_BACKEND=clickhouse path)"
    )


def test_datasource_uids_match_dashboard_targets(
    datasources_yaml: dict[str, Any], panels: list[dict[str, Any]]
) -> None:
    """The fixed UIDs in the dashboard targets must match the provisioned UIDs —
    otherwise Grafana can't resolve the datasource reference and every panel
    shows 'no data' / 'datasource not found'."""
    provisioned_uids: dict[str, str] = {}
    for s in datasources_yaml.get("datasources", []):
        provisioned_uids[s["type"]] = s["uid"]

    for p in panels:
        for t in p.get("targets", []):
            ds = t.get("datasource") or {}
            ds_type = ds.get("type")
            ds_uid = ds.get("uid")
            if ds_type in provisioned_uids:
                assert ds_uid == provisioned_uids[ds_type], (
                    f"panel {p.get('title')!r} target uid {ds_uid!r} doesn't match "
                    f"provisioned {ds_type} uid {provisioned_uids[ds_type]!r}"
                )


def test_sqlite_datasource_points_at_audit_db_volume_mount(
    datasources_yaml: dict[str, Any],
) -> None:
    """The SQLite datasource must read the audit DB written by the MCP gateway
    (mounted RO at /var/audit/audit.db)."""
    sources = datasources_yaml.get("datasources", [])
    src = next(s for s in sources if s.get("type") == "frser-sqlite-datasource")
    path = src.get("jsonData", {}).get("path")
    assert path == "/var/audit/audit.db", (
        f"SQLite datasource path must be /var/audit/audit.db (was {path!r})"
    )


def test_default_datasource_is_env_driven(datasources_yaml: dict[str, Any]) -> None:
    """``isDefault`` flips between the two datasources based on AUDIT_BACKEND."""
    raw = PROVISIONING_DATASOURCES.read_text(encoding="utf-8")
    assert "${AUDIT_BACKEND_IS_SQLITE}" in raw
    assert "${AUDIT_BACKEND_IS_CLICKHOUSE}" in raw


# --------------------------------------------------------------------------- #
# docker-compose integration                                                  #
# --------------------------------------------------------------------------- #


def test_compose_declares_grafana_service(compose: dict[str, Any]) -> None:
    services = compose.get("services", {})
    assert "grafana" in services, "docker-compose.yml must declare a grafana service"


def test_grafana_uses_official_image(compose: dict[str, Any]) -> None:
    svc = compose["services"]["grafana"]
    image = svc.get("image", "")
    assert image.startswith("grafana/grafana"), (
        f"grafana service must use the official grafana/grafana image (got {image!r})"
    )


def test_grafana_mounts_provisioning_and_dashboards(compose: dict[str, Any]) -> None:
    svc = compose["services"]["grafana"]
    volumes = [str(v) for v in svc.get("volumes", [])]
    assert any("/etc/grafana/provisioning" in v for v in volumes), (
        "grafana must mount config/grafana/provisioning -> /etc/grafana/provisioning"
    )
    assert any("/etc/grafana/dashboards" in v for v in volumes), (
        "grafana must mount config/grafana/dashboards -> /etc/grafana/dashboards"
    )


def test_grafana_mounts_audit_volume_readonly(compose: dict[str, Any]) -> None:
    """Grafana reads the SQLite audit DB written by mcp-gateway — must be RO
    so Grafana can never corrupt the audit store."""
    svc = compose["services"]["grafana"]
    volumes = [str(v) for v in svc.get("volumes", [])]
    audit_mounts = [v for v in volumes if "audit_data" in v]
    assert audit_mounts, "grafana must mount the audit_data named volume"
    assert any(":ro" in v for v in audit_mounts), (
        f"grafana audit_data mount must be read-only (got {audit_mounts})"
    )


def test_grafana_depends_on_mcp_gateway(compose: dict[str, Any]) -> None:
    """Grafana only matters once the MCP gateway is producing audit rows."""
    svc = compose["services"]["grafana"]
    depends = svc.get("depends_on", {})
    assert "mcp-gateway" in depends


def test_grafana_publishes_port_3000(compose: dict[str, Any]) -> None:
    svc = compose["services"]["grafana"]
    ports = [str(p) for p in svc.get("ports", [])]
    assert any("3000:" in p for p in ports), (
        f"grafana must publish port 3000 (got {ports})"
    )


def test_grafana_healthcheck_budget_under_15s(compose: dict[str, Any]) -> None:
    svc = compose["services"]["grafana"]
    hc = svc.get("healthcheck") or {}
    interval = _parse_duration(hc.get("interval", "30s"))
    retries = int(hc.get("retries", 3))
    start = _parse_duration(hc.get("start_period", "0s"))
    budget = interval * retries + start
    assert budget <= 15.0, f"grafana healthcheck budget {budget}s exceeds 15s"


def test_grafana_installs_required_plugins(compose: dict[str, Any]) -> None:
    """The SQLite + ClickHouse datasource plugins are NOT bundled with the
    official grafana image — must be installed at startup."""
    env = compose["services"]["grafana"].get("environment", {})
    plugins = env.get("GF_INSTALL_PLUGINS", "")
    assert "frser-sqlite-datasource" in plugins
    assert "grafana-clickhouse-datasource" in plugins


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _parse_duration(raw: object) -> float:
    if isinstance(raw, (int, float)):
        return float(raw)
    assert isinstance(raw, str), f"expected duration string, got {raw!r}"
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|s|m|h)?", raw.strip())
    assert match, f"unrecognized duration: {raw!r}"
    value = float(match.group(1))
    unit = match.group(2) or "s"
    return value * {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}[unit]
