"""RBAC loader for ``config/rbac.yaml``.

Resolves a user identity (plus any IdP-provided group claims) into the merged
set of roles, allowed MCP servers, and allowed tools that the auth gateway
embeds in a minted PASETO.

The YAML schema is::

    roles:
      <role_name>:
        inherits: [<role_name>, ...]              # optional
        allowed_servers: [<server_name>, ...]     # optional, defaults to []
        allowed_tools:                            # optional, defaults to {}
          <server_name>: ["*"] | [<tool>, ...]
          # OR top-level wildcard: "*"
    users:
      <email>:
        roles: [<role_name>, ...]
    groups:                                       # optional
      <group_name>:
        roles: [<role_name>, ...]

Inheritance merges ``allowed_servers`` (set union) and ``allowed_tools`` per
server (list concatenation; ``"*"`` absorbs everything). Cycles in
``inherits`` raise :class:`RBACConfigError`.

Hot-reload: :func:`resolve_user` checks the file mtime on every call and
reloads if it changed. With a typical token-mint cadence (many per second
under load, but at minimum a handful per minute in dev), changes propagate
well under the 5-second target mandated by US-003.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

WILDCARD = "*"

_RBAC_PATH_ENV = "RBAC_CONFIG_PATH"


class RBACError(Exception):
    """Base class for all RBAC errors."""


class RBACConfigError(RBACError):
    """Raised when ``rbac.yaml`` is malformed (unknown role refs, cycles, bad types)."""


class UnknownUserError(RBACError):
    """Raised by :func:`resolve_user` when ``email`` is not in users and no groups match."""


@dataclass(frozen=True)
class ResolvedUser:
    """Result of :func:`resolve_user`."""

    email: str
    roles: list[str] = field(default_factory=list)
    allowed_servers: list[str] = field(default_factory=list)
    # Mapping server_name -> sorted unique tool list. The special value
    # ``["*"]`` means all tools on that server. A server key of ``"*"`` with
    # value ``["*"]`` means all tools on all servers.
    allowed_tools: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class _Role:
    name: str
    inherits: list[str]
    allowed_servers: list[str]
    # Either a top-level wildcard or per-server tool lists.
    # Top-level wildcard is represented as ``{"*": ["*"]}``.
    allowed_tools: dict[str, list[str]]


@dataclass
class _Config:
    roles: dict[str, _Role]
    users: dict[str, list[str]]          # email -> role names
    groups: dict[str, list[str]]         # group name -> role names


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def _ensure_str_list(value: Any, *, ctx: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise RBACConfigError(f"{ctx}: expected list of strings, got {value!r}")
    return list(value)


def _parse_allowed_tools(raw: Any, *, ctx: str) -> dict[str, list[str]]:
    if raw is None:
        return {}
    # Top-level wildcard string ("allowed_tools: '*'")
    if isinstance(raw, str):
        if raw != WILDCARD:
            raise RBACConfigError(f"{ctx}: top-level allowed_tools string must be '*', got {raw!r}")
        return {WILDCARD: [WILDCARD]}
    if not isinstance(raw, dict):
        raise RBACConfigError(
            f"{ctx}: allowed_tools must be a mapping or '*', got {type(raw).__name__}"
        )
    out: dict[str, list[str]] = {}
    for server, tools in raw.items():
        if not isinstance(server, str):
            raise RBACConfigError(f"{ctx}: allowed_tools server key must be string, got {server!r}")
        if isinstance(tools, str):
            if tools != WILDCARD:
                raise RBACConfigError(
                    f"{ctx}: allowed_tools[{server}] string must be '*', got {tools!r}"
                )
            out[server] = [WILDCARD]
        else:
            out[server] = _ensure_str_list(tools, ctx=f"{ctx}.allowed_tools[{server}]")
    return out


def _parse_config(data: Any) -> _Config:
    if not isinstance(data, dict):
        raise RBACConfigError("top-level rbac.yaml must be a mapping")

    roles_raw = data.get("roles", {}) or {}
    if not isinstance(roles_raw, dict):
        raise RBACConfigError("'roles' must be a mapping")
    roles: dict[str, _Role] = {}
    for name, body in roles_raw.items():
        if not isinstance(name, str):
            raise RBACConfigError(f"role name must be a string, got {name!r}")
        body = body or {}
        if not isinstance(body, dict):
            raise RBACConfigError(f"role '{name}' body must be a mapping")
        roles[name] = _Role(
            name=name,
            inherits=_ensure_str_list(body.get("inherits"), ctx=f"role '{name}'.inherits"),
            allowed_servers=_ensure_str_list(
                body.get("allowed_servers"), ctx=f"role '{name}'.allowed_servers"
            ),
            allowed_tools=_parse_allowed_tools(
                body.get("allowed_tools"), ctx=f"role '{name}'"
            ),
        )

    # Validate inherits references and detect cycles via DFS.
    for role in roles.values():
        for parent in role.inherits:
            if parent not in roles:
                raise RBACConfigError(
                    f"role '{role.name}' inherits unknown role '{parent}'"
                )
        _detect_cycle(role.name, roles, stack=[])

    def _parse_principal_table(raw: Any, *, label: str) -> dict[str, list[str]]:
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            raise RBACConfigError(f"'{label}' must be a mapping")
        result: dict[str, list[str]] = {}
        for key, body in raw.items():
            if not isinstance(key, str):
                raise RBACConfigError(f"{label} key must be string, got {key!r}")
            body = body or {}
            if not isinstance(body, dict):
                raise RBACConfigError(f"{label}['{key}'] body must be a mapping")
            assigned = _ensure_str_list(body.get("roles"), ctx=f"{label}['{key}'].roles")
            for r in assigned:
                if r not in roles:
                    raise RBACConfigError(
                        f"{label}['{key}'] references unknown role '{r}'"
                    )
            result[key] = assigned
        return result

    users = _parse_principal_table(data.get("users"), label="users")
    groups = _parse_principal_table(data.get("groups"), label="groups")
    return _Config(roles=roles, users=users, groups=groups)


def _detect_cycle(name: str, roles: dict[str, _Role], *, stack: list[str]) -> None:
    if name in stack:
        cycle = " -> ".join([*stack, name])
        raise RBACConfigError(f"inheritance cycle detected: {cycle}")
    for parent in roles[name].inherits:
        _detect_cycle(parent, roles, stack=[*stack, name])


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #


def _merge_allowed_tools(
    base: dict[str, list[str]], new: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Merge two allowed_tools maps, honoring wildcards.

    - If either side has the top-level ``"*"`` wildcard, the result is the
      top-level wildcard.
    - Otherwise, per-server lists are unioned. If a per-server list contains
      ``"*"`` it absorbs the rest for that server.
    """
    if WILDCARD in base and base[WILDCARD] == [WILDCARD]:
        return dict(base)
    if WILDCARD in new and new[WILDCARD] == [WILDCARD]:
        return {WILDCARD: [WILDCARD]}
    out: dict[str, list[str]] = {k: list(v) for k, v in base.items()}
    for server, tools in new.items():
        if server in out:
            combined = out[server] + tools
            if WILDCARD in combined:
                out[server] = [WILDCARD]
            else:
                # Sorted, deduped for deterministic output.
                out[server] = sorted(set(combined))
        else:
            out[server] = [WILDCARD] if WILDCARD in tools else sorted(set(tools))
    return out


def _flatten_role(name: str, roles: dict[str, _Role], *, seen: set[str]) -> _Role:
    """Recursively resolve a role and its ancestors into a single merged role.

    ``seen`` is the set of role names already incorporated on the current
    resolution path; this prevents redundant re-merging of diamond-shaped
    inheritance (e.g. analyst <- base, l2_analyst <- analyst + base).
    """
    role = roles[name]
    seen.add(name)
    servers: set[str] = set(role.allowed_servers)
    tools: dict[str, list[str]] = {k: list(v) for k, v in role.allowed_tools.items()}
    for parent in role.inherits:
        if parent in seen:
            continue
        flat = _flatten_role(parent, roles, seen=seen)
        servers.update(flat.allowed_servers)
        tools = _merge_allowed_tools(tools, flat.allowed_tools)
    return _Role(
        name=name,
        inherits=[],
        allowed_servers=sorted(servers),
        allowed_tools=tools,
    )


# --------------------------------------------------------------------------- #
# Loader with hot-reload
# --------------------------------------------------------------------------- #


class RBACLoader:
    """File-backed RBAC loader with mtime-based hot reload.

    Designed as a singleton per process via :func:`get_loader`, but exposed
    as a class so tests can instantiate isolated loaders.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        self._mtime: float | None = None
        self._config: _Config | None = None
        # Populate eagerly so config errors surface at startup.
        self._reload_locked()

    @property
    def path(self) -> Path:
        return self._path

    def _reload_locked(self) -> None:
        if not self._path.exists():
            raise RBACConfigError(f"rbac config not found: {self._path}")
        mtime = self._path.stat().st_mtime
        with self._path.open("rb") as fh:
            data = yaml.safe_load(fh)
        self._config = _parse_config(data)
        self._mtime = mtime

    def _maybe_reload(self) -> None:
        try:
            mtime = self._path.stat().st_mtime
        except FileNotFoundError as exc:
            raise RBACConfigError(f"rbac config disappeared: {self._path}") from exc
        if self._mtime is None or mtime != self._mtime:
            self._reload_locked()

    def resolve_user(self, email: str, *, groups: list[str] | None = None) -> ResolvedUser:
        """Resolve an identity into a flat permission set.

        ``email`` is the OIDC subject the auth gateway is minting for.
        ``groups`` are IdP-provided group names; each matching entry in
        ``groups:`` contributes its roles. ``UnknownUserError`` is raised
        only if neither the email nor any group resolves to at least one role.
        """
        with self._lock:
            self._maybe_reload()
            assert self._config is not None  # populated by _reload_locked

            role_names: list[str] = []
            seen_roles: set[str] = set()

            for r in self._config.users.get(email, []):
                if r not in seen_roles:
                    role_names.append(r)
                    seen_roles.add(r)
            for g in groups or []:
                for r in self._config.groups.get(g, []):
                    if r not in seen_roles:
                        role_names.append(r)
                        seen_roles.add(r)

            if not role_names:
                raise UnknownUserError(
                    f"no roles for email={email!r} groups={groups!r}"
                )

            servers: set[str] = set()
            tools: dict[str, list[str]] = {}
            for r in role_names:
                flat = _flatten_role(r, self._config.roles, seen=set())
                servers.update(flat.allowed_servers)
                tools = _merge_allowed_tools(tools, flat.allowed_tools)

            return ResolvedUser(
                email=email,
                roles=role_names,
                allowed_servers=sorted(servers),
                allowed_tools=tools,
            )


# --------------------------------------------------------------------------- #
# Module-level convenience
# --------------------------------------------------------------------------- #

_default_loader: RBACLoader | None = None
_default_loader_lock = threading.Lock()


def _resolve_default_path() -> Path:
    env = os.getenv(_RBAC_PATH_ENV)
    if env:
        return Path(env)
    return Path("config/rbac.yaml")


def get_loader() -> RBACLoader:
    """Return the process-wide default loader.

    Reads ``RBAC_CONFIG_PATH`` (or falls back to ``config/rbac.yaml``) on
    first call. Subsequent calls return the same instance; mtime-based
    hot reload still applies inside the instance.
    """
    global _default_loader
    with _default_loader_lock:
        if _default_loader is None:
            _default_loader = RBACLoader(_resolve_default_path())
    return _default_loader


def reset_default_loader() -> None:
    """Drop the cached default loader. Intended for tests only."""
    global _default_loader
    with _default_loader_lock:
        _default_loader = None


def resolve_user(email: str, *, groups: list[str] | None = None) -> ResolvedUser:
    """Resolve an identity using the default loader."""
    return get_loader().resolve_user(email, groups=groups)
