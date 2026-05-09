#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

"""Configuration loading and validation."""

from __future__ import annotations

import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("zabbix_mcp.config")

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]


@dataclass(frozen=True)
class ZabbixServerConfig:
    """Configuration for a single Zabbix server."""

    name: str
    url: str
    api_token: str
    read_only: bool = True
    verify_ssl: bool = True
    skip_version_check: bool = False
    # Optional username + password used by ``graph_render`` to acquire
    # a Zabbix frontend session cookie when the API token alone is
    # rejected by ``/chart2.php`` (Zabbix 6.0+ frontend uses signed
    # session cookies, which only ``user.login`` can produce). Leave
    # empty to keep the token-only behaviour - graph_render will
    # surface a clear error if the frontend rejects it.
    frontend_username: str = ""
    frontend_password: str = ""
    # Request timeout (seconds). A hung Zabbix frontend must not stall
    # the MCP thread pool indefinitely. Default 300 s matches the
    # Zabbix PHP frontend's max_execution_time (and typical nginx
    # fastcgi_read_timeout), so whatever timeout your Zabbix UI
    # respects, we respect too. Expensive tools like
    # configuration.export of a large host or history.get over a
    # multi-day range can legitimately run that long.
    request_timeout: int = 300


@dataclass(frozen=True)
class ServerConfig:
    """MCP server configuration."""

    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8080
    log_level: str = "info"
    log_file: str | None = None
    auth_token: str | None = None
    rate_limit: int = 300
    tools: list[str] | None = None
    disabled_tools: list[str] | None = None
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    # External URL clients use to reach this server. Overrides the
    # auto-derived "{scheme}://{host}:{port}" when populating OAuth
    # discovery (issuer_url + resource_server_url) and the Client MCP
    # Wizard snippets / curl quick-test box. Required when host is
    # "0.0.0.0" / "::" and the server is exposed via a public DNS
    # name or reverse proxy - otherwise discovery advertises the bind
    # host literal (e.g. "https://0.0.0.0:8080/") and remote clients
    # cannot follow it. Empty = preserve legacy auto-derive behavior.
    public_url: str = ""
    cors_origins: list[str] | None = None
    allowed_import_dirs: list[str] | None = None
    allowed_hosts: list[str] | None = None
    # Optional explicit Origin header allowlist for DNS rebinding protection
    # (MCP 2025-11-25 §security). When unset and `public_url` is configured,
    # the scheme://host[:port] derived from it is used. When unset on a
    # localhost bind, FastMCP applies its own localhost wildcard defaults.
    # Wildcard ports work as ``http://example.com:*``. Same shape as
    # ``allowed_hosts`` but for the Origin header rather than Host.
    allowed_origins: list[str] | None = None
    # IPs of reverse proxies whose X-Forwarded-For / Forwarded headers
    # we trust for client-IP attribution. Empty (default) means we only
    # ever use the raw TCP peer. Populate with e.g. ["127.0.0.1"] when
    # running behind nginx on localhost.
    trusted_proxies: list[str] | None = None
    compact_output: bool = True
    response_max_chars: int = 50000
    report_logo: str | None = None
    report_company: str = ""
    report_subtitle: str = "IT Monitoring Service"
    # When the MCP runs over stdio (no bearer-token auth context),
    # ``raw_json=true`` is rejected by default so an LLM client like
    # Claude Desktop cannot strip its own prompt-injection mitigation.
    # Operators driving the stdio process from a non-LLM script can
    # opt in here. HTTP transport uses the per-token ``allow_raw_json``
    # flag instead and ignores this setting.
    stdio_allow_raw_json: bool = False
    # Tool-name prefix applied to every bundled Zabbix tool when this host
    # runs side-by-side with other MCP modules under a multi-plugin setup.
    # Default empty = bundled tools surface unprefixed (host_get,
    # problem_get, ...) - byte-identical to v1.30 behaviour. When set to
    # e.g. "zabbix", the same tools surface as zabbix__host_get etc. so
    # they cannot collide with tools from other plugins (netbox__device_get,
    # jira__issue_create, ...). Internal logic (token scope filter,
    # read-only write-tool detection, Tasks API augmentation) keys off the
    # canonical bare name regardless of the prefix.
    tool_prefix: str = ""


@dataclass(frozen=True)
class AdminAIConfig:
    """Admin portal AI assistant (report template generator).

    When `provider` and `api_key` are both set, the /templates page
    shows a "Generate with AI" button that calls an LLM to produce a
    Jinja2 template from a plain-English description. Missing or empty
    config disables the feature cleanly (the UI button is hidden).
    """

    enabled: bool = True  # admin-portal toggle; False hides the wizard even if keys are set
    # Supported providers: anthropic | openai | gemini | azure-openai | ollama | mistral | groq
    provider: str = ""
    api_key: str = ""  # supports ${ENV_VAR} expansion; optional for Ollama
    model: str = ""  # empty = provider default (e.g. claude-sonnet-4-6)
    # Custom endpoint for Ollama / Azure OpenAI / self-hosted deployments.
    # Ignored for providers with a canonical API host.
    api_base: str = ""
    max_tokens: int = 8000
    # Large reasoning models (Claude Opus, GPT-5) can take 90-150s for
    # a full template; 60s was too aggressive and routinely timed out
    # in the admin portal. 180s leaves headroom without making the UI
    # wait forever on a truly stuck call.
    timeout: int = 180


@dataclass(frozen=True)
class OAuthConfig:
    """OAuth 2.1 authorization server settings.

    When `enabled` is True, the MCP server boots an embedded OAuth
    authorization server that ChatGPT custom apps, Claude Desktop
    remote connectors, and any MCP 2025-11-25 client can negotiate
    against -- no external IdP needed. Authorization codes /
    refresh tokens are held in memory; registered clients persist
    in `[oauth_clients.<id>]` config sections and survive restart.

    Login uses the existing admin-portal users (scrypt hashes in
    `[admin.users.*]`); operators do not maintain a second identity
    store. Issued access tokens are bound by `aud` claim to
    `[server].public_url` so a leaked token cannot be replayed
    against a different MCP deployment (RFC 8707).
    """

    enabled: bool = False
    # Path on the MCP server where the user-agent is redirected for
    # the login + consent step of the authorize flow. Must live on
    # the same origin as the issuer URL (= [server].public_url).
    login_path: str = "/oauth/login"
    # When True, any client meeting RFC 7591 may register itself via
    # POST /register. When False, operators must add clients by hand
    # (or wait for the admin UI to grow a "register client" button).
    dynamic_registration_enabled: bool = True
    # Default scopes assigned to a client that does not list any in
    # its registration request. Mirrors the legacy bearer default
    # (full access) so an operator-driven flow does not have to
    # rediscover the scope catalog.
    default_scopes: list[str] = field(default_factory=lambda: ["*"])
    # Token lifetimes. Defaults follow OAuth 2.1 / industry norms.
    # Operators can shorten any of these for a tighter security
    # posture (paid for in a higher /token call rate from clients).
    auth_code_ttl_seconds: int = 600         # 10 min  (OAuth 2.1 §4.1.3)
    access_token_ttl_seconds: int = 3600     # 1 hour
    refresh_token_ttl_seconds: int = 30 * 24 * 3600  # 30 days, rotated
    # DCR profile (issue #49 Track B). ``conservative`` is the v1.31
    # default - a freshly-registered client gets a tighter posture out
    # of the box: refuse wildcard / pattern redirect URIs at /register
    # (only string-equal matches at /authorize), refuse ``scope=*`` in
    # the registration request (a client must enumerate the groups it
    # wants; wildcard can still be granted by the operator at consent),
    # and apply a 1800-second access-token TTL ceiling instead of the
    # global default. ``permissive`` is the legacy v1.30 behaviour and
    # exists so an operator running a niche internal client that
    # genuinely needs wildcards can opt back in. Per-client overrides
    # in ``[oauth_clients.<id>]`` always win over the profile default.
    dcr_profile: str = "conservative"
    # Override applied at /register when ``dcr_profile == 'conservative'``
    # if no explicit per-client TTL is set. 30 minutes is short enough
    # to limit the blast radius of a leaked access token while staying
    # comfortable for an interactive AI session that triggers the
    # rotate-via-refresh path on a slow tool call.
    dcr_conservative_access_ttl_seconds: int = 1800


@dataclass(frozen=True)
class AuditForwardConfig:
    """External SIEM / syslog forwarding for the audit log.

    The local audit log files are the primary source of truth - when
    forwarding is enabled, audit rows are *also* shipped to the
    configured destination. A drop / reconnect on the wire never
    affects the local log; the forwarder maintains an in-memory queue
    and re-tries on its own schedule.

    Five knobs:

    * ``enabled`` - master toggle for the forwarder. Off by default
      so a fresh install does not start dialing arbitrary network
      destinations.
    * ``host`` / ``port`` - SIEM / syslog endpoint.
    * ``protocol`` - one of ``tcp``, ``udp``, ``tls``. TLS is TCP
      with an optional ``ca_cert`` for server cert validation.
    * ``format`` - wire format: ``rfc5424`` (default), ``cef``,
      ``leef``, ``json``. Most SIEMs accept multiple formats; pick
      the one the operator's SOC has parsers for.
    * ``ca_cert`` - path to a PEM trust bundle for TLS. Empty falls
      back to system trust store (``ssl.create_default_context``).
    * ``queue_size`` - bounded in-memory queue between the audit
      write path and the forwarder thread. When full, the OLDEST
      queued row is dropped (record-side backpressure) and a single
      ``forwarder.queue_full`` self-event is emitted at most once
      per minute so the operator sees the SOC is lagging.
    """

    enabled: bool = False
    host: str = ""
    port: int = 514
    protocol: str = "rfc5424_udp"  # rfc5424_udp / rfc5424_tcp / rfc5424_tls / cef_udp / cef_tcp / cef_tls / leef_udp / leef_tcp / leef_tls / json_tcp / json_tls
    ca_cert: str = ""              # path to PEM, empty = system trust
    queue_size: int = 10000


@dataclass(frozen=True)
class AuditConfig:
    """Audit log behaviour - inspired by Zabbix's "Audit log" admin panel.

    Five knobs:

    * ``enabled`` - master kill switch. When False, NO audit row is
      written to either ``audit.log`` or ``client-audit.log`` and the
      ``audit_self_get`` ring buffer stops accepting pushes. The toggle
      itself is **always** audited (even when transitioning to
      disabled) so a compliance reviewer can see that audit logging
      was turned off and by whom. The admin portal renders a persistent
      banner while audit is disabled.
    * ``log_background_events`` - whether automated MCP server events
      (log rotation, retention purge, SIEM forwarder reconnect,
      background config reload) land in the audit log alongside
      user-driven actions. Default on so an operator new to the
      system can see "is the daemon doing its job?" without having
      to flip a hidden knob. Turn off only when the operator log is
      noisy and you only want user-driven actions.
    * ``housekeeping_enabled`` - whether the MCP server itself rotates
      and purges the audit log files. Default on. Disable when an
      external rsyslog / Fluentd / cron job manages rotation.
    * ``data_storage_period`` - retention window in seconds. Parsed
      from a Zabbix-style time-period string (``31d``, ``90d``,
      ``1y``, ...) at config load. Files older than the window are
      deleted by the housekeeping cycle. ``0`` disables time-based
      purge (size-based rotation still applies).
    * ``max_file_size_bytes`` - rotation threshold per file. Older
      files are gzipped and dated. Default 50 MB matches the v1.30
      shape so an upgrade is a no-op for existing logs.

    The four user-visible knobs map 1:1 to the Zabbix admin UI's Audit
    log panel - same field names, same defaults, same Reset defaults
    semantics.
    """

    enabled: bool = True
    # Three orthogonal audit categories the operator can mute
    # individually under the master toggle:
    #
    # * portal operations - admin UI / OAuth events (login, token CRUD,
    #   settings change, server CRUD, OAuth client lifecycle, consent).
    # * MCP actions - per-tool ``tool.invoke`` rows from the #49
    #   tool-level audit pipeline.
    # * background events - server-side automation (housekeeping cycle,
    #   forwarder reconnect, retention purge, system config reload).
    #
    # All on by default - a fresh install records every category so
    # the operator sees the full picture.
    log_portal_operations: bool = True
    log_mcp_actions: bool = True
    log_background_events: bool = True
    housekeeping_enabled: bool = True
    # Stored as seconds for runtime simplicity; the original Zabbix-style
    # string ("31d") is preserved on the config document so /settings
    # round-trips it without normalising user input.
    data_storage_period_seconds: int = 31 * 86400
    data_storage_period_raw: str = "31d"
    max_file_size_bytes: int = 50 * 1024 * 1024


@dataclass(frozen=True)
class AppConfig:
    """Top-level application configuration."""

    server: ServerConfig = field(default_factory=ServerConfig)
    zabbix_servers: dict[str, ZabbixServerConfig] = field(default_factory=dict)
    admin_ai: AdminAIConfig = field(default_factory=AdminAIConfig)
    oauth: OAuthConfig = field(default_factory=OAuthConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    audit_forward: AuditForwardConfig = field(default_factory=AuditForwardConfig)

    @property
    def default_server(self) -> str | None:
        """Return the name of the first configured Zabbix server."""
        servers = list(self.zabbix_servers)
        return servers[0] if servers else None


_ENV_VAR_RE = re.compile(r"\$\{([^}]+)}")


def _resolve_env_vars(value: str) -> str:
    """Replace ${VAR_NAME} references with environment variable values."""

    def _replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        env_value = os.environ.get(var_name)
        if env_value is None:
            raise ConfigError(
                f"Environment variable '{var_name}' referenced in config is not set"
            )
        return env_value

    return _ENV_VAR_RE.sub(_replace, value)


TOOL_GROUPS: dict[str, list[str]] = {
    "monitoring": [
        "host", "hostgroup", "hostinterface", "hostprototype",
        "item", "itemprototype", "trigger", "triggerprototype",
        "problem", "problem_active_get", "event", "history", "trend",
        "graph", "graphitem", "graphprototype",
        "discoveryrule", "discoveryruleprototype",
        "dcheck", "dhost", "drule", "dservice", "httptest", "sla",
        # Pre-correlated views (one-shot replacements for raw chains)
        "host_status_get", "hostgroup_overview_get",
        "infrastructure_summary_get", "item_history_summary_get",
    ],
    "data_collection": [
        "template", "templategroup", "templatedashboard",
        "valuemap", "dashboard",
    ],
    "alerts": [
        "action", "alert", "mediatype", "script",
    ],
    "users": [
        "user", "usergroup", "userdirectory", "usermacro",
        "token", "role", "mfa",
    ],
    "administration": [
        "settings", "housekeeping", "authentication", "autoregistration",
        "configuration", "connector", "correlation", "hanode",
        "iconmap", "image", "maintenance", "map", "module",
        "proxy", "proxygroup", "regexp", "report", "task",
        "auditlog",
    ],
    "extensions": [
        "graph_render", "anomaly_detect", "capacity_forecast",
        "item_threshold_search", "problem_active_get",
        "host_status_get", "hostgroup_overview_get",
        "infrastructure_summary_get", "item_history_summary_get",
        "report_generate", "action_prepare", "action_confirm",
        "zabbix_raw_api_call", "health_check",
    ],
}


def _parse_zabbix_server(name: str, srv: object) -> "ZabbixServerConfig":
    """Validate one [zabbix.<name>] section and build ZabbixServerConfig.

    Raises ConfigError on any problem so the caller can log and skip
    just this entry instead of failing the whole MCP boot.
    """
    if not isinstance(srv, dict):
        raise ConfigError(f"Invalid Zabbix server config for '{name}'")
    url = srv.get("url")
    if not url:
        raise ConfigError(f"Zabbix server '{name}' is missing 'url'")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise ConfigError(
            f"Zabbix server '{name}' has invalid URL '{url}'. "
            f"Must start with http:// or https://"
        )
    # Catch malformed hostnames like "0.0.0.0.0.0.0" or "host with
    # spaces" before they propagate to ZabbixAPI() and surface as a
    # cryptic urllib error mid-request. We do not resolve DNS here -
    # the Zabbix host may legitimately be down at MCP boot.
    from urllib.parse import urlparse as _urlparse
    try:
        _parsed = _urlparse(url)
    except ValueError as exc:
        raise ConfigError(
            f"Zabbix server '{name}' URL '{url}' could not be parsed: {exc}"
        ) from exc
    if not _parsed.hostname:
        raise ConfigError(
            f"Zabbix server '{name}' URL '{url}' has no hostname"
        )
    import re as _re_url
    from ipaddress import ip_address as _ip_addr_url
    host = _parsed.hostname
    is_valid = False
    try:
        _ip_addr_url(host)
        is_valid = True
    except ValueError:
        # RFC 1123 hostname: labels of [A-Za-z0-9-], 1-63 chars each,
        # total <=253. Reject all-numeric strings that are not valid
        # IPs (catches typos like 0.0.0.0.0.0.0 - too many octets).
        if 0 < len(host) <= 253 and _re_url.fullmatch(
            r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*", host
        ):
            if not _re_url.fullmatch(r"[0-9.]+", host):
                is_valid = True
    if not is_valid:
        raise ConfigError(
            f"Zabbix server '{name}' URL '{url}' has an invalid hostname "
            f"'{host}'. Use a DNS name (e.g. zabbix.example.com) or a valid "
            f"IPv4/IPv6 address."
        )
    api_token = srv.get("api_token")
    if not api_token:
        raise ConfigError(f"Zabbix server '{name}' is missing 'api_token'")
    api_token = _resolve_env_vars(api_token)
    if not api_token.strip():
        raise ConfigError(
            f"Zabbix server '{name}' has empty 'api_token' after resolving "
            f"environment variables"
        )
    return ZabbixServerConfig(
        name=name,
        url=url.rstrip("/"),
        api_token=api_token,
        read_only=srv.get("read_only", True),
        verify_ssl=srv.get("verify_ssl", True),
        skip_version_check=srv.get("skip_version_check", False),
        frontend_username=str(srv.get("frontend_username", "")),
        frontend_password=_resolve_env_vars(str(srv.get("frontend_password", ""))),
        request_timeout=int(srv.get("request_timeout", 300)),
    )


_TOOL_PREFIX_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def _validate_tool_prefix(value: object) -> str:
    """Validate [server].tool_prefix.

    Empty string (default) keeps the bundled module's tools unprefixed -
    backwards compatible with v1.30. Non-empty values must be lowercase,
    start with a letter, and contain only lowercase letters / digits /
    underscores so they form valid MCP tool name segments when joined
    with the double-underscore separator (e.g. ``zabbix`` ->
    ``zabbix__host_get``). Invalid values raise ConfigError so an
    operator typo surfaces at boot instead of producing un-callable
    tool names downstream.
    """
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        raise ConfigError(
            f"[server].tool_prefix must be a string, got {type(value).__name__}"
        )
    s = value.strip()
    if not s:
        return ""
    if not _TOOL_PREFIX_RE.match(s):
        raise ConfigError(
            f"[server].tool_prefix '{s}' is invalid. Must match {_TOOL_PREFIX_RE.pattern} "
            f"(lowercase letter first, then letters / digits / underscores). "
            f"Example: tool_prefix = \"zabbix\""
        )
    return s


def _validate_dcr_profile(value: object) -> str:
    """Coerce / validate ``[oauth].dcr_profile``. Default ``conservative``."""
    if value is None or value == "":
        return "conservative"
    s = str(value).strip().lower()
    if s in ("conservative", "permissive"):
        return s
    raise ConfigError(
        f"[oauth].dcr_profile must be 'conservative' or 'permissive', got {value!r}"
    )


# Zabbix-style time period units. Lowercase ``m`` is minutes, uppercase
# ``M`` is months - matching the Zabbix server's own convention so an
# operator who already speaks Zabbix time periods does not have to
# learn a second grammar.
_TIME_PERIOD_UNITS: dict[str, int] = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 7 * 86400,
    "M": 30 * 86400,
    "y": 365 * 86400,
}
_TIME_PERIOD_RE = re.compile(r"^\s*(\d+)\s*([smhdwMy]?)\s*$")


def parse_time_period(value: object, *, default_unit: str = "s") -> int:
    """Parse a Zabbix-style time period (``31d``, ``1y``, ``90d``, ``2h``) into seconds.

    Accepts integer-as-string (``"3600"``) or unit-suffixed (``"31d"``).
    Returns ``0`` for the empty string and for the literal value ``"0"``,
    matching the Zabbix housekeeping-disabled convention.

    The unit alphabet follows the Zabbix server: ``s``/``m``/``h``/``d``/
    ``w``/``M``/``y``. Lowercase ``m`` is minutes, uppercase ``M`` is
    months. Anything else raises :class:`ConfigError` so a typo
    surfaces at boot rather than silently coming back as a wrong
    duration.
    """
    if value is None:
        return 0
    s = str(value).strip()
    if s == "" or s == "0":
        return 0
    m = _TIME_PERIOD_RE.match(s)
    if not m:
        raise ConfigError(
            f"Invalid time period {value!r}: expected '<digits>[smhdwMy]' "
            "(e.g. '31d', '90d', '1y', '6h'); see Zabbix time-period grammar."
        )
    n = int(m.group(1))
    unit = m.group(2) or default_unit
    return n * _TIME_PERIOD_UNITS[unit]


def _validate_public_url(value: str, tls_cert_file: object) -> str:
    """Validate the optional `[server].public_url` override.

    Empty string is allowed - falls through to legacy auto-derive.
    Non-empty must be:
      - a valid http:// or https:// URL
      - https:// when tls_cert_file is set (server is serving TLS)
      - bare URL only - no path, query, or fragment (we append /mcp etc.
        downstream so a path here would compound)
      - host part non-empty and not a wildcard bind address
    """
    if not value:
        return ""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(value)
    except ValueError as e:
        raise ConfigError(f"'public_url' is not a valid URL: {e}") from e
    if parsed.scheme not in {"http", "https"}:
        raise ConfigError(
            f"'public_url' must start with http:// or https:// (got '{value}')"
        )
    if not parsed.hostname:
        raise ConfigError(f"'public_url' is missing the host part: '{value}'")
    if parsed.hostname in {"0.0.0.0", "::", "[::]"}:
        raise ConfigError(
            f"'public_url' cannot be a wildcard bind address ('{parsed.hostname}'); "
            "use the actual public DNS name or IP that clients reach"
        )
    if parsed.path and parsed.path not in {"", "/"}:
        raise ConfigError(
            f"'public_url' must be a bare URL with no path ('{parsed.path}' "
            "found); the /mcp or /sse path is appended automatically"
        )
    if parsed.query or parsed.fragment:
        raise ConfigError("'public_url' must not contain a query string or fragment")
    if tls_cert_file and parsed.scheme != "https":
        raise ConfigError(
            "'public_url' must use https:// when tls_cert_file is set "
            f"(got '{value}')"
        )
    # Strip trailing slash so downstream concatenation is predictable.
    return value.rstrip("/")


def _expand_tool_groups(tools: list[str]) -> list[str]:
    """Expand group names (e.g. 'monitoring') into individual tool prefixes."""
    expanded: list[str] = []
    for entry in tools:
        entry = entry.lower()
        if entry in TOOL_GROUPS:
            expanded.extend(TOOL_GROUPS[entry])
        else:
            expanded.append(entry)
    return list(dict.fromkeys(expanded))  # deduplicate, preserve order


class ConfigError(Exception):
    """Raised when configuration is invalid."""


def load_config(path: str | Path) -> AppConfig:
    """Load and validate configuration from a TOML file."""
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except Exception as e:
        raise ConfigError(f"Failed to parse {path}: {e}") from e

    server_raw = raw.get("server", {})
    transport = server_raw.get("transport", "stdio")
    if transport not in ("stdio", "http", "sse"):
        raise ConfigError(f"Invalid transport '{transport}', must be 'stdio', 'http', or 'sse'")

    # Validate log_level
    log_level = server_raw.get("log_level", "info")
    if log_level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        raise ConfigError(
            f"Invalid log_level '{log_level}', must be one of: debug, info, warning, error, critical"
        )

    # Validate port range
    port = server_raw.get("port", 8080)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConfigError(f"Invalid port '{port}', must be an integer between 1 and 65535")

    tools_raw = server_raw.get("tools")
    tools_filter: list[str] | None = None
    if tools_raw is not None:
        if not isinstance(tools_raw, list):
            raise ConfigError("'tools' must be a list of tool group names")
        tools_filter = _expand_tool_groups([str(t) for t in tools_raw])

    disabled_tools_raw = server_raw.get("disabled_tools")
    disabled_tools_filter: list[str] | None = None
    if disabled_tools_raw is not None:
        if not isinstance(disabled_tools_raw, list):
            raise ConfigError("'disabled_tools' must be a list of tool group names")
        disabled_tools_filter = _expand_tool_groups([str(t) for t in disabled_tools_raw])

    # TLS configuration
    tls_cert_file = server_raw.get("tls_cert_file")
    tls_key_file = server_raw.get("tls_key_file")
    if tls_cert_file and not tls_key_file:
        raise ConfigError("tls_key_file is required when tls_cert_file is set")
    if tls_key_file and not tls_cert_file:
        raise ConfigError("tls_cert_file is required when tls_key_file is set")

    # Public URL override - what we advertise to clients (OAuth discovery,
    # wizard snippets) instead of the auto-derived "{scheme}://{host}:{port}".
    # See `_validate_public_url` for the rules. Empty = legacy auto-derive.
    public_url_raw = server_raw.get("public_url", "") or ""
    public_url = _validate_public_url(str(public_url_raw).strip(), tls_cert_file)

    # CORS configuration
    cors_raw = server_raw.get("cors_origins")
    cors_origins: list[str] | None = None
    if cors_raw is not None:
        if not isinstance(cors_raw, list):
            raise ConfigError("'cors_origins' must be a list of origin URLs")
        cors_origins = [str(o) for o in cors_raw]

    # Allowed import directories for source_file feature
    import_dirs_raw = server_raw.get("allowed_import_dirs")
    allowed_import_dirs: list[str] | None = None
    if import_dirs_raw is not None:
        if not isinstance(import_dirs_raw, list):
            raise ConfigError("'allowed_import_dirs' must be a list of directory paths")
        allowed_import_dirs = [str(d) for d in import_dirs_raw]

    # IP allowlist configuration
    allowed_hosts_raw = server_raw.get("allowed_hosts")
    allowed_hosts: list[str] | None = None
    if allowed_hosts_raw is not None:
        if not isinstance(allowed_hosts_raw, list):
            raise ConfigError("'allowed_hosts' must be a list of IP addresses or CIDR ranges")
        allowed_hosts = [str(h) for h in allowed_hosts_raw]

    allowed_origins_raw = server_raw.get("allowed_origins")
    allowed_origins: list[str] | None = None
    if allowed_origins_raw is not None:
        if not isinstance(allowed_origins_raw, list):
            raise ConfigError("'allowed_origins' must be a list of origin URLs (e.g. 'https://app.example.com')")
        from urllib.parse import urlsplit
        cleaned: list[str] = []
        for raw_origin in allowed_origins_raw:
            entry = str(raw_origin).strip()
            if not entry:
                continue
            if not entry.startswith(("http://", "https://")):
                raise ConfigError(
                    f"'allowed_origins' entry '{entry}' must start with http:// or https://"
                )
            # Strip the ``:*`` port-wildcard before URL parsing; it is
            # FastMCP-internal syntax that urlsplit otherwise rejects.
            probe = entry[:-2] if entry.endswith(":*") else entry
            try:
                parts = urlsplit(probe)
            except ValueError as e:
                raise ConfigError(f"'allowed_origins' entry '{entry}' is not a valid URL: {e}")
            if not parts.hostname:
                raise ConfigError(f"'allowed_origins' entry '{entry}' is missing a host")
            if parts.path not in ("", "/"):
                raise ConfigError(
                    f"'allowed_origins' entry '{entry}' must not include a path - "
                    f"drop everything after host[:port]"
                )
            if parts.query or parts.fragment:
                raise ConfigError(
                    f"'allowed_origins' entry '{entry}' must not include query / fragment"
                )
            cleaned.append(entry)
        allowed_origins = cleaned or None

    trusted_proxies_raw = server_raw.get("trusted_proxies")
    trusted_proxies: list[str] | None = None
    if trusted_proxies_raw is not None:
        if not isinstance(trusted_proxies_raw, list):
            raise ConfigError("'trusted_proxies' must be a list of IP addresses")
        trusted_proxies = [str(h) for h in trusted_proxies_raw]

    log_file = server_raw.get("log_file")

    compact_output_raw = server_raw.get("compact_output", True)
    if not isinstance(compact_output_raw, bool):
        raise ConfigError("'compact_output' must be a boolean (true or false)")

    response_max_chars_raw = server_raw.get("response_max_chars", 50000)
    if not isinstance(response_max_chars_raw, int) or response_max_chars_raw < 5000:
        raise ConfigError("'response_max_chars' must be an integer >= 5000")

    server_config = ServerConfig(
        transport=transport,
        host=server_raw.get("host", "127.0.0.1"),
        port=port,
        log_level=log_level,
        log_file=log_file,
        auth_token=_resolve_env_vars(server_raw["auth_token"]) if server_raw.get("auth_token") else None,
        rate_limit=server_raw.get("rate_limit", 300),
        tools=tools_filter,
        disabled_tools=disabled_tools_filter,
        tls_cert_file=tls_cert_file,
        tls_key_file=tls_key_file,
        public_url=public_url,
        cors_origins=cors_origins,
        allowed_import_dirs=allowed_import_dirs,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
        trusted_proxies=trusted_proxies,
        compact_output=compact_output_raw,
        response_max_chars=response_max_chars_raw,
        report_logo=server_raw.get("report_logo"),
        report_company=server_raw.get("report_company", ""),
        report_subtitle=server_raw.get("report_subtitle", "IT Monitoring Service"),
        stdio_allow_raw_json=bool(server_raw.get("stdio_allow_raw_json", False)),
        tool_prefix=_validate_tool_prefix(server_raw.get("tool_prefix", "")),
    )

    zabbix_raw = raw.get("zabbix", {})
    if not zabbix_raw:
        raise ConfigError(
            "No Zabbix servers configured. Add at least one [zabbix.<name>] section."
        )

    zabbix_servers: dict[str, ZabbixServerConfig] = {}
    skipped_servers: list[tuple[str, str]] = []
    for name, srv in zabbix_raw.items():
        # Per-server validation now logs a warning and SKIPS the bad
        # server instead of killing the whole MCP. A single broken
        # [zabbix.*] section (typo in URL, expired token env var,
        # malformed hostname) used to take down the entire service at
        # boot - reported by tester 2026-04-17 ("saved and restarted.
        # mcp dead :D"). Skipping isolates the failure: other Zabbix
        # servers still register, the broken one is reported on the
        # /servers admin page so the operator can fix it.
        try:
            zabbix_servers[name] = _parse_zabbix_server(name, srv)
        except ConfigError as exc:
            logger.warning(
                "Skipping Zabbix server '%s' because of config error: %s",
                name, exc,
            )
            skipped_servers.append((name, str(exc)))

    if not zabbix_servers and not skipped_servers:
        raise ConfigError(
            "No Zabbix servers configured. Add at least one [zabbix.<name>] section."
        )
    if not zabbix_servers and skipped_servers:
        raise ConfigError(
            "All configured Zabbix servers failed validation: "
            + "; ".join(f"{n}: {e}" for n, e in skipped_servers)
        )

    # Optional [admin.ai] block for the report-template AI assistant.
    # Missing section = feature disabled, no error.
    admin_raw = raw.get("admin", {}) or {}
    ai_raw = admin_raw.get("ai", {}) or {}
    admin_ai = AdminAIConfig(
        enabled=bool(ai_raw.get("enabled", True)),
        provider=str(ai_raw.get("provider", "") or "").strip().lower(),
        api_key=str(ai_raw.get("api_key", "") or "").strip(),
        model=str(ai_raw.get("model", "") or "").strip(),
        api_base=str(ai_raw.get("api_base", "") or "").strip(),
        max_tokens=int(ai_raw.get("max_tokens", 8000) or 8000),
        timeout=int(ai_raw.get("timeout", 180) or 180),
    )

    # Optional [oauth] block for the embedded OAuth 2.1 AS. Missing
    # section = feature disabled (the legacy bearer-token path stays
    # active).  When enabled, [server].public_url MUST be set so the
    # issuer URL on metadata documents is reachable from remote
    # clients (Claude Desktop, ChatGPT custom apps).
    oauth_raw = raw.get("oauth", {}) or {}
    default_scopes_raw = oauth_raw.get("default_scopes", ["*"])
    if not isinstance(default_scopes_raw, list):
        default_scopes_raw = ["*"]
    oauth_cfg = OAuthConfig(
        enabled=bool(oauth_raw.get("enabled", False)),
        login_path=str(oauth_raw.get("login_path", "/oauth/login") or "/oauth/login"),
        dynamic_registration_enabled=bool(oauth_raw.get("dynamic_registration_enabled", True)),
        default_scopes=[str(s) for s in default_scopes_raw],
        auth_code_ttl_seconds=int(oauth_raw.get("auth_code_ttl_seconds", 600) or 600),
        access_token_ttl_seconds=int(oauth_raw.get("access_token_ttl_seconds", 3600) or 3600),
        refresh_token_ttl_seconds=int(oauth_raw.get("refresh_token_ttl_seconds", 30 * 24 * 3600) or 30 * 24 * 3600),
        dcr_profile=_validate_dcr_profile(oauth_raw.get("dcr_profile", "conservative")),
        dcr_conservative_access_ttl_seconds=int(oauth_raw.get("dcr_conservative_access_ttl_seconds", 1800) or 1800),
    )

    # [audit] section - Zabbix-style admin panel knobs (issue #49 follow-up).
    audit_raw = raw.get("audit", {}) or {}
    audit_period_raw = audit_raw.get("data_storage_period", "31d")
    audit_period_str = str(audit_period_raw).strip() if audit_period_raw is not None else "31d"
    if audit_period_str == "":
        audit_period_str = "31d"
    audit_period_seconds = parse_time_period(audit_period_str, default_unit="d")
    audit_max_size_mb_raw = audit_raw.get("max_file_size_mb", 50)
    try:
        audit_max_size_mb = int(audit_max_size_mb_raw)
    except (TypeError, ValueError):
        raise ConfigError(
            f"[audit].max_file_size_mb must be an integer (MB), got {audit_max_size_mb_raw!r}"
        ) from None
    if audit_max_size_mb < 1:
        raise ConfigError("[audit].max_file_size_mb must be >= 1")
    # ``log_background_events`` was previously named ``log_system_actions``
    # (v1.31 dev). Read the old key as a fallback so an operator who
    # set it during the v1.31 dev cycle is not surprised by the toggle
    # silently flipping back to default.
    log_bg_raw = audit_raw.get(
        "log_background_events",
        audit_raw.get("log_system_actions", True),
    )
    audit_cfg = AuditConfig(
        enabled=bool(audit_raw.get("enabled", True)),
        log_portal_operations=bool(audit_raw.get("log_portal_operations", True)),
        log_mcp_actions=bool(audit_raw.get("log_mcp_actions", True)),
        log_background_events=bool(log_bg_raw),
        housekeeping_enabled=bool(audit_raw.get("housekeeping_enabled", True)),
        data_storage_period_seconds=audit_period_seconds,
        data_storage_period_raw=audit_period_str,
        max_file_size_bytes=audit_max_size_mb * 1024 * 1024,
    )

    # [audit.forward] - external SIEM / syslog destination. Off by
    # default so a fresh install does not start dialing arbitrary
    # network endpoints.
    forward_raw = (audit_raw.get("forward") or {}) if isinstance(audit_raw.get("forward"), dict) else {}
    valid_protocols = {
        "rfc5424_udp", "rfc5424_tcp", "rfc5424_tls",
        "cef_udp", "cef_tcp", "cef_tls",
        "leef_udp", "leef_tcp", "leef_tls",
        "json_tcp", "json_tls",
    }
    forward_protocol = str(forward_raw.get("protocol", "rfc5424_udp") or "rfc5424_udp").strip().lower()
    if forward_protocol not in valid_protocols:
        raise ConfigError(
            f"[audit.forward].protocol must be one of {sorted(valid_protocols)}, "
            f"got {forward_protocol!r}"
        )
    forward_port_raw = forward_raw.get("port", 514)
    try:
        forward_port = int(forward_port_raw)
    except (TypeError, ValueError):
        raise ConfigError(
            f"[audit.forward].port must be an integer, got {forward_port_raw!r}"
        ) from None
    if forward_port < 1 or forward_port > 65535:
        raise ConfigError("[audit.forward].port must be between 1 and 65535")
    forward_queue_raw = forward_raw.get("queue_size", 10000)
    try:
        forward_queue = int(forward_queue_raw)
    except (TypeError, ValueError):
        raise ConfigError(
            f"[audit.forward].queue_size must be an integer, got {forward_queue_raw!r}"
        ) from None
    if forward_queue < 100 or forward_queue > 1000000:
        raise ConfigError(
            "[audit.forward].queue_size must be between 100 and 1,000,000"
        )
    audit_forward_cfg = AuditForwardConfig(
        enabled=bool(forward_raw.get("enabled", False)),
        host=str(forward_raw.get("host", "") or "").strip(),
        port=forward_port,
        protocol=forward_protocol,
        ca_cert=str(forward_raw.get("ca_cert", "") or "").strip(),
        queue_size=forward_queue,
    )

    # Optional [plugins.<id>] blocks - the contract is locked in v1.31
    # but the plugin loader itself ships in a follow-up release (issue
    # #47). Eager operators may have already added plugin entries to
    # config.toml against the documented schema; we accept and ignore
    # them so they do not crash startup. A single info-level log line
    # records that the entries were seen but not activated.
    plugins_raw = raw.get("plugins", {}) or {}
    if plugins_raw:
        if isinstance(plugins_raw, dict):
            ids = ", ".join(sorted(plugins_raw.keys()))
            logger.info(
                "Found %d [plugins.X] section(s) in config (%s); plugin loader is "
                "not yet shipped (tracked under issue #47), entries are ignored. "
                "See SECURITY.md plugin section for the contract design.",
                len(plugins_raw), ids,
            )
        else:
            logger.warning(
                "Ignoring [plugins] config entry - expected a table of "
                "[plugins.<id>] sections, got %s.",
                type(plugins_raw).__name__,
            )

    # Optional [modules.<id>] blocks - operator-side toggle for bundled
    # modules. v1.31 parses but does not enforce the `enabled = false`
    # toggle (the disable / re-enable runtime lands with the loader
    # release per issue #47). We log when an operator has set
    # enabled=false on a bundled module so the next-release upgrade can
    # be predicted ("when v1.32 lands, this Zabbix module will stop
    # registering tools"). The bundled module always registers in v1.31
    # regardless of this block - the v1.31 contract is no behavioural
    # change for end users.
    modules_raw = raw.get("modules", {}) or {}
    if modules_raw:
        if isinstance(modules_raw, dict):
            disabled_in_config = [
                mid for mid, mcfg in modules_raw.items()
                if isinstance(mcfg, dict) and mcfg.get("enabled") is False
            ]
            if disabled_in_config:
                logger.info(
                    "Found [modules.X] section(s) with enabled=false (%s); "
                    "the bundled-module disable runtime ships with the plugin "
                    "loader (issue #47), so v1.31 still registers these "
                    "modules. The toggle takes effect on the loader release.",
                    ", ".join(sorted(disabled_in_config)),
                )
        else:
            logger.warning(
                "Ignoring [modules] config entry - expected a table of "
                "[modules.<id>] sections, got %s.",
                type(modules_raw).__name__,
            )

    return AppConfig(
        server=server_config, zabbix_servers=zabbix_servers,
        admin_ai=admin_ai, oauth=oauth_cfg, audit=audit_cfg,
        audit_forward=audit_forward_cfg,
    )
