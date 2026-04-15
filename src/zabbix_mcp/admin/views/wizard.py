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

"""MCP Client Wizard - admin portal page that generates copy-paste-ready
config snippets and per-client install instructions for any AI client.

Single-page progressive disclosure at /wizard. State is kept in URL
query string so users can bookmark / share / refresh without losing
their selections.

Reuses (no duplication):
- server enumeration: same pattern as views/servers.py
- token enumeration: token_store.list_tokens() + filter by allowed_servers
- tool group descriptions: TOOL_GROUPS + _TOOL_DATA from views/tokens.py
- client metadata: wizard_clients.CLIENTS (single source of truth)
"""

from __future__ import annotations

import logging
import socket
import subprocess
from urllib.parse import quote_plus

from jinja2 import Template
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from zabbix_mcp.admin.config_writer import (
    load_config_document,
    TOMLKIT_AVAILABLE,
)
from zabbix_mcp.admin.wizard_clients import CLIENTS, get_client
from zabbix_mcp.config import TOOL_GROUPS, _expand_tool_groups

logger = logging.getLogger("zabbix_mcp.admin")


def _get_host_ips() -> list[str]:
    """Return host IP addresses (IPv4 first), excluding loopback.

    Used when [server].host = 0.0.0.0 to suggest concrete addresses for
    the client config snippet. Mirrors deploy/install.sh _get_host_ips.
    """
    ips: list[str] = []
    # Prefer `hostname -I` (Linux) - fast, no name resolution
    try:
        result = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=2,
        )
        if result.returncode == 0:
            for ip in result.stdout.split():
                ip = ip.strip()
                if ip and ip not in ips:
                    ips.append(ip)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: socket.gethostbyname_ex for the hostname
    if not ips:
        try:
            hostname = socket.gethostname()
            _, _, addrs = socket.gethostbyname_ex(hostname)
            for ip in addrs:
                if ip and ip not in ips and not ip.startswith("127."):
                    ips.append(ip)
        except OSError:
            pass

    # Final fallback so the wizard always has something to show
    if not ips:
        ips = ["127.0.0.1"]
    return ips


def _compose_url(
    scheme: str,
    host: str,
    port: int,
    transport: str,
) -> str:
    """Build the MCP endpoint URL for a client config snippet.

    transport in ("http", "stdio") -> /mcp path
    transport == "sse"             -> /sse path
    """
    path = "/sse" if transport == "sse" else "/mcp"
    # IPv6 hosts need bracket notation in URLs
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{host_part}:{port}{path}"


def _get_servers(admin_app) -> list[dict]:
    """Enumerate Zabbix servers from config (source of truth)."""
    servers: list[dict] = []
    if not TOMLKIT_AVAILABLE:
        return servers
    try:
        doc = load_config_document(admin_app.config_path)
        for name, raw in doc.get("zabbix", {}).items():
            cfg = dict(raw)
            servers.append({
                "name": name,
                "url": cfg.get("url", ""),
                "read_only": cfg.get("read_only", True),
            })
    except Exception as exc:
        logger.warning("wizard: failed to load servers from config: %s", exc)
    servers.sort(key=lambda s: s["name"])
    return servers


def _get_compatible_tokens(admin_app, server_name: str | None) -> list[dict]:
    """List tokens whose allowed_servers includes server_name (or *).

    Returns a list of dicts shaped for the template, NOT raw TokenInfo.
    Tokens with revoked=True or expired are still returned but marked.
    """
    tokens_out: list[dict] = []
    try:
        token_infos = admin_app.token_store.list_tokens()
    except Exception as exc:
        logger.warning("wizard: failed to list tokens: %s", exc)
        return tokens_out

    for ti in token_infos:
        # Filter by allowed_servers
        if server_name and ti.allowed_servers:
            if "*" not in ti.allowed_servers and server_name not in ti.allowed_servers:
                continue
        # Build human-readable scope summary (chip list)
        if "*" in ti.scopes:
            scope_chips = ["all (*)"]
        else:
            scope_chips = list(ti.scopes)
        # IP restriction summary
        ip_summary = "any IP"
        if ti.allowed_ips:
            count = len(ti.allowed_ips)
            ip_summary = f"{count} IP rule" + ("s" if count != 1 else "")
        tokens_out.append({
            "id": ti.id,
            "name": ti.name,
            "scope_chips": scope_chips,
            "read_only": ti.read_only,
            "ip_summary": ip_summary,
            "expires_at": ti.expires_at,
            "is_legacy": ti.is_legacy,
            "revoked": ti.revoked,
            "token_prefix": ti.token_prefix,
        })
    # Stable order: legacy first, then by name
    tokens_out.sort(key=lambda t: (not t["is_legacy"], t["name"]))
    return tokens_out


def _expand_scope_tools(scopes: list[str]) -> list[str]:
    """Turn a token's scopes (groups + prefixes) into a sorted unique
    list of individual tool prefixes. Used to show the operator exactly
    which API methods this token can call."""
    if "*" in scopes:
        # all tools across all groups
        all_prefixes = set()
        for tools in TOOL_GROUPS.values():
            all_prefixes.update(tools)
        return sorted(all_prefixes)
    return sorted(set(_expand_tool_groups(scopes)))


def _resolve_url_context(
    admin_app,
    transport: str,
    override_host: str | None,
) -> dict:
    """Build the context for URL composition: scheme, host, port,
    detected IPs (when host = 0.0.0.0), final URL.
    """
    config = admin_app.config
    scheme = "https" if config.server.tls_cert_file else "http"
    raw_host = config.server.host
    port = getattr(config, "_runtime_port", None) or config.server.port

    # Pick effective host
    detected_ips: list[str] = []
    needs_override = raw_host in ("0.0.0.0", "::")
    if needs_override:
        detected_ips = _get_host_ips()
        host = override_host or detected_ips[0]
    else:
        host = override_host or raw_host

    url = _compose_url(scheme, host, port, transport)
    return {
        "scheme": scheme,
        "raw_host": raw_host,
        "host": host,
        "port": port,
        "needs_override": needs_override,
        "detected_ips": detected_ips,
        "url": url,
    }


def _render_snippet(
    client_meta: dict,
    server_key: str,
    transport: str,
    url: str,
    token: str,
) -> str:
    """Render the per-client config snippet."""
    try:
        return Template(client_meta["template"]).render(
            server_key=server_key,
            transport=transport,
            url=url,
            token=token,
        )
    except Exception as exc:
        logger.warning("wizard: snippet render failed: %s", exc)
        return f"# Error rendering snippet: {exc}"


def _render_instructions(
    client_meta: dict,
    server_key: str,
    config_path: str,
) -> list[str]:
    """Render the install instructions, substituting {config_path} and
    {server_key} placeholders. Uses str.replace (not str.format) so
    instruction text can safely contain other curly braces - e.g. the
    Codex tip mentions ``${ZABBIX_MCP_TOKEN}`` and the JSON template
    samples shown inline."""
    out: list[str] = []
    for step in client_meta.get("instructions", []):
        rendered = step.replace("{config_path}", config_path).replace("{server_key}", server_key)
        out.append(rendered)
    return out


async def wizard_view(request: Request) -> Response:
    """Render the MCP Client Wizard page."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session:
        return RedirectResponse("/login", status_code=303)

    # Query string state
    qp = request.query_params
    server_name = qp.get("server") or ""
    token_id = qp.get("token") or ""
    client_id = qp.get("client") or ""
    transport = qp.get("transport") or ""
    override_host = qp.get("override_host") or ""
    os_choice = qp.get("os") or ""

    # Step 1: servers
    servers = _get_servers(admin_app)
    selected_server = next((s for s in servers if s["name"] == server_name), None)

    # Step 2: tokens compatible with the selected server
    tokens = _get_compatible_tokens(admin_app, server_name if selected_server else None)
    # "auth_enabled" = the MCP server currently requires a Bearer token.
    # False means the server accepts anonymous requests (no [tokens.*]
    # entries AND no legacy [server].auth_token). In that mode the wizard
    # lets the operator progress without picking a token.
    auth_enabled = (
        admin_app.token_store.token_count > 0
        or bool(admin_app.config.server.auth_token)
    )
    # Sentinel "none" token_id means the operator explicitly chose to
    # skip auth for the generated snippet (valid only when auth_enabled
    # is False). Handling it as a sentinel keeps the URL bookmarkable
    # and uses the same query-string plumbing as real token IDs.
    skip_auth = (token_id == "none") and not auth_enabled
    selected_token = None
    if token_id and not skip_auth:
        selected_token = next((t for t in tokens if t["id"] == token_id), None)

    # Tools the selected token can call (for the operator's sanity check)
    selected_token_tools: list[str] = []
    if selected_token:
        # Pull raw scopes from the underlying TokenInfo
        try:
            ti = next(
                (x for x in admin_app.token_store.list_tokens() if x.id == token_id),
                None,
            )
            if ti:
                selected_token_tools = _expand_scope_tools(ti.scopes)
        except Exception:
            pass

    # Step 3: client. Gated on either a picked token OR explicit skip_auth.
    # Without that gate we'd render Step 3 on a fresh /wizard hit where
    # the user hasn't even picked a server yet.
    token_step_done = bool(selected_token) or skip_auth
    selected_client = get_client(client_id) if client_id and token_step_done else None

    # The transport the running MCP server is actually serving. Read from
    # the live config so the wizard can show "current detected" vs "example
    # only" badges in the transport picker - clients connecting to this
    # server will need to use the detected transport unless the operator
    # restarts with a different one.
    server_transport = (admin_app.config.server.transport or "http").lower()

    # Step 4: URL composition + snippet (only when client is chosen)
    url_ctx: dict = {}
    snippet = ""
    instructions: list[str] = []
    config_path_display = ""
    effective_transport = ""
    if selected_client:
        # Pick a transport:
        # - if user explicitly picked one in the URL and it's supported, use it
        # - else default to the server's actual transport if the client supports it
        # - else fall back to the first transport this client supports
        supported = selected_client.get("transports", ["http"])
        if transport in supported:
            effective_transport = transport
        elif server_transport in supported:
            effective_transport = server_transport
        else:
            effective_transport = supported[0]
        url_ctx = _resolve_url_context(admin_app, effective_transport, override_host or None)
        # Pick a config path to show in instructions (first OS by default)
        cfg_paths = selected_client.get("config_paths", {})
        if cfg_paths:
            chosen_os = os_choice if os_choice in cfg_paths else next(iter(cfg_paths))
            config_path_display = cfg_paths[chosen_os]
        # Render snippet WITH a placeholder token. The page-side JS
        # replaces YOUR_TOKEN_HERE with whatever the operator pastes
        # into the bearer-token input. We cannot inject the raw token
        # server-side because it is not retrievable from the hash store.
        # Pass an empty token string when the server has no auth and the
        # user picked "Continue without token". All per-client Jinja2
        # templates guard the Authorization header with {% if token %},
        # so empty token -> snippet without auth header.
        snippet_token = "" if skip_auth else "YOUR_TOKEN_HERE"
        snippet = _render_snippet(
            selected_client,
            server_key=server_name or "zabbix",
            transport=effective_transport,
            url=url_ctx.get("url", ""),
            token=snippet_token,
        )
        instructions = _render_instructions(
            selected_client,
            server_key=server_name or "zabbix",
            config_path=config_path_display,
        )

    # Build the return_to URL for token creation chain
    return_to = "/wizard"
    if server_name:
        return_to += f"?server={quote_plus(server_name)}"
        if client_id:
            return_to += f"&client={quote_plus(client_id)}"

    return admin_app.render("wizard.html", request, {
        "active": "wizard",
        "page_title": "Client MCP Wizard",
        # Step 1 data
        "servers": servers,
        "selected_server": selected_server,
        # Don't call this key "server_name" - base.html uses that for the
        # "MCP available at ..." banner label.
        "zabbix_server_name": server_name,
        # Step 2 data
        "tokens": tokens,
        "selected_token": selected_token,
        "selected_token_tools": selected_token_tools,
        "token_id": token_id,
        "return_to": return_to,
        "auth_enabled": auth_enabled,
        "skip_auth": skip_auth,
        # Step 3 data
        "clients": list(CLIENTS.items()),
        "selected_client": selected_client,
        "client_id": client_id,
        # Step 4 data
        "url_ctx": url_ctx,
        "transport": effective_transport,
        "server_transport": server_transport,
        "snippet": snippet,
        "snippet_format": (selected_client or {}).get("format", "text"),
        "instructions": instructions,
        "config_path_display": config_path_display,
        "os_choice": os_choice,
        "notes": (selected_client or {}).get("notes", ""),
        # Permissions
        "can_create_token": session.role in ("admin", "operator"),
    })
