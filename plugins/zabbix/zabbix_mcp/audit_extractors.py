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

"""Per-tool extraction of resource references and filter flags for the
audit log (Phase 1 of issue #49).

The audit log row schema has two bounded objects, ``target`` and
``filters``, that are stable across tools. Different tools refer to
different resources (host_get carries hostids, item_get carries itemids,
etc.) and accept different filter flags (severities, monitored,
active_only, recent, period). This module classifies each call's kwargs
into the two buckets so the audit row stays grep-friendly without
forcing every tool through the same model.

Per the reviewer (musaabhasan, #49 comment):

> keep the common fields (``oauth_subject``, ``mapped_zabbix_user``,
> ``mcp_session_id``, ``tool_name``, ``scopes``, ``policy_decision``,
> ``denial_reason``, ``result_count``) fixed, and put resource-specific
> values such as ``host_id``, ``group_id``, ``trigger_id``,
> ``severities``, and ``active_only`` into a bounded ``target`` /
> ``filters`` object.

> a denied request should still write a denial audit row, but must not
> include sensitive argument values beyond redacted resource references.

So this module is also the **redaction boundary** for tool kwargs:
a denied call's audit row gets only the resource references
(``host_id``, ``hostgroup_id``, ``severities``), never the full kwargs
or potentially-sensitive values like macros, passwords, commands, ...

Default behaviour for unmapped tools: ``target`` and ``filters`` are
both empty dicts. The audit row still records the tool name, scopes,
and policy decision - the ``target`` / ``filters`` granularity is a
nice-to-have, not a blocker.
"""

from __future__ import annotations

from typing import Any

# Resource-reference keys we extract into the ``target`` bucket. These
# are all numeric IDs / names that point at a Zabbix object - safe to
# log because (a) they are non-sensitive resource handles, (b) the
# caller already knows them (they passed them in).
_TARGET_KEYS = frozenset({
    # Hosts / groups / interfaces
    "hostid", "hostids", "host", "groupids", "groupid", "templateids", "templateid",
    "hostinterfaceid", "hostinterfaceids", "interfaceid", "interfaceids",
    # Items / triggers / graphs / discovery
    "itemid", "itemids", "triggerid", "triggerids", "graphid", "graphids",
    "discoveryruleid", "discoveryruleids", "ruleid", "ruleids",
    "itemprototypeid", "triggerprototypeid", "graphprototypeid", "hostprototypeid",
    # Events / problems / actions
    "eventid", "eventids", "problemid", "problemids", "actionid", "actionids",
    # Users / roles / tokens
    "userid", "userids", "roleid", "usrgrpid", "usrgrpids",
    "user_tokenid", "tokenid", "tokenids", "mfaid",
    # Maps / dashboards / templates
    "sysmapid", "sysmapids", "dashboardid", "dashboardids", "templatedashboardid",
    "templategroupid", "templategroupids",
    # Maintenance / proxy / scripts / mediatypes
    "maintenanceid", "maintenanceids", "proxyid", "proxyids", "proxygroupid",
    "scriptid", "scriptids", "mediatypeid", "mediatypeids",
    "iconmapid", "imageid", "regexpid", "valuemapid",
    "connectorid", "correlationid", "slaid",
    # Reports / configuration
    "reportid", "reportids",
    # Server selector (when the call routes to a non-default Zabbix instance)
    "server",
})

# Filter / scope keys we extract into the ``filters`` bucket. These
# describe what the caller is asking for, not what they sent. Severity
# floors, time windows, status flags, search patterns - non-secret,
# review-relevant.
_FILTER_KEYS = frozenset({
    "severities", "severity", "status", "active_only", "monitored", "recent",
    "filter", "search", "searchbyany", "searchwildcardsenabled",
    "limit", "countoutput", "output", "sortfield", "sortorder",
    "period", "time_from", "time_till", "history", "trends",
    "with_items", "with_triggers", "with_graphs", "with_httptests",
})


def extract(tool_name: str, arguments: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split a tool's kwargs into (target, filters) buckets.

    Returns two dicts: resource references and filter flags. Anything
    not in either bucket is dropped from the audit row - this is
    intentional. We do NOT pass through the full kwargs, because tool
    arguments can carry secrets (a hypothetical ``host_create`` with
    ``inventory.serial_number`` or a ``script_execute`` with command
    arguments) and even after the redactor's denylist there are
    plenty of misnamed fields we cannot anticipate.

    The ``params`` wrapper (used by every wrapped Zabbix API method) is
    flattened transparently so ``host_create({"params": {"host": "x",
    ...}})`` extracts the same way as ``host_create({"host": "x", ...})``.

    Tool name is currently unused in the extraction logic - all tools
    share the same key set - but the parameter is kept so future
    per-tool overrides (e.g. ``zabbix_raw_api_call`` which has different
    semantics) can specialise without changing the call site.
    """
    if not arguments:
        return ({}, {})

    # Flatten the {"params": {...}} wrapper that wrapped Zabbix API
    # methods use. Otherwise our key matching looks at "params" and
    # finds nothing.
    flat: dict[str, Any] = dict(arguments)
    if "params" in flat and isinstance(flat["params"], dict):
        nested = flat.pop("params")
        # Nested keys win when both layers carry the same key (caller
        # would have used the nested form).
        for k, v in nested.items():
            flat.setdefault(k, v)

    target: dict[str, Any] = {}
    filters: dict[str, Any] = {}
    for k, v in flat.items():
        kl = k.lower()
        if kl in _TARGET_KEYS:
            target[kl] = _shrink(v)
        elif kl in _FILTER_KEYS:
            filters[kl] = _shrink(v)
        # Any other key is dropped. Intentional - see docstring above.

    # Special-case: zabbix_raw_api_call carries the actual API method
    # name as ``method`` and the API-level params as ``params``. We
    # surface the method name as a target reference so an audit grep
    # can find "anyone called host.create via raw_api?". The params
    # are NOT extracted because they can carry secrets (e.g. a custom
    # macro value, a usermacro_create global secret).
    if tool_name == "zabbix_raw_api_call":
        method = arguments.get("method")
        if method:
            target["api_method"] = str(method)[:128]

    return (target, filters)


def _shrink(value: Any) -> Any:
    """Trim long lists / strings to keep the audit row compact.

    A request with ``hostids = [1, 2, ..., 10000]`` should not balloon
    the audit log - record the first 8 plus a count. Same for long
    strings (search patterns can be 200+ chars; trim to 128).
    """
    if isinstance(value, list):
        if len(value) <= 8:
            return value
        return list(value[:8]) + [f"... and {len(value) - 8} more"]
    if isinstance(value, str) and len(value) > 128:
        return value[:128] + f"... [+{len(value) - 128}]"
    return value
