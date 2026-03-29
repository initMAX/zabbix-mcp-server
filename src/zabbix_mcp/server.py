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

"""MCP server setup, lifespan management, and dynamic tool registration."""

import inspect
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Optional

from pydantic import Field
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings

from zabbix_mcp.api import ALL_METHODS
from zabbix_mcp.api.types import MethodDef, ParamDef
from zabbix_mcp.client import ClientManager, RateLimitError, ReadOnlyError
from zabbix_mcp.config import AppConfig

logger = logging.getLogger("zabbix_mcp.server")

# Map param_type strings to Python types for dynamic signature building
_PYTHON_TYPES: dict[str, type] = {
    "str": str,
    "int": int,
    "bool": bool,
    "list[str]": list[str],
    "list": list,
    "dict": dict,
}


# ---------------------------------------------------------------------------
# Symbolic name → numeric ID mappings for Zabbix API enum fields.
# Source: Zabbix source (ui/include/defines.inc.php) and API documentation.
# ---------------------------------------------------------------------------

# Item preprocessing step types (preprocessing[].type)
_PREPROCESSING_TYPES: dict[str, int] = {
    "MULTIPLIER": 1,
    "RTRIM": 2,
    "LTRIM": 3,
    "TRIM": 4,
    "REGEX": 5,
    "BOOL_TO_DECIMAL": 6,
    "OCTAL_TO_DECIMAL": 7,
    "HEX_TO_DECIMAL": 8,
    "SIMPLE_CHANGE": 9,
    "CHANGE_PER_SECOND": 10,
    "XMLPATH": 11,
    "JSONPATH": 12,
    "IN_RANGE": 13,
    "MATCHES_REGEX": 14,
    "NOT_MATCHES_REGEX": 15,
    "CHECK_JSON_ERROR": 16,
    "CHECK_XML_ERROR": 17,
    "CHECK_REGEX_ERROR": 18,
    "DISCARD_UNCHANGED": 19,
    "DISCARD_UNCHANGED_HEARTBEAT": 20,
    "JAVASCRIPT": 21,
    "PROMETHEUS_PATTERN": 22,
    "PROMETHEUS_TO_JSON": 23,
    "CSV_TO_JSON": 24,
    "STR_REPLACE": 25,
    "CHECK_NOT_SUPPORTED": 26,
    "XML_TO_JSON": 27,
    "SNMP_WALK_VALUE": 28,
    "SNMP_WALK_TO_JSON": 29,
    "SNMP_GET_VALUE": 30,
}

# Preprocessing error handler (preprocessing[].error_handler)
_PREPROCESSING_ERROR_HANDLERS: dict[str, int] = {
    "DEFAULT": 0,
    "DISCARD_VALUE": 1,
    "SET_VALUE": 2,
    "CUSTOM_VALUE": 2,
    "SET_ERROR": 3,
    "CUSTOM_ERROR": 3,
}

# Preprocessing types that do NOT support error_handler / error_handler_params.
# Sending these fields on these types causes Zabbix API errors.
_PREPROC_NO_ERROR_HANDLER: set[int] = {
    19,  # DISCARD_UNCHANGED
    20,  # DISCARD_UNCHANGED_HEARTBEAT
}

# Item / item prototype collection type (type)
_ITEM_TYPES: dict[str, int] = {
    "ZABBIX_PASSIVE": 0,
    "TRAPPER": 2,
    "SIMPLE_CHECK": 3,
    "INTERNAL": 5,
    "ZABBIX_ACTIVE": 7,
    "WEB_ITEM": 9,
    "EXTERNAL_CHECK": 10,
    "DATABASE_MONITOR": 11,
    "IPMI": 12,
    "SSH": 13,
    "TELNET": 14,
    "CALCULATED": 15,
    "JMX": 16,
    "SNMP_TRAP": 17,
    "DEPENDENT": 18,
    "HTTP_AGENT": 19,
    "SNMP_AGENT": 20,
    "SCRIPT": 21,
    "BROWSER": 22,
}

# Item / item prototype value type (value_type)
_VALUE_TYPES: dict[str, int] = {
    "FLOAT": 0,
    "CHAR": 1,
    "LOG": 2,
    "UNSIGNED": 3,
    "TEXT": 4,
    "BINARY": 5,
}

# Trigger severity / priority (priority)
_SEVERITY_LEVELS: dict[str, int] = {
    "NOT_CLASSIFIED": 0,
    "INFORMATION": 1,
    "WARNING": 2,
    "AVERAGE": 3,
    "HIGH": 4,
    "DISASTER": 5,
}

# Host interface type (type)
_INTERFACE_TYPES: dict[str, int] = {
    "AGENT": 1,
    "SNMP": 2,
    "IPMI": 3,
    "JMX": 4,
}

# Media type transport (type)
_MEDIATYPE_TYPES: dict[str, int] = {
    "EMAIL": 0,
    "SCRIPT": 1,
    "SMS": 2,
    "WEBHOOK": 4,
}

# Script type (type)
_SCRIPT_TYPES: dict[str, int] = {
    "SCRIPT": 0,
    "IPMI": 1,
    "SSH": 2,
    "TELNET": 3,
    "WEBHOOK": 5,
    "URL": 6,
}

# Script scope (scope)
_SCRIPT_SCOPES: dict[str, int] = {
    "ACTION_OPERATION": 1,
    "MANUAL_HOST": 2,
    "MANUAL_EVENT": 4,
}

# Script execute_on (execute_on)
_SCRIPT_EXECUTE_ON: dict[str, int] = {
    "AGENT": 0,
    "SERVER": 1,
    "SERVER_PROXY": 2,
}

# Action / event source (eventsource)
_EVENT_SOURCES: dict[str, int] = {
    "TRIGGER": 0,
    "DISCOVERY": 1,
    "AUTOREGISTRATION": 2,
    "INTERNAL": 3,
    "SERVICE": 4,
}

# HTTP agent item authentication type (authtype)
_AUTHTYPES: dict[str, int] = {
    "NONE": 0,
    "BASIC": 1,
    "NTLM": 2,
    "KERBEROS": 3,
    "DIGEST": 4,
}

# HTTP agent item request body type (post_type)
_POST_TYPES: dict[str, int] = {
    "RAW": 0,
    "JSON": 2,
}

# Proxy operating mode (operating_mode)
_PROXY_OPERATING_MODES: dict[str, int] = {
    "ACTIVE": 0,
    "PASSIVE": 1,
}

# User macro type (type)
_USERMACRO_TYPES: dict[str, int] = {
    "TEXT": 0,
    "SECRET": 1,
    "VAULT": 2,
}

# Connector data type (data_type)
_CONNECTOR_DATA_TYPES: dict[str, int] = {
    "ITEM_VALUES": 0,
    "EVENTS": 1,
}

# User role type (type)
_ROLE_TYPES: dict[str, int] = {
    "USER": 1,
    "ADMIN": 2,
    "SUPER_ADMIN": 3,
    "GUEST": 4,
}

# Discovery check type (dchecks[].type in drule.create/update)
_DCHECK_TYPES: dict[str, int] = {
    "SSH": 0,
    "LDAP": 1,
    "SMTP": 2,
    "FTP": 3,
    "HTTP": 4,
    "POP": 5,
    "NNTP": 6,
    "IMAP": 7,
    "TCP": 8,
    "ZABBIX_AGENT": 9,
    "SNMPV1": 10,
    "SNMPV2C": 11,
    "ICMP": 12,
    "SNMPV3": 13,
    "HTTPS": 14,
    "TELNET": 15,
}

# Maintenance type (maintenance_type)
_MAINTENANCE_TYPES: dict[str, int] = {
    "DATA_COLLECTION": 0,
    "NO_DATA": 1,
}

# Registry: API method prefix → {field_name: mapping}
# Used by _normalize_enum_fields to resolve symbolic names in top-level params.
_ENUM_FIELDS: dict[str, dict[str, dict[str, int]]] = {
    "item.": {"type": _ITEM_TYPES, "value_type": _VALUE_TYPES, "authtype": _AUTHTYPES, "post_type": _POST_TYPES},
    "itemprototype.": {"type": _ITEM_TYPES, "value_type": _VALUE_TYPES, "authtype": _AUTHTYPES, "post_type": _POST_TYPES},
    "discoveryrule.": {"type": _ITEM_TYPES},
    "discoveryruleprototype.": {"type": _ITEM_TYPES},
    "trigger.": {"priority": _SEVERITY_LEVELS},
    "triggerprototype.": {"priority": _SEVERITY_LEVELS},
    "hostinterface.": {"type": _INTERFACE_TYPES},
    "mediatype.": {"type": _MEDIATYPE_TYPES},
    "script.": {"type": _SCRIPT_TYPES, "scope": _SCRIPT_SCOPES, "execute_on": _SCRIPT_EXECUTE_ON},
    "action.": {"eventsource": _EVENT_SOURCES},
    "proxy.": {"operating_mode": _PROXY_OPERATING_MODES},
    "usermacro.": {"type": _USERMACRO_TYPES},
    "connector.": {"data_type": _CONNECTOR_DATA_TYPES},
    "role.": {"type": _ROLE_TYPES},
    "httptest.": {"authentication": _AUTHTYPES},
    "maintenance.": {"maintenance_type": _MAINTENANCE_TYPES},
}

# Fields that Zabbix API expects as arrays of objects.
# LLMs often send a single dict instead of a list — we auto-wrap it.
_ARRAY_FIELDS: set[str] = {
    "groups", "host_groups", "template_groups",
    "templates", "tags", "interfaces", "macros",
    "timeperiods", "steps", "operations",
    "recovery_operations", "update_operations",
    "preprocessing", "dchecks",
}


# Fields that contain Unix timestamps.  LLMs often send ISO 8601 strings
# (e.g. "2026-04-01 08:00:00") instead of ints — we auto-convert them.
_TIMESTAMP_FIELDS: set[str] = {
    "active_since", "active_till",
    "time_from", "time_till",
    "expires_at", "clock",
}

# Common ISO 8601 formats that LLMs produce.
_TIMESTAMP_FORMATS: list[str] = [
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
]


def _try_parse_timestamp(value: str) -> int | None:
    """Try to parse an ISO 8601 string into a Unix timestamp.

    Returns the integer timestamp on success, ``None`` if the string
    does not match any known format.
    """
    for fmt in _TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            # If no timezone info, assume UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            continue
    return None


def _normalize_timestamps(params: dict[str, Any]) -> dict[str, Any]:
    """Convert ISO 8601 datetime strings to Unix timestamps in known fields.

    Only touches fields listed in ``_TIMESTAMP_FIELDS``.  Integer values
    and numeric strings pass through unchanged.
    """
    changed = False
    result = params
    for field in _TIMESTAMP_FIELDS:
        if field not in params:
            continue
        raw = params[field]
        if isinstance(raw, int):
            continue
        if isinstance(raw, str):
            if raw.isdigit():
                continue
            ts = _try_parse_timestamp(raw)
            if ts is not None:
                if not changed:
                    result = {**params}
                    changed = True
                result[field] = ts
    return result


def _resolve_enum_value(raw: Any, mapping: dict[str, int]) -> Any:
    """Resolve a single value against a mapping.

    Returns the numeric ID if *raw* is a recognised symbolic name,
    otherwise returns *raw* unchanged (int, numeric string, or unknown
    name — let the Zabbix API validate).
    """
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        if raw.isdigit():
            return raw
        resolved = mapping.get(raw.upper())
        if resolved is not None:
            return resolved
    return raw


def _normalize_preprocessing(params: dict[str, Any]) -> dict[str, Any]:
    """Normalize preprocessing steps: translate symbolic names and fix error_handler.

    1. Translates symbolic type names (``"JSONPATH"`` → ``12``).
    2. Translates symbolic error_handler names (``"DISCARD_VALUE"`` → ``1``).
    3. Auto-fills ``error_handler: 0`` and ``error_handler_params: ""`` on
       steps that support error handling but are missing these fields.
       Without this, Zabbix API returns confusing errors.
    4. Auto-strips ``error_handler`` and ``error_handler_params`` from steps
       that don't support them (DISCARD_UNCHANGED, DISCARD_UNCHANGED_HEARTBEAT).
       Without this, Zabbix API rejects the request with "value must be empty".
    """
    if "preprocessing" not in params or not isinstance(params["preprocessing"], list):
        return params

    steps = params["preprocessing"]
    changed = False

    for step in steps:
        if not isinstance(step, dict):
            continue

        # Resolve symbolic type name
        if "type" in step:
            new_val = _resolve_enum_value(step["type"], _PREPROCESSING_TYPES)
            if new_val is not step["type"]:
                step["type"] = new_val
                changed = True

        # Resolve symbolic error_handler name
        if "error_handler" in step:
            new_val = _resolve_enum_value(step["error_handler"], _PREPROCESSING_ERROR_HANDLERS)
            if new_val is not step["error_handler"]:
                step["error_handler"] = new_val
                changed = True

        # Determine the resolved type (int) for error_handler logic
        step_type = step.get("type")
        if isinstance(step_type, str) and step_type.isdigit():
            step_type = int(step_type)

        if isinstance(step_type, int):
            if step_type in _PREPROC_NO_ERROR_HANDLER:
                # Strip error_handler fields from types that don't support them
                if "error_handler" in step:
                    del step["error_handler"]
                    changed = True
                if "error_handler_params" in step:
                    del step["error_handler_params"]
                    changed = True
            else:
                # Auto-fill default error_handler on types that require it
                if "error_handler" not in step:
                    step["error_handler"] = 0
                    step.setdefault("error_handler_params", "")
                    changed = True
                elif "error_handler_params" not in step:
                    step["error_handler_params"] = ""
                    changed = True

    if changed:
        return {**params, "preprocessing": steps}
    return params


def _normalize_nested_interfaces(params: dict[str, Any]) -> dict[str, Any]:
    """Translate symbolic type names inside nested interfaces arrays.

    Handles the ``interfaces`` field in host.create/update params, where
    each interface dict has a ``type`` field (AGENT, SNMP, IPMI, JMX).
    """
    if "interfaces" not in params or not isinstance(params["interfaces"], list):
        return params

    changed = False
    for iface in params["interfaces"]:
        if not isinstance(iface, dict) or "type" not in iface:
            continue
        new_val = _resolve_enum_value(iface["type"], _INTERFACE_TYPES)
        if new_val is not iface["type"]:
            iface["type"] = new_val
            changed = True

    if changed:
        return {**params, "interfaces": params["interfaces"]}
    return params


def _normalize_nested_dchecks(params: dict[str, Any]) -> dict[str, Any]:
    """Translate symbolic type names inside nested dchecks arrays.

    Handles the ``dchecks`` field in drule.create/update params, where
    each dcheck dict has a ``type`` field (SSH, LDAP, HTTP, ICMP, etc.).
    """
    if "dchecks" not in params or not isinstance(params["dchecks"], list):
        return params

    changed = False
    for check in params["dchecks"]:
        if not isinstance(check, dict) or "type" not in check:
            continue
        new_val = _resolve_enum_value(check["type"], _DCHECK_TYPES)
        if new_val is not check["type"]:
            check["type"] = new_val
            changed = True

    if changed:
        return {**params, "dchecks": params["dchecks"]}
    return params


def _auto_wrap_arrays(params: dict[str, Any]) -> dict[str, Any]:
    """Wrap single dicts into arrays for fields that expect lists.

    LLMs often send e.g. ``"groups": {"groupid": "1"}`` instead of
    ``"groups": [{"groupid": "1"}]``.  Detects known array fields and
    wraps a bare dict in a list.
    """
    changed = False
    result = params
    for field in _ARRAY_FIELDS:
        if field in params and isinstance(params[field], dict):
            if not changed:
                result = {**params}
                changed = True
            result[field] = [params[field]]
    return result


def _normalize_enum_fields(params: dict[str, Any], api_method: str) -> dict[str, Any]:
    """Translate symbolic enum names in top-level params fields to numeric IDs.

    Uses the ``_ENUM_FIELDS`` registry to determine which fields to
    normalise based on the API method being called.
    """
    # Find matching field mappings by method prefix
    field_mappings: dict[str, dict[str, int]] = {}
    for prefix, mappings in _ENUM_FIELDS.items():
        if api_method.startswith(prefix):
            field_mappings = mappings
            break

    if not field_mappings:
        return params

    changed = False
    result = params
    for field_name, mapping in field_mappings.items():
        if field_name in params:
            new_val = _resolve_enum_value(params[field_name], mapping)
            if new_val is not params[field_name]:
                if not changed:
                    result = {**params}
                    changed = True
                result[field_name] = new_val

    return result


# Regex for valid UUIDv4 format
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-?[0-9a-f]{4}-?4[0-9a-f]{3}-?[89ab][0-9a-f]{3}-?[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _resolve_source_file(params: dict[str, Any]) -> dict[str, Any]:
    """Read file content for configuration.import when ``source_file`` is used.

    LLMs find it impractical to send large YAML/JSON templates as inline
    strings.  This allows ``"source_file": "/path/to/template.yaml"``
    as an alternative to ``"source": "<huge YAML string>"``.
    """
    if "source_file" not in params or "source" in params:
        return params

    path = Path(params["source_file"])
    if not path.is_file():
        raise ValueError(f"source_file not found: {path}")

    content = path.read_text(encoding="utf-8")
    result = {**params, "source": content}
    del result["source_file"]

    # Auto-detect format from extension if not specified
    if "format" not in result:
        ext = path.suffix.lower()
        if ext in (".yaml", ".yml"):
            result["format"] = "yaml"
        elif ext in (".xml",):
            result["format"] = "xml"
        elif ext in (".json",):
            result["format"] = "json"

    return result


def _validate_import_uuids(params: dict[str, Any]) -> None:
    """Validate UUID format in configuration.import source before sending.

    Scans the source string for ``uuid:`` fields and checks they are
    valid UUIDv4.  Raises ``ValueError`` with a clear message if any
    invalid UUIDs are found, saving the user from cryptic Zabbix errors.
    """
    source = params.get("source", "")
    if not isinstance(source, str) or not source:
        return

    # Find uuid: lines in YAML/JSON source
    invalid: list[str] = []
    for line in source.splitlines():
        stripped = line.strip()
        # Match YAML: "uuid: <value>" or JSON: "\"uuid\": \"<value>\""
        if stripped.startswith("uuid:"):
            value = stripped[5:].strip().strip("'\"")
            if value and not _UUID_RE.match(value):
                invalid.append(value)
        elif '"uuid"' in stripped or "'uuid'" in stripped:
            # JSON-style: try to extract the value
            parts = stripped.split(":", 1)
            if len(parts) == 2:
                value = parts[1].strip().strip(",").strip().strip("'\"")
                if value and not _UUID_RE.match(value):
                    invalid.append(value)

    if invalid:
        examples = ", ".join(invalid[:3])
        raise ValueError(
            f"Invalid UUID(s) in import source: {examples}. "
            f"UUIDs must be valid v4 format (e.g. '550e8400-e29b-41d4-a716-446655440000'). "
            f"Generate with: python -c \"import uuid; print(uuid.uuid4())\""
        )


def _snake_to_camel(name: str) -> str:
    """Convert snake_case to camelCase (e.g. 'discovery_rules' -> 'discoveryRules')."""
    parts = name.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _normalize_import_rules(params: dict[str, Any], zabbix_version: str | None = None) -> dict[str, Any]:
    """Normalize configuration.import rules for the target Zabbix version.

    Handles two common issues:
    1. snake_case keys — LLMs generate e.g. ``discovery_rules`` instead of
       ``discoveryRules``.  Note: the Zabbix API is inconsistent — most rule
       keys are camelCase but ``host_groups`` and ``template_groups`` (>=6.2)
       are snake_case.
    2. Version-specific group parameters — Zabbix <6.2 uses ``groups``,
       >=6.2 uses ``host_groups`` + ``template_groups``.
    """
    if "rules" not in params or not isinstance(params["rules"], dict):
        return params

    rules = params["rules"]

    # Keys that must stay snake_case (Zabbix >=6.2 API expects them this way)
    _KEEP_SNAKE = {"host_groups", "template_groups"}

    # Step 1: normalize key names
    normalized: dict[str, Any] = {}
    for key, value in rules.items():
        if key in _KEEP_SNAKE:
            # Already correct snake_case for >=6.2
            normalized[key] = value
        elif "_" in key:
            normalized[_snake_to_camel(key)] = value
        else:
            normalized[key] = value

    # Step 2: fix camelCase variants of group keys that LLMs may generate
    if "hostGroups" in normalized:
        normalized.setdefault("host_groups", normalized.pop("hostGroups"))
    if "templateGroups" in normalized:
        normalized.setdefault("template_groups", normalized.pop("templateGroups"))

    # Step 3: version-aware group parameter fixup
    if zabbix_version:
        major_minor = tuple(int(x) for x in zabbix_version.split(".")[:2])

        if major_minor < (6, 2):
            # Zabbix <6.2: only "groups" exists
            groups_val = (
                normalized.pop("host_groups", None)
                or normalized.pop("template_groups", None)
            )
            if groups_val and "groups" not in normalized:
                normalized["groups"] = groups_val
            normalized.pop("host_groups", None)
            normalized.pop("template_groups", None)
        else:
            # Zabbix >=6.2: "groups" was split into host_groups + template_groups
            if "groups" in normalized:
                val = normalized.pop("groups")
                normalized.setdefault("host_groups", val)
                normalized.setdefault("template_groups", val)

    return {**params, "rules": normalized}


def _build_zabbix_params(
    method_def: MethodDef,
    kwargs: dict[str, Any],
    zabbix_version: str | None = None,
) -> Any:
    """Convert tool keyword arguments into Zabbix API parameters."""
    args = {k: v for k, v in kwargs.items() if k != "server" and v is not None}

    # Methods that pass a single param as a plain array (e.g. history.clear, user.unblock)
    if method_def.array_param and method_def.array_param in args:
        return args[method_def.array_param]

    # Delete methods expect a plain list of IDs
    if "ids" in args and method_def.api_method.endswith(".delete"):
        return args["ids"]

    # create/update/mass/special methods: the 'params' dict IS the API payload
    if "params" in args:
        params = args["params"]
        if method_def.api_method in ("configuration.import", "configuration.importcompare"):
            params = _resolve_source_file(params)
            _validate_import_uuids(params)
            params = _normalize_import_rules(params, zabbix_version)
        if isinstance(params, dict):
            params = _auto_wrap_arrays(params)
            params = _normalize_preprocessing(params)
            params = _normalize_enum_fields(params, method_def.api_method)
            params = _normalize_nested_interfaces(params)
            params = _normalize_nested_dchecks(params)
            params = _normalize_timestamps(params)
        return params

    # For get methods: build params dict from individual arguments
    params: dict[str, Any] = {}
    for param_def in method_def.params:
        if param_def.name == "extra_params":
            continue  # handled below
        if param_def.name in args:
            value = args[param_def.name]
            # Split comma-separated output fields
            if param_def.name == "output" and isinstance(value, str) and value != "extend":
                if "," in value:
                    value = [f.strip() for f in value.split(",")]
            # Split comma-separated sort fields
            if param_def.name == "sortfield" and isinstance(value, str) and "," in value:
                value = [f.strip() for f in value.split(",")]
            params[param_def.name] = value

    # Default output to "extend" so LLMs get full objects, not just IDs
    if method_def.read_only and "output" not in params and "countOutput" not in params:
        params["output"] = "extend"

    # Convert ISO timestamps in get params (e.g. time_from, time_till)
    params = _normalize_timestamps(params)

    # Merge extra_params (selectXxx, etc.) — typed params take precedence
    if "extra_params" in args and isinstance(args["extra_params"], dict):
        for k, v in args["extra_params"].items():
            params.setdefault(k, v)

    return params


def _make_tool_handler(
    method_def: MethodDef,
    client_manager: ClientManager,
    server_names: list[str],
):
    """Create a tool handler with a proper typed signature for FastMCP schema generation."""

    # Build the actual handler that does the work
    async def handler(**kwargs: Any) -> str:
        server_name = kwargs.get("server") or client_manager.default_server
        if not server_name:
            return "Error: No Zabbix server configured."

        try:
            server_name = client_manager.resolve_server(server_name)

            if not method_def.read_only:
                client_manager.check_write(server_name)

            zabbix_version = client_manager.get_version(server_name)
            params = _build_zabbix_params(method_def, kwargs, zabbix_version)
            result = client_manager.call(server_name, method_def.api_method, params)

            text = json.dumps(result, indent=2, default=str, ensure_ascii=False)
            if len(text) > 50000:
                text = text[:50000] + "\n\n... [truncated, use 'limit' parameter to reduce results]"
            return text

        except (ReadOnlyError, RateLimitError) as e:
            return f"Error: {e}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.exception("Error calling %s on server '%s'", method_def.api_method, server_name)
            return f"Error calling {method_def.api_method}: {e}"

    # Build a dynamic function signature so FastMCP generates proper JSON Schema
    sig_params: list[inspect.Parameter] = []

    # Server parameter
    server_desc = (
        f"Target Zabbix server. Available: {', '.join(server_names)}. "
        f"Defaults to '{server_names[0]}' if omitted."
    )
    sig_params.append(inspect.Parameter(
        "server",
        inspect.Parameter.KEYWORD_ONLY,
        default=None,
        annotation=Annotated[Optional[str], Field(description=server_desc)],
    ))

    # Method-specific parameters
    for p in method_def.params:
        python_type = _PYTHON_TYPES.get(p.param_type, str)
        if p.required:
            annotation = Annotated[python_type, Field(description=p.description)]
            default = inspect.Parameter.empty
        else:
            annotation = Annotated[Optional[python_type], Field(description=p.description)]
            default = p.default
        sig_params.append(inspect.Parameter(
            p.name,
            inspect.Parameter.KEYWORD_ONLY,
            default=default,
            annotation=annotation,
        ))

    handler.__signature__ = inspect.Signature(sig_params, return_annotation=str)
    handler.__name__ = method_def.tool_name
    handler.__doc__ = method_def.description
    handler.__qualname__ = method_def.tool_name

    return handler


def _register_tools(mcp: FastMCP, client_manager: ClientManager) -> int:
    """Register all Zabbix API methods as MCP tools. Returns tool count."""
    server_names = client_manager.server_names
    count = 0

    for method_def in ALL_METHODS:
        handler = _make_tool_handler(method_def, client_manager, server_names)
        mcp.add_tool(handler, name=method_def.tool_name, description=method_def.description)
        count += 1

    # Generic raw API call tool
    server_desc = (
        f"Target Zabbix server. Available: {', '.join(server_names)}. "
        f"Defaults to '{server_names[0]}' if omitted."
    )

    async def zabbix_raw_api_call(
        *,
        method: Annotated[str, Field(description="Full Zabbix API method name, e.g. 'host.get', 'trigger.create'")],
        params: Annotated[Optional[dict], Field(description="API method parameters as a JSON object")] = None,
        server: Annotated[Optional[str], Field(description=server_desc)] = None,
    ) -> str:
        """Execute any Zabbix API method directly. Use this for methods not covered
        by dedicated tools, or for advanced/undocumented API calls."""
        server_name = server or client_manager.default_server
        if not server_name:
            return "Error: No Zabbix server configured."
        try:
            server_name = client_manager.resolve_server(server_name)
            result = client_manager.call(server_name, method, params or {})
            text = json.dumps(result, indent=2, default=str, ensure_ascii=False)
            if len(text) > 50000:
                text = text[:50000] + "\n\n... [truncated]"
            return text
        except Exception as e:
            return f"Error: {e}"

    mcp.add_tool(zabbix_raw_api_call)
    count += 1

    # Health check tool
    async def health_check() -> str:
        """Check the health of the MCP server and its connections to Zabbix servers.
        Returns the status of each configured Zabbix server (version, connectivity)."""
        from zabbix_mcp import __version__
        results: dict[str, Any] = {
            "mcp_server": "ok",
            "version": __version__,
            "tools": count,
            "zabbix_servers": {},
        }
        for name in client_manager.server_names:
            try:
                client = client_manager._get_client(name)
                version = client.api_version()
                results["zabbix_servers"][name] = {"status": "ok", "zabbix_version": str(version)}
            except Exception as e:
                results["zabbix_servers"][name] = {"status": "error", "error": str(e)}
        return json.dumps(results, indent=2)

    mcp.add_tool(health_check)
    count += 1

    return count


class _BearerTokenVerifier:
    """Simple bearer token verifier for HTTP transport authentication."""

    def __init__(self, expected_token: str) -> None:
        self._expected_token = expected_token

    async def verify_token(self, token: str) -> AccessToken | None:
        if token == self._expected_token:
            return AccessToken(
                token=token,
                client_id="mcp-client",
                scopes=["all"],
                expires_at=int(time.time()) + 86400,
            )
        return None


def run_server(
    config: AppConfig,
    *,
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8080,
) -> None:
    """Create and run the MCP server."""
    client_manager = ClientManager(config)

    # Set up bearer token auth for HTTP transport
    auth_kwargs: dict[str, Any] = {}
    if config.server.auth_token and transport == "http":
        server_url = f"http://{host}:{port}"
        auth_kwargs["token_verifier"] = _BearerTokenVerifier(config.server.auth_token)
        auth_kwargs["auth"] = AuthSettings(
            issuer_url=server_url,
            resource_server_url=server_url,
        )
        logger.info("Bearer token authentication enabled")
    elif transport == "http" and not config.server.auth_token:
        logger.warning("No auth_token configured - HTTP server is unauthenticated!")

    mcp = FastMCP(
        name="zabbix-mcp-server",
        host=host,
        port=port,
        instructions=(
            "Zabbix MCP Server provides full access to the Zabbix monitoring API. "
            "Use the tools to query hosts, problems, triggers, items, and all other "
            "Zabbix objects. Most 'get' tools support filtering via 'filter', 'search', "
            "and 'limit' parameters. Write operations (create/update/delete) are only "
            "allowed on servers not configured as read_only."
        ),
        **auth_kwargs,
    )

    tool_count = _register_tools(mcp, client_manager)
    logger.info("Registered %d tools", tool_count)

    try:
        if transport == "http":
            mcp.run(transport="streamable-http")
        else:
            mcp.run(transport="stdio")
    finally:
        client_manager.close()
