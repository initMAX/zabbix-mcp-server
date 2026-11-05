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

"""Declarative types for the Zabbix API method registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ParamDef:
    """Definition of a single tool parameter."""

    name: str
    # "str", "int", "timestamp" (int | ISO 8601 str), "bool", "list[str]", "list", "dict",
    # "str|list[str]" (one name or a list of names)
    param_type: str
    description: str
    required: bool = False
    default: Any = None
    # JSON Schema of the value, when the contract knows more than the type
    # (api/schema_constraints.py); None keeps what the type generates.
    schema: dict[str, Any] | None = field(default=None, compare=False)
    # The name Zabbix has for this parameter, where the tool's own name
    # differs (proxygroup_get "proxygroupids" is proxygroup.get
    # "proxy_groupids"). The value is sent under this name.
    # "filter.<property>" sends it as that key of the method's "filter"
    # (action.get has no "eventsource" parameter, the property is filterable).
    api_name: str | None = None

    @property
    def sent_as(self) -> str:
        """The key this parameter travels under in the API call."""
        return self.api_name or self.name


@dataclass(frozen=True)
class MethodDef:
    """Definition of a Zabbix API method mapped to an MCP tool."""

    api_method: str       # e.g. "host.get"
    tool_name: str        # e.g. "host_get"
    description: str      # Rich description for LLM consumption
    read_only: bool       # If True, allowed on read-only servers
    params: list[ParamDef] = field(default_factory=list)
    array_param: str | None = None  # Param to extract as plain list for array-based API methods
    compact_fields: tuple[str, ...] | None = None  # Key fields for compact output mode
