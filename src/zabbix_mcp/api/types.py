"""Declarative types for the Zabbix API method registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ParamDef:
    """Definition of a single tool parameter."""

    name: str
    param_type: str  # "str", "int", "bool", "list[str]", "dict"
    description: str
    required: bool = False
    default: Any = None


@dataclass(frozen=True)
class MethodDef:
    """Definition of a Zabbix API method mapped to an MCP tool."""

    api_method: str       # e.g. "host.get"
    tool_name: str        # e.g. "host_get"
    description: str      # Rich description for LLM consumption
    read_only: bool       # If True, allowed on read-only servers
    params: list[ParamDef] = field(default_factory=list)
