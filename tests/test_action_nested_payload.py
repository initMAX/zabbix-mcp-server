#!/usr/bin/env python3

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

"""Nested operation IDs returned by action.get must not reach action writes."""

import asyncio
import copy
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer

from zabbix_mcp.api.action_payload import strip_for_write
from zabbix_mcp.config import AppConfig, ServerConfig
from zabbix_mcp.server import _register_tools


def _read_operation() -> dict:
    return {
        "operationid": "42", "actionid": "3", "operationtype": "1", "evaltype": "1",
        "opconditions": [
            {"opconditionid": "71", "operationid": "42", "conditiontype": "14", "operator": "0", "value": "0"},
            {"opconditionid": "72", "operationid": "42", "conditiontype": 14, "operator": 0, "value": "1"},
        ],
        "opcommand": {"scriptid": "7"},
        "opcommand_hst": [{"opcommand_hstid": "81", "hostid": 0},
                          {"opcommand_hstid": "82", "hostid": "10101"}],
        "opcommand_grp": [{"opcommand_grpid": "91", "groupid": "20"},
                          {"opcommand_grpid": "92", "groupid": "30"}],
    }


def _write_operation() -> dict:
    return {
        "operationtype": "1", "evaltype": "1",
        "opconditions": [{"conditiontype": "14", "operator": "0", "value": "0"},
                         {"conditiontype": 14, "operator": 0, "value": "1"}],
        "opcommand": {"scriptid": "7"},
        "opcommand_hst": [{"hostid": 0}, {"hostid": "10101"}],
        "opcommand_grp": [{"groupid": "20"}, {"groupid": "30"}],
    }


def test_nested_read_only_ids_are_removed_in_place() -> None:
    operation = _read_operation()
    conditions = operation["opconditions"]
    hosts = operation["opcommand_hst"]
    groups = operation["opcommand_grp"]
    payload = {"eventsource": 0, "operations": [operation]}

    assert strip_for_write(payload) is payload

    assert payload == {"eventsource": 0, "operations": [_write_operation()]}
    assert payload["operations"][0] is operation
    assert operation["opconditions"] is conditions
    assert operation["opcommand_hst"] is hosts
    assert operation["opcommand_grp"] is groups
    cleaned = copy.deepcopy(payload)
    assert strip_for_write(payload) == cleaned


def test_nested_id_removal_is_scoped_to_exact_keys() -> None:
    payload = {"operations": [{
        "opconditions": [{"opconditionid": "71", "operationid": "42", "caller_field": "keep"}],
        "opcommand_hst": [{"opcommand_hstid": "81", "future_id": "keep", "hostid": "0"}],
        "opcommand_grp": [{"opcommand_grpid": "91", "caller_field": "keep", "groupid": "20"}],
    }]}

    assert strip_for_write(payload) == {"operations": [{
        "opconditions": [{"caller_field": "keep"}],
        "opcommand_hst": [{"future_id": "keep", "hostid": "0"}],
        "opcommand_grp": [{"caller_field": "keep", "groupid": "20"}],
    }]}


@pytest.mark.parametrize("source", [0, "0", "1", "2", "3", "4", None])
@pytest.mark.parametrize("group", ["operations", "recovery_operations", "update_operations"])
def test_nested_ids_follow_existing_source_and_operation_group_rules(source: Any, group: str) -> None:
    payload = {group: [_read_operation()]}
    expected = _write_operation()
    if group != "operations" or source not in (0, "0", None):
        expected.pop("evaltype")
        expected.pop("opconditions")
    if group == "recovery_operations" and source in ("1", "2"):
        assert strip_for_write(payload, eventsource=source) == {}
    elif group == "update_operations" and source in ("1", "2", "3"):
        assert strip_for_write(payload, eventsource=source) == {}
    else:
        assert strip_for_write(payload, eventsource=source) == {group: [expected]}


def test_explicit_empty_operation_and_nested_arrays_stay() -> None:
    payload = {
        "eventsource": "0", "operations": [
            {"operationtype": "1", "opconditions": [], "opcommand_hst": [], "opcommand_grp": []}],
        "recovery_operations": [], "update_operations": [],
    }
    expected = copy.deepcopy(payload)

    assert strip_for_write(payload) == expected


@pytest.mark.parametrize("field", ["opconditions", "opcommand_hst", "opcommand_grp"])
@pytest.mark.parametrize("value", [None, "not a list", 1, {"operationid": "keep"}])
def test_non_list_nested_values_keep_existing_tolerance(field: str, value: Any) -> None:
    payload = {"eventsource": "0", "operations": [{field: copy.deepcopy(value)}]}
    expected = copy.deepcopy(payload)

    assert strip_for_write(payload) == expected


def test_non_dict_nested_members_are_untouched() -> None:
    payload = {"eventsource": "0", "operations": [None, "not an operation", {
        "opconditions": [None, 0, [], {"opconditionid": "71", "operationid": "42", "value": "0"}],
        "opcommand_hst": [None, "host", [], {"opcommand_hstid": "81", "hostid": "0"}],
        "opcommand_grp": [None, 0, [], {"opcommand_grpid": "91", "groupid": "20"}],
    }]}

    assert strip_for_write(payload) == {"eventsource": "0", "operations": [None, "not an operation", {
        "opconditions": [None, 0, [], {"value": "0"}],
        "opcommand_hst": [None, "host", [], {"hostid": "0"}],
        "opcommand_grp": [None, 0, [], {"groupid": "20"}],
    }]}


class _ActionManager:
    """Capture the real registered handlers' outbound calls without a client."""

    server_names = ["t"]
    default_server = "t"

    def __init__(self, *, lookup_fails: bool = False) -> None:
        self.config = AppConfig(server=ServerConfig(timezone="UTC"))
        self.lookup_fails = lookup_fails
        self.sent: list[tuple[str, Any]] = []
        self.write_checks: list[str] = []

    def resolve_server(self, server: str) -> str:
        assert server == "t"
        return server

    def check_write(self, server: str) -> None:
        self.write_checks.append(server)

    def get_version(self, server: str) -> str:
        assert server == "t"
        return "7.4.14"

    def call(self, server: str, method: str, params: Any) -> Any:
        assert server == "t"
        self.sent.append((method, copy.deepcopy(params)))
        if method == "action.get":
            if self.lookup_fails:
                raise RuntimeError("eventsource lookup unavailable")
            return [{"eventsource": "0"}]
        assert method in ("action.create", "action.update")
        return {"actionids": ["3"]}


@pytest.mark.parametrize("tool,source", [
    ("action_create", "TRIGGER"), ("action_update", "0"), ("action_update", None),
])
def test_registered_action_tools_send_clean_payload_with_fixture_isolation(tool: str, source: Any) -> None:
    manager = _ActionManager()
    mcp = MCPServer(name="nested-action-test")
    _register_tools(mcp, manager, tools_filter=["action"])
    payload = {"name": "nested operation", "operations": [_read_operation()],
               "recovery_operations": [_read_operation()], "update_operations": [_read_operation()]}
    secondary = _write_operation()
    del secondary["evaltype"], secondary["opconditions"]
    expected = {"name": "nested operation", "operations": [_write_operation()],
                "recovery_operations": [copy.deepcopy(secondary)], "update_operations": [secondary]}
    if tool == "action_update":
        payload["actionid"] = "3"
        expected["actionid"] = "3"
    if source is not None:
        payload["eventsource"] = source
        expected["eventsource"] = 0 if source == "TRIGGER" else source
    snapshot = copy.deepcopy(payload)

    # The sanitizer is in-place; isolate the read fixture before dispatch.
    asyncio.run(mcp.call_tool(tool, {"params": copy.deepcopy(payload)}))

    lookup = [("action.get", {"output": ["eventsource"], "actionids": ["3"]})] if source is None else []
    assert manager.sent == lookup + [(tool.replace("_", "."), expected)]
    assert manager.write_checks == ["t"]
    assert payload == snapshot


def test_failed_source_lookup_still_strips_nested_read_only_ids() -> None:
    manager = _ActionManager(lookup_fails=True)
    mcp = MCPServer(name="nested-action-lookup-test")
    _register_tools(mcp, manager, tools_filter=["action"])
    payload = {"actionid": "3", "operations": [_read_operation()]}
    snapshot = copy.deepcopy(payload)

    # The sanitizer is in-place; isolate the read fixture before dispatch.
    asyncio.run(mcp.call_tool("action_update", {"params": copy.deepcopy(payload)}))

    assert manager.sent == [
        ("action.get", {"output": ["eventsource"], "actionids": ["3"]}),
        ("action.update", {"actionid": "3", "operations": [_write_operation()]}),
    ]
    assert manager.write_checks == ["t"]
    assert payload == snapshot
