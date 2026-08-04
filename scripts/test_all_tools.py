#!/usr/bin/env python3
"""End-to-end smoke test of every registered MCP tool.

Drives the local MCP server over its real HTTP transport using the
official ``mcp`` Python SDK, calls every tool listed by ``tools/list``,
and produces a markdown report of who passed / failed / skipped.

Read-only tools (``*_get``, ``*_export``, ``health_check``, ...) get
minimal valid arguments derived from sample IDs probed up front
(``host_get`` -> hostid, ``hostgroup_get`` -> groupid, ...).

Write tools (``*_create`` / ``*_update`` / ``*_delete`` / ``*_massadd``
etc.) get a per-category CRUD lifecycle: create a throwaway entity
with a timestamp-suffixed name, exercise update / massupdate, then
delete. Failures inside a lifecycle do not block the rest of the
suite - we just record the error and move on.

Usage::

    .venv/bin/python scripts/test_all_tools.py \\
        --url http://127.0.0.1:18081/mcp \\
        --token "$BEARER" \\
        --server "Wiki-topics" \\
        --report tools_test_report.md
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

VERBOSE = False


@dataclass
class ToolResult:
    name: str
    status: str  # "ok" | "error" | "skip"
    detail: str = ""
    elapsed_ms: int = 0


@dataclass
class Suite:
    server: str
    sample_ids: dict[str, Any] = field(default_factory=dict)
    created_ids: dict[str, str] = field(default_factory=dict)
    results: list[ToolResult] = field(default_factory=list)
    suffix: str = ""

    def record(self, name: str, status: str, detail: str = "", elapsed_ms: int = 0) -> None:
        self.results.append(ToolResult(name, status, detail, elapsed_ms))
        marker = {"ok": "\033[32m✓\033[0m", "error": "\033[31m✗\033[0m", "skip": "\033[33m-\033[0m"}.get(status, "?")
        if VERBOSE or status == "error":
            print(f"  {marker} {name:55s} {detail[:80] if status == 'error' else ''}")
        else:
            print(f"  {marker} {name}")


async def call_tool(s: ClientSession, name: str, args: dict, suite: Suite) -> tuple[bool, str]:
    """Invoke *name* with *args* and return (ok, detail).

    Adapts the per-tool dict from ``build_args`` to the actual tool schema:
    ``*_create`` and ``*_update`` only accept a single ``params`` dict; ``*_delete``
    only accepts a single ``ids`` list. ``build_args`` keeps the human-friendly
    flat shape so the lookup table stays readable; the wrapping happens here.
    """
    if name.endswith("_create") and "params" not in args:
        args = {"params": args}
    elif name.endswith("_update") and "params" not in args:
        args = {"params": args}
    elif name.endswith("_delete") and "ids" not in args:
        # All *_delete tools take a single ``ids`` list. build_args returns
        # an entity-specific dict (``{"hostids": [...]}``); flatten the
        # values into the generic ``ids`` field.
        merged: list[str] = []
        for v in args.values():
            if isinstance(v, list):
                merged.extend(str(x) for x in v)
            elif v is not None:
                merged.append(str(v))
        args = {"ids": merged}
    args = {**args, "server": suite.server}
    t0 = time.time()
    try:
        result = await asyncio.wait_for(s.call_tool(name, args), timeout=20)
    except asyncio.TimeoutError:
        suite.record(name, "error", "timeout 20s", int((time.time() - t0) * 1000))
        return False, "timeout"
    elapsed = int((time.time() - t0) * 1000)
    if result.is_error:
        text = result.content[0].text if result.content else ""
        suite.record(name, "error", text[:160], elapsed)
        return False, text
    text = result.content[0].text if result.content else ""
    suite.record(name, "ok", "", elapsed)
    return True, text


def parse_payload(text: str) -> Any:
    """Parse the JSON body, tolerating the security disclaimer preamble."""
    if text.startswith("[System:"):
        text = text.split("\n", 1)[1] if "\n" in text else text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


async def discover_sample_ids(s: ClientSession, suite: Suite) -> None:
    """Run *_get(limit=1) on the staple entity types so we have IDs for
    write-side tests."""
    print("\n=== Phase 1: discover sample IDs ===")
    # tuple = (tool, output_field_name_from_zabbix, semantic_key_in_sample_ids)
    # The semantic key is what `build_args` looks up; the output_field_name
    # is whatever Zabbix's API uses (e.g. templategroup.get returns its id
    # as ``groupid``, but we file it under ``templategroupid`` so it does
    # not collide with hostgroup.get).
    discovery = [
        ("host_get", "hostid", "hostid"),
        ("hostgroup_get", "groupid", "groupid"),
        ("template_get", "templateid", "templateid"),
        ("templategroup_get", "groupid", "templategroupid"),
        ("item_get", "itemid", "itemid"),
        ("trigger_get", "triggerid", "triggerid"),
        ("hostinterface_get", "interfaceid", "interfaceid"),
        ("graph_get", "graphid", "graphid"),
        ("user_get", "userid", "userid"),
        ("usergroup_get", "usrgrpid", "usrgrpid"),
        ("role_get", "roleid", "roleid"),
        ("action_get", "actionid", "actionid"),
        ("mediatype_get", "mediatypeid", "mediatypeid"),
        ("script_get", "scriptid", "scriptid"),
        ("maintenance_get", "maintenanceid", "maintenanceid"),
        ("proxy_get", "proxyid", "proxyid"),
        ("valuemap_get", "valuemapid", "valuemapid"),
        ("dashboard_get", "dashboardid", "dashboardid"),
        ("regexp_get", "regexpid", "regexpid"),
        ("iconmap_get", "iconmapid", "iconmapid"),
        ("image_get", "imageid", "imageid"),
        ("drule_get", "druleid", "druleid"),
        ("httptest_get", "httptestid", "httptestid"),
    ]
    for tool, zbx_field, semantic_key in discovery:
        ok, payload = await call_tool(s, tool, {"output": zbx_field, "limit": 1}, suite)
        if not ok:
            continue
        data = parse_payload(payload)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            suite.sample_ids[semantic_key] = data[0].get(zbx_field)

    # Recent event / problem may need a time window
    ok, payload = await call_tool(s, "problem_get", {"recent": True, "limit": 1}, suite)
    if ok:
        data = parse_payload(payload)
        if isinstance(data, list) and data:
            suite.sample_ids["eventid"] = data[0].get("eventid")

    # task.create "check now" (type 6) needs an item whose host has a
    # real, registered agent. Pick a Zabbix-agent (type 0 = passive) or
    # active-agent (type 7) item from a monitored host that already has
    # successful collection (lastclock > 0) - the safest "this works"
    # signal we have without booting an actual agent process.
    ok, payload = await call_tool(s, "item_get", {
        "filter": {"type": [0, 7], "status": 0, "state": 0},
        "monitored": True,
        "output": "extend",
        "limit": 5,
    }, suite)
    if ok:
        data = parse_payload(payload)
        if isinstance(data, list):
            for it in data:
                if int(it.get("lastclock") or 0) > 0:
                    suite.sample_ids["agent_itemid"] = it.get("itemid")
                    break
    print(f"  collected: {sorted(suite.sample_ids.keys())}")


class _Skip:
    """Sentinel returned by build_args to signal skip with a human-readable reason."""
    __slots__ = ("reason",)
    def __init__(self, reason: str) -> None:
        self.reason = reason


def _SKIP(reason: str) -> _Skip:
    return _Skip(reason)


def build_args(tool_name: str, suite: Suite):
    """Construct minimal valid arguments for *tool_name*.

    Returns one of:
    - ``dict``: arguments to pass to call_tool
    - ``_Skip(reason)``: skip with a documented reason
    - ``None``: skip with generic "no minimal args" reason
    """
    s = suite.sample_ids
    suf = suite.suffix
    cid = suite.created_ids
    n = tool_name

    # ===== Reads =====
    # Pre-correlated view tools (host_status_get, hostgroup_overview_get,
    # infrastructure_summary_get, item_history_summary_get, problem_active_get)
    # do NOT accept the generic limit/output kwargs - their schema is
    # purpose-built. Match them first, fall through to per-tool handlers
    # below (must come before the catch-all _get branch).
    _CUSTOM_GETS = {
        "host_status_get", "hostgroup_overview_get", "infrastructure_summary_get",
        "item_history_summary_get", "problem_active_get",
        "graph_render", "anomaly_detect", "capacity_forecast", "item_threshold_search",
    }
    if n.endswith("_get") and n not in _CUSTOM_GETS:
        # Default: small limit, common output filter to keep responses tiny.
        # ``output`` must be a string ("extend" or comma-separated field list)
        # per the MCPServer schema; passing a list trips Pydantic validation.
        return {"limit": 2, "output": "extend"} if n != "configuration_get" else {}

    if n == "apiinfo_version":
        return {}
    # NOTE: user_checkauthentication / user_logout handled in the
    # later session-only block, with explicit _SKIP reasons.

    # ===== Health, simple read-only extensions =====
    if n == "health_check":
        return {}
    if n == "configuration_export":
        # configuration.export takes a single ``params`` dict per the
        # tool schema; the entity-specific fields go inside that.
        if "templateid" in s:
            return {"params": {"format": "yaml", "options": {"templates": [s["templateid"]]}}}
        return None
    if n == "configuration_import":
        # Round-trip: configuration.export the smoke template into YAML,
        # then import the exact same payload back. ``createMissing=False``
        # keeps it as a no-op merge - nothing on Wiki-topics actually
        # changes, but the wrapper + the import path are exercised.
        if not cid.get("template_export"):
            return _SKIP("configuration_import needs configuration_export to have run first")
        return {"params": {
            "format": "yaml",
            "rules": {
                "templates": {"createMissing": False, "updateExisting": True},
                "host_groups": {"createMissing": False, "updateExisting": False},
                "template_groups": {"createMissing": False, "updateExisting": False},
            },
            "source": cid["template_export"],
        }}
    if n == "configuration_importcompare":
        # Diffs the same exported payload against the live config.
        # No-op compare; should report zero changes.
        if not cid.get("template_export"):
            return _SKIP("configuration_importcompare needs configuration_export to have run first")
        return {"params": {
            "format": "yaml",
            "rules": {
                "templates": {"createMissing": False, "updateExisting": True},
            },
            "source": cid["template_export"],
        }}
    if n == "graph_render":
        return {"graphid": s.get("graphid"), "period": "1h", "width": 200, "height": 100} if s.get("graphid") else None
    if n == "anomaly_detect":
        # The smoke host has no trend data (no agent), so use the
        # production "Zabbix servers" host group (id 4) which has real
        # CPU monitoring on the actual Wiki-topics Zabbix server.
        return {
            "item_key": "system.cpu.util",
            "hostgroupid": "4",  # Zabbix servers
            "period": "7d",
        }
    if n == "capacity_forecast":
        # Same reason as anomaly_detect: smoke item has no history.
        # Forecast on the Wiki-topics Zabbix server itself (host 10084),
        # which has real CPU history.
        return {
            "hostid": "10084",  # Zabbix server (built-in)
            "item_key": "system.cpu.util",
            "threshold": 90,
        }
    if n == "item_threshold_search":
        return {"search": {"key_": "system.cpu"}, "lastvalue_ge": 0, "result_limit": 2}
    if n == "host_status_get":
        return {"host_id": s.get("hostid")} if s.get("hostid") else _SKIP("no smoke hostid available")
    if n == "hostgroup_overview_get":
        return {"groupid": s.get("groupid"), "top_n": 3} if s.get("groupid") else _SKIP("no smoke groupid available")
    if n == "infrastructure_summary_get":
        return {"top_n": 3}
    if n == "item_history_summary_get":
        return {"itemid": s.get("itemid"), "period": "1h", "limit": 50} if s.get("itemid") else _SKIP("no smoke itemid available")
    if n == "report_generate":
        return {"report_type": "availability", "hostgroupid": s.get("groupid"), "period": "7d"} if s.get("groupid") else None
    if n == "action_prepare":
        return {"action": "host.update", "params": {"hostid": s.get("hostid"), "description": "smoke-test"}} if s.get("hostid") else None
    if n == "action_confirm":
        # Use the confirmation token captured from action_prepare.
        if not cid.get("action_token"):
            return _SKIP("action_prepare did not return a confirmation token")
        return {"confirmation_token": cid["action_token"]}
    if n == "zabbix_raw_api_call":
        return {"method": "apiinfo.version"}
    if n == "history_push":
        # Tool's typed signature has ``items`` as the top-level array
        # (MCPServer-injected wrap turns the call into the right Zabbix
        # API shape underneath). One float value on our smoke item.
        if not cid.get("item"):
            return _SKIP("history_push needs the item fixture")
        return {"items": [{"itemid": cid["item"], "value": 1.0}]}
    if n == "history_clear":
        # Zabbix rejects history.clear when compression is on at the
        # server level (config.toml on the Zabbix box, not in our MCP
        # config). Wiki-topics has compression enabled, so skip.
        return _SKIP("'History cleanup is not supported if compression is enabled' on Wiki-topics; needs admin to disable compression server-side")
    if n == "task_create":
        # task.create type 6 = "Check now" only works on items whose
        # host has a real registered agent. Our synthetic fixture has
        # no agent process to receive the request, so target a real
        # monitored item discovered from the live Zabbix server itself
        # (sample_ids["agent_itemid"]: a passive/active-agent item
        # with lastclock > 0).
        if not s.get("agent_itemid"):
            return _SKIP("no real monitored agent item discovered on this Zabbix server (item.get(monitored=True, type=[0,7], lastclock>0) returned empty)")
        return {"params": {
            "type": 6,
            "request": {"itemid": s["agent_itemid"]},
        }}
    if n == "user_login":
        # Acquire a session id for the smoke test user we just created.
        # The session id is captured below and used by user_logout /
        # user_checkauthentication. user.login does not need an
        # existing session - it CREATES one - so this is the entry
        # point for the session-cookie tier.
        return {"username": f"smoketest-user-{suf}", "password": "Tr@ilbl4z3r-Quark-2026"}
    if n == "user_logout":
        # Use the session id captured from user.login; the MCP wrapper
        # passes ``auth_sessionid`` through to the JSON-RPC auth field
        # so this logs out THAT session and leaves the configured
        # server-level api_token untouched.
        if not cid.get("user_session"):
            return _SKIP("user_login did not establish a session")
        return {"auth_sessionid": cid["user_session"]}
    if n == "user_checkauthentication":
        if not cid.get("user_session"):
            return _SKIP("user_login did not establish a session")
        return {
            "auth_sessionid": cid["user_session"],
            "sessionid": cid["user_session"],
        }
    if n == "user_provision":
        # Provision a user from the userdirectory fixture. The wrapper
        # tool takes a single ``params`` dict; the API will reject the
        # call at the LDAP connectivity layer (example.com does not
        # run LDAP), but that exercises the wrapper end-to-end.
        if not cid.get("userdirectory"):
            return _SKIP("user_provision needs the userdirectory fixture")
        return {"params": {"userid": cid.get("user", "1")}}
    if n == "user_resettotp":
        # Reset TOTP for the smoke user we created. Returns OK even
        # when the user has no TOTP enrolled - it is a no-op clear.
        if not cid.get("user"):
            return _SKIP("user_resettotp needs a user fixture")
        return {"userids": [cid["user"]]}
    if n == "user_unblock":
        # Unblock the smoke user. No-op if the user is not currently
        # blocked, which is fine - the API still returns OK.
        if not cid.get("user"):
            return _SKIP("user_unblock needs a user fixture")
        return {"userids": [cid["user"]]}
    # Mass operations - all take ``params`` wrap (see CREATE_PARAMS shape).
    # We exercise them against the ad-hoc ``host`` / ``hostgroup`` /
    # ``template`` we built earlier in the run, so the dependency on a
    # write-side fixture is honoured by ordering.
    if n == "host_massadd":
        if not (cid.get("host") and (cid.get("hostgroup") or s.get("groupid"))):
            return None
        gid = cid.get("hostgroup") or s.get("groupid")
        return {"params": {"hosts": [{"hostid": cid["host"]}], "groups": [{"groupid": gid}]}}
    if n == "host_massupdate":
        if not cid.get("host"):
            return None
        return {"params": {"hosts": [{"hostid": cid["host"]}], "description": "smoke-mass"}}
    # NOTE: host_massremove handled in the dedicated mass-remove block
    # later, where it is paired with the matching hostids+groupids shape.
    if n == "hostgroup_massadd":
        if not (cid.get("hostgroup") and cid.get("host")):
            return None
        return {"params": {"groups": [{"groupid": cid["hostgroup"]}], "hosts": [{"hostid": cid["host"]}]}}
    if n == "hostgroup_massupdate":
        # hostgroup.massupdate replaces the hosts/templates assigned to
        # the given groups - it does NOT take field-level updates like
        # description (that is only on hostgroup.update). Send our host
        # as the replacement set so the call is meaningful.
        if not (cid.get("hostgroup") and cid.get("host")):
            return None
        return {"params": {"groups": [{"groupid": cid["hostgroup"]}], "hosts": [{"hostid": cid["host"]}]}}
    # NOTE: hostgroup_massremove handled in the dedicated mass-remove block.
    if n == "hostgroup_propagate":
        if not cid.get("hostgroup"):
            return None
        return {"params": {"groups": [{"groupid": cid["hostgroup"]}], "permissions": True}}
    if n == "templategroup_massadd":
        if not (cid.get("templategroup") and cid.get("template")):
            return None
        return {"params": {"groups": [{"groupid": cid["templategroup"]}], "templates": [{"templateid": cid["template"]}]}}
    if n == "templategroup_massupdate":
        # Same shape as hostgroup.massupdate: it replaces the assigned
        # templates of the given groups. Need both the group AND a
        # template fixture for the call to be valid.
        if not (cid.get("templategroup") and cid.get("template")):
            return None
        return {"params": {"groups": [{"groupid": cid["templategroup"]}], "templates": [{"templateid": cid["template"]}]}}
    # NOTE: templategroup_massremove handled later.
    if n == "templategroup_propagate":
        if not cid.get("templategroup"):
            return None
        # ``permissions=true`` propagates the parent group's permissions
        # down to descendant groups; safe no-op if there are none.
        return {"params": {"groups": [{"groupid": cid["templategroup"]}], "permissions": True}}
    if n == "template_massadd":
        if not (cid.get("template") and (cid.get("templategroup") or s.get("templategroupid"))):
            return None
        gid = cid.get("templategroup") or s.get("templategroupid")
        return {"params": {"templates": [{"templateid": cid["template"]}], "groups": [{"groupid": gid}]}}
    if n == "template_massupdate":
        # template.massupdate replaces template_group / templates_link /
        # macros assignments on multiple templates - it does NOT take
        # field-level updates like description (those live on
        # template.update). Send the existing template + its existing
        # group as a no-op-ish replacement.
        if not cid.get("template"):
            return None
        gid = cid.get("templategroup") or s.get("templategroupid")
        if not gid:
            return None
        return {"params": {
            "templates": [{"templateid": cid["template"]}],
            "groups": [{"groupid": gid}],
        }}
    # NOTE: template_massremove handled later.
    if n == "hostinterface_massadd":
        if not cid.get("host"):
            return None
        return {"params": {
            "hosts": [{"hostid": cid["host"]}],
            "interfaces": [{"type": 1, "main": 0, "useip": 1, "ip": "127.0.0.3", "dns": "", "port": "10052"}],
        }}
    # NOTE: hostinterface_massremove handled later.
    if n == "hostinterface_replacehostinterfaces":
        # Replace the primary agent interface that host_create made
        # with an equivalent one. Runs BEFORE hostinterface_create
        # via tool_priority below, so the secondary fixture
        # (cid["hostinterface"]) is still produced unaffected.
        if not cid.get("host"):
            return None
        return {"params": {
            "hostid": cid["host"],
            "interfaces": [{
                "type": 1, "main": 1, "useip": 1,
                "ip": "127.0.0.1", "dns": "", "port": "10050",
            }],
        }}
    # NOTE: usermacro_*global handled later, paired with the createglobal fixture.

    if n == "settings_update":
        # No-op style update: re-set ``default_theme`` to its current
        # value via the same API. Wiki-topics is a test instance, but
        # we still avoid actually changing operator-visible settings.
        return {"params": {"default_theme": "blue-theme"}}
    if n == "housekeeping_update":
        # Read-modify-write: keep the current history retention.
        return {"params": {"hk_history_global": "1", "hk_history": "31d"}}
    if n == "authentication_update":
        # No-op: keep internal auth as the default.
        return {"params": {"authentication_type": "0"}}
    if n == "autoregistration_update":
        # No-op: clear-text autoregistration.
        return {"params": {"tls_accept": "1"}}

    if n == "userdirectory_test":
        # Test the public Forumsys LDAP fixture used in userdirectory_create.
        # ``test_username`` / ``test_password`` are sample credentials
        # documented at forumsys.com (read-only-admin). No real
        # connectivity from Wiki-topics - the test traffic actually
        # leaves the Zabbix server.
        if not cid.get("userdirectory"):
            return _SKIP("userdirectory_test needs the userdirectory fixture")
        return {"params": {
            "userdirectoryid": cid["userdirectory"],
            "test_username": "tesla", "test_password": "password",
        }}
    if n == "report_generate" or n == "task_get":
        return None

    # ===== CREATE =====
    if n == "hostgroup_create":
        return {"name": f"smoketest-hg-{suf}"}
    if n == "templategroup_create":
        return {"name": f"smoketest-tg-{suf}"}
    if n == "host_create":
        # Need a groupid + a host name. Use sample group if present.
        gid = cid.get("hostgroup") or s.get("groupid")
        if not gid:
            return None
        return {
            "host": f"smoketest-host-{suf}",
            "groups": [{"groupid": gid}],
            "interfaces": [{
                "type": 1, "main": 1, "useip": 1, "ip": "127.0.0.1",
                "dns": "", "port": "10050",
            }],
        }
    if n == "template_create":
        gid = cid.get("templategroup") or s.get("templategroupid")
        if not gid:
            return None
        return {"host": f"smoketest-tpl-{suf}", "groups": [{"groupid": gid}]}
    if n == "valuemap_create":
        hid = cid.get("template") or s.get("templateid")
        if not hid:
            return None
        return {
            "name": f"smoketest-vm-{suf}", "hostid": hid,
            "mappings": [{"value": "1", "newvalue": "Up"}],
        }
    if n == "item_create":
        hid = cid.get("host") or s.get("hostid")
        if not hid:
            return None
        # type 7 = Zabbix agent (active). Avoids the "interfaceid is
        # missing" rejection that passive-agent (type 0) gets without
        # an explicit interface fixture, AND avoids the "trapper"
        # restriction that prevents task_create from working.
        # value_type 0 = numeric float so graph.create can later
        # attach this item. delay 30s.
        return {
            "name": f"smoketest-item-{suf}", "key_": f"smoketest.item.{suf}",
            "hostid": hid, "type": 7, "value_type": 0, "delay": "30s",
        }
    if n == "trigger_create":
        # Need an item key; use the created item if any
        if not cid.get("host"):
            return None
        return {
            "description": f"smoketest-trig-{suf}",
            "expression": f"last(/smoketest-host-{suf}/smoketest.item.{suf})>0",
        }
    if n == "maintenance_create":
        gid = cid.get("hostgroup") or s.get("groupid")
        if not gid:
            return None
        now = int(time.time())
        # Zabbix 6.0+ requires the object-list form ({groups: [{groupid: X}]});
        # the legacy ``groupids: [X]`` flat array is rejected with
        # ``unexpected parameter "groupids"``.
        return {
            "name": f"smoketest-mnt-{suf}",
            "active_since": now, "active_till": now + 3600,
            "groups": [{"groupid": gid}],
            "timeperiods": [{"timeperiod_type": 0, "period": 3600, "start_date": now}],
        }
    if n == "usergroup_create":
        return {"name": f"smoketest-ug-{suf}"}
    if n == "user_create":
        ugid = cid.get("usergroup") or s.get("usrgrpid")
        if not ugid:
            return None
        # Password must not contain the username / name / surname (any
        # case-insensitive substring match), and Zabbix 7.x enforces a
        # complexity rule (mixed case + digit + symbol) by default.
        return {
            "username": f"smoketest-user-{suf}",
            "passwd": "Tr@ilbl4z3r-Quark-2026",
            "usrgrps": [{"usrgrpid": ugid}],
            "roleid": s.get("roleid", "1"),
        }
    if n == "mediatype_create":
        # Zabbix 7.0+ replaced ``content_type`` (int) with ``message_format``
        # (which now lives on the per-message template). Bare ``content_type``
        # on the create payload is rejected as ``unexpected parameter``.
        return {"name": f"smoketest-mt-{suf}", "type": "0", "smtp_server": "smtp.example.com",
                "smtp_helo": "example.com", "smtp_email": "noreply@example.com"}
    if n == "script_create":
        # type 5 = Webhook (JavaScript); ``command`` must compile as
        # JS. ``echo ok`` is shell, not JS, and trips ``cannot compile
        # script: SyntaxError`` at execute time. Use a single-line
        # ``return`` statement instead so script_execute can run it.
        return {"name": f"smoketest-sc-{suf}", "type": "5",
                "command": "return JSON.stringify({status: 'ok'});",
                "scope": "2"}
    if n == "regexp_create":
        # ``exp_delimiter`` must be empty for expression types other than
        # ``Result is FALSE`` (3) / ``Result is TRUE`` (4); type 0 (Character
        # string included) is the most common and rejects a non-empty
        # delimiter with ``value must be empty``.
        return {"name": f"smoketest-re-{suf}",
                "expressions": [{"expression": "smoketest", "expression_type": "0",
                                 "exp_delimiter": "", "case_sensitive": "0"}]}
    # NOTE: iconmap_create handled later, paired with the image fixture.
    if n == "drule_create":
        return {"name": f"smoketest-drule-{suf}", "iprange": "127.0.0.1",
                "dchecks": [{"type": "9", "ports": "10050", "uniq": "0",
                             "host_source": "1", "name_source": "0", "key_": "system.uname"}]}
    if n == "httptest_create":
        hid = cid.get("host") or s.get("hostid")
        if not hid:
            return None
        return {
            "name": f"smoketest-http-{suf}", "hostid": hid,
            "steps": [{"name": "homepage", "url": "http://example.com", "no": "1",
                       "status_codes": "200"}],
        }
    if n == "proxy_create":
        return {"name": f"smoketest-proxy-{suf}", "operating_mode": "0"}
    if n == "proxygroup_create":
        return {"name": f"smoketest-proxygrp-{suf}", "failover_delay": "10s",
                "min_online": "1"}
    if n == "dashboard_create":
        if not s.get("userid"):
            return _SKIP("needs a userid fixture (none discovered)")
        return {"name": f"smoketest-dash-{suf}", "userid": s.get("userid"),
                "private": "1", "pages": [{"widgets": []}]}
    # NOTE: graphprototype_create + hostmacro_* + discoveryrule_create
    # / *_prototype_create handled in the later "Prototype tools" block.
    if n == "hostinterface_create":
        hid = cid.get("host")
        if not hid:
            return None
        # Use Zabbix agent (type 1) - SNMP (type 2) requires a `details` block
        # with version/community/securityname etc. that our generic test
        # cannot fabricate generically. main must be 0 because the host is
        # created with a primary agent interface already.
        return {"hostid": hid, "type": 1, "main": 0, "useip": 1, "ip": "127.0.0.2",
                "dns": "", "port": "10051"}
    # ---- Map / network map ----
    if n == "map_create":
        return {"params": {
            "name": f"smoketest-map-{suf}", "width": 800, "height": 600,
        }}
    if n == "map_update":
        return {"sysmapid": cid.get("map"), "name": f"smoketest-map-{suf}-renamed"} if cid.get("map") else None
    if n == "map_delete":
        return {"ids": [cid.get("map")]} if cid.get("map") else None

    # ---- Proxy group update / delete (cascade after proxygroup_create) ----
    if n == "proxygroup_update":
        return {"proxy_groupid": cid.get("proxygroup"), "description": "smoke"} if cid.get("proxygroup") else None
    if n == "proxygroup_delete":
        return {"ids": [cid.get("proxygroup")]} if cid.get("proxygroup") else None

    # ---- SLI report on the SLA we created ----
    if n == "sla_getsli":
        if not cid.get("sla"):
            return None
        # Period type 0 = daily, must include period_from/to as epoch
        # seconds. Use a fixed past day to keep the test deterministic.
        return {"slaid": cid["sla"], "period_from": "1735689600", "period_to": "1735776000"}

    # ---- Task create - send a "diagnostic info" task to the server ----
    if n == "task_create":
        # Type 1 = check now (works on any item id we already have).
        if not cid.get("item"):
            return _SKIP("task.create needs an item id (item_create skipped)")
        return {"params": {
            "type": "6",  # check_now
            "request": {"itemids": [cid["item"]]},
        }}

    # ----- Lone creates (no fixture parents needed beyond what's discovered) -----
    if n == "role_create":
        # Minimal role definition - just a name and a base type. Type
        # 1 = User, 2 = Admin, 3 = Super-admin.
        return {"params": {"name": f"smoketest-role-{suf}", "type": 1}}
    if n == "service_create":
        # IT service tree node. Algorithm 1 = problem if at least one
        # child has problem; sortorder is required.
        return {"params": {
            "name": f"smoketest-svc-{suf}", "algorithm": "1", "sortorder": "0",
        }}
    if n == "sla_create":
        # SLA needs schedule + service-tag filter; minimal weekly schedule.
        return {"params": {
            "name": f"smoketest-sla-{suf}",
            "period": "0", "slo": "99.9",
            "effective_date": "1735689600",  # 2025-01-01 UTC
            "timezone": "UTC",
            "service_tags": [{"tag": "smoke-test", "operator": "0", "value": "1"}],
        }}
    if n == "mfa_create":
        # Hash-OTP MFA (TOTP-style); sha256 hash function, 6-digit code.
        return {"params": {
            "name": f"smoketest-mfa-{suf}", "type": "1",
            "hash_function": "1", "code_length": "6",
        }}
    if n == "correlation_create":
        # Zabbix 7.x correlation condition type codes:
        #   0 = New event tag (just `tag`)
        #   1 = Old event tag (just `tag`)
        #   2 = New event host group (needs `groupid` + `operator`)
        #   3 = Tag pair (needs `oldtag` + `newtag`)
        #   4 = Old event tag value / 5 = New event tag value
        # Type 0 with a single ``tag`` is the simplest valid shape.
        return {"params": {
            "name": f"smoketest-corr-{suf}",
            "filter": {"evaltype": "0", "conditions": [
                {"type": "0", "tag": "smoke"},
            ]},
            "operations": [{"type": "0"}],
        }}
    if n == "connector_create":
        # Minimal HTTP item-value connector pointing at a stub URL.
        return {"params": {
            "name": f"smoketest-conn-{suf}",
            "url": "https://example.com/connector",
        }}
    if n == "templatedashboard_create":
        if not cid.get("template"):
            return _SKIP("templatedashboard.create needs the template fixture which was not created")
        return {"params": {
            "templateid": cid["template"],
            "name": f"smoketest-tdash-{suf}",
            "pages": [{"name": "p1", "widgets": []}],
        }}
    if n == "image_create":
        # 1x1 transparent PNG, base64-encoded.
        tiny_png = (
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII="
        )
        return {"params": {
            "name": f"smoketest-img-{suf}", "imagetype": "1",
            "image": tiny_png,
        }}
    if n == "module_create":
        return {"params": {
            "id": f"smoketest_module_{suf}",
            "relative_path": f"smoketest_module_{suf}",
            "status": "1",
        }}
    if n == "userdirectory_create":
        # Public Forumsys test LDAP - reachable from anywhere with no
        # bind credentials needed. Lets userdirectory.test return a
        # real success against an actual LDAP server.
        return {"params": {
            "name": f"smoketest-ud-{suf}", "idp_type": "1",
            "host": "ldap.forumsys.com", "port": "389",
            "base_dn": "dc=example,dc=com",
            "search_attribute": "uid",
            "bind_dn": "cn=read-only-admin,dc=example,dc=com",
            "bind_password": "password",
        }}
    if n == "report_create":
        if not (s.get("userid") and s.get("dashboardid")):
            return _SKIP("scheduled report needs both a userid and a dashboardid (none discovered)")
        # Zabbix 6.0+ requires at least one user OR usergroup recipient.
        return {"params": {
            "userid": s["userid"], "dashboardid": s["dashboardid"],
            "name": f"smoketest-rpt-{suf}", "period": "0",  # daily
            "users": [{"userid": s["userid"]}],
        }}
    if n == "token_create":
        if not s.get("userid"):
            return _SKIP("Zabbix-side token.create needs a userid (none discovered)")
        return {"params": {
            "name": f"smoketest-tok-{suf}", "userid": s["userid"],
        }}
    if n == "action_create":
        # Minimal trigger-action (eventsource 0); no conditions, just
        # a single notification operation against an existing user.
        if not s.get("userid"):
            return _SKIP("action_create needs a userid for the operation target")
        return {"params": {
            "name": f"smoketest-act-{suf}", "eventsource": "0",
            "operations": [{
                "operationtype": "0",
                "opmessage_usr": [{"userid": s["userid"]}],
                "opmessage": {"default_msg": "1", "mediatypeid": "0"},
            }],
        }}

    # ----- usermacro / hostmacro - simple parent-bound key/value pairs -----
    if n == "usermacro_create":
        # User-level (host) macro on the test host fixture.
        if not cid.get("host"):
            return _SKIP("hostmacro needs the test host fixture which was not created")
        return {"params": {
            "hostid": cid["host"],
            "macro": "{$SMOKE.TEST}", "value": "smoke",
        }}
    # NOTE: usermacro_update / usermacro_delete handled later, where
    # cid["usermacro"] (the hostmacroid returned by usermacro_create) is in scope.
    if n == "usermacro_createglobal":
        return {"params": {
            "macro": f"{{$SMOKE_TEST_{suf}}}", "value": "smoke",
        }}
    # NOTE: usermacro_updateglobal / usermacro_deleteglobal handled later
    # once cid["usermacro_global"] (the globalmacroid) is filled.

    # ----- Discovery rules / prototypes - needs a parent host or LLD -----
    if n == "discoveryrule_create":
        # Low-level discovery rule on the test host. Trapper items push
        # values - their delay MUST be 0 (Zabbix rejects any other
        # value with ``Invalid parameter "/1/delay": value must be 0``).
        if not cid.get("host"):
            return _SKIP("discoveryrule_create needs the test host fixture")
        return {"params": {
            "hostid": cid["host"],
            "name": f"smoketest-lld-{suf}",
            "key_": f"smoketest.lld.{suf}",
            "type": "2",  # Trapper
            "delay": "0",
        }}
    # NOTE: prototype creates handled in the later "Prototype tools -
    # chained from a parent LLD" block, where they are wired to the
    # discoveryrule fixture.

    if n == "graph_create":
        # Build a graph from the smoke item created earlier.
        if not cid.get("item"):
            return _SKIP("graph_create needs the test item fixture")
        return {"params": {
            "name": f"smoketest-graph-{suf}",
            "width": 900, "height": 200,
            "gitems": [{"itemid": cid["item"], "color": "00AA00"}],
        }}

    # ----- iconmap - needs at least one image -----
    if n == "iconmap_create":
        # Prefer the image we created earlier in the run, fall back to
        # whatever image the discovery phase found (Zabbix ships several
        # built-in images so this is virtually always non-empty).
        img = cid.get("image") or s.get("imageid")
        if not img:
            return _SKIP("iconmap_create needs an existing image; none discovered")
        return {"params": {
            "name": f"smoketest-im-{suf}",
            "default_iconid": img,
            "mappings": [{
                "inventory_link": "1",
                "expression": "smoke",
                "iconid": img,
            }],
        }}
    if n == "event_acknowledge":
        if not s.get("eventid"):
            return None
        return {"eventids": [s["eventid"]], "action": "4", "message": "smoke-test ack"}
    if n == "alert_get":
        return {"limit": 2}
    if n == "host_delete":
        return {"hostids": [cid.get("host")]} if cid.get("host") else None
    if n == "hostgroup_delete":
        return {"groupids": [cid.get("hostgroup")]} if cid.get("hostgroup") else None
    if n == "templategroup_delete":
        return {"groupids": [cid.get("templategroup")]} if cid.get("templategroup") else None
    if n == "template_delete":
        return {"templateids": [cid.get("template")]} if cid.get("template") else None
    if n == "valuemap_delete":
        return {"valuemapids": [cid.get("valuemap")]} if cid.get("valuemap") else None
    if n == "item_delete":
        return {"itemids": [cid.get("item")]} if cid.get("item") else None
    if n == "trigger_delete":
        return {"triggerids": [cid.get("trigger")]} if cid.get("trigger") else None
    if n == "maintenance_delete":
        return {"maintenanceids": [cid.get("maintenance")]} if cid.get("maintenance") else None
    if n == "user_delete":
        return {"userids": [cid.get("user")]} if cid.get("user") else None
    if n == "usergroup_delete":
        return {"usrgrpids": [cid.get("usergroup")]} if cid.get("usergroup") else None
    if n == "mediatype_delete":
        return {"mediatypeids": [cid.get("mediatype")]} if cid.get("mediatype") else None
    if n == "script_delete":
        return {"scriptids": [cid.get("script")]} if cid.get("script") else None
    if n == "script_execute":
        # Run our own smoke script (Webhook type, ``echo ok``) against
        # our own smoke host. Webhook scripts don't actually shell out
        # on a proxy/agent - the JS executor inside the Zabbix server
        # handles them - so this is safe even on production.
        if not (cid.get("script") and cid.get("host")):
            return _SKIP("script_execute needs both script_create and host_create fixtures")
        return {"scriptid": cid["script"], "hostid": cid["host"]}
    if n == "script_getscriptsbyhosts":
        if s.get("hostid"):
            return {"hostids": [s["hostid"]]}
        return None
    if n == "script_getscriptsbyevents":
        # Needs eventids; use the discovered one if any.
        if s.get("eventid"):
            return {"eventids": [s["eventid"]]}
        return None
    if n == "regexp_delete":
        return {"regexpids": [cid.get("regexp")]} if cid.get("regexp") else None
    if n == "drule_delete":
        return {"druleids": [cid.get("drule")]} if cid.get("drule") else None
    if n == "httptest_delete":
        return {"httptestids": [cid.get("httptest")]} if cid.get("httptest") else None
    if n == "proxy_delete":
        return {"proxyids": [cid.get("proxy")]} if cid.get("proxy") else None
    if n == "proxygroup_delete":
        return {"proxygroupids": [cid.get("proxygroup")]} if cid.get("proxygroup") else None
    if n == "dashboard_delete":
        return {"dashboardids": [cid.get("dashboard")]} if cid.get("dashboard") else None
    if n == "hostinterface_delete":
        return {"interfaceids": [cid.get("hostinterface")]} if cid.get("hostinterface") else None
    # NOTE: discoveryrule / *_prototype / graph deletes handled in the
    # later "Updates / deletes for the second-tier fixtures" block.

    # ===== UPDATE =====
    if n == "host_update":
        return {"hostid": cid.get("host"), "description": "smoke-test updated"} if cid.get("host") else None
    if n == "hostgroup_update":
        return {"groupid": cid.get("hostgroup"), "name": f"smoketest-hg-{suf}-renamed"} if cid.get("hostgroup") else None
    if n == "templategroup_update":
        return {"groupid": cid.get("templategroup"), "name": f"smoketest-tg-{suf}-renamed"} if cid.get("templategroup") else None
    if n == "template_update":
        return {"templateid": cid.get("template"), "description": "smoke-test"} if cid.get("template") else None
    if n == "item_update":
        return {"itemid": cid.get("item"), "description": "smoke-test"} if cid.get("item") else None
    if n == "trigger_update":
        return {"triggerid": cid.get("trigger"), "comments": "smoke-test"} if cid.get("trigger") else None
    if n == "valuemap_update":
        return {"valuemapid": cid.get("valuemap"), "name": f"smoketest-vm-{suf}-renamed"} if cid.get("valuemap") else None
    if n == "user_update":
        return {"userid": cid.get("user"), "name": "Smoke", "surname": "Test"} if cid.get("user") else None
    if n == "usergroup_update":
        return {"usrgrpid": cid.get("usergroup"), "name": f"smoketest-ug-{suf}-renamed"} if cid.get("usergroup") else None
    if n == "mediatype_update":
        return {"mediatypeid": cid.get("mediatype"), "description": "smoke"} if cid.get("mediatype") else None
    if n == "script_update":
        return {"scriptid": cid.get("script"), "description": "smoke"} if cid.get("script") else None
    if n == "maintenance_update":
        return {"maintenanceid": cid.get("maintenance"), "description": "smoke"} if cid.get("maintenance") else None
    if n == "regexp_update":
        return {"regexpid": cid.get("regexp"), "test_string": "smoketest"} if cid.get("regexp") else None
    if n == "drule_update":
        return {"druleid": cid.get("drule"), "name": f"smoketest-drule-{suf}-renamed"} if cid.get("drule") else None
    if n == "httptest_update":
        return {"httptestid": cid.get("httptest"), "name": f"smoketest-http-{suf}-renamed"} if cid.get("httptest") else None
    if n == "proxy_update":
        return {"proxyid": cid.get("proxy"), "description": "smoke"} if cid.get("proxy") else None
    if n == "proxygroup_update":
        return {"proxygroupid": cid.get("proxygroup"), "description": "smoke"} if cid.get("proxygroup") else None
    if n == "dashboard_update":
        return {"dashboardid": cid.get("dashboard"), "name": f"smoketest-dash-{suf}-renamed"} if cid.get("dashboard") else None
    if n == "hostinterface_update":
        return {"interfaceid": cid.get("hostinterface"), "port": "10051"} if cid.get("hostinterface") else None

    # ---- Updates / deletes for the second-tier fixtures ----
    if n == "role_update":
        return {"roleid": cid.get("role"), "name": f"smoketest-role-{suf}-renamed"} if cid.get("role") else None
    if n == "role_delete":
        return {"ids": [cid.get("role")]} if cid.get("role") else None
    if n == "service_update":
        return {"serviceid": cid.get("service"), "name": f"smoketest-svc-{suf}-renamed"} if cid.get("service") else None
    if n == "service_delete":
        return {"ids": [cid.get("service")]} if cid.get("service") else None
    if n == "sla_update":
        return {"slaid": cid.get("sla"), "description": "smoke"} if cid.get("sla") else None
    if n == "sla_delete":
        return {"ids": [cid.get("sla")]} if cid.get("sla") else None
    if n == "mfa_update":
        return {"mfaid": cid.get("mfa"), "name": f"smoketest-mfa-{suf}-renamed"} if cid.get("mfa") else None
    if n == "mfa_delete":
        return {"ids": [cid.get("mfa")]} if cid.get("mfa") else None
    if n == "correlation_update":
        return {"correlationid": cid.get("correlation"), "name": f"smoketest-corr-{suf}-renamed"} if cid.get("correlation") else None
    if n == "correlation_delete":
        return {"ids": [cid.get("correlation")]} if cid.get("correlation") else None
    if n == "connector_update":
        return {"connectorid": cid.get("connector"), "description": "smoke"} if cid.get("connector") else None
    if n == "connector_delete":
        return {"ids": [cid.get("connector")]} if cid.get("connector") else None
    if n == "image_update":
        return {"imageid": cid.get("image"), "name": f"smoketest-img-{suf}-renamed"} if cid.get("image") else None
    if n == "image_delete":
        return {"ids": [cid.get("image")]} if cid.get("image") else None
    if n == "module_update":
        return {"moduleid": cid.get("module"), "status": "0"} if cid.get("module") else None
    if n == "module_delete":
        return {"ids": [cid.get("module")]} if cid.get("module") else None
    if n == "userdirectory_update":
        return {"userdirectoryid": cid.get("userdirectory"), "description": "smoke"} if cid.get("userdirectory") else None
    if n == "userdirectory_delete":
        return {"ids": [cid.get("userdirectory")]} if cid.get("userdirectory") else None
    if n == "userdirectory_test":
        if not cid.get("userdirectory"):
            return None
        return {"userdirectoryid": cid["userdirectory"], "username": "smoke", "password": "smoke"}
    if n == "report_update":
        return {"reportid": cid.get("report"), "name": f"smoketest-rpt-{suf}-renamed"} if cid.get("report") else None
    if n == "report_delete":
        return {"ids": [cid.get("report")]} if cid.get("report") else None
    if n == "token_update":
        return {"tokenid": cid.get("token"), "description": "smoke"} if cid.get("token") else None
    if n == "token_delete":
        return {"ids": [cid.get("token")]} if cid.get("token") else None
    if n == "token_generate":
        # token.generate is a non-standard signature - takes a
        # ``tokenids`` array directly (not under ``params`` and not
        # under generic ``ids``). Bypass the create/update/delete wrap.
        return {"tokenids": [cid.get("token")]} if cid.get("token") else None
    if n == "action_update":
        return {"actionid": cid.get("action"), "name": f"smoketest-act-{suf}-renamed"} if cid.get("action") else None
    if n == "action_delete":
        return {"ids": [cid.get("action")]} if cid.get("action") else None
    if n == "discoveryrule_update":
        return {"itemid": cid.get("discoveryrule"), "name": f"smoketest-lld-{suf}-renamed"} if cid.get("discoveryrule") else None
    if n == "discoveryrule_delete":
        return {"ids": [cid.get("discoveryrule")]} if cid.get("discoveryrule") else None
    if n == "graph_update":
        return {"graphid": cid.get("graph"), "name": f"smoketest-graph-{suf}-renamed"} if cid.get("graph") else None
    if n == "graph_delete":
        return {"ids": [cid.get("graph")]} if cid.get("graph") else None
    if n == "iconmap_update":
        return {"iconmapid": cid.get("iconmap"), "name": f"smoketest-im-{suf}-renamed"} if cid.get("iconmap") else None
    if n == "iconmap_delete":
        return {"ids": [cid.get("iconmap")]} if cid.get("iconmap") else None
    if n == "templatedashboard_update":
        return {"dashboardid": cid.get("templatedashboard"), "name": f"smoketest-tdash-{suf}-renamed"} if cid.get("templatedashboard") else None
    if n == "templatedashboard_delete":
        return {"ids": [cid.get("templatedashboard")]} if cid.get("templatedashboard") else None
    if n == "usermacro_update":
        return {"hostmacroid": cid.get("usermacro"), "value": "updated"} if cid.get("usermacro") else None
    if n == "usermacro_delete":
        return {"ids": [cid.get("usermacro")]} if cid.get("usermacro") else None
    if n == "usermacro_updateglobal":
        if not cid.get("usermacro_global"):
            return None
        # ``*_updateglobal`` wraps under ``params`` like the regular
        # *_update tools, but the call_tool dispatcher only matches
        # ``endswith("_update")`` for the wrap, so do it explicitly.
        return {"params": {"globalmacroid": cid["usermacro_global"], "value": "updated"}}
    if n == "usermacro_deleteglobal":
        if not cid.get("usermacro_global"):
            return None
        return {"ids": [cid["usermacro_global"]]}

    # ---- Prototype tools - chained from a parent LLD ----
    if n == "itemprototype_create":
        if not cid.get("discoveryrule"):
            return None
        # Trapper item prototype - delay MUST be 0 (Zabbix rejects any
        # other value). value_type 0 = numeric float so graphprototype
        # can later attach this prototype.
        return {"params": {
            "ruleid": cid["discoveryrule"], "hostid": cid.get("host"),
            "name": f"smoketest-itemp-{suf}",
            "key_": f"smoketest.itemp.{suf}[{{#SMOKE}}]",
            "type": "2", "value_type": "0", "delay": "0",
        }}
    if n == "itemprototype_update":
        # Trapper prototypes need delay=0; just rename to avoid the
        # delay validator entirely.
        if not cid.get("itemprototype"):
            return None
        return {"itemid": cid["itemprototype"], "name": f"smoketest-itemp-{suf}-renamed"}
    if n == "itemprototype_delete":
        return {"ids": [cid.get("itemprototype")]} if cid.get("itemprototype") else None
    if n == "triggerprototype_create":
        if not cid.get("itemprototype"):
            return None
        return {"params": {
            "description": f"smoketest-trigp-{suf} {{HOST.NAME}}",
            "expression": f"last(/smoketest-host-{suf}/smoketest.itemp.{suf}[{{#SMOKE}}])>0",
        }}
    if n == "triggerprototype_update":
        return {"triggerid": cid.get("triggerprototype"), "comments": "smoke"} if cid.get("triggerprototype") else None
    if n == "triggerprototype_delete":
        return {"ids": [cid.get("triggerprototype")]} if cid.get("triggerprototype") else None
    if n == "graphprototype_create":
        if not cid.get("itemprototype"):
            return None
        return {"params": {
            "name": f"smoketest-graphp-{suf}", "width": 900, "height": 200,
            "gitems": [{"itemid": cid["itemprototype"], "color": "00AA00"}],
        }}
    if n == "graphprototype_update":
        return {"graphid": cid.get("graphprototype"), "width": 800} if cid.get("graphprototype") else None
    if n == "graphprototype_delete":
        return {"ids": [cid.get("graphprototype")]} if cid.get("graphprototype") else None
    if n == "hostprototype_create":
        if not cid.get("discoveryrule"):
            return None
        gid = cid.get("hostgroup") or s.get("groupid")
        return {"params": {
            "ruleid": cid["discoveryrule"],
            "host": "{#SMOKE.NAME}",
            "groupLinks": [{"groupid": gid}],
        }} if gid else None
    if n == "hostprototype_update":
        return {"hostid": cid.get("hostprototype"), "status": "1"} if cid.get("hostprototype") else None
    if n == "hostprototype_delete":
        return {"ids": [cid.get("hostprototype")]} if cid.get("hostprototype") else None
    if n == "discoveryruleprototype_create":
        # 3-level LLD chain. Requires a host prototype that itself
        # came out of a real LLD-discovery run (otherwise Zabbix
        # rejects with "No permissions to referred object" because
        # the host prototype is just a template until discovery
        # actually instantiates it). Our trapper-based parent LLD
        # rule never receives values, so the host prototype stays
        # unmaterialized.
        return _SKIP("3-level LLD construct: host prototype must be materialized by an actual discovery cycle (parent LLD rule needs real values pushed). Out of scope for the synthetic CRUD smoke fixture")
    if n == "discoveryruleprototype_update":
        return _SKIP("blocked by discoveryruleprototype_create skip; same root cause")
    if n == "discoveryruleprototype_delete":
        return _SKIP("blocked by discoveryruleprototype_create skip; same root cause")

    # ---- Mass remove tools - distinct id-name shape ----
    # Zabbix forbids removing the LAST host group from a host (or the
    # last template group from a template) - it would orphan the
    # entity. Our test fixture only has one group, so we target a
    # discovered SECONDARY group to remove the host/template from.
    # The fixture host/template was never actually a member of that
    # secondary group, so the call is essentially a no-op but exercises
    # the API surface.
    if n == "host_massremove":
        if not (cid.get("host") and s.get("groupid")):
            return None
        return {"params": {"hostids": [cid["host"]], "groupids": [s["groupid"]]}}
    if n == "hostgroup_massremove":
        if not (cid.get("hostgroup") and s.get("hostid")):
            return None
        # Remove the (already in another group) discovered host from
        # our smoke-test group; the host stays valid via its other
        # memberships.
        return {"params": {"groupids": [cid["hostgroup"]], "hostids": [s["hostid"]]}}
    if n == "templategroup_massremove":
        if not (cid.get("templategroup") and s.get("templateid")):
            return None
        return {"params": {"groupids": [cid["templategroup"]], "templateids": [s["templateid"]]}}
    if n == "template_massremove":
        if not (cid.get("template") and s.get("templategroupid")):
            return None
        return {"params": {"templateids": [cid["template"]], "groupids": [s["templategroupid"]]}}
    if n == "hostinterface_massremove":
        # Zabbix 7.x docs: hostinterface.massremove needs ``hostids`` +
        # an ``interfaces`` array of {ip, port} pairs to match. The
        # interface created by hostinterface_create above used port
        # 10052, so target that.
        if not cid.get("host"):
            return None
        return {"params": {"hostids": [cid["host"]], "interfaces": [{"ip": "127.0.0.3", "dns": "", "port": "10052"}]}}

    # ---- Session-only methods - need username/password to acquire a sessionid ----
    # The script can run user.login first if SESSION_USER / SESSION_PASS are
    # provided via CLI; otherwise these stay skipped because an API token
    # cannot do session-cookie work.
    if n in ("user_login", "user_logout", "user_checkauthentication"):
        return _SKIP("session-cookie auth; an API token cannot issue user.login - separate fixture pending")
    if n == "user_provision":
        return _SKIP("LDAP/SAML user provisioning; needs an external IdP that Wiki-topics does not have")
    if n == "user_resettotp":
        return _SKIP("MFA reset target needs a real TOTP-enabled user; out of generic scope")
    if n == "user_unblock":
        if not cid.get("user"):
            return None
        return {"params": {"userids": [cid["user"]]}}

    if n == "host_update" or n == "user_update":
        return None

    return None


# Track which write tools created which entity (key = entity short name)
CREATE_TO_KEY = {
    "hostgroup_create": "hostgroup",
    "templategroup_create": "templategroup",
    "template_create": "template",
    "host_create": "host",
    "valuemap_create": "valuemap",
    "item_create": "item",
    "trigger_create": "trigger",
    "maintenance_create": "maintenance",
    "usergroup_create": "usergroup",
    "user_create": "user",
    "mediatype_create": "mediatype",
    "script_create": "script",
    "regexp_create": "regexp",
    "drule_create": "drule",
    "httptest_create": "httptest",
    "proxy_create": "proxy",
    "proxygroup_create": "proxygroup",
    "dashboard_create": "dashboard",
    "hostinterface_create": "hostinterface",
    "role_create": "role",
    "service_create": "service",
    "sla_create": "sla",
    "mfa_create": "mfa",
    "correlation_create": "correlation",
    "connector_create": "connector",
    "image_create": "image",
    "module_create": "module",
    "userdirectory_create": "userdirectory",
    "report_create": "report",
    "token_create": "token",
    "action_create": "action",
    "discoveryrule_create": "discoveryrule",
    "graph_create": "graph",
    "iconmap_create": "iconmap",
    "templatedashboard_create": "templatedashboard",
    "usermacro_create": "usermacro",
    "usermacro_createglobal": "usermacro_global",
    "map_create": "map",
    "itemprototype_create": "itemprototype",
    "triggerprototype_create": "triggerprototype",
    "graphprototype_create": "graphprototype",
    "hostprototype_create": "hostprototype",
    "discoveryruleprototype_create": "discoveryruleprototype",
}

CREATE_RESPONSE_KEY = {
    "hostgroup_create": "groupids",
    "templategroup_create": "groupids",
    "template_create": "templateids",
    "host_create": "hostids",
    "valuemap_create": "valuemapids",
    "item_create": "itemids",
    "trigger_create": "triggerids",
    "maintenance_create": "maintenanceids",
    "usergroup_create": "usrgrpids",
    "user_create": "userids",
    "mediatype_create": "mediatypeids",
    "script_create": "scriptids",
    "regexp_create": "regexpids",
    "drule_create": "druleids",
    "httptest_create": "httptestids",
    "proxy_create": "proxyids",
    "proxygroup_create": "proxy_groupids",
    "dashboard_create": "dashboardids",
    "hostinterface_create": "interfaceids",
    "role_create": "roleids",
    "service_create": "serviceids",
    "sla_create": "slaids",
    "mfa_create": "mfaids",
    "correlation_create": "correlationids",
    "connector_create": "connectorids",
    "image_create": "imageids",
    "module_create": "moduleids",
    "userdirectory_create": "userdirectoryids",
    "report_create": "reportids",
    "token_create": "tokenids",
    "action_create": "actionids",
    "discoveryrule_create": "itemids",
    "graph_create": "graphids",
    "iconmap_create": "iconmapids",
    "templatedashboard_create": "dashboardids",
    "usermacro_create": "hostmacroids",
    "usermacro_createglobal": "globalmacroids",
    "map_create": "sysmapids",
    "itemprototype_create": "itemids",
    "triggerprototype_create": "triggerids",
    "graphprototype_create": "graphids",
    "hostprototype_create": "hostids",
    "discoveryruleprototype_create": "itemids",
}

# Tool ordering: get / extension / create / update / delete.
# Inside the delete bucket we sub-order so children come before their
# parent and maintenance before its host group, otherwise Zabbix bails
# with ``No permissions to referred object`` (already-cascaded child)
# or ``Cannot delete host group: maintenance must contain at least one
# host``.
# Create order: parents before their dependents (hostgroup -> host ->
# hostinterface / item / trigger, templategroup -> template, ...).
# Anything not listed defaults to a middle slot.
_CREATE_ORDER = {
    "hostgroup_create": 0,
    "templategroup_create": 0,
    "usergroup_create": 0,
    "image_create": 0,            # iconmap depends on image
    "host_create": 1,
    "template_create": 1,
    "iconmap_create": 1,
    "user_create": 2,
    "valuemap_create": 2,
    "hostinterface_create": 2,
    "item_create": 3,
    "discoveryrule_create": 3,
    "usermacro_create": 3,        # depends on host
    "usermacro_createglobal": 3,
    "trigger_create": 4,
    "httptest_create": 4,
    "graph_create": 4,
    "itemprototype_create": 4,    # depends on discoveryrule
    "hostprototype_create": 4,
    "maintenance_create": 5,
    "dashboard_create": 5,
    "templatedashboard_create": 5,
    "triggerprototype_create": 5,
    "graphprototype_create": 5,
    "discoveryruleprototype_create": 5,
    "report_create": 6,           # depends on dashboard + user
    "service_create": 1,
    "sla_create": 2,              # may reference services later
    "role_create": 0,
    "mfa_create": 0,
    "correlation_create": 1,
    "connector_create": 1,
    "module_create": 0,
    "userdirectory_create": 0,
    "token_create": 3,            # depends on user
    "action_create": 5,
    "map_create": 0,
}

_DELETE_ORDER = {
    # Reports / actions / dashboards reference users + dashboards.
    "report_delete": -3,
    "action_delete": -3,
    "templatedashboard_delete": -3,
    "dashboard_delete": -3,
    # ----- Prototype tear-down (deeply nested) -----
    # Order: triggerprototype + graphprototype reference itemprototype,
    # so they go FIRST. Then itemprototype + hostprototype.
    # Then discoveryrule (the parent LLD). Then ordinary items / hosts.
    # Each LLD-prototype must be removed before its parent LLD rule,
    # otherwise the parent's deletion cascades and our explicit
    # ``*_prototype_delete`` call hits ``No permissions to referred
    # object``.
    "triggerprototype_delete": -3,
    "graphprototype_delete": -3,
    "itemprototype_delete": -2,
    "hostprototype_delete": -2,
    "discoveryrule_delete": -1,   # parent LLD on the host
    # Triggers reference items - delete triggers BEFORE items.
    "trigger_delete": -1,
    "graph_delete": -1,
    # Iconmap references images so iconmap before image.
    "iconmap_delete": -1,
    # Tokens reference users
    "token_delete": -1,
    "user_unblock": -2,           # last user op before user_delete
    # Other host-children - cascade-deleted by host_delete.
    "hostinterface_delete": 0,
    "item_delete": 0,
    "discoveryruleprototype_delete": 0,
    "httptest_delete": 0,
    "valuemap_delete": 0,
    "usermacro_delete": 0,        # host-bound macros before host
    # Maintenance must lose its host-group dependency BEFORE hostgroup.delete
    "maintenance_delete": 1,
    # Hosts and templates next
    "host_delete": 2,
    "template_delete": 2,
    # Containers / groups last
    "hostgroup_delete": 3,
    "templategroup_delete": 3,
    # Stand-alone fixtures with no parent to wait for
    "role_delete": 0,
    "service_delete": 0,
    "sla_delete": 0,
    "mfa_delete": 0,
    "correlation_delete": 0,
    "connector_delete": 0,
    "image_delete": 0,
    "module_delete": 0,
    "userdirectory_delete": 0,
    "usermacro_deleteglobal": 0,
    "map_delete": 0,
}


def tool_priority(name: str) -> tuple[int, int]:
    if name.endswith("_get") or name.endswith("_export"):
        return (0, 0)
    if name.endswith("_create"):
        return (2, _CREATE_ORDER.get(name, 99))
    if name.endswith("_update"):
        return (3, 0)
    if name.endswith("_delete"):
        return (4, _DELETE_ORDER.get(name, 1))
    if name.endswith("massadd") or name.endswith("massupdate") or name.endswith("massremove"):
        return (3, 0)
    # Tools that act on an entity created earlier in the run
    # (hostgroup_propagate, sla_getsli, token_generate, ...) must run
    # AFTER the corresponding _create. Treat them as update-tier so
    # they pick up the create-time fixtures.
    if (name.endswith("_propagate") or name.endswith("_getsli")
            or name.endswith("_generate")):
        return (3, 0)
    # ``hostinterface_replacehostinterfaces`` swaps out the primary
    # agent interface created by host_create. Run it BEFORE
    # hostinterface_create so the secondary interface fixture
    # (``cid["hostinterface"]``) remains stable for the
    # update/delete tests that follow.
    if name.endswith("_replacehostinterfaces"):
        # Slot it between host_create (sub-priority 1) and
        # hostinterface_create (sub-priority 2) inside the create
        # tier so the host already exists, but the secondary
        # interface fixture has not yet been built.
        return (2, 1.5)
    # Session-cookie tier: user.login depends on user.create having
    # produced a usable user, then logout/checkauthentication depend
    # on the session id from login. Force them into update-tier with
    # explicit ordering so they outrun the user_delete on the same run.
    if name == "user_login":
        return (3, 50)
    if name == "user_checkauthentication":
        return (3, 51)
    if name == "user_provision":
        return (3, 53)
    if name == "user_resettotp":
        return (3, 54)
    if name == "user_unblock":
        return (3, 55)
    if name == "userdirectory_test":
        # Must run BEFORE user_logout - the same captured session id
        # backs both, and logout invalidates it.
        return (3, 56)
    if name == "user_logout":
        # ``user.logout`` invalidates the captured session id, so run
        # it AFTER every other tool that consumes ``auth_sessionid``.
        return (3, 58)
    if name in ("history_push", "history_clear", "task_create", "script_execute",
                "anomaly_detect", "capacity_forecast"):
        return (3, 60)
    # ``*_updateglobal`` / ``*_deleteglobal`` need the matching
    # ``*_createglobal`` (a *_create tool, priority 2) to have produced
    # a global macro id. Push them into update/delete tier explicitly.
    if name.endswith("_updateglobal"):
        return (3, 65)
    if name.endswith("_deleteglobal"):
        return (4, 50)
    if name in ("settings_update", "housekeeping_update", "authentication_update", "autoregistration_update"):
        return (3, 70)
    if name == "configuration_import" or name == "configuration_importcompare":
        return (3, 80)  # after configuration_export ran
    if name == "action_confirm":
        return (3, 81)  # after action_prepare ran
    return (1, 0)  # extensions, misc


async def run_suite(url: str, token: str, server: str, report_path: str) -> int:
    suite = Suite(server=server, suffix=str(int(time.time())))
    headers = {"Authorization": f"Bearer {token}"}
    print(f"=== Connecting to {url} (target Zabbix: {server}) ===")
    import httpx2
    async with streamable_http_client(
        url, http_client=httpx2.AsyncClient(headers=headers, timeout=60.0),
    ) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            print(f"  protocol: {init.protocol_version}, server: {init.server_info.name} {init.server_info.version}")
            tools = (await s.list_tools()).tools
            print(f"  registered tools: {len(tools)}")

            await discover_sample_ids(s, suite)

            # Sort: reads first, then non-CRUD extensions, then
            # create/update/delete chain (with delete sub-ordering so
            # children come before their parent host).
            sorted_tools = sorted(tools, key=lambda t: (*tool_priority(t.name), t.name))

            print(f"\n=== Phase 2: invoke each tool ({len(sorted_tools)}) ===")
            for tool in sorted_tools:
                name = tool.name
                args = build_args(name, suite)
                if isinstance(args, _Skip):
                    suite.record(name, "skip", args.reason, 0)
                    continue
                if args is None:
                    suite.record(name, "skip", "no minimal args", 0)
                    continue
                ok, payload = await call_tool(s, name, args, suite)

                # Capture created IDs so subsequent update/delete can target them
                if ok and name in CREATE_TO_KEY:
                    data = parse_payload(payload)
                    if isinstance(data, dict):
                        ids_field = CREATE_RESPONSE_KEY[name]
                        ids = data.get(ids_field) or []
                        if ids:
                            suite.created_ids[CREATE_TO_KEY[name]] = ids[0]
                        elif VERBOSE:
                            print(f"     WARN: {name} OK but no '{ids_field}' in payload: {str(data)[:100]}")
                # Capture the session id that user_login returns so
                # the session-only tier (user_logout, user_checkauthentication)
                # can use it.
                if ok and name == "user_login":
                    text = payload
                    if text.startswith("[System:"):
                        text = text.split("\n", 1)[1] if "\n" in text else text
                    try:
                        body = json.loads(text)
                    except json.JSONDecodeError:
                        body = None
                    if isinstance(body, str):
                        # user.login returns just the session id as a
                        # bare JSON string.
                        suite.created_ids["user_session"] = body
                # Capture the action_prepare confirmation token so
                # action_confirm has something real to validate.
                if ok and name == "action_prepare":
                    text = payload
                    if text.startswith("[System:"):
                        text = text.split("\n", 1)[1] if "\n" in text else text
                    try:
                        body = json.loads(text)
                    except json.JSONDecodeError:
                        body = None
                    if isinstance(body, dict) and body.get("confirmation_token"):
                        suite.created_ids["action_token"] = body["confirmation_token"]

                # Stash the YAML body of configuration_export so the
                # later configuration_import / importcompare tests can
                # round-trip it.
                if ok and name == "configuration_export":
                    text = payload
                    if text.startswith("[System:"):
                        text = text.split("\n", 1)[1] if "\n" in text else text
                    # Zabbix wraps the YAML in JSON ``"..."`` because the
                    # API returns a string-typed result. Try to unwrap.
                    try:
                        body = json.loads(text)
                    except json.JSONDecodeError:
                        body = text
                    if isinstance(body, str) and body.strip():
                        suite.created_ids["template_export"] = body

    # ----- Report -----
    by_status: dict[str, list[ToolResult]] = defaultdict(list)
    for r in suite.results:
        by_status[r.status].append(r)

    total = len(suite.results)
    ok_n = len(by_status["ok"])
    err_n = len(by_status["error"])
    skip_n = len(by_status["skip"])

    print("\n=== Summary ===")
    print(f"  total : {total}")
    print(f"  ok    : {ok_n}")
    print(f"  error : {err_n}")
    print(f"  skip  : {skip_n}")

    lines = []
    lines.append(f"# Tool smoke test report")
    lines.append("")
    lines.append(f"- **Server**: `{server}`")
    lines.append(f"- **Total tools**: {total}")
    lines.append(f"- **OK**: {ok_n}  |  **Error**: {err_n}  |  **Skipped**: {skip_n}")
    lines.append(f"- **Generated**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    lines.append("")
    if by_status["error"]:
        lines.append("## Failures")
        lines.append("")
        lines.append("| Tool | Error |")
        lines.append("|---|---|")
        for r in sorted(by_status["error"], key=lambda x: x.name):
            err = r.detail.replace("|", "\\|").replace("\n", " ")[:200]
            lines.append(f"| `{r.name}` | {err} |")
        lines.append("")
    if by_status["skip"]:
        lines.append("## Skipped")
        lines.append("")
        lines.append("| Tool | Reason |")
        lines.append("|---|---|")
        for r in sorted(by_status["skip"], key=lambda x: x.name):
            lines.append(f"| `{r.name}` | {r.detail} |")
        lines.append("")
    lines.append("## Passed")
    lines.append("")
    lines.append("| Tool | Time (ms) |")
    lines.append("|---|---|")
    for r in sorted(by_status["ok"], key=lambda x: x.name):
        lines.append(f"| `{r.name}` | {r.elapsed_ms} |")

    with open(report_path, "w") as f:
        f.write("\n".join(lines))
    print(f"  report written to {report_path}")

    return 0 if err_n == 0 else 1


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://127.0.0.1:18081/mcp")
    p.add_argument("--token", required=True)
    p.add_argument("--server", default="Wiki-topics", help="Zabbix server name from config")
    p.add_argument("--report", default="tools_test_report.md")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    global VERBOSE
    VERBOSE = args.verbose
    sys.exit(asyncio.run(run_suite(args.url, args.token, args.server, args.report)))


if __name__ == "__main__":
    main()
