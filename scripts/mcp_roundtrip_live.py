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
"""Round trip through the MCP server itself: ``<object>_get`` -> ``<object>_update``
with the object unchanged, for every object kind the server can update.

``scripts/audit_write_roundtrip_live.py`` measures what a real Zabbix refuses;
this script proves the other half: that the shipped write contract and the
hand rules make the unchanged payload go through the real tool handlers. The
tools are registered in-process (the same handler path as the HTTP server)
against the Zabbix at URL, with a temporary API token that is deleted at the
end.

    python3 scripts/mcp_roundtrip_live.py URL USER PASSWORD [--fixtures] [--only=a,b] [--dump]

``--fixtures`` creates the objects of ``scripts/roundtrip_fixtures.py`` first
and deletes them afterwards; ``--only`` limits the run to the named objects;
``--dump`` prints the payload of a failing plain object and the values of a
key that changed. Printed per object: plain ok/total, and templated /
discovered / dependent ok/total, which Zabbix is expected to refuse with its
own message.

An accepted update is not yet an unchanged object (``template.update`` takes
an empty ``templates`` and unlinks every parent without a word), so every
object that went through is read on its own before and after the update,
with the same selects, and the two are compared, values a server changes on
its own (``VOLATILE``) left aside. For an object that hosts and templates
inherit (an item, trigger, graph, LLD rule ... on a template) the inherited
copies are compared as well: ``graph.update`` of a template's graph with the
``gitems[].graphid`` that ``graph.get`` returns empties the inherited graphs.

Every distinct shape of every object is sent once, and every fixture object
(``rt-...``) is sent whatever its shape: a stock object of the same shape
does not stand in for it, because only the fixtures have every relation.

Exit status 1 when a plain object fails for a reason not listed in
``EXPECTED``, comes back different, or cannot be read again to be compared.
"""

from __future__ import annotations

import asyncio
import copy
import json
import sys
import urllib.request
from collections import OrderedDict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

from mcp.server.mcpserver import MCPServer  # noqa: E402
from mcp.server.mcpserver.exceptions import ToolError  # noqa: E402

from audit_write_roundtrip_live import INHERITING, OBJECTS, _category, _get_params, _shape  # noqa: E402
from zabbix_mcp.api.contracts import contract_for  # noqa: E402
from zabbix_mcp.api.versions import unavailable_reason  # noqa: E402
from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.server import _register_tools  # noqa: E402

# Refusals that are Zabbix's own and say nothing about the payload.
EXPECTED = (
    'Not allowed to set language for user "guest"',
    "Cannot update readonly user role",
    '"/1/username": cannot be empty',                    # the stock Gmail / Office365 media types
    "with templated items cannot contain items from other hosts",   # a stock 6.x graph
    "Invalid IP address \"{#",                           # a prototype interface listed by hostinterface.get on 6.x
)
# (release, object, id): a row a release cannot update at all, whatever is sent.
EXPECTED_ROWS = {
    ("6.2", "graph", "404"),   # stock "Zabbix data gathering process busy %": graph.update dies with a PHP fatal on 6.2
}


class Raw:
    """Minimal JSON-RPC client for the setup calls (login, token, fixtures)."""

    def __init__(self, url: str, user: str, password: str) -> None:
        self.url = url.rstrip("/") + "/api_jsonrpc.php"
        self.n = 0
        self.auth = None
        self.version = self.call("apiinfo.version", {})
        release = tuple(int(x) for x in self.version.split(".")[:2])
        self.header = release >= (6, 4)
        field = "username" if release >= (5, 4) else "user"
        self.auth = self.call("user.login", {field: user, "password": password})

    def call(self, method: str, params):
        self.n += 1
        body = {"jsonrpc": "2.0", "method": method, "params": params, "id": self.n}
        headers = {"Content-Type": "application/json-rpc"}
        if self.auth:
            if self.header:
                headers["Authorization"] = "Bearer " + self.auth
            else:
                body["auth"] = self.auth
        req = urllib.request.Request(self.url, json.dumps(body).encode(), headers)
        data = json.loads(urllib.request.urlopen(req, timeout=300).read())
        if "error" in data:
            raise RuntimeError(f"{data['error'].get('message')} {data['error'].get('data')}")
        return data["result"]


def _text(result) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, (list, tuple)):
        return "".join(getattr(c, "text", "") or "" for c in result)
    content = getattr(result, "content", None)
    if content:
        return "".join(getattr(c, "text", "") or "" for c in content)
    return str(result)


def _strip_preamble(text: str) -> str:
    while text.startswith("[System:") and "\n" in text and text.split("\n", 1)[0].rstrip().endswith("]"):
        text = text.split("\n", 1)[1]
    return text


def _rows(mcp: MCPServer, tool: str, args: dict) -> list:
    """Call a get tool; on an API failure (a PHP memory limit on a big get) retry smaller."""
    try:
        text = _text(asyncio.run(mcp.call_tool(tool, args)))
    except ToolError:
        text = _text(asyncio.run(mcp.call_tool(tool, dict(args, limit=30))))
    rows = json.loads(_strip_preamble(text))
    return [rows] if isinstance(rows, dict) else rows


# What a server changes on its own between two reads of the same object,
# wherever it sits (an item's lastvalue inside a host read with selectItems,
# an interface's availability, a trigger's regenerated function ids).
VOLATILE = frozenset({
    "lastclock", "lastns", "lastvalue", "prevvalue", "lastaccess", "lastchange", "lastcheck", "nextcheck",
    "lastlogsize", "mtime", "error", "state", "errors_from", "disable_until", "attempt_clock", "attempt_failed",
    "attempt_ip", "ts_delete", "ts_disable", "active_available", "available", "rowscount",
    # a trigger's functions get new ids whenever its expression is sent again
    "functionid",
    # on 6.x the macro path rows of the inherited LLD rules are written anew
    # (same macro, same path, new id) whenever the template's rule is updated
    "lld_macro_pathid",
})
# The same for names that are configuration further down: a proxy reports its
# own "version" at the top level, an SNMP interface's details.version is a setting.
VOLATILE_TOP = frozenset({"version", "compatibility"})


def _stable(value, top: bool = True):
    """*value* without what a server changes on its own. Lists keep their
    order: the order of preprocessing steps or value mappings is part of the
    object."""
    if isinstance(value, dict):
        return {k: _stable(v, False) for k, v in value.items()
                if k not in VOLATILE and not k.endswith("_local") and not (top and k in VOLATILE_TOP)}
    if isinstance(value, list):
        return [_stable(v, False) for v in value]
    return value


# Lists that Zabbix reads without an ORDER BY: the elements and links of a map
# come back in the order the database has them in, and that order can change
# when map.update writes the rows again (seen once on 6.2.9 in six runs: the
# same two elements, the other way round). Compared as sets.
UNORDERED = frozenset({"selements", "links"})


def _comparable(key: str, value):
    if key in UNORDERED and isinstance(value, list):
        return sorted(json.dumps(v, sort_keys=True) for v in value)
    return json.dumps(value, sort_keys=True)


def _changed_keys(before: dict, after: dict) -> list[str]:
    """Top-level keys whose value differs after the object went through its update tool."""
    a, b = _stable(before), _stable(after)
    return sorted(k for k in set(a) | set(b) if _comparable(k, a.get(k)) != _comparable(k, b.get(k)))


def _is_fixture(row: dict) -> bool:
    return any(str(row.get(k) or "").startswith("rt-") for k in ("name", "host", "description", "macro", "key_"))


def _children(raw, obj: str, id_field: str | None, row: dict, version: str) -> dict | None:
    """The copies of *row* that hosts and templates inherit, by id; ``None``
    for an object that is not the origin of any."""
    if obj not in INHERITING or id_field is None or str(row.get("templateid", "")) != "0":
        return None
    try:
        rows = raw.call(f"{obj}.get", dict(_get_params(obj, version), filter={"templateid": row.get(id_field)}))
    except Exception:
        return None
    return {str(r.get(id_field)): r for r in rows if isinstance(r, dict)}


def _children_changed(before: dict, after: dict) -> list[str]:
    out = []
    for cid in sorted(set(before) | set(after)):
        if cid not in after:
            out.append(f"inherited {cid} gone")
        elif cid not in before:
            out.append(f"inherited {cid} new")
        else:
            keys = _changed_keys(before[cid], after[cid])
            if keys:
                out.append(f"inherited {cid}: " + ", ".join(keys))
    return out


def _reread(mcp: MCPServer, obj: str, id_field: str | None, row: dict, extra: dict) -> dict | None:
    """The same object again, through the same get tool with the same selects."""
    args: dict = {"output": "extend", "extra_params": dict(extra)}
    if id_field is not None:
        contract = contract_for(f"{obj}.get")
        plural = id_field + "s"   # templateids, proxyids, ...: an ID is not always a filterable property
        if contract is not None and plural in contract.params:
            args["extra_params"][plural] = [str(row.get(id_field))]
        else:
            args["extra_params"]["filter"] = {id_field: row.get(id_field)}
    try:
        rows = _rows(mcp, f"{obj}_get", args)
    except (ToolError, json.JSONDecodeError):
        return None
    rows = [r for r in rows if isinstance(r, dict) and "_truncated" not in r]
    return rows[0] if len(rows) == 1 else None


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    opts = [a for a in argv if a.startswith("--")]
    if len(args) != 3:
        raise SystemExit(__doc__)
    url, user, password = args
    only = None
    for o in opts:
        if o.startswith("--only="):
            only = set(o[7:].split(","))
    raw = Raw(url, user, password)
    version = raw.version
    print(f"Zabbix {version}")
    me = raw.call("user.get", {"output": ["userid"], "filter": {"username": user}})[0]["userid"]
    token_id = raw.call("token.create", {"name": "mcp-roundtrip-tmp", "userid": me})["tokenids"][0]
    token = raw.call("token.generate", [token_id])[0]["token"]
    cleanup = []
    unexpected = 0
    try:
        if "--fixtures" in opts:
            from roundtrip_fixtures import create_fixtures
            cleanup = create_fixtures(raw.call, version)
            print(f"fixtures: {sum(len(i) for _, i in cleanup)} objects")
        # rate_limit 0: the harness is one client making thousands of calls on purpose
        cfg = AppConfig(server=ServerConfig(timezone="UTC", response_max_chars=50_000_000, rate_limit=0),
                        zabbix_servers={"t": ZabbixServerConfig(name="t", url=url, api_token=token, read_only=False)})
        # the server class of the real thing: a call with an argument the
        # tool does not have fails here as it would for a client
        from zabbix_mcp.server import ZabbixMCPServer
        mcp = ZabbixMCPServer(name="roundtrip")
        _register_tools(mcp, ClientManager(cfg), response_max_chars=cfg.server.response_max_chars)
        tools = {t.name for t in mcp._tool_manager.list_tools()}
        total = {"plain": [0, 0], "templated": [0, 0], "discovered": [0, 0], "dependent": [0, 0]}
        reread = [0, 0, 0]   # compared, came back different, could not be read again
        not_reread: dict[str, int] = {}
        for obj, (id_field, _) in OBJECTS.items():
            if only and obj not in only:
                continue
            if unavailable_reason(f"{obj}.update", version) or unavailable_reason(f"{obj}.get", version):
                continue
            if f"{obj}_get" not in tools or f"{obj}_update" not in tools:
                print(f"  {obj}: no tool")
                continue
            extra = {k: v for k, v in _get_params(obj, version).items() if k != "output"}
            call_args = {"output": "extend", "extra_params": extra}
            if obj in INHERITING:
                call_args["extra_params"] = dict(extra, filter={"templateid": "0"})
            if id_field is not None:
                call_args["limit"] = 150
            try:
                rows = _rows(mcp, f"{obj}_get", call_args)
            except (ToolError, json.JSONDecodeError) as exc:
                print(f"  {obj}: get failed: {str(exc)[:150]}")
                unexpected += 1
                continue
            if obj in INHERITING:
                for more in ({"filter": {"templateid": "0"}, "sortfield": id_field, "sortorder": "DESC", "limit": 100},
                             {"inherited": True, "limit": 20}, {"filter": {"flags": "4"}, "limit": 10}):
                    try:
                        rows += _rows(mcp, f"{obj}_get", {"output": "extend", "extra_params": dict(extra, **more),
                                                          "limit": more["limit"]})
                    except (ToolError, json.JSONDecodeError):
                        pass
            picked: OrderedDict = OrderedDict()
            for row in rows:
                if isinstance(row, dict) and "_truncated" not in row:
                    key = (_category(obj, row), _shape(row))
                    if _is_fixture(row) and id_field is not None:
                        key += (str(row.get(id_field)),)   # every fixture, whatever its shape
                    picked.setdefault(key, row)
            counts: dict[str, list[int]] = {}
            first_err: dict[str, str] = {}
            changed_rows: list[str] = []
            for key, row in picked.items():
                cat = key[0]
                count = counts.setdefault(cat, [0, 0])
                kids_before = _children(raw, obj, id_field, row, version)
                # The object on its own, before and after: the row of a list
                # is not always what a single read returns (script.get of
                # 6.2.9 attaches actions / parameters to the wrong script
                # when several rows are read with selectActions).
                before = _reread(mcp, obj, id_field, row, extra)
                try:
                    asyncio.run(mcp.call_tool(f"{obj}_update", {"params": copy.deepcopy(row)}))
                    count[0] += 1
                    # "accepted" is not "unchanged": read it again and compare
                    again = _reread(mcp, obj, id_field, row, extra) if before is not None else None
                    if again is None:
                        # not compared is not "unchanged": it fails the run
                        reread[2] += 1
                        unexpected += 1
                        not_reread[obj] = not_reread.get(obj, 0) + 1
                    else:
                        reread[0] += 1
                        keys = _changed_keys(before, again)
                        if kids_before is not None:
                            kids_after = _children(raw, obj, id_field, row, version)
                            if kids_after is not None:
                                keys += _children_changed(kids_before, kids_after)
                        if keys:
                            reread[1] += 1
                            unexpected += 1
                            changed_rows.append(
                                f"[{id_field}={row.get(id_field)} {str(row.get('name') or row.get('host') or '')[:30]!r}] "
                                + ", ".join(keys))
                            if "--dump" in opts:
                                for k in keys:
                                    print(f"      {k}: {json.dumps(before.get(k))[:300]} -> {json.dumps(again.get(k))[:300]}")
                except ToolError as exc:
                    count[1] += 1
                    message = str(exc)
                    label = f"{id_field}={row.get(id_field)} {str(row.get('name') or row.get('key_') or row.get('description') or '')[:30]!r}"
                    first_err.setdefault(cat, f"[{label}] " + message[:420].replace("\n", " "))
                    known_row = (".".join(version.split(".")[:2]), obj, str(row.get(id_field))) in EXPECTED_ROWS
                    if cat == "plain" and not known_row and not any(e in message for e in EXPECTED):
                        unexpected += 1
                        if "--dump" in opts:
                            print("      SENT:", json.dumps(row)[:1500])
            for cat, (ok, bad) in counts.items():
                total[cat][0] += ok
                total[cat][1] += bad
            summary = " ".join(f"{cat} {ok}/{ok + bad}" for cat, (ok, bad) in counts.items())
            flag = ""
            if "plain" in first_err:
                flag = f"\n      PLAIN FAIL: {first_err['plain']}"
            elif first_err:
                cat = next(iter(first_err))
                flag = f"\n      ({cat}: {first_err[cat]})"
            for line in changed_rows:
                flag += f"\n      CHANGED AFTER ROUND TRIP: {line}"
            print(f"  {obj}: {len(rows)} rows, {summary}{flag}")
        print("TOTAL " + " ".join(f"{cat} {ok}/{ok + bad}" for cat, (ok, bad) in total.items()))
        print(f"read again after the update: {reread[0]} compared, {reread[1]} came back different, "
              f"{reread[2]} could not be read again"
              + (" (" + ", ".join(f"{o} {n}" for o, n in sorted(not_reread.items())) + ")" if not_reread else ""))
        print(f"unexpected plain failures or changes: {unexpected}")
    finally:
        if cleanup:
            from roundtrip_fixtures import delete_fixtures, deleted_report
            print(deleted_report(delete_fixtures(raw.call, cleanup)))
        raw.call("token.delete", [token_id])
        print(f"token deleted ({raw.n} setup calls)")
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
