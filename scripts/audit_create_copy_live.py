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

"""Measure what ``X.create`` refuses of a copy of what ``X.get`` returns.

"Clone this host / template / item" makes a model read the object and send
the answer to ``X.create`` with a new name. ``audit_write_roundtrip_live.py``
measures updates; a create refuses keys an update takes (``macros[].automatic``
on ``host.create``, which ``host.update`` accepts) and keys the update audit
never saw. This script creates one plain host, one template with an agent item,
an HTTP agent item, an LLD rule and a trigger, reads each back (``output``
extend plus the selects a clone needs), renames the copy and sends it to
``X.create``; on an ``unexpected parameter`` (or ``Cannot set "X"``) answer it
drops exactly that key (nested paths too: ``macros[].automatic``) and tries
again. Only keys Zabbix names are recorded. When it refuses without naming
one (``Incorrect input parameters.`` for ``auto_compress`` on 6.x, ``Incorrect
arguments passed to function`` for the interface status fields), the copy goes
through what the server already drops (``strip_for_write``,
``trim_references``) and the measurement goes on; those keys are not recorded
again, they are already in the contract from the update audit. The refused paths
are added to ``write_contracts_src/create_observed_<release>.json``, which
``build_write_contracts.py`` merges into ``api/write_contracts.json``.

Everything it creates is named ``cprobe*`` and deleted at the end. Needs a host
group named by --group (created when missing) and the template group Templates.

Usage: audit_create_copy_live.py URL TOKEN [--group NAME] [--out DIR]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from zabbix_mcp.api.write_contracts import strip_for_write  # noqa: E402
from zabbix_mcp.api.write_shapes import trim_references  # noqa: E402


class Api:
    def __init__(self, url: str, token: str) -> None:
        self.url = url.rstrip("/") + "/api_jsonrpc.php"
        self.token = token
        self.version = self._call("apiinfo.version", {}, auth=False)[0]
        self.vt = tuple(int(x) for x in self.version.split(".")[:2])

    def _call(self, method: str, params, auth: bool = True):
        body = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        headers = {"Content-Type": "application/json-rpc"}
        if auth and self.vt < (6, 4):
            body["auth"] = self.token           # no Bearer header before 6.4
        elif auth:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.url, json.dumps(body).encode(), headers)
        answer = json.loads(urllib.request.urlopen(req, timeout=60).read())
        return answer.get("result"), (answer.get("error") or {}).get("data")

    vt: tuple = (0, 0)

    def __call__(self, method: str, params):
        return self._call(method, params)

    def ok(self, method: str, params):
        result, error = self(method, params)
        if result is None:
            raise SystemExit(f"{method}: {error}")
        return result


def _drop(node, segments: list[str]) -> None:
    if not segments or not isinstance(node, dict):
        return
    if len(segments) == 1:
        node.pop(segments[0], None)
        return
    child = node.get(segments[0])
    for element in child if isinstance(child, list) else [child]:
        _drop(element, segments[1:])


def _refused_path(error: str) -> list[str] | None:
    """'Invalid parameter "/1/macros/1": unexpected parameter "automatic"' -> [macros, automatic]."""
    m = re.search(r'Invalid parameter "/1((?:/[A-Za-z_]+(?:/\d+)?)*)": unexpected parameter "([^"]+)"', error or "")
    if m:
        return [x for x in m.group(1).split("/") if x and not x.isdigit()] + [m.group(2)]
    # a refused value ("value must be empty") is no refused key: not recorded
    m = re.search(r'Cannot set "([A-Za-z_]+)" for ', error or "")
    return [m.group(1)] if m else None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url"); ap.add_argument("token")
    ap.add_argument("--group", default="Demo / Application")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "write_contracts_src"))
    a = ap.parse_args()
    z = Api(a.url, a.token)
    groups = z.ok("hostgroup.get", {"output": ["groupid"], "filter": {"name": [a.group]}})
    gid = groups[0]["groupid"] if groups else z.ok("hostgroup.create", {"name": a.group})["groupids"][0]
    tg_method = "hostgroup.get" if z.vt < (6, 2) else "templategroup.get"
    tgid = z.ok(tg_method, {"output": ["groupid"], "filter": {"name": ["Templates"]}})[0]["groupid"]

    def clean() -> None:
        for h in z.ok("host.get", {"output": ["hostid"], "search": {"host": "cprobe"}}):
            z("host.delete", [h["hostid"]])
        for t in z.ok("template.get", {"output": ["templateid"], "search": {"host": "cprobe"}}):
            z("template.delete", [t["templateid"]])

    clean()
    hid = z.ok("host.create", {"host": "cprobe", "groups": [{"groupid": gid}],
                               "interfaces": [{"type": 1, "main": 1, "useip": 1, "ip": "192.0.2.1", "dns": "", "port": "10050"}],
                               "macros": [{"macro": "{$A}", "value": "1"}], "tags": [{"tag": "t", "value": "v"}]})["hostids"][0]
    tid = z.ok("template.create", {"host": "cprobe tpl", "groups": [{"groupid": tgid}],
                                   "macros": [{"macro": "{$B}", "value": "2"}], "tags": [{"tag": "t", "value": "v"}]})["templateids"][0]
    z.ok("item.create", {"hostid": tid, "name": "u", "key_": "system.uptime", "type": 0, "value_type": 3, "delay": "1m"})
    z.ok("item.create", {"hostid": tid, "name": "h", "key_": "h.page", "type": 19, "value_type": 4, "delay": "1m", "url": "http://192.0.2.1/"})
    z.ok("discoveryrule.create", {"hostid": tid, "name": "d", "key_": "vfs.fs.discovery", "type": 0, "delay": "1h"})
    z.ok("trigger.create", {"description": "x", "expression": "last(/cprobe tpl/system.uptime)<600", "priority": 2})

    hg = "selectHostGroups" if z.vt >= (6, 2) else "selectGroups"
    tgs = "selectTemplateGroups" if z.vt >= (6, 2) else "selectGroups"

    # A copy is what a model sends: the get answer with a new name. Its own ID and the
    # IDs inside it (interfaceid, hostmacroid) stay, they are what a create refuses; only
    # the uuid goes, which would name the original, and the lists a get calls otherwise
    # are renamed (the server says so instead of renaming, write_shapes.problems).
    def host_copy(o):
        o.update(host="cprobe2", name="cprobe2")
        o["templates"] = o.pop("parentTemplates", [])
        if "hostgroups" in o:
            o["groups"] = o.pop("hostgroups")

    def template_copy(o):
        o.update(host="cprobe tpl2", name="cprobe tpl2"); o.pop("uuid", None)
        if "templategroups" in o:
            o["groups"] = o.pop("templategroups")

    def item_copy(o):
        o["key_"] += ".c"; o.pop("uuid", None)

    def lld_copy(o):
        o["key_"] = "vfs.fs.discovery[c]"; o.pop("uuid", None)

    def trigger_copy(o):
        o["description"] = "x copy"; o.pop("uuid", None)

    cases = [
        ("host.create", z.ok("host.get", {"output": "extend", "hostids": [hid], hg: "extend", "selectInterfaces": "extend",
                                          "selectMacros": "extend", "selectTags": "extend", "selectParentTemplates": ["templateid"]})[0], host_copy),
        ("template.create", z.ok("template.get", {"output": "extend", "templateids": [tid], tgs: "extend",
                                                  "selectMacros": "extend", "selectTags": "extend"})[0], template_copy),
    ]
    cases += [("item.create", o, item_copy) for o in z.ok("item.get", {"output": "extend", "templateids": [tid],
                                                                        "selectTags": "extend", "selectPreprocessing": "extend"})]
    cases += [("discoveryrule.create", o, lld_copy) for o in z.ok("discoveryrule.get", {"output": "extend", "templateids": [tid]})]
    cases += [("trigger.create", o, trigger_copy) for o in z.ok("trigger.get", {"output": "extend", "templateids": [tid],
                                                                                 "selectTags": "extend", "expandExpression": True})]
    ids = {"host.create": "hostids", "template.create": "templateids", "item.create": "itemids",
           "discoveryrule.create": "itemids", "trigger.create": "triggerids"}
    refused_by_method: dict[str, set[str]] = {}
    for method, obj, make_copy in cases:
        payload = json.loads(json.dumps(obj))
        make_copy(payload)
        refused: list[str] = []
        stripped = False
        result, error = z(method, payload)
        while result is None and len(refused) < 60:
            segments = _refused_path(error)
            path = ".".join([s + "[]" for s in segments[:-1]] + [segments[-1]]) if segments else None
            if path is None and not stripped:
                # a refusal that names no key: drop what the server drops anyway, go on
                strip_for_write(method, payload, z.version)
                trim_references(method, payload)
                stripped = True
                result, error = z(method, payload)
                continue
            if path is None or path in refused:
                print(f"  {method}: stopped on {error!r}", file=sys.stderr)
                break
            refused.append(path)
            _drop(payload, segments)
            result, error = z(method, payload)
        refused_by_method.setdefault(method, set()).update(refused)
        print(f"{z.version} {method:22} refused: {', '.join(refused) or '-'}")
        if result:
            z(method.replace(".create", ".delete"), result[ids[method]])
    clean()
    out = Path(a.out) / f"create_observed_{z.version}.json"
    # Zabbix names one refused key per answer and the order depends on the payload; after
    # an unnamed refusal the server's own rules take some keys out unmeasured. So a run adds
    # to what earlier runs on this release found (delete the file to measure from scratch).
    if out.exists():
        for method, paths in (json.loads(out.read_text(encoding="utf-8")).get("refused") or {}).items():
            refused_by_method.setdefault(method, set()).update(paths)
    out.write_text(json.dumps({"zabbix": z.version, "refused": {m: sorted(v) for m, v in sorted(refused_by_method.items())}},
                              indent=1) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
