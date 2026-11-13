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

"""Measure which fields each ``selectXxx`` of each get method returns (#106).

For every get method of the catalog that the release has, and every select of
it the release has:

1. The select is sent as a list with a name no object has. Most selects check
   the list and refuse it with ``value must be one of "a", "b", ...``: that
   list is the exact set of fields the list form takes (``strict``), whether or
   not the server has any object under the select. It is smaller than what
   ``"extend"`` returns (``selectHosts`` of ``hostgroup.get`` returns
   ``active_available`` and refuses it in a list).
2. A select that fails the whole read on the unknown name (an internal "field
   ... does not exist", ``selectTags`` on 6.0 and 5.x) takes exactly what it
   returns: measured as in 3., recorded as strict.
3. A select that takes the unknown name (it ignores it) has no list of its own:
   the method is called with ``output: "extend"`` alone and with the select set
   to ``"extend"``, and the fields of the objects the second answer adds are
   recorded (``returned``), when the server had any; otherwise the select is
   not measured and the server keeps it open in the schema.

Run it after ``roundtrip_fixtures.py --keep`` for a server with something
under most selects.

The result goes to ``select_fields_src/select_fields_<release>.json``;
``build_select_fields.py`` merges the releases into ``api/select_fields.json``.

Usage: audit_select_fields_live.py URL TOKEN [--out DIR]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from zabbix_mcp.api.contracts import CONTRACTS  # noqa: E402
from zabbix_mcp.api.versions import unavailable_reason  # noqa: E402

LIMIT = 200


class Api:
    def __init__(self, url: str, token: str) -> None:
        self.url = url.rstrip("/") + "/api_jsonrpc.php"
        self.token = token
        self.vt = (0, 0)
        self.version = self._call("apiinfo.version", {}, auth=False)[0]
        self.vt = tuple(int(x) for x in self.version.split(".")[:2])

    def _call(self, method: str, params, auth: bool = True):
        body = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        headers = {"Content-Type": "application/json-rpc"}
        if auth and self.vt < (6, 4):
            body["auth"] = self.token          # no Bearer header before 6.4
        elif auth:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.url, json.dumps(body).encode(), headers)
        try:
            answer = json.loads(urllib.request.urlopen(req, timeout=120).read() or b"{}")
        except (ValueError, OSError) as exc:          # an empty or broken answer
            return None, f"no JSON answer ({type(exc).__name__})"
        return answer.get("result"), (answer.get("error") or {}).get("data")

    def __call__(self, method: str, params):
        return self._call(method, params)


def _rows(result) -> list[dict]:
    if isinstance(result, dict):
        result = list(result.values())
    return [r for r in result if isinstance(r, dict)] if isinstance(result, list) else []


def _objects(value) -> list[dict]:
    if isinstance(value, dict):
        # a keyed answer (preservekeys) or one object (inventory, discoveryRule)
        inner = list(value.values())
        if inner and all(isinstance(v, dict) for v in inner) and not any(isinstance(v, (str, int)) for v in inner):
            return inner
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


_PROBE = "zz_no_such_field"
# "value must be one of "a", "b"" or, with one value, "value must be "groupid""
_ONE_OF = re.compile(r'value must be (?:one of )?(".+?)\.?$')


def measure(z: Api) -> dict:
    out: dict[str, dict] = {}
    for method, contract in sorted(CONTRACTS.items()):
        if not contract.selects or unavailable_reason(method, z.version):
            continue
        base = None
        selects: dict[str, dict] = {}
        for name, spec in sorted(contract.selects.items()):
            if not spec.available(z.version):
                continue
            res, err = z(method, {"output": [], name: [_PROBE], "limit": 1})
            m = _ONE_OF.search(str(err or "")) if res is None else None
            # the path names the select, or "/output/1": some selects check their list as
            # the output of the query behind them (the probe's own output is empty)
            if m and (f"/{name}" in str(err) or '"/output/1"' in str(err)):
                fields = set(re.findall(r'"([^"]+)"', m.group(1)))
                # a select behind several queries (selectGroups on 7.0: host and template
                # groups) names the list of the first one that refuses; the list is sent
                # back until it is taken, keeping what every query takes
                for _ in range(5):
                    res2, err2 = z(method, {"output": [], name: sorted(fields), "limit": 1})
                    m2 = _ONE_OF.search(str(err2 or "")) if res2 is None else None
                    if res2 is not None or not m2:
                        break
                    fields &= set(re.findall(r'"([^"]+)"', m2.group(1)))
                entry = {"measured": True, "strict": True, "fields": sorted(fields)}
                if res2 is None:
                    entry["list_error"] = str(err2)[:200]
                selects[name] = entry
                continue
            fails_on_unknown = res is None and "does not exist" in str(err or "")
            if res is None and not fails_on_unknown:
                # not a projection of fields (selectStatusTimeline takes periods) or refused
                selects[name] = {"measured": False, "error": str(err)[:200]}
                continue
            if base is None:
                b, _ = z(method, {"output": "extend", "limit": LIMIT})
                base = set().union(*[set(r) for r in _rows(b)]) if _rows(b) else set()
            res, err = z(method, {"output": "extend", name: "extend", "limit": LIMIT})
            rows = _rows(res)
            added = set().union(*[set(r) for r in rows]) - base if rows else set()
            fields: set[str] = set()
            for row in rows:
                for key in added:
                    for obj in _objects(row.get(key)):
                        fields.update(obj)
            # a select that fails the whole read on an unknown name (selectTags on 6.0 and
            # 5.x: "field host_tag.zz... does not exist", an internal error) takes exactly
            # what it returns: as strict as a checked list, measured from "extend"
            entry: dict = {"measured": bool(fields), "strict": bool(fields) and fails_on_unknown}
            if fails_on_unknown:
                entry["fails_on_unknown"] = True
            if fields:
                entry["fields"] = sorted(fields)
            selects[name] = entry
        out[method] = selects
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("token")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "select_fields_src"))
    a = ap.parse_args()
    z = Api(a.url, a.token)
    result = measure(z)
    n_sel = sum(len([s for s in m if not s.startswith("_")]) for m in result.values())
    n_meas = sum(1 for m in result.values() for s, e in m.items() if isinstance(e, dict) and e.get("measured"))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"select_fields_{z.version}.json"
    path.write_text(json.dumps({"zabbix": z.version, "methods": result}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{z.version}: {len(result)} methods, {n_sel} selects, {n_meas} measured -> {path}")


if __name__ == "__main__":
    main()
