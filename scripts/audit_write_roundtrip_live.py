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

"""Measure what ``X.update`` refuses of what ``X.get`` returns, on a running
Zabbix, for every object the server has an update tool for.

The natural model workflow is "read the object, change one thing, write it
back". For every object with ``X.get`` + ``X.update`` this script takes
sample objects from the server (``output=extend`` plus every ``selectXxx``
the get contract knows for this release), sends each one back through
``X.update`` *unchanged*, and on an ``unexpected parameter`` answer drops
exactly that key and tries again, until the update is accepted or Zabbix
answers with something else. The dropped paths, normalised
(``operations[].opconditions[].opconditionid``), are the write contract of
the release: ``scripts/build_write_contracts.py`` turns the per-release
files into ``api/write_contracts.json``.

Samples are grouped by shape (which keys are present and which nested
arrays are non-empty) so every distinct shape is probed once. Objects a
template or an LLD rule owns (``templateid`` != 0, ``flags`` = 4) are probed
in their own category, because Zabbix refuses *changing* fields on them
that it accepts on a plain object; the generic contract is built from the
plain category only.

Usage: audit_write_roundtrip_live.py URL TOKEN   (or URL USER PASSWORD)
       [--fixtures] [--only object,object] [--max-per-shape N]

``--fixtures`` first creates the ``rt-`` fixture set from
``scripts/roundtrip_fixtures.py`` (every nested structure the API has) and
deletes it at the end. Writes ``write_roundtrip_observed_<version>.json``
into the current directory. The updates send the object back unchanged, so
nothing on the server is altered; the only writes are the fixtures.
"""

from __future__ import annotations

import http.client
import json
import re
import sys
import urllib.error
import urllib.request
from collections import OrderedDict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from zabbix_mcp.api import trigger_expressions  # noqa: E402
from zabbix_mcp.api.contracts import CONTRACTS, OBJECTS as OBJECTS_SPEC  # noqa: E402
from zabbix_mcp.api.versions import unavailable_reason  # noqa: E402

# object -> (id field, extra get params). Singletons have no id: get returns
# one dict, update takes it back.
OBJECTS: dict[str, tuple[str | None, dict]] = {
    "action": ("actionid", {}),
    "authentication": (None, {}),
    "autoregistration": (None, {}),
    "connector": ("connectorid", {}),
    "correlation": ("correlationid", {}),
    "dashboard": ("dashboardid", {}),
    "discoveryrule": ("itemid", {}),
    "discoveryruleprototype": ("itemid", {}),
    "drule": ("druleid", {}),
    "graph": ("graphid", {}),
    "graphprototype": ("graphid", {}),
    "host": ("hostid", {}),
    "hostgroup": ("groupid", {}),
    "hostinterface": ("interfaceid", {}),
    "hostprototype": ("hostid", {}),
    "housekeeping": (None, {}),
    "httptest": ("httptestid", {}),
    "iconmap": ("iconmapid", {}),
    "image": ("imageid", {"select_image": True}),
    "item": ("itemid", {}),
    "itemprototype": ("itemid", {}),
    "maintenance": ("maintenanceid", {}),
    "map": ("sysmapid", {}),
    "mediatype": ("mediatypeid", {}),
    "mfa": ("mfaid", {}),
    "module": ("moduleid", {}),
    "proxy": ("proxyid", {}),
    "proxygroup": ("proxy_groupid", {}),
    "regexp": ("regexpid", {}),
    "report": ("reportid", {}),
    "role": ("roleid", {}),
    "script": ("scriptid", {}),
    "service": ("serviceid", {}),
    "ceprule": ("cep_ruleid", {}),
    "settings": (None, {}),
    "sla": ("slaid", {}),
    "template": ("templateid", {}),
    "templatedashboard": ("dashboardid", {}),
    "templategroup": ("groupid", {}),
    "token": ("tokenid", {}),
    # read as stored and rebuilt by _fetch: Zabbix's own expandExpression puts the
    # value of every user macro in, and this script sends what it reads back
    "trigger": ("triggerid", {}),
    "triggerprototype": ("triggerid", {}),
    "user": ("userid", {}),
    "userdirectory": ("userdirectoryid", {}),
    "usergroup": ("usrgrpid", {}),
    "usermacro": ("hostmacroid", {}),
    "valuemap": ("valuemapid", {}),
}

# Objects whose ``templateid`` names the parent they inherit from (a
# template's own item has templateid 0 and is "plain").
INHERITING = {"item", "trigger", "graph", "discoveryrule", "httptest", "itemprototype",
              "triggerprototype", "graphprototype", "hostprototype", "discoveryruleprototype"}

_CANNOT_UPDATE = re.compile(r'Cannot update "([^"]+)" for ')
# 7.0 returns both the deprecated and the new name of a renamed field
# (mediatype content_type / message_format, usergroup rights /
# hostgroup_rights) and refuses them together on write.
_DEPRECATED = re.compile(r'Deprecated parameter "([^"]*)" cannot be used with "([^"]*)"')
_UNEXPECTED = re.compile(r'Invalid parameter "([^"]*)": unexpected parameter "([^"]+)"\.?')
_SHOULD_BE_EMPTY = re.compile(r'Invalid parameter "([^"]*)": (should be empty|cannot be (?:updated|changed)|value must be empty)')
_SEGMENT = re.compile(r"^\d+$")


class Api:
    def __init__(self, url: str, token: str | None, user: str | None, password: str | None):
        self.url = url.rstrip("/") + "/api_jsonrpc.php"
        self.token = token
        self.n = 0
        self.version = self.call("apiinfo.version", {}, auth=False)
        major_minor = tuple(int(x) for x in self.version.split(".")[:2])
        self.header_auth = major_minor >= (6, 4)
        if not token:
            field = "username" if major_minor >= (5, 4) else "user"
            self.token = self.call("user.login", {field: user, "password": password}, auth=False)

    def call(self, method: str, params, auth: bool = True):
        self.n += 1
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": self.n}
        headers = {"Content-Type": "application/json-rpc"}
        if auth and self.token:
            if self.header_auth:
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                payload["auth"] = self.token
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise ApiError(f"HTTP {e.code}", "") from None
        except (http.client.IncompleteRead, urllib.error.URLError, TimeoutError, OSError) as e:
            # PHP cut the answer (memory / execution time): same fallback as a 500
            raise ApiError(f"HTTP read failed: {type(e).__name__}", "") from None
        if "error" in data:
            raise ApiError(data["error"].get("message", ""), data["error"].get("data", ""))
        return data["result"]


class ApiError(RuntimeError):
    def __init__(self, message: str, data: str):
        super().__init__(f"{message} {data}")
        self.message, self.data = message, data


def _get_params(obj: str, version: str) -> dict:
    params: dict = {"output": "extend"}
    contract = CONTRACTS.get(f"{obj}.get")
    if contract:
        for name, spec in contract.selects.items():
            # "query" selects take "extend"; the others want their own
            # object (service.get selectStatusTimeline wants periods)
            if spec.available(version) and spec.type == "query":
                params[name] = "extend"
    params.update(OBJECTS[obj][1])
    return params


def _fetch(api: Api, obj: str, params: dict) -> list:
    """The objects to send back, trigger expressions in the form that can be written
    (function calls written out, user macros kept: api/trigger_expressions.py)."""
    rows = _fetch_stored(api, obj, params)
    if f"{obj}.get" in trigger_expressions.METHODS:
        trigger_expressions.rewrite(rows, f"{obj}.get", api.call)
    return rows


def _fetch_stored(api: Api, obj: str, params: dict) -> list:
    """Plain objects (``templateid`` 0: the first 500 and the newest 100,
    which is where the fixtures are) plus a bounded sample of the rest, so
    a box with ten thousand templated items stays cheap."""
    if obj not in INHERITING:
        return _get_with_fallback(api, obj, params)
    id_field = OBJECTS[obj][0]
    rows: list = []
    seen: set = set()
    for extra in ({"filter": {"templateid": "0"}, "limit": 500},
                  # the newest plain objects: where the fixtures are. Without this
                  # batch a box with thousands of template items never reaches them
                  # (the first 500 by id are all stock).
                  {"filter": {"templateid": "0"}, "sortfield": id_field, "sortorder": "DESC", "limit": 100},
                  {"inherited": True, "limit": 60},
                  {"filter": {"flags": "4"}, "limit": 40}):
        try:
            batch = _get_with_fallback(api, obj, dict(params, **extra))
        except ApiError as e:
            print(f"  {obj}.get {extra}: {e}", file=sys.stderr)
            continue
        for r in batch:
            if r.get(id_field) not in seen:
                seen.add(r.get(id_field))
                rows.append(r)
    return rows


def _get_with_fallback(api: Api, obj: str, params: dict) -> list:
    """A get with every select on a big box can exhaust PHP memory (HTTP
    500); fall back to a bounded sample, then to a sample without the
    selects that pull whole sub-objects."""
    attempts = [params, dict(params, limit=100), dict(params, limit=20)]
    slim = {k: v for k, v in params.items() if not k.startswith("select")}
    attempts.append(dict(slim, limit=20))
    last = None
    for p in attempts:
        try:
            return api.call(f"{obj}.get", p)
        except ApiError as e:
            if not e.message.startswith("HTTP"):
                raise
            last = e
            print(f"  {obj}.get {e.message}, retrying smaller", file=sys.stderr)
    raise last


def _shape(value, depth: int = 0) -> str:
    """Keys present and which nested arrays are non-empty, two levels deep."""
    if isinstance(value, dict):
        if depth >= 2:
            return "{}"
        return "{" + ",".join(f"{k}:{_shape(v, depth + 1)}" for k, v in sorted(value.items())) + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        return "[" + _shape(value[0], depth + 1) + "]"
    return "."


def _category(obj: str, row: dict) -> str:
    if str(row.get("flags", "0")) == "4":
        return "discovered"
    if obj in INHERITING and str(row.get("templateid", "0")) not in ("0", ""):
        return "templated"
    if obj in ("item", "discoveryrule", "itemprototype", "discoveryruleprototype") and str(row.get("type")) == "18":
        return "dependent"
    return "plain"


def _drop(payload, path: str) -> bool:
    """Drop the key named by a Zabbix error path (``/1/operations/2/opconditions/1/opconditionid``).

    The leading ``/1`` is Zabbix wrapping the single object into an array;
    further numeric segments are 1-based list indexes."""
    segments = [s for s in path.split("/") if s]
    if segments and _SEGMENT.match(segments[0]):
        segments = segments[1:]
    node = payload
    for seg in segments[:-1]:
        if isinstance(node, list):
            if not _SEGMENT.match(seg):
                return False
            idx = int(seg) - 1
            if idx < 0 or idx >= len(node):
                return False
            node = node[idx]
        elif isinstance(node, dict):
            if seg not in node:
                return False
            node = node[seg]
        else:
            return False
    last = segments[-1] if segments else None
    if last is None:
        return False
    if isinstance(node, dict) and last in node:
        del node[last]
        return True
    if isinstance(node, list) and _SEGMENT.match(last):
        idx = int(last) - 1
        if 0 <= idx < len(node):
            del node[idx]
            return True
    return False


def _drop_siblings(payload, segments: list[str]) -> None:
    """After ``users/3/name`` was refused, ``users/1/name`` and ``users/2/name``
    will be too: drop the key from every element of every list on the path,
    which keeps the number of rounds proportional to the number of distinct
    keys, not rows."""
    def walk(node, rest):
        if not rest:
            return
        if len(rest) == 1:
            if isinstance(node, dict):
                node.pop(rest[0], None)
            return
        seg = rest[0]
        if isinstance(node, list):
            for child in node:
                walk(child, rest[1:] if _SEGMENT.match(seg) else rest)
        elif isinstance(node, dict) and seg in node:
            walk(node[seg], rest[1:])
    # numeric segments stand for "every element" here
    walk(payload, segments)


def _rows_with(value, prefix: str = "", out: dict | None = None) -> dict:
    """How many rows (dicts) carry each key path pattern: a key refused on
    every row that has it is read-only; a key refused on some rows only
    depends on the row's values (a maintenance time period's ``start_date``
    is refused on a daily period and required on a one-time one)."""
    if out is None:
        out = {}
    if isinstance(value, dict):
        for k, v in value.items():
            path = f"{prefix}.{k}" if prefix else k
            out[path] = out.get(path, 0) + 1
            _rows_with(v, path, out)
    elif isinstance(value, list):
        for v in value:
            _rows_with(v, prefix + "[]", out)
    return out


def _present_paths(value, prefix: str = "", out: set | None = None) -> set:
    """Every key path pattern present in a get result."""
    if out is None:
        out = set()
    if isinstance(value, dict):
        for k, v in value.items():
            path = f"{prefix}.{k}" if prefix else k
            out.add(path)
            _present_paths(v, path, out)
    elif isinstance(value, list):
        for v in value:
            _present_paths(v, prefix + "[]", out)
    return out


def _pattern(path: str, key: str | None) -> str:
    segments = [s for s in path.split("/") if s]
    if segments and _SEGMENT.match(segments[0]):
        segments = segments[1:]
    out = []
    for seg in segments:
        if _SEGMENT.match(seg):
            if out:
                out[-1] += "[]"
        else:
            out.append(seg)
    if key:
        out.append(key)
    return ".".join(out) if out else "(root)"


def probe(api: Api, obj: str, row: dict, id_field: str | None, max_rounds: int = 800) -> dict:
    """Send *row* back through ``obj.update`` until it is accepted."""
    payload = json.loads(json.dumps(row))
    rows_with = _rows_with(row)
    dropped: list[dict] = []

    def finish(status: str, **extra) -> dict:
        # one record per pattern; "unexpected" only when every row that had
        # the key was refused with it, else the refusal depends on the row
        by_pattern: dict[str, dict] = {}
        for d in dropped:
            e = by_pattern.setdefault(d["path"], {"path": d["path"], "kind": d["kind"], "n": 0})
            e["n"] += 1
        out = []
        for e in by_pattern.values():
            if e["kind"] == "unexpected" and e["n"] < rows_with.get(e["path"], 1):
                e["kind"] = "row-dependent"
            out.append({"path": e["path"], "kind": e["kind"]})
        return {"status": status, "dropped": out, **extra}

    for _ in range(max_rounds):
        try:
            api.call(f"{obj}.update", payload)
            return finish("ok")
        except ApiError as e:
            m = _UNEXPECTED.search(e.data)
            if m:
                path, key = m.group(1), m.group(2)
                full = path.rstrip("/") + "/" + key
                if not _drop(payload, full):
                    return finish("stuck", error=e.data)
                dropped.append({"path": _pattern(path, key), "kind": "unexpected"})
                continue
            m = _SHOULD_BE_EMPTY.search(e.data)
            if m:
                path = m.group(1)
                if not _drop(payload, path):
                    return finish("stuck", error=e.data)
                dropped.append({"path": _pattern(path, None), "kind": m.group(2)})
                continue
            m = _DEPRECATED.search(e.data)
            if m:
                path = m.group(1)
                if not _drop(payload, path):
                    return finish("stuck", error=e.data)
                # refused only next to its successor: the contract keeps the
                # sibling's name so the strip stays conditional
                dropped.append({"path": _pattern(path, None), "kind": "deprecated:" + _pattern(m.group(2), None)})
                continue
            m = _CANNOT_UPDATE.search(e.data)
            if m and m.group(1) in payload:
                del payload[m.group(1)]
                dropped.append({"path": m.group(1), "kind": "cannot be updated"})
                continue
            # An error that names no parameter ("Incorrect arguments passed to
            # function."): find the top-level key that causes it by leaving
            # each one out in turn.
            culprits = _bisect(api, obj, payload, id_field, e.data)
            if not culprits:
                return finish("stuck", error=e.data)
            for segments in culprits:
                _drop_siblings(payload, segments)
                dropped.append({"path": ".".join(seg if i == 0 or not _SEGMENT.match(seg) else "" for i, seg in enumerate(segments)).replace("..", "[]."),
                                "kind": f"opaque: {e.data[:120]}"})
    return finish("stuck", error="too many rounds")


def _bisect(api: Api, obj: str, payload: dict, id_field: str | None, error: str) -> list[list[str]]:
    """Which keys cause an error that names no parameter. Zabbix raises
    ``Incorrect arguments passed to function.`` for *any one* of several
    read-only keys (hostinterface ``available`` / ``error`` / ``errors_from``
    / ``disable_until``), so leaving one out at a time proves nothing: each
    key is tried alone next to the id, and a key that reproduces the very
    same error on its own is a culprit. When no top-level key does, the
    cause sits inside a nested list or object, and the nested keys are
    tried the same way (the key removed from every element)."""
    def same_error(trial) -> bool:
        try:
            api.call(f"{obj}.update", trial)
            return False
        except ApiError as e:
            return e.data == error

    base = {id_field: payload[id_field]} if id_field else {}
    top = [key for key in payload if key != id_field and same_error(dict(base, **{key: payload[key]}))]
    candidates = top or [key for key in payload if key != id_field]
    culprits: list[list[str]] = []
    for key in candidates:
        value = payload[key]
        sample = value[0] if isinstance(value, list) and value and isinstance(value[0], dict) else value if isinstance(value, dict) else None
        nested: list[list[str]] = []
        if isinstance(sample, dict):
            # each nested key alone (next to the id-like keys of its row)
            for sub in list(sample):
                def slim(row):
                    return {k: v for k, v in row.items() if k == sub or k.endswith("id")}
                trial = dict(base)
                trial[key] = [slim(r) for r in value if isinstance(r, dict)] if isinstance(value, list) else slim(value)
                if same_error(trial):
                    nested.append([key, "1", sub] if isinstance(value, list) else [key, sub])
        # every nested key alone reproduces it: the whole key is foreign to
        # the update (a select echo); only some: those keys are read-only
        if nested and len(nested) < len(sample):
            culprits.extend(nested)
        elif key in top:
            culprits.append([key])
    return culprits


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    opts = [a for a in argv if a.startswith("--")]
    if len(args) == 2:
        api = Api(args[0], args[1], None, None)
    elif len(args) == 3:
        api = Api(args[0], None, args[1], args[2])
    else:
        raise SystemExit(__doc__)
    only = None
    max_per_shape = 1
    for o in opts:
        if o.startswith("--only="):
            only = set(o[7:].split(","))
        if o.startswith("--max-per-shape="):
            max_per_shape = int(o[16:])
    version = api.version
    print(f"Zabbix {version}")

    cleanup = []
    if "--fixtures" in opts:
        from roundtrip_fixtures import create_fixtures, delete_fixtures  # noqa: E402
        cleanup = create_fixtures(api.call, version)
        print(f"fixtures: {sum(len(ids) for _, ids in cleanup)} objects")

    result = {"zabbix": version, "objects": {}}
    try:
        for obj, (id_field, _) in OBJECTS.items():
            if only and obj not in only:
                continue
            if unavailable_reason(f"{obj}.update", version) or unavailable_reason(f"{obj}.get", version):
                continue
            params = _get_params(obj, version)
            try:
                rows = _fetch(api, obj, params)
            except ApiError as e:
                print(f"  {obj}.get failed: {e}", file=sys.stderr)
                result["objects"][obj] = {"error": str(e)}
                continue
            if isinstance(rows, dict):
                rows = [rows]
            if not rows:
                result["objects"][obj] = {"samples": 0}
                print(f"  {obj}: no rows")
                continue
            # one probe per (category, shape)
            picked: OrderedDict[tuple, list] = OrderedDict()
            for row in rows:
                key = (_category(obj, row), _shape(row))
                picked.setdefault(key, [])
                if len(picked[key]) < max_per_shape:
                    picked[key].append(row)
            entries = []
            for (cat, _), sample in picked.items():
                for row in sample:
                    label = row.get(id_field) if id_field else "singleton"
                    r = probe(api, obj, row, id_field)
                    r["present"] = _present_paths(row)
                    r["category"] = cat
                    r["id"] = label
                    r["name"] = row.get("name") or row.get("key_") or row.get("description") or row.get("username") or row.get("alias") or ""
                    entries.append(r)
            # per path: how often it was refused, and in how many *completed*
            # probes it was present (a probe that got stuck may not have
            # reached every refused key, so it cannot vouch for acceptance)
            paths: dict[str, dict] = {}
            for e in entries:
                for d in e["dropped"]:
                    p = paths.setdefault(d["path"], {"kind": d["kind"], "categories": {}, "count": 0, "present": 0})
                    cat = p["categories"].setdefault(e["category"], {"refused": 0, "present": 0})
                    p["count"] += 1
                    if e["status"] == "ok":
                        cat["refused"] += 1
            for e in entries:
                if e["status"] != "ok":
                    continue
                for path in e["present"]:
                    if path in paths and e["category"] in paths[path]["categories"]:
                        paths[path]["categories"][e["category"]]["present"] += 1
                        paths[path]["present"] += 1
            stuck = [e for e in entries if e["status"] != "ok"]
            result["objects"][obj] = {
                "samples": len(entries),
                "rows": len(rows),
                "ok": len(entries) - len(stuck),
                "paths": {p: {"kind": v["kind"], "categories": v["categories"], "count": v["count"],
                              "present": v["present"]}
                          for p, v in sorted(paths.items())},
                "stuck": [{"id": e["id"], "category": e["category"], "name": e["name"], "error": e.get("error"),
                           "dropped": [d["path"] for d in e["dropped"]]} for e in stuck],
            }
            flag = "" if not stuck else f"  STUCK {len(stuck)}"
            print(f"  {obj}: {len(rows)} rows, {len(entries)} probed, {len(paths)} refused paths{flag}")
    finally:
        if cleanup:
            from roundtrip_fixtures import delete_fixtures, deleted_report  # noqa: E402
            print(deleted_report(delete_fixtures(api.call, cleanup)))

    out = Path(f"write_roundtrip_observed_{version}.json")
    if only and out.exists():
        # a partial run (--only) refreshes those objects in the existing file
        previous = json.loads(out.read_text(encoding="utf-8"))
        if previous.get("zabbix") == version:
            previous["objects"].update(result["objects"])
            result = previous
    out.write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out} ({api.n} API calls)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
