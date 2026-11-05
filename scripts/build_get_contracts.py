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

"""Merge the per-batch get-contract catalogs into ``api/get_contracts.json``.

Input: one or more JSON files of the shape
``{"methods": {...}, "objects": {...}, "sources": [...]}`` collected from the
Zabbix API reference pages (5.0 ... 8.0). Output: a single, normalised and
sorted file the server loads at import (``zabbix_mcp.api.contracts``).

    python3 scripts/build_get_contracts.py catalog_1.json catalog_2.json ... \
        [--observed get_contracts_observed_7.4.14.json ...]

``--observed`` files come from ``scripts/audit_get_contracts_live.py``: the
properties a real server returns (or accepts in ``output``) that the reference
pages do not list, and the catalogued properties a strict method refuses in
``output``. The former are added with an ``observed`` tag (available on every
release, since nobody documented when they appeared), the latter are tagged
``no_output`` so ``output`` validation leaves them out.

The script refuses inconsistent input (an object described twice with
different properties, a method without its object, a since/removed value
that is not a known release) so a bad batch never reaches the package.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RELEASES = ("5.0", "5.2", "5.4", "6.0", "6.2", "6.4", "7.0", "7.2", "7.4", "8.0")
OUT = Path(__file__).resolve().parent.parent / "src" / "zabbix_mcp" / "api" / "get_contracts.json"


def _version(value, where):
    if value in (None, "", "null"):
        return None
    value = str(value)
    if value not in RELEASES:
        raise SystemExit(f"{where}: unknown release {value!r}")
    return value


def _spec(raw: dict, where: str, *, prop: bool) -> dict:
    out = {"type": str(raw.get("type") or "").strip()}
    since = _version(raw.get("since"), where)
    removed = _version(raw.get("removed"), where)
    if since:
        out["since"] = since
    if removed:
        out["removed"] = removed
    if prop and raw.get("readonly"):
        out["readonly"] = True
    deprecated = _version(raw.get("deprecated"), where)
    if deprecated:
        out["deprecated"] = deprecated
        if raw.get("replaced_by"):
            out["replaced_by"] = str(raw["replaced_by"])
    if raw.get("values"):
        out["values"] = {str(k): str(v) for k, v in raw["values"].items()}
    if raw.get("default") not in (None, ""):
        out["default"] = str(raw["default"])
    return out


def main(argv: list[str]) -> None:
    paths, observed_paths = [], []
    bucket = paths
    for a in argv:
        if a == "--observed":
            bucket = observed_paths
            continue
        bucket.append(a)
    methods: dict[str, dict] = {}
    objects: dict[str, dict] = {}
    sources: list[str] = []
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for name, raw in (data.get("methods") or {}).items():
            if name in methods:
                raise SystemExit(f"{path}: method {name} already defined")
            common = sorted(set(raw.get("common") or []))
            methods[name] = {
                "object": raw.get("object") or name.split(".")[0],
                "sortfield": list(raw.get("sortfield") or []),
                "sortfield_versions": {f: _spec(r, f"{name}.sortfield.{f}", prop=False)
                                       for f, r in sorted((raw.get("sortfield_versions") or {}).items())},
                "common": common,
                "params": {p: _spec(r, f"{name}.params.{p}", prop=False)
                           for p, r in sorted((raw.get("params") or {}).items())},
                "selects": {p: _spec(r, f"{name}.selects.{p}", prop=False)
                            for p, r in sorted((raw.get("selects") or {}).items())},
                "filter_props": raw.get("filter_props"),
                "search_props": raw.get("search_props"),
                "notes": list(raw.get("notes") or []),
            }
        for name, raw in (data.get("objects") or {}).items():
            props = {p: _spec(r, f"object {name}.{p}", prop=True)
                     for p, r in sorted((raw.get("props") or {}).items())}
            if name in objects and objects[name]["props"] != props:
                raise SystemExit(f"{path}: object {name} differs from an earlier batch")
            objects[name] = {"props": props, "notes": list(raw.get("notes") or [])}
        sources.extend(data.get("sources") or [])

    # Observations from real servers. ``returned`` (every key output=extend gave
    # back, per object and release) dates an undocumented property: it exists
    # from the release after the last probed release that lacked it, and is
    # gone from the first probed release that lacked it after it was seen.
    probes: dict[str, dict[str, set]] = {}   # object -> release -> keys returned
    obs_types: dict[tuple[str, str], str] = {}
    flags: dict[tuple[str, str], set] = {}
    for path in observed_paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        release = ".".join(str(data.get("zabbix")).split(".")[:2])
        if release not in RELEASES:
            raise SystemExit(f"{path}: unknown release {release}")
        for obj, keys in (data.get("returned") or {}).items():
            probes.setdefault(obj, {})[release] = set(keys)
        for obj, props in (data.get("observed") or {}).items():
            for prop, raw in props.items():
                obs_types.setdefault((obj, prop), raw.get("type") or "")
        for key, flag in (("not_output", "no_output"), ("not_filter", "no_filter"), ("not_search", "no_search")):
            for obj, props in (data.get(key) or {}).items():
                for prop in props:
                    flags.setdefault((obj, prop), set()).add(flag)
    for obj, by_release in probes.items():
        if obj not in objects:
            raise SystemExit(f"observed object {obj} is not in the catalog")
        existing = objects[obj]["props"]
        releases = sorted(by_release, key=RELEASES.index)
        seen_props = set().union(*by_release.values())
        # an object introduced in release X (every documented property is X+)
        # cannot have an undocumented property from before X
        floors = [p.get("since") for p in existing.values() if not p.get("removed")]
        floor = min(floors, key=RELEASES.index) if floors and all(floors) else None
        for prop in sorted(seen_props - set(existing)):
            present = [r for r in releases if prop in by_release[r]]
            absent_before = [r for r in releases if RELEASES.index(r) < RELEASES.index(present[0]) and prop not in by_release[r]]
            absent_after = [r for r in releases if RELEASES.index(r) > RELEASES.index(present[-1]) and prop not in by_release[r]]
            entry = {"type": obs_types.get((obj, prop), ""), "observed": ",".join(present)}
            if absent_before:
                entry["since"] = RELEASES[RELEASES.index(absent_before[-1]) + 1]
            elif floor:
                entry["since"] = floor
            if absent_after:
                entry["removed"] = absent_after[0]
            existing[prop] = entry
            objects[obj]["notes"].append(
                f"{prop}: not on the reference page, returned by Zabbix {', '.join(present)}")
        objects[obj]["props"] = dict(sorted(existing.items()))
    for (obj, prop), flagset in flags.items():
        if prop in objects.get(obj, {}).get("props", {}):
            for flag in sorted(flagset):
                objects[obj]["props"][prop][flag] = True

    for name, m in methods.items():
        if m["object"] not in objects:
            raise SystemExit(f"method {name}: object {m['object']} has no property list")
        for s in m["selects"]:
            if not s.startswith("select"):
                raise SystemExit(f"method {name}: {s} is not a selectXxx parameter")
        for f in m["sortfield"]:
            if f not in objects[m["object"]]["props"] and m["object"] not in ("history", "trend"):
                print(f"note: {name} sortfield {f!r} is not a listed {m['object']} property", file=sys.stderr)

    out = {
        "_comment": "Generated by scripts/build_get_contracts.py from the Zabbix API reference (5.0-8.0). Do not edit by hand.",
        "methods": dict(sorted(methods.items())),
        "objects": dict(sorted(objects.items())),
        "sources": sorted(set(sources)),
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{OUT}: {len(methods)} methods, {len(objects)} objects, "
          f"{sum(len(o['props']) for o in objects.values())} properties")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    main(sys.argv[1:])
