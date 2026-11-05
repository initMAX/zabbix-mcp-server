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
"""Compare the Zabbix API reference of one release with what the server ships.

Reads every object page and every method page of the reference
(``https://www.zabbix.com/documentation/<release>/en/manual/api/reference``)
and reports where the tool catalog (``zabbix_mcp.api.ALL_METHODS``), the
version table (``api/versions.py``) and the get contracts
(``api/get_contracts.json``) disagree with it:

* a documented method without a tool, or a tool the table says the release
  has but the reference does not list;
* a parameter, ``selectXxx``, sort field or object property the reference
  lists and the contract does not offer on that release, and the reverse;
* a property whose read-only mark differs, a ``selectXxx`` the page calls
  deprecated that the contract does not mark (and the reverse).

    python3 scripts/audit_api_reference.py 8.0 [--cache DIR] [--verbose]

``--cache DIR`` keeps the fetched pages (``<release>_<object>.html``,
``<release>_<object>_<method>.html``) and reuses them on the next run, so
the pages are downloaded once. Exit status 1 when anything differs.

The reference is not the last word: a row listed under "known" below is a
place where the reference is wrong or silent and a live server was asked
instead (see ``scripts/audit_api_frontend.py`` for the methods a frontend
exposes that the reference never mentions).
"""

from __future__ import annotations

import html
import re
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from zabbix_mcp.api import ALL_METHODS  # noqa: E402
from zabbix_mcp.api.contracts import OBJECTS, contract_for  # noqa: E402
from zabbix_mcp.api.versions import deprecated_reason, parse_version, unavailable_reason  # noqa: E402

BASE = "https://www.zabbix.com/documentation/{release}/en/manual/api/reference"
COMMON = {"countOutput", "editable", "excludeSearch", "filter", "limit", "output", "preservekeys", "search",
          "searchByAny", "searchWildcardsEnabled", "sortfield", "sortorder", "startSearch", "limitSelects"}
# pages under an object that are not methods
NOT_METHODS = {"object", "widget_fields"}

# On no page of any release, in the option table of two dozen get() classes
# and honoured by a live server (6.0 to 8.0): the source audit
# (scripts/audit_api_sources.py) is what checks these, method by method.
UNDOCUMENTED_EVERYWHERE = (" param groupCount: in the contract, not on the ",)

# Where the reference and a live server disagree, the server wins. Each entry
# was checked against a running frontend of that release.
KNOWN: dict[str, set[str]] = {
    "8.0": {
        # the reference lists "discovered", every 8.0 server accepts "discover" only
        # ("Sorting by field "discovered" not allowed" on 8.0.0)
        "graphprototype.get sortfield discovered", "hostprototype.get sortfield discovered",
        "itemprototype.get sortfield discovered", "triggerprototype.get sortfield discovered",
        "graphprototype.get sortfield discover", "hostprototype.get sortfield discover",
        "itemprototype.get sortfield discover", "triggerprototype.get sortfield discover",
        # exposed by the frontend since 7.0, never documented (scripts/audit_api_frontend.py)
        "hostdashboard.get: tool offered",
        # "Sorting by field "status" not allowed" on a live 8.0
        "template.get sortfield status",
        # the global macro table of the usermacro page, catalogued as its own object
        "usermacro prop globalmacroid",
        # taken by the API classes of the 8.0.0 frontend and verified on a live
        # server, absent from the pages (scripts/audit_api_sources.py reads the
        # options and sort columns of every get() out of the source)
        "apmlog.get param severity_numbers", "dashboard.get sortfield name", "dcheck.get param limitSelects",
        "discoveryrule.get select selectDiscoveryRule", "discoveryruleprototype.get select selectDiscoveryData",
        "discoveryruleprototype.get sortfield discover", "sla.get param evaltype", "sla.get param service_tags",
        "triggerprototype.get param itemids", "user.get param current", "usermacro.get param templateids",
        "valuemap.get param hostids",
    },
}


def _fetch(url: str) -> str:
    for _ in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            return urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - retried, then reported as an empty page
            time.sleep(2)
    return ""


class Pages:
    def __init__(self, release: str, cache: Path | None):
        self.release, self.cache = release, cache
        if cache:
            cache.mkdir(parents=True, exist_ok=True)

    def get(self, *parts: str) -> str:
        name = "_".join((self.release,) + parts) + ".html"
        if self.cache and (self.cache / name).is_file() and (self.cache / name).stat().st_size > 1000:
            return (self.cache / name).read_text(encoding="utf-8")
        text = _fetch("/".join((BASE.format(release=self.release),) + parts))
        if self.cache and text:
            (self.cache / name).write_text(text, encoding="utf-8")
        return text


def _clean(cell: str) -> str:
    cell = re.sub(r"<br\s*/?>", " ", cell)
    cell = re.sub(r"<[^>]+>", "", cell)
    return html.unescape(re.sub(r"\s+", " ", cell)).strip()


def _tables(page: str) -> list[tuple[list[str], list[list[str]]]]:
    out = []
    for table in re.findall(r"<table>(.*?)</table>", page, re.S):
        head = [_clean(h) for h in re.findall(r"<th[^>]*>(.*?)</th>", table, re.S)]
        rows = [tds for tds in (re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)
                                for tr in re.findall(r"<tr>(.*?)</tr>", table, re.S)) if tds]
        out.append((head, rows))
    return out


def _intro(page: str) -> str:
    """The text between the page title and its first section heading."""
    start = page.rfind("<h1")
    if start < 0:
        return ""
    body = page[start:]
    end = re.search(r"<h[2-4][ >]", body)
    return _clean(body[:end.start()] if end else body[:4000])


def page_says_deprecated(page: str) -> bool:
    """The class page (or a method page) opens with a deprecation notice:
    "This feature is deprecated and may be removed in future releases."""
    return bool(re.search(r"\bdeprecated\b", _intro(page), re.I))


def parse_get(page: str) -> dict:
    res = {"params": {}, "selects": {}, "common": set(), "sortfield": [], "deprecated": set(), "table": False}
    for head, rows in _tables(page):
        if head[:1] != ["Parameter"]:
            continue
        res["table"] = True
        for tds in rows:
            name = _clean(tds[0]).replace("(required)", "").strip().split(" ")[0]
            kind = _clean(tds[1]) if len(tds) > 1 else ""
            desc = tds[2] if len(tds) > 2 else ""
            if name == "sortfield":
                # only the plain list: "Possible values when used together with ..." names other parameters
                first = re.split(r"Possible values when", desc)[0]
                res["sortfield"] = [html.unescape(c) for c in re.findall(r"<code>(.*?)</code>", first)]
                res["common"].add(name)
            elif name in COMMON:
                res["common"].add(name)
            elif name.startswith("select"):
                res["selects"][name] = kind
                if re.search(r"deprecated", _clean(desc), re.I):
                    res["deprecated"].add(name)
            elif name:
                res["params"][name] = kind
        break
    return res


def parse_object(page: str) -> dict[str, bool]:
    """Top-level properties of the object -> read-only mark. Empty when the
    page has no property table (not downloaded, or its layout changed)."""
    props: dict[str, bool] = {}
    for head, rows in _tables(page):
        if head[:1] != ["Property"]:
            continue
        for tds in rows:
            raw = _clean(tds[0])
            desc = _clean(tds[2]) if len(tds) > 2 else ""
            behavior = re.search(r"Property behavior:(.*)$", desc)
            readonly = bool(behavior and re.search(r"- read-only(?! for)", behavior.group(1))) or "(readonly)" in raw
            name = raw.split(" ")[0]
            if name and not name[0].isupper() and "-" not in name:
                props[name] = readonly
        break
    return props


def audit(release: str, cache: Path | None, verbose: bool = False) -> list[str]:
    pages = Pages(release, cache)
    version = release + ".0"
    index = pages.get()
    if not index:
        raise SystemExit(f"cannot read the {release} reference index")
    objects = sorted(set(re.findall(
        rf'href="/documentation/{re.escape(release)}/en/manual/api/reference/([a-z_]+)"', index)))
    documented: dict[str, list[str]] = {}
    issues: list[str] = []
    deprecated_pages: set[str] = set()
    for obj in objects:
        page = pages.get(obj)
        documented[obj] = sorted(set(re.findall(
            rf'href="/documentation/{re.escape(release)}/en/manual/api/reference/{obj}/([a-z_]+)"', page)))
        if not documented[obj]:
            # a page that did not arrive must not read as "nothing to compare"
            issues.append(f"{obj}: the class page lists no methods (not downloaded, or its layout changed)")
        if page_says_deprecated(page):
            deprecated_pages.add(obj)
        if verbose:
            print(f"  {obj}: {' '.join(documented[obj])}", file=sys.stderr)

    tools = {m.api_method.lower(): m for m in ALL_METHODS}
    available = {name for name in tools if not unavailable_reason(name, version)}
    doc_methods = {f"{o}.{m}" for o, ms in documented.items() for m in ms if m not in NOT_METHODS}
    for method in sorted(doc_methods - set(tools)):
        issues.append(f"{method}: documented on {release}, no tool")
    for method in sorted(doc_methods & set(tools) - available):
        issues.append(f"{method}: documented on {release}, the version table says it is not there "
                      f"({unavailable_reason(method, version)})")
    for method in sorted(available - doc_methods):
        if method.split(".")[0] in documented:
            issues.append(f"{method}: tool offered on {release}, not on the reference pages")
        else:
            issues.append(f"{method}: tool offered on {release}, object has no reference page")

    # deprecated methods: the class page says so for the whole object, a
    # method page for itself; METHOD_DEPRECATED has to say the same
    for obj, methods in sorted(documented.items()):
        for name in methods:
            if name in NOT_METHODS:
                continue
            method = f"{obj}.{name}"
            on_page = obj in deprecated_pages or page_says_deprecated(pages.get(obj, name))
            ours = bool(deprecated_reason(method, version))
            if on_page and not ours and not unavailable_reason(method, version):
                issues.append(f"{method}: deprecated on the {release} pages, not in METHOD_DEPRECATED")
            elif ours and not on_page:
                issues.append(f"{method}: in METHOD_DEPRECATED for {release}, the pages do not say so")

    for obj, methods in sorted(documented.items()):
        if "get" in methods:
            contract = contract_for(f"{obj}.get")
            if contract is None:
                issues.append(f"{obj}.get: no get contract")
            else:
                ref = parse_get(pages.get(obj, "get"))
                if not ref["table"]:
                    issues.append(f"{obj}.get: the page has no parameter table (not downloaded, or its layout changed)")
                for name in ref["params"]:
                    spec = contract.params.get(name)
                    if spec is None:
                        issues.append(f"{obj}.get param {name}: not in the contract")
                    elif not spec.available(version):
                        issues.append(f"{obj}.get param {name}: contract says not on {release} "
                                      f"(since {spec.since}, removed {spec.removed})")
                for name, spec in contract.params.items():
                    if spec.available(version) and name not in ref["params"] and name not in ref["common"]:
                        issues.append(f"{obj}.get param {name}: in the contract, not on the {release} page")
                for name in ref["selects"]:
                    spec = contract.selects.get(name)
                    if spec is None:
                        issues.append(f"{obj}.get select {name}: not in the contract")
                    elif not spec.available(version):
                        issues.append(f"{obj}.get select {name}: contract says not on {release}")
                for name, spec in contract.selects.items():
                    if spec.available(version) and name not in ref["selects"]:
                        issues.append(f"{obj}.get select {name}: in the contract, not on the {release} page")
                for name in sorted(ref["deprecated"]):
                    spec = contract.selects.get(name)
                    if spec is not None and not spec.deprecated:
                        issues.append(f"{obj}.get select {name}: deprecated on the {release} page, not marked in the contract")
                for name, spec in contract.selects.items():
                    if spec.deprecated and spec.available(version) and name in ref["selects"] \
                            and name not in ref["deprecated"] \
                            and parse_version(version) >= parse_version(spec.deprecated):
                        issues.append(f"{obj}.get select {name}: marked deprecated in the contract, not on the {release} page")
                ours = {f for f in contract.sortfield
                        if contract.sort_specs.get(f) is None or contract.sort_specs[f].available(version)}
                for name in sorted(set(ref["sortfield"]) - ours):
                    issues.append(f"{obj}.get sortfield {name}: not in the contract")
                for name in sorted(ours - set(ref["sortfield"])):
                    issues.append(f"{obj}.get sortfield {name}: in the contract, not on the {release} page")
        if "object" in methods:
            spec_obj = OBJECTS.get(obj)
            if spec_obj is None:
                issues.append(f"{obj}: object has no catalog entry")
                continue
            page_props = parse_object(pages.get(obj, "object"))
            if not page_props:
                issues.append(f"{obj}: the object page has no property table (not downloaded, or its layout changed)")
            for name, readonly in page_props.items():
                spec = spec_obj.props.get(name)
                if spec is None:
                    issues.append(f"{obj} prop {name}: not in the catalog")
                elif not spec.available(version):
                    issues.append(f"{obj} prop {name}: catalog says not on {release} "
                                  f"(since {spec.since}, removed {spec.removed})")
                elif bool(spec.readonly) != readonly and not spec.observed:
                    issues.append(f"{obj} prop {name}: read-only on the page = {readonly}, in the catalog = {bool(spec.readonly)}")
    known = KNOWN.get(release, set())
    return [i for i in issues
            if not any(i.startswith(k) for k in known) and not any(u in i for u in UNDOCUMENTED_EVERYWHERE)]


def main(argv: list[str]) -> int:
    cache = None
    rest = list(argv)
    if "--cache" in rest:
        at = rest.index("--cache")
        if at + 1 >= len(rest):
            raise SystemExit(__doc__)
        cache = Path(rest[at + 1])
        del rest[at:at + 2]
    args = [a for a in rest if not a.startswith("--")]
    if len(args) != 1:
        raise SystemExit(__doc__)
    release = args[0]
    issues = audit(release, cache, verbose="--verbose" in rest)
    for issue in issues:
        print(issue)
    print(f"{release}: {len(issues)} difference(s)", file=sys.stderr)
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
