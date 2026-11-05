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
"""Compare what the ``get`` methods of a Zabbix frontend take, as written in
its PHP source, with the get contracts.

``audit_api_frontend.py`` answers "which methods exist"; this script answers
"which parameters does each ``X.get`` accept and which fields does it sort
by", straight from the API classes: the options of ``get()`` (``$defOptions``
in the classic classes, ``$api_input_rules`` in the validated ones) and
``$sortColumns``. The reference pages lag behind and are wrong in places
(the 8.0 pages name a sort field ``discovered`` that no server accepts), so
the source is the last word. Reported:

* an option the source takes that the contract does not know (a tool would
  refuse it as "not a parameter of X.get"),
* an option the contract offers on that release that the source does not
  take (Zabbix would ignore or reject it),
* a generic get parameter the source takes that the contract leaves out
  (the tool does not offer it for that method),
* a sort column on one side only,
* where a class validates ``output`` against its own list of fields
  (``'in' => implode(',', self::OUTPUT_FIELDS)``): a field on one side only,
* a parameter a tool types by hand that the source does not take, for the
  get tools and for the methods with a signature of their own
  (``event.acknowledge``, ``script.execute``, ``sla.getsli`` ...), and a
  field such a method takes that its tool has no parameter for.

    python3 scripts/audit_api_sources.py /usr/share/zabbix/ui
    python3 scripts/audit_api_sources.py --docker zabbix-web:/usr/share/zabbix/ui [--verbose]

Exit status 1 when anything differs that is not listed in ``KNOWN``. A
``get`` whose options cannot be read from the source is a difference too.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit_api_frontend import _from_docker  # noqa: E402
from zabbix_mcp.api import ALL_METHODS  # noqa: E402
from zabbix_mcp.api.common import CREATE_PARAMS, DELETE_PARAMS, MASS_PARAMS, UPDATE_PARAMS  # noqa: E402
from zabbix_mcp.api.contracts import (  # noqa: E402
    COMMON_GET_PARAMETERS, MCP_SIDE_PARAMS, contract_for, filter_props, output_props,
)
from zabbix_mcp.api.versions import parse_version  # noqa: E402
from zabbix_mcp.api.versions import unavailable_reason  # noqa: E402

# Options of get() that are not part of the public API: switches the
# frontend passes to itself (see CApiService and the callers in the UI).
INTERNAL = frozenset({
    "nopermissions", "nodeids",
})

# ("object.get", kind, name) -> why the difference is expected, on every
# release that shows it. Each entry was checked against running servers
# (6.0.48, 6.2.9, 6.4.21, 7.0.30, 7.4.14, 8.0.0).
KNOWN: dict[tuple[str, str, str], str] = {
    ("hostinterface.get", "option", "groupids"):
        "in the option table, read by nothing: a live server returns every interface whatever the group",
    ("itemprototype.get", "option", "groupids"):
        "in the option table, read by nothing: a live server returns every prototype whatever the group",
    ("usermacro.get", "option", "itemids"):
        "in the option table, read by nothing: a live server returns every macro",
    ("usermacro.get", "option", "triggerids"):
        "in the option table, read by nothing: a live server returns every macro",
    ("task.get", "sortfield", "taskid"):
        "the class sorts by it on its own; a caller's sortfield is answered with 'unexpected parameter'",
    ("problem.get", "option", "any"):
        "an internal switch of the 6.x frontend, undocumented, refused from 7.0",
    ("action.get", "common", "editable"):
        "a default every class inherits; CAction does not read it",
    ("event.get", "tool parameter", "severity_min"):
        "the tool's own: _build_zabbix_params turns it into severities before the call",
    ("problem.get", "tool parameter", "severity_min"):
        "the tool's own: _build_zabbix_params turns it into severities before the call",
}


# Parameters of the hand-typed tools that are this server's own, not Zabbix's.
OWN_PARAMS = frozenset({"auth_sessionid", "params", "ids", "extra_params"})

# (method, parameter) -> first release whose source takes it. A hand-typed
# parameter carries its release in the description only.
TYPED_SINCE: dict[tuple[str, str], str] = {
    ("event.acknowledge", "suppress_until"): "6.2",
    ("event.acknowledge", "cause_eventid"): "6.4",
    ("script.execute", "manualinput"): "7.0",
    ("script.getscriptsbyhosts", "scriptid"): "7.0",
    ("script.getscriptsbyhosts", "manualinput"): "7.0",
    ("script.getscriptsbyevents", "scriptid"): "7.0",
    ("script.getscriptsbyevents", "manualinput"): "7.0",
}

# Tools whose one parameter is the plain array the method takes (ids, items):
# the tool's name for it is its own.
ARRAY_TOOLS = frozenset({
    "history.clear", "history.push", "user.unblock", "user.resettotp", "token.generate",
})


def _first_level_keys(source: str, open_bracket: int) -> list[str]:
    """Keys of the first level of the PHP array literal that starts at
    ``source[open_bracket] == '['``."""
    depth, i, keys = 1, open_bracket + 1, []
    while i < len(source) and depth:
        ch = source[i]
        if ch in "'\"":
            end = i + 1
            while end < len(source) and (source[end] != ch or source[end - 1] == "\\"):
                end += 1
            if depth == 1 and re.match(r"\s*=>", source[end + 1:end + 12]):
                keys.append(source[i + 1:end])
            i = end
        elif ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        elif source.startswith("//", i) or source.startswith("#", i):
            i = source.find("\n", i)
            if i < 0:
                break
        i += 1
    return keys


def _class_source(services: Path, cls: str) -> tuple[str, str | None]:
    path = services / f"{cls}.php"
    if not path.is_file():
        return "", None
    source = path.read_text(encoding="utf-8", errors="replace")
    parent = re.search(rf"class\s+{cls}\s+extends\s+(C[A-Za-z]+)", source)
    return source, parent.group(1) if parent else None


def _method_body(source: str, name: str) -> str | None:
    """The text of ``function <name>(`` up to the next method of the class."""
    start = re.search(rf"\n\t(?:public|protected|private)\s+(?:static\s+)?function\s+{name}\s*\(", source)
    if not start:
        return None
    nxt = re.search(r"\n\t(?:public|protected|private|final|abstract)\s+(?:static\s+)?function\s+\w+\s*\(",
                    source[start.end():])
    return source[start.start():start.end() + nxt.start()] if nxt else source[start.start():]


def _lineage(services: Path, cls: str) -> list[str]:
    """Sources of *cls* and its parents, nearest first."""
    out, seen = [], 0
    while cls and seen < 6:
        source, parent = _class_source(services, cls)
        if not source:
            break
        out.append(source)
        cls, seen = parent, seen + 1
    return out


# How a class says which options its get() takes. The classic classes merge
# the caller's options into a table of defaults; the validated ones describe
# them in ``$api_input_rules``.
_OPTION_TABLES = (
    r"\$(?:defOptions|default_options)\s*=\s*\[",                # $defOptions = [ ... ]  (local or a class property)
    r"\$options\s*\+=\s*\[",                                    # $options += [ ... ]
    r"\$this->getOptions\s*=\s*(?:zbx_)?array_merge\(\$this->getOptions,\s*\[",   # in the constructor
    r"\$api_input_rules\s*=\s*\[\s*'type'\s*=>\s*API_OBJECT\b[^\n]*?'fields'\s*=>\s*\[",
)
# Methods get() hands its options to.
_HELPERS = r"(?:self::|static::|\$this->)(doGet\w*|validateGet\w*|getInputRules\w*)\s*\("


def _global_get_options(services: Path) -> list[str]:
    """``CApiService::$globalGetOptions``: what every class that merges
    ``$this->getOptions`` / ``$this->globalGetOptions`` takes."""
    base = services.parent / "CApiService.php"
    if not base.is_file():
        return []
    source = base.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"\$this->globalGetOptions\s*=\s*\[", source)
    return _first_level_keys(source, match.end() - 1) if match else []


def output_fields(services: Path, cls: str) -> list[str] | None:
    """The fields ``<cls>::get()`` validates ``output`` against, where it
    names them (a list constant, or the keys of a column map); ``None`` when
    the class takes ``output`` without such a list."""
    sources = _lineage(services, cls)
    texts = _get_texts(sources)
    for text in texts:
        match = re.search(
            r"'output'\s*=>\s*\[[^\n]*?'in'\s*=>\s*implode\(',',\s*(array_keys\()?(?:self|static)::(\w+)", text)
        if not match:
            continue
        for source in sources:
            declared = re.search(rf"const\s+{match.group(2)}\s*=\s*\[", source)
            if not declared:
                continue
            start = declared.end() - 1
            if match.group(1):
                return _first_level_keys(source, start)
            depth, i = 1, start + 1
            while i < len(source) and depth:
                depth += source[i] == "["
                depth -= source[i] == "]"
                i += 1
            return re.findall(r"'([A-Za-z_0-9]+)'", source[start:i])
    return None


def _get_texts(sources: list[str]) -> list[str]:
    """The body of get() and of the methods it hands its options to."""
    texts: list[str] = []
    for source in sources:
        body = _method_body(source, "get")
        if body is None:
            continue
        texts.append(body)
        for helper in re.findall(_HELPERS, body):
            for src in sources:
                extra = _method_body(src, helper)
                if extra is not None:
                    texts.append(extra)
                    break
        break
    return texts


def get_options(services: Path, cls: str) -> list[str] | None:
    """Option names ``<cls>::get()`` accepts, or ``None`` when they cannot be read."""
    sources = _lineage(services, cls)
    texts: list[str] = []
    for source in sources:
        body = _method_body(source, "get")
        if body is None:
            continue
        texts.append(body)
        for helper in re.findall(_HELPERS, body):
            for src in sources:
                extra = _method_body(src, helper)
                if extra is not None:
                    texts.append(extra)
                    break
        if re.search(r"\$this->(?:defOptions|getOptions)\b", body):
            # the table is a class property, filled where it is declared or in the constructor
            for src in sources:
                declared = re.search(r"\n\t(?:private|protected|public)\s+(?:static\s+)?\$defOptions\s*=\s*\[", src)
                if declared:
                    texts.append(src[declared.start():declared.start() + 20000])
                constructor = _method_body(src, "__construct")
                if constructor is not None:
                    texts.append(constructor)
        break
    keys: list[str] = []
    found = False
    # A validated get() without API_ALLOW_UNEXPECTED names everything it
    # takes; whatever else the method sets on $options afterwards is its own.
    strict = None
    for text in texts:
        for match in re.finditer(
                r"\$api_input_rules\s*=\s*\[\s*'type'\s*=>\s*API_OBJECT,\s*'fields'\s*=>\s*\[", text):
            table = _first_level_keys(text, match.end() - 1)
            if "output" in table:   # the options of get(), not the rules for one of its values
                strict, keys, found = match, table, True
                break
        if strict:
            break
    if strict is None:
        for text in texts:
            for pattern in _OPTION_TABLES:
                for match in re.finditer(pattern, text):
                    keys += _first_level_keys(text, match.end() - 1)
                    found = True
        if any(re.search(r"\$this->(?:getOptions|globalGetOptions)\b", t) for t in texts):
            keys += _global_get_options(services)
            found = True
        if found:
            # an option read without a default: if (isset($options['expandName']))
            for text in texts:
                keys += re.findall(r"\$options\['(\w+)'\]", text)
    if not found:
        return None
    out = []
    for key in keys:
        if key not in out:
            out.append(key)
    return out


# Fields the source still takes under a deprecated name ('user' for
# 'username' in user.login up to 6.2): (class, method) -> names, filled by
# method_fields(). The tool types the current name only.
DEPRECATED_FIELDS: dict[tuple[str, str], set[str]] = {}


def method_fields(services: Path, cls: str, method: str) -> list[str] | None:
    """Field names the PHP method behind ``object.<method>`` validates: the
    first level of every ``API_OBJECT`` / ``API_OBJECTS`` rule table in its
    body and in the ``validate...`` helpers it calls, with what the method
    adds to the table afterwards (``$api_input_rules['fields'] += [...]``:
    device.offboard takes ``force`` from a Super admin only). ``None`` when
    the method has no such table (it takes a plain array, or checks by hand)."""
    sources = _lineage(services, cls)
    for source in sources:
        name = next((n for n in re.findall(r"function\s+(\w+)\s*\(", source) if n.lower() == method.lower()), None)
        if name is None:
            continue
        texts = [_method_body(source, name) or ""]
        for helper in set(re.findall(r"(?:self::|static::|\$this->)(validate\w*)\s*\(", texts[0])):
            for src in sources:
                extra = _method_body(src, helper)
                if extra is not None:
                    texts.append(extra)
                    break
        fields: list[str] = []
        found = False
        for text in texts:
            for match in re.finditer(
                    r"\$api_input_rules\s*=\s*\[\s*'type'\s*=>\s*API_OBJECTS?\b[^\n]*?'fields'\s*=>\s*\[", text):
                found = True
                for key in _first_level_keys(text, match.end() - 1):
                    if key not in fields:
                        fields.append(key)
            for match in re.finditer(r"\$api_input_rules\['fields'\]\s*\+=\s*\[", text):
                for key in _first_level_keys(text, match.end() - 1):
                    if key not in fields:
                        fields.append(key)
            for key in re.findall(r"'(\w+)'\s*=>\s*\[[^\n]*\bAPI_DEPRECATED\b", text):
                if key in fields:
                    DEPRECATED_FIELDS.setdefault((cls, method.lower()), set()).add(key)
        return fields if found else None
    return None


def sort_columns(services: Path, cls: str) -> list[str] | None:
    for source in _lineage(services, cls):
        match = (re.search(r"\$sortColumns\s*=\s*\[([^\]]*)\]", source)
                 or re.search(r"const\s+SORT_COLUMNS\s*=\s*\[([^\]]*)\]", source))
        if match:
            return re.findall(r"'([^']+)'", match.group(1))
    for source in _lineage(services, cls):
        body = _method_body(source, "get") or ""
        match = re.search(r"'sortfield'\s*=>\s*\[[^\n]*?'in'\s*=>\s*implode\(',',\s*\[([^\]]*)\]", body)
        if match:
            return re.findall(r"'([^']+)'", match.group(1))
        match = re.search(r"'sortfield'\s*=>\s*\[[^\n]*?'in'\s*=>\s*'([^']*)'", body)
        if match:
            return [f for f in match.group(1).split(",") if f]
    return None


def audit(root: Path, verbose: bool = False) -> tuple[str, list[str], int]:
    api = root / "include" / "classes" / "api"
    services = api / "services"
    defines = (root / "include" / "defines.inc.php").read_text(encoding="utf-8", errors="replace")
    found = re.search(r"define\('ZABBIX_VERSION',\s*'([^']+)'", defines)
    version = found.group(1) if found else "unknown"
    release = ".".join(version.split(".")[:2])
    factory = (api / "CApiServiceFactory.php").read_text(encoding="utf-8", errors="replace")
    classes = dict(re.findall(r"'([a-z]+)'\s*=>\s*(C[A-Za-z]+)::class", factory))
    tools = {m.api_method.lower() for m in ALL_METHODS}
    by_method = {m.api_method.lower(): m for m in ALL_METHODS}
    issues: list[str] = []
    checked = 0

    def report(method: str, kind: str, name: str, text: str) -> None:
        why = KNOWN.get((method, kind, name))
        if why:
            print(f"note: {method} {kind} {name}: {why}", file=sys.stderr)
        else:
            issues.append(f"{method} {kind} {name}: {text}")

    for obj, cls in sorted(classes.items()):
        method = f"{obj}.get"
        contract = contract_for(method)
        if method not in tools or contract is None or unavailable_reason(method, version):
            continue
        options = get_options(services, cls)
        if options is None:
            issues.append(f"{method}: the options of {cls}::get() could not be read from the source")
            continue
        checked += 1
        if "search" in options:
            # read by CApiService for every class that searches, listed or not
            options = options + [o for o in ("searchByAny", "startSearch", "excludeSearch", "searchWildcardsEnabled")
                                 if o not in options]
        takes = [o for o in options if o not in INTERNAL]
        known = {n for n, s in {**contract.params, **contract.selects}.items() if s.available(version)}
        if verbose:
            print(f"  {method} ({cls}): {' '.join(takes)}", file=sys.stderr)
        for name in takes:
            if name in COMMON_GET_PARAMETERS:
                if name not in contract.common:
                    report(method, "common", name, "taken by the source, left out of the contract's common parameters")
            elif name not in known:
                spec = contract.params.get(name) or contract.selects.get(name)
                dated = f" (the contract dates it since {spec.since}, removed {spec.removed})" if spec else ""
                report(method, "option", name, f"taken by the {version} source, not offered by the contract{dated}")
        for name in sorted(known - set(options)):
            report(method, "option", name, f"offered by the contract on {release}, not taken by the source")
        for name in sorted(contract.common - set(options)):
            report(method, "common", name, "in the contract's common parameters, not taken by the source")
        fields = output_fields(services, cls)
        if fields is not None:
            offered = [p.name for p in output_props(contract, version)]
            for name in fields:
                if name not in offered:
                    report(method, "output", name, f"an output field in the {version} source, not a property in the contract")
            for name in offered:
                if name not in fields:
                    report(method, "output", name, f"a property the contract offers on {release}, not an output field in the source")
        # what the tool types by hand must be something the method takes
        # (under the name it is sent as: ParamDef.api_name)
        tool = by_method.get(method)
        for param in (tool.params if tool else []):
            name = param.name
            if name in COMMON_GET_PARAMETERS or name in OWN_PARAMS or (method, name) in MCP_SIDE_PARAMS:
                continue
            sent = param.sent_as
            if sent.startswith("filter."):
                # travels as a filter key: a property the method filters by
                prop = sent[len("filter."):]
                if "filter" not in options:
                    report(method, "tool parameter", name, f"sent as {sent}, the {version} source takes no filter")
                elif prop not in [p.name for p in filter_props(contract, version)]:
                    report(method, "tool parameter", name, f"sent as {sent}, not a filterable property on {release}")
                elif fields is not None and prop not in fields:
                    report(method, "tool parameter", name, f"sent as {sent}, not a field of the object in the {version} source")
                continue
            spec = contract.params.get(sent) or contract.selects.get(sent)
            if spec is not None and not spec.available(version):
                continue
            if sent not in options:
                report(method, "tool parameter", name, f"typed on the tool, not taken by the {version} source"
                       + (f" (sent as {sent})" if sent != name else ""))
        columns = sort_columns(services, cls)
        ours = list(contract.sortable(version))
        if columns is None:
            if ours:
                report(method, "sortfield", "*", f"the contract sorts by {', '.join(ours)}, the source declares no sort columns")
        else:
            for name in columns:
                if name not in ours:
                    report(method, "sortfield", name, f"sort column in the {version} source, not in the contract")
            for name in ours:
                if name not in columns:
                    report(method, "sortfield", name, f"in the contract on {release}, not a sort column in the source")
    # the methods with a signature of their own (not get, not the generic
    # create / update / delete / mass shapes)
    generic = {tuple(p.name for p in shape) for shape in (CREATE_PARAMS, UPDATE_PARAMS, DELETE_PARAMS, MASS_PARAMS)}
    current = parse_version(version)
    for tool in ALL_METHODS:
        method = tool.api_method.lower()
        obj, _, name = method.partition(".")
        typed = tuple(p.name for p in tool.params)
        if name == "get" or typed in generic or not typed or method in ARRAY_TOOLS or obj not in classes:
            continue
        if unavailable_reason(method, version):
            continue
        fields = method_fields(services, classes[obj], name)
        if fields is None:
            continue
        checked += 1
        ours = [p for p in typed if p not in OWN_PARAMS]
        if verbose:
            print(f"  {method} ({classes[obj]}): source {' '.join(fields)} | tool {' '.join(ours)}", file=sys.stderr)
        array_param = getattr(tool, "array_param", None)
        for param in ours:
            since = TYPED_SINCE.get((method, param))
            if since and current is not None and current < parse_version(since):
                continue
            if param == array_param:
                continue   # the tool's own name for the list it turns into the method's objects
            if param not in fields:
                report(method, "tool parameter", param, f"typed on the tool, not a field of the method in the {version} source")
        if "params" not in typed:   # a tool with a free 'params' object passes any field on
            old_names = DEPRECATED_FIELDS.get((classes[obj], name), set())
            for field in fields:
                if field in old_names:
                    continue   # a deprecated name of a field the tool types
                if field not in ours and not (array_param and field in ("hostid", "eventid")):
                    report(method, "field", field, f"taken by the method in the {version} source, the tool has no parameter for it")
    return version, issues, checked


def main(argv: list[str]) -> int:
    verbose = "--verbose" in argv
    args = [a for a in argv if a != "--verbose"]
    if len(args) == 2 and args[0] == "--docker":
        root = _from_docker(args[1])
    elif len(args) == 1 and not args[0].startswith("--"):
        root = Path(args[0])
    else:
        raise SystemExit(__doc__)
    version, issues, checked = audit(root, verbose)
    for issue in issues:
        print(issue)
    print(f"{version}: {checked} methods read from the source, {len(issues)} difference(s)", file=sys.stderr)
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
