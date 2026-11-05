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

"""What each ``*.get`` method really accepts, per Zabbix release.

A model building a call from ``tools/list`` alone has to know *which*
properties ``output`` / ``filter`` / ``search`` / ``sortfield`` take on this
particular method and *which* ``selectXxx`` and native parameters exist,
otherwise it guesses (issues #79, #98). Zabbix makes guessing expensive in
a quiet way: an unknown ``selectXxx`` or top-level parameter, an unknown
``output`` property and a ``filter`` on a ``text`` property are silently
ignored (the model believes it filtered), while a wrong ``sortfield`` or a
restricted ``filter`` key is an API error.

``get_contracts.json`` (next to this module) is the per-method contract and
the per-object property list, taken from the official API reference pages
of 5.0, 6.0, 6.2, 6.4, 7.0, 7.2, 7.4 and 8.0 (``scripts/build_get_contracts.py``
merges the collected data). This module

* renders method-specific descriptions for the generic get parameters,
* drops a generic parameter the method does not have (``trend.get`` has no
  ``filter`` / ``search`` / ``sortfield``), and
* validates a get request before it leaves the server, with a message that
  names the allowed values and the release that introduced a parameter.

``zabbix_raw_api_call`` is not validated against the catalog: it is the
escape hatch for a parameter the catalog does not know.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from zabbix_mcp.api.versions import METHOD_SINCE, is_removed, parse_version

_DATA_FILE = Path(__file__).with_name("get_contracts.json")

# The generic get parameters every classic get method accepts (reference
# commentary). ``common`` in a contract lists the subset the method's own
# reference page documents.
COMMON_GET_PARAMETERS: frozenset[str] = frozenset({
    "countOutput", "editable", "excludeSearch", "filter", "limit", "output",
    "preservekeys", "search", "searchByAny", "searchWildcardsEnabled",
    "sortfield", "sortorder", "startSearch",
})

# Property types that ``filter`` cannot use and ``search`` can (reference
# commentary: filter "does not support properties of text", search
# "supports only properties of string and text").
_TEXT_TYPES = frozenset({"text"})
_SEARCHABLE_TYPES = frozenset({"string", "text"})


@dataclass(frozen=True)
class Spec:
    """One parameter, select or property: when it exists and what it is."""

    name: str
    type: str = ""
    since: str | None = None      # first release that has it; None = 5.0 or older
    removed: str | None = None    # first release without it
    readonly: bool = False
    values: dict[str, str] = field(default_factory=dict)   # documented value -> meaning
    default: str | None = None
    no_output: bool = False       # a catalogued property ``output`` cannot name (sub-object; use selectXxx)
    no_filter: bool = False       # a real server ignores ``filter`` on it (text column behind a "string" type)
    no_search: bool = False       # a real server ignores ``search`` on it
    observed: str | None = None   # returned by a real server of this version, absent from the reference page
    deprecated: str | None = None   # first release whose reference calls it deprecated (it still works)
    replaced_by: str | None = None  # what the reference says to use instead

    def available(self, version: str | None) -> bool:
        """True unless *version* is known and lies outside [since, removed)."""
        current = parse_version(version)
        if current is None:
            return True
        if self.since and current < parse_version(self.since):
            return False
        if self.removed and is_removed(version, self.removed):
            return False
        return True

    def marker(self) -> str:
        """`` (7.0+)`` / `` (removed in 8.0)`` suffix for a description."""
        bits = []
        if self.since:
            bits.append(f"{self.since}+")
        if self.removed:
            bits.append(f"removed in {self.removed}")
        if self.deprecated:
            bits.append(f"deprecated in {self.deprecated}" + (f", use {self.replaced_by}" if self.replaced_by else ""))
        return f" ({', '.join(bits)})" if bits else ""


@dataclass(frozen=True)
class ObjectSpec:
    name: str
    props: dict[str, Spec]
    notes: tuple[str, ...] = ()

    def available(self, version: str | None) -> list[Spec]:
        return [p for p in self.props.values() if p.available(version)]


@dataclass(frozen=True)
class GetContract:
    method: str
    object: str
    sortfield: tuple[str, ...]            # every sort field any supported release accepts
    sort_specs: dict[str, Spec]           # name -> when a release accepts it
    common: frozenset[str]
    params: dict[str, Spec]
    selects: dict[str, Spec]
    filter_props: tuple[str, ...] | None
    search_props: tuple[str, ...] | None
    notes: tuple[str, ...] = ()

    @property
    def classic(self) -> bool:
        """A list-returning get with the generic parameter set (not a singleton)."""
        return "filter" in self.common or "sortfield" in self.common

    def sortable(self, version: str | None = None) -> tuple[str, ...]:
        """The sort fields a server running *version* accepts."""
        return tuple(n for n in self.sortfield if self.sort_specs[n].available(version))


def _spec(name: str, raw: dict[str, Any]) -> Spec:
    return Spec(
        name=name,
        type=str(raw.get("type") or ""),
        since=raw.get("since") or None,
        removed=raw.get("removed") or None,
        readonly=bool(raw.get("readonly", False)),
        values={str(k): str(v) for k, v in (raw.get("values") or {}).items()},
        default=None if raw.get("default") is None else str(raw["default"]),
        no_output=bool(raw.get("no_output", False)),
        no_filter=bool(raw.get("no_filter", False)),
        no_search=bool(raw.get("no_search", False)),
        observed=raw.get("observed") or None,
        deprecated=raw.get("deprecated") or None,
        replaced_by=raw.get("replaced_by") or None,
    )


def _load() -> tuple[dict[str, GetContract], dict[str, ObjectSpec]]:
    if not _DATA_FILE.exists():
        return {}, {}
    data = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    objects: dict[str, ObjectSpec] = {}
    for name, raw in (data.get("objects") or {}).items():
        props = {p: _spec(p, r) for p, r in (raw.get("props") or {}).items()}
        objects[name] = ObjectSpec(name=name, props=props, notes=tuple(raw.get("notes") or ()))
    methods: dict[str, GetContract] = {}
    for method, raw in (data.get("methods") or {}).items():
        sort_versions = raw.get("sortfield_versions") or {}
        sort_names = list(raw.get("sortfield") or ())
        for extra in sort_versions:
            if extra not in sort_names:
                sort_names.append(extra)
        methods[method] = GetContract(
            method=method,
            object=str(raw.get("object") or method.split(".")[0]),
            sortfield=tuple(sort_names),
            sort_specs={n: _spec(n, sort_versions.get(n) or {}) for n in sort_names},
            common=frozenset(raw.get("common") or ()),
            params={p: _spec(p, r) for p, r in (raw.get("params") or {}).items()},
            selects={p: _spec(p, r) for p, r in (raw.get("selects") or {}).items()},
            filter_props=None if raw.get("filter_props") is None else tuple(raw["filter_props"]),
            search_props=None if raw.get("search_props") is None else tuple(raw["search_props"]),
            notes=tuple(raw.get("notes") or ()),
        )
    return methods, objects


CONTRACTS, OBJECTS = _load()


def contract_for(api_method: str) -> GetContract | None:
    return CONTRACTS.get(api_method.lower())


def object_for(contract: GetContract) -> ObjectSpec | None:
    return OBJECTS.get(contract.object)


# ---------------------------------------------------------------------------
# Property sets a method's filter / search / output accept
# ---------------------------------------------------------------------------

def output_props(contract: GetContract, version: str | None = None) -> list[Spec]:
    """Properties ``output`` may name: the object's properties minus the
    sub-objects a strict method refuses there (``no_output``)."""
    obj = object_for(contract)
    return [p for p in obj.available(version) if not p.no_output] if obj else []


def filter_props(contract: GetContract, version: str | None = None) -> list[Spec]:
    """Properties ``filter`` accepts: the documented restriction when the
    reference page states one, otherwise every non-text property."""
    obj = object_for(contract)
    if contract.filter_props is not None:
        if obj is None:
            return [Spec(name=n) for n in contract.filter_props]
        return [obj.props.get(n) or Spec(name=n) for n in contract.filter_props
                if (obj.props.get(n) or Spec(name=n)).available(version)]
    if obj is None:
        return []
    return [p for p in obj.available(version)
            if p.type.lower() not in _TEXT_TYPES and not p.no_filter and not p.no_output]


def search_props(contract: GetContract, version: str | None = None) -> list[Spec]:
    """Properties ``search`` accepts: documented restriction, else string/text ones."""
    obj = object_for(contract)
    if contract.search_props is not None:
        if obj is None:
            return [Spec(name=n) for n in contract.search_props]
        return [obj.props.get(n) or Spec(name=n) for n in contract.search_props
                if (obj.props.get(n) or Spec(name=n)).available(version)]
    if obj is None:
        return []
    return [p for p in obj.available(version)
            if p.type.lower() in _SEARCHABLE_TYPES and not p.no_search and not p.no_output]


# Descriptions leave out what disappeared in 6.0 or earlier (5.x is long out
# of support); validation still knows those entries for a 5.x server.
_DESCRIBE_HIDE_REMOVED_UPTO = (6, 0)


def _for_description(specs: Iterable[Spec]) -> list[Spec]:
    out = []
    for s in specs:
        removed = parse_version(s.removed) if s.removed else None
        if removed is not None and removed <= _DESCRIBE_HIDE_REMOVED_UPTO:
            continue
        out.append(s)
    return out


def _names(specs: Iterable[Spec], *, markers: bool = True, base: str | None = None) -> str:
    """Comma-separated names with release markers; a ``since`` that is not
    later than *base* (the method's own first release) is not worth a marker."""
    floor = parse_version(base) if base else None
    out = []
    for s in _for_description(specs):
        text = s.name
        if markers:
            if floor and s.since and parse_version(s.since) <= floor:
                text += Spec(name=s.name, removed=s.removed, deprecated=s.deprecated,
                             replaced_by=s.replaced_by).marker()
            else:
                text += s.marker()
        out.append(text)
    return ", ".join(out)


def _base(contract: GetContract) -> str | None:
    return METHOD_SINCE.get(contract.method)


def compact_output_for(api_method: str, compact: Iterable[str], version: str | None) -> list[str]:
    """The default compact ``output`` of a tool, minus the properties the
    server's release does not have (``proxy.get`` ``name`` is 7.0+, so a 6.4
    server gets the rest). Unknown method or version: unchanged."""
    contract = contract_for(api_method)
    obj = object_for(contract) if contract else None
    fields = list(compact)
    if obj is None or parse_version(version) is None:
        return fields
    kept = [f for f in fields if f not in obj.props or obj.props[f].available(version)]
    if len(kept) < len(fields) and len(kept) < 2:
        return ["extend"]   # a lone ID is no overview; the release reworked the object
    return kept


# ---------------------------------------------------------------------------
# Descriptions
# ---------------------------------------------------------------------------

def describe_output(contract: GetContract, compact: tuple[str, ...] | None, *, lists: bool = False) -> str | None:
    """*lists*: the schema offers a list of names (api/schema_constraints.py),
    so the text asks for a list, not for a comma-separated string."""
    props = output_props(contract)
    if not props:
        return None
    default = (
        f"Default when omitted: {', '.join(compact)}."
        if compact else "Default when omitted: 'extend'."
    )
    form = "a list of property names" if lists else "a comma-separated list of property names"
    # only where the method has countOutput (the server sends 'count' as that)
    count = "'count' for the number of matches only, " if "countOutput" in contract.common else ""
    return (
        f"Properties of the {contract.object} object to return. "
        f"Pass 'extend' for all, {count}or "
        f"{form}. {default} "
        f"Properties: {_names(props, base=_base(contract))}."
    )


def describe_filter(contract: GetContract) -> str | None:
    props = filter_props(contract)
    if not props:
        return None
    head = "Only these keys are accepted" if contract.filter_props is not None else "Keys"
    return (
        f"Return only results whose properties exactly match the given values "
        f"(a single value or a list of values per key). "
        f"Example: {{\"status\": 0}} or {{\"status\": [0, 1]}}. "
        f"{head}: {_names(props, base=_base(contract))}. Text properties cannot be filtered; use 'search' for them."
    )


def describe_search(contract: GetContract) -> str | None:
    props = search_props(contract)
    if not props:
        return None
    head = "Only these keys are accepted" if contract.search_props is not None else "Keys"
    return (
        f"Return results whose string properties contain the given pattern "
        f"(case-insensitive; '*' is a wildcard when searchWildcardsEnabled is true). "
        f"Example: {{\"name\": \"web\"}}. {head}: {_names(props, base=_base(contract))}."
    )


def describe_sortfield(contract: GetContract, *, lists: bool = False) -> str | None:
    if not contract.sortfield:
        return None
    names = _names([contract.sort_specs[n] for n in contract.sortfield], base=_base(contract))
    several = "a list for several" if lists else "comma-separated for several"
    text = (
        f"Sort by one or more of: {names} "
        f"({several}; pair with 'sortorder'). No other property is sortable."
    )
    newest = NEWEST_FIRST.get(contract.method)
    if newest:
        needs = NEWEST_FIRST_NEEDS.get(contract.method)
        when = f"When omitted and '{needs}' is given" if needs else "When omitted"
        text += f" {when}, the result is sorted by {newest} with the newest first."
        if needs:
            text += f" Without '{needs}' nothing is sorted."
    return text


def describe_sortorder(contract: GetContract) -> str | None:
    """The sort order of a log, where leaving the sort out means newest first."""
    if contract.method not in NEWEST_FIRST or not contract.sortfield:
        return None
    return (
        "Sort order: 'ASC' (ascending) or 'DESC' (descending). 'DESC' while "
        "'sortfield' is omitted (newest first); 'ASC' alone returns the oldest first."
    )


# ---------------------------------------------------------------------------
# Logs: the newest rows first
# ---------------------------------------------------------------------------

# A get with a limit and no sort answers with the oldest rows or with an
# arbitrary slice, never with the newest (measured on 6.0 to 8.0: history.get
# with limit 3 returned values a month old, problem.get the oldest problems).
# Whoever asks a log for a few rows wants its end, so these methods are sorted
# descending when the call names no sort field. The fields are the ones the
# Zabbix 8.0 frontend sorts the same lists by (item history, Problems, the
# action log, the audit log), and each has an index. An audit ID is a CUID,
# which starts with its time: 3000 rows by auditid were in time order on
# every release from 6.0 to 8.0.
NEWEST_FIRST: dict[str, str] = {
    "history.get": "clock",
    "problem.get": "eventid",
    "event.get": "eventid",
    "alert.get": "alertid",
    "auditlog.get": "auditid",
}

# history.get is sorted for named items only: the database keeps the values of
# one item in time order, while sorting those of every item reads the table.
NEWEST_FIRST_NEEDS: dict[str, str] = {"history.get": "itemids"}


def default_sort(api_method: str, params: dict[str, Any]) -> str | None:
    """The sort field that puts the newest rows first, when *params* (the
    request as it would leave) names none and asks for rows, not for a count."""
    field_name = NEWEST_FIRST.get(api_method)
    if field_name is None or params.get("sortfield") or params.get("countOutput"):
        return None
    needs = NEWEST_FIRST_NEEDS.get(api_method)
    if needs and not params.get(needs):
        return None
    return field_name


# Not on the reference pages, in the option table of two dozen get classes and
# used by the frontend itself: with countOutput the count comes per ID of the
# ID filters the method groups by. Honoured by the same methods the source
# names on every release probed (6.0 to 8.0); the validated methods refuse it.
GROUP_COUNT = "groupCount"


def false_means_unset(contract: GetContract, name: str) -> bool:
    """True for a Zabbix "flag": a parameter that is on as soon as it is
    present, whatever its value. ``trigger.get`` with ``only_true: false``
    returns the triggers in problem state, exactly as with ``true`` (measured
    on 6.0 to 8.0, scripts/audit_get_flags_live.py), so a ``false`` is the
    same as leaving the parameter out and is not sent.

    ``hostgroup.get`` took its ``with_*`` parameters that way in 6.0; from
    6.2 on they are booleans whose ``false`` equals leaving them out, so
    dropping it is right on every release. A real boolean keeps its
    ``false`` (``templated: false`` is "not templated", not "any")."""
    spec = contract.params.get(name)
    if spec is None:
        return False
    return spec.type == "flag" or (contract.method == "hostgroup.get" and name.startswith("with_"))


def describe_extra_params(contract: GetContract, typed: Iterable[str]) -> str:
    """List the native parameters of this method that are not typed on the tool."""
    typed_names = set(typed)
    native = [s for n, s in contract.params.items() if n not in typed_names]
    selects = [s for n, s in contract.selects.items() if n not in typed_names]
    parts = [f"Other native {contract.method} parameters, merged into the request as-is."]
    if native:
        parts.append(f"Parameters: {_names(native, base=_base(contract))}.")
        switches = [s.name for s in _for_description(native) if false_means_unset(contract, s.name)]
        if switches:
            parts.append(
                f"Switches (true turns one on, false is the same as leaving it out): "
                f"{', '.join(switches)}."
            )
        if GROUP_COUNT in switches:
            parts.append(
                f"{_names([contract.params[GROUP_COUNT]], base=_base(contract))} goes with output='count': "
                f"the count is then split by the ID filters the "
                f"method groups by (hostids, groupids ...), one row per ID with 'rowscount'; a single row "
                f"without such a filter."
            )
    if selects:
        parts.append(
            f"Sub-object selects (value 'extend', 'count' or a list of property names): "
            f"{_names(selects, base=_base(contract))}."
        )
    if not native and not selects:
        parts.append(f"{contract.method} has no parameters beyond the typed ones.")
    parts.append(
        "Any other key is refused here, because Zabbix would silently ignore it. "
        "For a parameter you are sure exists on your release but is not listed, "
        "use zabbix_raw_api_call."
    )
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class GetParamError(ValueError):
    """A get request the catalog knows Zabbix would reject or silently ignore."""


def _fmt_version(version: str | None) -> str:
    return f"this server runs {version}" if version else "server version unknown"


def _check_spec_version(spec: Spec, what: str, method: str, version: str | None) -> None:
    current = parse_version(version)
    if current is None:
        return
    if spec.since and current < parse_version(spec.since):
        raise GetParamError(
            f"{what} '{spec.name}' of {method} requires Zabbix {spec.since} or later "
            f"({_fmt_version(version)})."
        )
    if spec.removed and current >= parse_version(spec.removed):
        raise GetParamError(
            f"{what} '{spec.name}' of {method} was removed in Zabbix {spec.removed} "
            f"({_fmt_version(version)})."
        )


def validate_get_params(
    api_method: str,
    params: Any,
    version: str | None,
    typed: Iterable[str] = (),
    unsupported: Iterable[str] = (),
) -> None:
    """Raise ``GetParamError`` for a parameter, sort field, filter/search key
    or output property that this method does not have on *version*.

    *typed* are the parameter names the tool declares itself (always
    accepted at the top level); everything else must be a common get
    parameter, a native parameter or a select of the method.
    An unknown *version* only disables the release checks.
    *unsupported* are parameters of the method that the calling tool cannot
    work with: they are left out of the list a refusal offers.
    """
    contract = contract_for(api_method)
    if contract is None or not isinstance(params, dict):
        return
    method = contract.method
    known_top = set(typed) | contract.common | set(contract.params) | set(contract.selects)
    hidden = set(unsupported)
    allowed_hint = (
        f"Allowed: {', '.join(sorted(contract.common - hidden))}; native: "
        f"{', '.join(n for n in contract.params if n not in hidden) or '-'}; "
        f"selects: {', '.join(contract.selects) or '-'}."
    )
    for key in params:
        if key not in known_top:
            raise GetParamError(
                f"'{key}' is not a parameter of {method}; Zabbix would silently ignore it. "
                f"{allowed_hint} If you are sure it exists on your release, use zabbix_raw_api_call."
            )
        spec = contract.params.get(key) or contract.selects.get(key)
        if spec is not None:
            _check_spec_version(spec, "Parameter", method, version)

    # A grouped count without the count. Zabbix ignores it at best (no ID
    # filter, or a method that reads it under countOutput only); next to an ID
    # filter 8.0 answers "Database error occurred." and 6.0 an empty list
    # (measured), and neither says why. A count is true and nothing else:
    # PHP reads countOutput "0" as off, Python would read it as on.
    if params.get(GROUP_COUNT) and GROUP_COUNT in contract.params and params.get("countOutput") is not True:
        raise GetParamError(
            f"'{GROUP_COUNT}' splits the count of {method}: pass output='count' (countOutput) with it. "
            f"Without a count Zabbix ignores it or, next to an ID filter, answers with a database error "
            f"or an empty list."
        )

    # sortfield
    sort = params.get("sortfield")
    if sort is not None and contract.sortfield:
        values = sort if isinstance(sort, list) else [sort]
        for v in values:
            if str(v) in contract.sort_specs:
                _check_spec_version(contract.sort_specs[str(v)], "Sort field", method, version)
        sortable = contract.sortable(version)
        bad = [str(v) for v in values if str(v) not in sortable]
        if bad:
            raise GetParamError(
                f"{method} cannot sort by {', '.join(bad)}. "
                f"Sortable: {', '.join(sortable)}."
            )
    order = params.get("sortorder")
    if order is not None:
        values = order if isinstance(order, list) else [order]
        bad = [str(v) for v in values if str(v).upper() not in ("ASC", "DESC")]
        if bad:
            raise GetParamError(f"sortorder must be 'ASC' or 'DESC', not {', '.join(bad)}.")

    obj = object_for(contract)

    # filter / search keys
    for key, pick, label in (
        ("filter", filter_props, "filtered"),
        ("search", search_props, "searched"),
    ):
        value = params.get(key)
        if not isinstance(value, dict):
            continue
        allowed = pick(contract, version)
        if not allowed:
            continue
        names = {s.name for s in allowed}
        for prop in value:
            if prop in names:
                continue
            if obj is not None and prop in obj.props:
                spec = obj.props[prop]
                _check_spec_version(spec, "Property", method, version)
                if spec.no_output:
                    kind = "a sub-object"
                elif spec.type.lower() in _TEXT_TYPES or (key == "filter" and spec.no_filter):
                    kind = "a text property"
                else:
                    kind = f"a property of type {spec.type}"
                raise GetParamError(
                    f"{method} {key}: '{prop}' is {kind} and cannot be {label} this way; "
                    f"Zabbix would silently ignore it. {key} keys: {', '.join(s.name for s in allowed)}."
                )
            raise GetParamError(
                f"{method} {key}: '{prop}' is not a {contract.object} property. "
                f"{key} keys: {', '.join(s.name for s in allowed)}."
            )

    # output property names
    output = params.get("output")
    if isinstance(output, list) and obj is not None and obj.props:
        for prop in output:
            spec = obj.props.get(str(prop))
            if spec is None:
                raise GetParamError(
                    f"{method} output: '{prop}' is not a {contract.object} property; "
                    f"Zabbix would silently leave it out. Properties: "
                    f"{', '.join(p.name for p in output_props(contract, version))}."
                )
            if spec.no_output:
                select = next((s for s in contract.selects if s.lower() == f"select{prop}".lower()), None)
                hint = f"; use {select} instead" if select else ""
                raise GetParamError(
                    f"{method} output: '{prop}' is a sub-object, not an output property{hint}. "
                    f"Properties: {', '.join(p.name for p in output_props(contract, version))}."
                )
            _check_spec_version(spec, "Property", method, version)


# ---------------------------------------------------------------------------
# Tool schema: the generic get parameters, made specific to one method
# ---------------------------------------------------------------------------

# Parameters a tool accepts that are applied by this server after the call
# and never reach Zabbix (``_build_zabbix_params`` strips them).
MCP_SIDE_PARAMS: frozenset[tuple[str, str]] = frozenset({
    ("problem.get", "monitored"),
})


def specialise_params(method_def: Any, constraints: bool = True) -> list[Any]:
    """Return *method_def.params* rewritten for its contract: generic get
    parameters the method does not have are dropped, ``output`` / ``filter``
    / ``search`` / ``sortfield`` / ``extra_params`` get method-specific
    descriptions, MCP-side parameters say so. Other methods come back as-is.

    With *constraints* (``[server].schema_constraints``, issue #106) the same
    contract is attached as JSON Schema (``ParamDef.schema``), and ``output``
    / ``sortfield`` take a list of names as well as a string.
    """
    from dataclasses import replace

    from zabbix_mcp.api import schema_constraints as sc

    contract = contract_for(getattr(method_def, "api_method", ""))
    params = list(getattr(method_def, "params", []) or [])
    if contract is None:
        return params
    # A parameter the tool types under a name of its own (ParamDef.api_name)
    # is still offered in extra_params under Zabbix's name: the validation
    # takes it there, and the schema is never narrower than the validation.
    sent = {p.name: getattr(p, "sent_as", p.name) for p in params}
    typed = [p.name for p in params if p.name not in COMMON_GET_PARAMETERS and p.name != "extra_params"]
    tool_params = [p.name for p in params]
    out = []
    for p in params:
        name = p.name
        if name in COMMON_GET_PARAMETERS and name not in contract.common:
            continue  # the reference page does not list it for this method
        text = None
        schema = None
        if name == "output":
            schema = sc.output_schema(contract)
            text = describe_output(contract, getattr(method_def, "compact_fields", None),
                                   lists=constraints and schema is not None)
        elif name == "filter":
            text = describe_filter(contract)
            if text is None and contract.filter_props == ():
                continue
            schema = sc.filter_schema(contract)
        elif name == "search":
            text = describe_search(contract)
            if text is None and contract.search_props == ():
                continue
            schema = sc.search_schema(contract)
        elif name == "sortfield":
            schema = sc.sortfield_schema(contract)
            text = describe_sortfield(contract, lists=constraints and schema is not None)
        elif name == "sortorder":
            schema = sc.SORTORDER_SCHEMA
            text = describe_sortorder(contract)
        elif name == "extra_params":
            text = describe_extra_params(contract, typed)
            schema = sc.extra_params_schema(contract, tool_params)
        elif (contract.method, name) in MCP_SIDE_PARAMS:
            text = f"[MCP-side filter, applied after the Zabbix call; not a {contract.method} parameter] {p.description}"
        else:
            schema = sc.value_enum_schema(contract.params.get(sent[name]), p.param_type)
        changes: dict[str, Any] = {}
        if text:
            changes["description"] = text
        if constraints and schema is not None:
            changes["schema"] = schema
            if name in ("output", "sortfield", "sortorder") and p.param_type == "str":
                changes["param_type"] = "str|list[str]"
        out.append(replace(p, **changes) if changes else p)
    return out
