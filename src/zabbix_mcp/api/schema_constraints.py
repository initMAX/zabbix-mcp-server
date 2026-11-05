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

"""The get contracts as JSON Schema, for ``tools/list`` (issue #106).

Since v1.39 the description of ``output`` / ``filter`` / ``search`` /
``sortfield`` / ``extra_params`` names what the method takes, and the
server refuses anything else. That is text: a client that feeds the tool
schemas to a structured-output decoder or to a JSON Schema validator sees
``string | null`` and lets the model write ``"sortfield": "clock"`` for
``problem.get``, which is then refused at run time.

This module turns the same contract into schema fragments:

* ``sortfield``     - an enum of the sortable fields (a list for several),
* ``sortorder``     - ``ASC`` / ``DESC``,
* ``output``        - ``extend`` / ``count`` or a list of property names,
* ``filter``        - an object whose keys are the filterable properties,
* ``search``        - an object whose keys are the searchable properties,
* ``extra_params``  - an object whose keys are the native parameters and
  selects the tool does not type itself,
* a typed integer parameter with a documented closed value set - an enum.

The names are the contract's: every name a description lists, plus the few
it leaves out because they left in Zabbix 6.0 or earlier (a 5.x server still
takes them). The schema is never narrower than what the server accepts
(``tests/test_schema_constraints.py`` checks both directions).

Only standard keywords that a consumer either understands or may safely
ignore are used (``enum``, ``items``, ``minItems``, ``propertyNames``), and
never at the top level of a tool schema: several model APIs refuse
``anyOf`` / ``oneOf`` there, so "one of these two arguments is required"
stays in the description.

The listed schema is stricter than what the handler accepts: a
comma-separated string for ``output`` / ``sortfield`` still works when a
caller sends it, the schema just no longer suggests it. A release is not
part of the schema (one catalog serves servers of several releases);
``validate_get_params`` still checks the call against the server it goes to.
"""

from __future__ import annotations

import copy
from typing import Any, Callable, Iterable

from zabbix_mcp.api.contracts import (
    GetContract, Spec, _for_description, filter_props, output_props, search_props,
)

def _listed(specs: Iterable[Spec]) -> list[str]:
    """The names of *specs*: the ones a description lists first, in its
    order, then the ones it hides (gone since 6.0 or earlier)."""
    specs = list(specs)
    shown = [s.name for s in _for_description(specs)]
    return shown + [s.name for s in specs if s.name not in shown]


def _one_or_list(names: list[str]) -> dict[str, Any]:
    """One of *names*, or a list of them."""
    return {"anyOf": [
        {"type": "string", "enum": list(names)},
        {"type": "array", "items": {"type": "string", "enum": list(names)}, "minItems": 1},
    ]}


# One direction for every sort field, or one per sort field.
SORTORDER_SCHEMA: dict[str, Any] = _one_or_list(["ASC", "DESC"])
# For a tool that sorts by a single field.
SORTORDER_ONE: dict[str, Any] = {"type": "string", "enum": ["ASC", "DESC"]}


def _keys(names: list[str]) -> dict[str, Any]:
    if not names:
        return {"type": "object", "additionalProperties": False}   # the server refuses every key
    return {"type": "object", "propertyNames": {"enum": list(names)}}


def output_schema(contract: GetContract, count: bool | None = None) -> dict[str, Any] | None:
    """``extend`` (and ``count`` where the method has ``countOutput``, unless
    *count* says otherwise) or a list of the object's properties."""
    props = _listed(output_props(contract))
    if not props:
        return None
    counts = ("countOutput" in contract.common) if count is None else count
    words = ["extend", "count"] if counts else ["extend"]
    return {"anyOf": [
        {"type": "string", "enum": words},
        {"type": "array", "items": {"type": "string", "enum": props}, "minItems": 1},
    ]}


def sortfield_schema(contract: GetContract) -> dict[str, Any] | None:
    names = _listed(contract.sort_specs[n] for n in contract.sortfield)
    return _one_or_list(names) if names else None


def filter_schema(contract: GetContract) -> dict[str, Any] | None:
    names = _listed(filter_props(contract))
    return _keys(names) if names else None


def search_schema(contract: GetContract) -> dict[str, Any] | None:
    names = _listed(search_props(contract))
    return _keys(names) if names else None


def extra_param_names(contract: GetContract, tool_params: Iterable[str]) -> list[str]:
    """What ``extra_params`` may carry: the generic get parameters, native
    parameters and selects of the method that the tool does not type itself."""
    typed = set(tool_params)
    names = [n for n in sorted(contract.common) if n not in typed]
    names += [n for n in _listed(contract.params.values()) if n not in typed]
    names += [n for n in _listed(contract.selects.values()) if n not in typed and n not in names]
    return names


def extra_params_schema(
    contract: GetContract, tool_params: Iterable[str], exclude: Iterable[str] = (),
) -> dict[str, Any]:
    """*exclude*: keys the method has and this tool cannot work with."""
    skip = set(exclude)
    return _keys([n for n in extra_param_names(contract, tool_params) if n not in skip])


def value_enum_schema(spec: Spec | None, param_type: str) -> dict[str, Any] | None:
    """An integer parameter whose reference page lists every value it takes
    (``history.get`` ``history``: 0 ... 6)."""
    if spec is None or param_type != "int" or not spec.values:
        return None
    try:
        values = sorted({int(v) for v in spec.values})
    except ValueError:
        return None
    return {"type": "integer", "enum": values}


def schema_extra(fragment: dict[str, Any]) -> Callable[[dict[str, Any]], None]:
    """A pydantic ``json_schema_extra`` hook that replaces the generated
    value schema of one parameter with *fragment* and keeps the rest
    (``null`` for an optional parameter, description, title, default)."""
    branches = fragment["anyOf"] if set(fragment) == {"anyOf"} else [fragment]

    def patch(schema: dict[str, Any]) -> None:
        if "anyOf" in schema:   # Optional[...]: [<value>, {"type": "null"}]
            nullable = any(isinstance(b, dict) and b.get("type") == "null" for b in schema["anyOf"])
            schema["anyOf"] = copy.deepcopy(branches) + ([{"type": "null"}] if nullable else [])
            return
        for key in ("type", "items", "additionalProperties"):
            schema.pop(key, None)
        if len(branches) == 1:
            schema.update(copy.deepcopy(branches[0]))
        else:
            schema["anyOf"] = copy.deepcopy(branches)

    return patch
