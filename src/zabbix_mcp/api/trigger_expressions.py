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

"""A trigger expression in the form that can be read and written back.

``trigger.get`` returns ``{13093}>{$UTIL.MAX}``: function IDs nobody can read,
and a form ``trigger.update`` refuses. With ``expandExpression`` Zabbix turns
the IDs into ``avg(/host/key,10m)`` and, in the same pass, every user macro
into its current value: in the expression, in the function parameters and in
the item keys. v1.40 and v1.41 asked for that expansion by default, so a
trigger read with ``trigger_get`` and sent back through ``trigger_update``
came out as ``avg(/host/key,10m)>75``. The threshold no longer followed the
macro, and nothing said so (more than half of the triggers of a stock Zabbix
use a user macro).

``editable_expression`` rebuilds the form the frontend shows and the export
writes: the function calls from the trigger's own ``functions``, everything
else as it is stored. Measured on 6.0.48 to 8.0.0 against Zabbix's own
expansion for every trigger and trigger prototype of the test servers (46 000
objects): identical wherever there is no user macro, and with the macro where
Zabbix puts its value.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable, Mapping

from zabbix_mcp.api.versions import parse_version

METHODS = frozenset({"trigger.get", "triggerprototype.get"})
FIELDS = ("expression", "recovery_expression")
# the expression syntax with functions written as func(/host/key, ...)
SINCE = (5, 4)
_CHUNK = 500

# what the rebuild reads for each trigger, in a call of its own so that the
# caller's output, selects, limit and sort stay exactly as asked
_SELECTS: dict[str, Any] = {
    # "extend": asked for by name, Zabbix leaves the "function" field out (6.0 to 8.0)
    "selectFunctions": "extend",
    "selectItems": ["itemid", "hostid", "key_"],
    "selectHosts": ["hostid", "host"],
}

# A user macro with its context ({$M}, {$M:ctx}, {$M:"ctx"}, {$M:regex:"..."}; a
# context may hold an LLD macro and, unquoted, a lone quote), a quoted string
# (both left alone), or a function placeholder. The macro comes first: a quote
# inside an unquoted context must not open a string.
USER_MACRO = r'\{\$[A-Z0-9_.]+(?::(?:regex:)?(?:"(?:[^"\\]|\\.)*"|(?:[^{}]|\{#[^}]*\})*))?\}'
_TOKEN = re.compile(USER_MACRO + r'|"(?:[^"\\]|\\.)*"|\{(\d+)\}')
_PLACEHOLDER = re.compile(r"\{\d+\}")


class NotRebuilt(ValueError):
    """The stored pieces do not add up to an expression (the stored form is left as it is)."""


def editable_expression(raw: str, functions: Mapping[str, Mapping[str, Any]],
                        items: Mapping[str, Mapping[str, Any]], hosts: Mapping[str, str]) -> str:
    """*raw* with every ``{functionid}`` replaced by ``function(/host/key<parameters>)``.

    *functions* by functionid, *items* by itemid, *hosts* technical names by
    hostid. A function is stored as its name and a parameter string whose
    first character stands for the item (``$,10m``).
    """
    def call(match: re.Match) -> str:
        if match.group(1) is None:
            return match.group(0)
        function = functions.get(match.group(1))
        if function is None:
            raise NotRebuilt(f"function {match.group(1)} is not one of the trigger's")
        item = items.get(str(function.get("itemid")))
        host = hosts.get(str(item.get("hostid"))) if item else None
        name = function.get("function")
        key = item.get("key_") if item else None
        parameter = str(function.get("parameter", ""))
        if not name or not key or host is None or not parameter.startswith("$"):
            raise NotRebuilt(f"function {match.group(1)} cannot be written out")
        return f"{name}(/{host}/{key}{parameter[1:]})"

    return _TOKEN.sub(call, raw)


def wanted(api_method: str, kwargs: Mapping[str, Any], version: str | None) -> bool:
    """Whether a get of *api_method* is answered with editable expressions.

    Yes for the two trigger methods on a release with the current expression
    syntax, unless the caller chose: ``expandExpression: true`` is Zabbix's
    own expansion (the values of the user macros, for reading), ``false`` the
    stored form.
    """
    if api_method not in METHODS:
        return False
    current = parse_version(version)
    if current is None or tuple(current[:2]) < SINCE:
        return False
    if kwargs.get("expandExpression") is not None:
        return False
    extra = kwargs.get("extra_params")
    return not (isinstance(extra, Mapping) and "expandExpression" in extra)


def _rows(result: Any) -> list[dict]:
    if isinstance(result, dict):          # preservekeys
        result = list(result.values())
    return [row for row in result if isinstance(row, dict)] if isinstance(result, list) else []


def rewrite(result: Any, api_method: str, call: Callable[[str, dict], Any]) -> list[str]:
    """Replace the stored expressions in a ``trigger.get`` answer by the editable form, in place.

    *call* is ``(api_method, params) -> result`` against the same server.
    Returns the IDs of the triggers whose pieces did not add up. Those keep
    the stored form: unreadable, and refused by ``trigger.update``, which is
    the point. Zabbix's own expansion would read well and take the macros
    with it when written back.
    """
    rows = [row for row in _rows(result)
            if row.get("triggerid") and any(_PLACEHOLDER.search(str(row.get(f) or "")) for f in FIELDS)]
    if not rows:
        return []
    ids = [str(row["triggerid"]) for row in rows]
    pieces: dict[str, dict] = {}
    for start in range(0, len(ids), _CHUNK):
        answer = call(api_method, {"triggerids": ids[start:start + _CHUNK], "output": ["triggerid"], **_SELECTS})
        for piece in _rows(answer):
            pieces[str(piece.get("triggerid"))] = piece

    failed: list[str] = []
    for row in rows:
        triggerid = str(row["triggerid"])
        piece = pieces.get(triggerid) or {}
        functions = {str(f.get("functionid")): f for f in _as_list(piece.get("functions"))}
        items = {str(i.get("itemid")): i for i in _as_list(piece.get("items"))}
        hosts = {str(h.get("hostid")): str(h.get("host")) for h in _as_list(piece.get("hosts"))}
        try:
            rebuilt = {f: editable_expression(str(row[f]), functions, items, hosts) for f in FIELDS if row.get(f)}
        except NotRebuilt:
            failed.append(triggerid)
            continue
        row.update(rebuilt)          # both fields or neither
    return failed


def _as_list(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, dict):
        value = list(value.values())
    return [v for v in value if isinstance(v, Mapping)] if isinstance(value, list) else []
