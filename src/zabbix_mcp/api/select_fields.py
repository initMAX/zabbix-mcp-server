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

"""The fields a ``selectXxx`` takes as a list, measured per release (#106).

``select_fields.json`` is built by ``scripts/build_select_fields.py`` from
``scripts/audit_select_fields_live.py``: for each select that a release checks
itself, the exact list it takes (Zabbix's own "value must be one of ...").
Selects that take any name and ignore the unknown ones are not in it, and are
neither described nor checked by field.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

from zabbix_mcp.api.versions import parse_version


@lru_cache(maxsize=1)
def _data() -> dict:
    try:
        text = resources.files("zabbix_mcp.api").joinpath("select_fields.json").read_text(encoding="utf-8")
    except FileNotFoundError:
        return {"methods": {}}
    return json.loads(text)


def _release(version: str | None) -> str | None:
    parsed = parse_version(version)
    return f"{parsed[0]}.{parsed[1]}" if parsed else None


def fields_on(method: str, select: str, version: str | None) -> list[str] | None:
    """The fields *select* of *method* takes on *version*, or ``None`` when that is not
    known (a select that takes any name, an unmeasured release, an unknown version)."""
    entry = (_data().get("methods") or {}).get(method, {}).get(select)
    release = _release(version)
    if not entry or release is None or release not in entry.get("releases", []):
        return None
    return [f for f, where in entry["fields"].items() if not where or release in where]


def _returned(method: str, select: str, release: str | None) -> list[str] | None:
    if release is None:
        return None
    return ((_data().get("returned") or {}).get(method, {}).get(select) or {}).get(release)


def not_on(method: str, select: str, version: str | None) -> list[str]:
    """Fields of *select* that other releases check and take, and that *version* (which
    does not check the select itself) does not return: fields of another release.
    Zabbix may fail the whole read on them; a name no release has is not in it."""
    entry = (_data().get("methods") or {}).get(method, {}).get(select)
    release = _release(version)
    if not entry or release is None or release in entry.get("releases", []):
        return []
    here = _returned(method, select, release)
    if here is None:
        return []
    return sorted(set(entry["fields"]) - set(here))


def left_out(method: str, select: str, version: str | None, names: list) -> list[str]:
    """Names in *select* that *version* (which does not check the select) does not
    return and no release takes: Zabbix leaves them out of the answer without a word."""
    entry = (_data().get("methods") or {}).get(method, {}).get(select) or {}
    release = _release(version)
    if release in entry.get("releases", []):
        return []
    here = _returned(method, select, release)
    if here is None:
        return []
    known = set(here) | set(entry.get("fields") or {})
    return [str(n) for n in names if str(n) not in known]


def any_release(method: str, select: str) -> list[str] | None:
    """Every field *select* of *method* takes on some release that checks it (the schema
    serves servers of several releases; the call is checked against its own)."""
    entry = (_data().get("methods") or {}).get(method, {}).get(select)
    return sorted(entry["fields"]) if entry else None


def measured_selects(method: str) -> list[str]:
    return sorted((_data().get("methods") or {}).get(method, {}))
