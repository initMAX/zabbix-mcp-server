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

"""What ``X.update`` / ``X.create`` refuse of what ``X.get`` returns.

``write_contracts.json`` is measured, not written: for every object with an
update method, ``scripts/audit_write_roundtrip_live.py`` sends the objects of
a real Zabbix back through ``X.update`` unchanged and records every key the
server refuses, on each supported release; ``scripts/build_write_contracts.py``
keeps the keys that were refused on every plain object that carried them. The
result is three kinds of key:

* read-only properties (``templateid``, ``flags``, ``state``, ``error``,
  ``lastclock``, ``uuid`` on a dashboard, the ``available`` / ``error`` quartet
  on an interface, which Zabbix refuses with a bare ``Incorrect arguments
  passed to function``);
* row identifiers and parent references inside nested arrays
  (``operations[].operationid``, ``tags[].automatic``, the whole user object
  echoed inside ``usergroup.users[]`` except ``userid``);
* sub-objects a ``selectXxx`` produced (``hosts``, ``triggers``,
  ``discoveryRule``, ``valuemap``), which are not write fields at all;
* on 7.0, the deprecated twin of a renamed field returned next to the new
  one (``content_type`` / ``message_format`` on a media type, ``rights`` /
  ``hostgroup_rights`` on a user group), refused only when both are sent,
  so it is dropped only next to its successor.

``strip_for_write`` drops exactly those from a payload before the call, so
"read it, change one thing, write it back" works through the dedicated tools.
Keys whose acceptance depends on the object's state (``formulaid`` without a
custom expression, the escalation fields of a non-trigger action) are not
here; ``action_payload.py`` and ``server._sanitize_create_params`` handle
them. ``zabbix_raw_api_call`` is never touched.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Any

from zabbix_mcp.api.contracts import parse_version


@dataclass(frozen=True)
class StripRule:
    path: tuple[str, ...]       # ("operations[]", "opconditions[]", "opconditionid")
    releases: tuple[str, ...] = ()   # measured refused on these releases only; () = on every one
    kind: str = "unexpected"
    only_with: str | None = None    # dropped only next to this sibling key (a deprecated twin)

    def available(self, version: str | None) -> bool:
        """A universal rule applies everywhere (an unmeasured release too); a
        dated one only on a release it was measured on."""
        if not self.releases:
            return True
        current = parse_version(version)
        if current is None:
            return False
        return ".".join(str(x) for x in current[:2]) in self.releases


def _load() -> dict[str, tuple[StripRule, ...]]:
    text = resources.files("zabbix_mcp.api").joinpath("write_contracts.json").read_text(encoding="utf-8")
    raw = json.loads(text)
    out: dict[str, tuple[StripRule, ...]] = {}
    for method, spec in (raw.get("methods") or {}).items():
        rules = []
        for path, entry in (spec.get("strip") or {}).items():
            rules.append(StripRule(
                path=tuple(path.split(".")),
                releases=tuple(entry.get("releases") or ()),
                kind=entry.get("kind", "unexpected"),
                only_with=entry.get("only_with"),
            ))
        out[method] = tuple(rules)
    return out


WRITE_CONTRACTS: dict[str, tuple[StripRule, ...]] = _load()


def rules_for(api_method: str, version: str | None = None) -> list[StripRule]:
    return [r for r in WRITE_CONTRACTS.get(api_method, ()) if r.available(version)]


def _strip_path(node: Any, path: tuple[str, ...], dropped: list[str], prefix: str,
                only_with: str | None = None) -> None:
    """Remove *path* from *node* in place; ``name[]`` means every element."""
    if not path:
        return
    seg, rest = path[0], path[1:]
    is_list = seg.endswith("[]")
    key = seg[:-2] if is_list else seg
    if not isinstance(node, dict) or key not in node:
        return
    here = f"{prefix}.{seg}" if prefix else seg
    if not rest:
        if only_with and only_with not in node:
            return
        del node[key]
        dropped.append(here)
        return
    child = node[key]
    if is_list:
        if isinstance(child, list):
            for element in child:
                _strip_path(element, rest, dropped, here, only_with)
    else:
        _strip_path(child, rest, dropped, here, only_with)


def strip_for_write(api_method: str, params: Any, version: str | None = None) -> list[str]:
    """Drop the measured read-only keys from *params* (a dict, or a list of
    dicts for a bulk call) in place. Returns the dotted paths removed."""
    rules = rules_for(api_method, version)
    if not rules:
        return []
    dropped: list[str] = []
    targets = params if isinstance(params, list) else [params]
    for target in targets:
        if not isinstance(target, dict):
            continue
        for rule in rules:
            before = len(dropped)
            _strip_path(target, rule.path, dropped, "", rule.only_with)
            # a path that hits many rows still counts once
            if len(dropped) > before + 1:
                del dropped[before + 1:]
    return dropped


def describe(api_method: str) -> str | None:
    """One sentence for a tool description: what the server drops before the call."""
    rules = WRITE_CONTRACTS.get(api_method)
    if not rules:
        return None
    # Four kinds, said apart: "drops (groups, tags)" would read as if
    # host.update lost its groups, and "drops (rights)" as if a user group
    # could not be given rights.
    #   always     the key goes on every release, whatever else is sent
    #   inside     the key stays, keys inside it go
    #   dated      the key goes on the releases measured to refuse it
    #   twins      the key goes only next to its successor (a deprecated name)
    lone = [r for r in rules if len(r.path) == 1]
    always = sorted({r.path[0] for r in lone if not r.releases and not r.only_with})
    twins = sorted({(r.path[0], r.only_with) for r in lone if r.only_with and r.path[0] not in always})
    dated = sorted({r.path[0] for r in lone if r.releases and not r.only_with} - set(always))
    inside = sorted({r.path[0].rstrip("[]") for r in rules if len(r.path) > 1} - set(always))

    def shown(names: list[str]) -> str:
        return ", ".join(names[:12]) + (", ..." if len(names) > 12 else "")

    parts = []
    if always:
        parts.append(shown(always))
    if inside:
        parts.append(f"inside {shown(inside)} only the keys refused there")
    if dated:
        parts.append(f"{shown(dated)} on the releases that refuse {'it' if len(dated) == 1 else 'them'}")
    if twins:
        parts.append(", ".join(f"{name} next to {twin}" for name, twin in twins))
    return (f"An object copied from the get tool can be sent as is: before the call the server drops "
            f"the read-only and sub-object keys {api_method} refuses ({'; '.join(parts)}).")
