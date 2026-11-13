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

"""Shapes of a write that Zabbix refuses without saying what is wrong.

Two mistakes a model makes, seen in a live session on Zabbix 8.0 with
``host_create``, where Zabbix's own answers did not help it correct them:

* a reference list written as IDs, ``"groups": ["2"]``. Zabbix wants objects,
  ``[{"groupid": "2"}]``, and answers ``Invalid parameter "/1/groups/1": an
  array is expected``, which reads as if the list itself were wrong;
* an interface with SNMP settings that are not what Zabbix calls them, or on
  an interface that is not SNMP. Zabbix answers ``Incorrect arguments passed
  to function`` and nothing else.

``problems`` names the field by its path and says what goes there instead;
it changes nothing, a call is refused before it is sent or goes out as it was
written. Two helpers do change a payload, only where the meaning is the same:
``rename_get_lists`` writes a create's copied ``hostgroups`` as ``groups``, and
``trim_references`` keeps only the ID inside a reference entry. What is checked is what Zabbix refuses (or, for
SNMP settings on another interface type, ignores) on every supported release,
measured in the API sources of 6.0 to 8.0 (``CHostInterface``).
"""

from __future__ import annotations

import json
from typing import Any

from zabbix_mcp.api.versions import parse_version

# Reference lists of a write: each entry is an object carrying the ID field.
REFERENCE_LISTS: dict[str, str] = {
    "groups": "groupid",
    "templates": "templateid",
    "templates_clear": "templateid",
    "hosts": "hostid",
    "usrgrps": "usrgrpid",
    "users": "userid",
}

# Methods whose top-level reference lists are checked (the ones whose API page lists
# these properties as objects).
_REFERENCE_METHODS = frozenset({
    "host.create", "host.update", "host.massadd", "host.massupdate", "host.massremove",
    "template.create", "template.update", "template.massadd", "template.massupdate", "template.massremove",
    "hostgroup.massadd", "hostgroup.massupdate", "hostgroup.massremove", "hostgroup.propagate",
    "templategroup.massadd", "templategroup.massupdate", "templategroup.massremove", "templategroup.propagate",
    "hostprototype.create", "hostprototype.update",
    "maintenance.create", "maintenance.update",
    "user.create", "user.update", "usergroup.create", "usergroup.update",
})

# Mass methods that refuse "tags" ('unexpected parameter "tags"', no hint), although the
# server instructions say a list property can be changed with massadd. host.massupdate
# takes them (a replace, until it is gone in 8.0).
_NO_TAGS = frozenset({"host.massadd", "template.massadd", "template.massupdate"})

# Mass methods of templates that take no hosts (measured on 6.4 and 7.0: 'unexpected
# parameter "hosts"'); the link goes the other way, host_massadd / host_massremove.
_NO_HOSTS = {"template.massadd": "hosts", "template.massremove": "hostids"}

# Methods that carry interfaces: in an "interfaces" list, or as the payload itself.
_INTERFACE_LISTS = frozenset({
    "host.create", "host.update", "host.massadd", "host.massupdate",
    "hostprototype.create", "hostprototype.update",
})
_INTERFACE_ITSELF = frozenset({"hostinterface.create", "hostinterface.update"})

SNMP = 2
_TYPE_NAMES = {"AGENT": 1, "SNMP": 2, "IPMI": 3, "JMX": 4}

# SNMP "details" keys per release (CHostInterface, $snmp_fields).
_SNMP_BASE = ("version", "bulk", "community", "securityname", "securitylevel", "authpassphrase",
              "privpassphrase", "authprotocol", "privprotocol", "contextname")
_SNMP_SINCE: dict[str, tuple[int, int]] = {"max_repetitions": (6, 4), "retries": (8, 0)}
_SNMP_VERSIONS = {"1": "SNMPv1", "2": "SNMPv2c", "3": "SNMPv3"}

INTERFACE_HELP = (
    "An SNMP interface is type 2 (or \"SNMP\") with its settings in details: "
    "{\"type\": 2, \"main\": 1, \"useip\": 1, \"ip\": \"192.0.2.10\", \"dns\": \"\", \"port\": \"161\", "
    "\"details\": {\"version\": 2, \"bulk\": 1, \"community\": \"{$SNMP_COMMUNITY}\"}} "
    "(version 1, 2 = SNMPv2c or 3; v1/v2c take community, v3 securityname, securitylevel and the "
    "auth/priv keys)."
)


def snmp_keys(version: str | None) -> tuple[str, ...]:
    """The keys an SNMP interface's details may have on *version* (all of them when unknown)."""
    parsed = parse_version(version)
    extra = tuple(k for k, since in _SNMP_SINCE.items() if parsed is None or tuple(parsed[:2]) >= since)
    return _SNMP_BASE + extra


def _type_of(interface: dict) -> Any:
    raw = interface.get("type")
    if isinstance(raw, str) and raw.strip().upper() in _TYPE_NAMES:
        return _TYPE_NAMES[raw.strip().upper()]
    try:
        return int(raw)
    except (TypeError, ValueError):
        return raw


def _interface_problems(path: str, interface: Any, version: str | None, *, update: bool) -> list[str]:
    if not isinstance(interface, dict):
        return [f"{path}: an interface is an object, got {type(interface).__name__} {interface!r:.60}. {INTERFACE_HELP}"]
    found: list[str] = []
    kind = _type_of(interface)
    details = interface.get("details")
    if details is not None and not isinstance(details, (dict, list)):
        return [f"{path}.details: an object, got {type(details).__name__}. {INTERFACE_HELP}"]
    if isinstance(details, list):
        details = {} if not details else None
        if details is None:
            return [f"{path}.details: an object, got a list. {INTERFACE_HELP}"]
    if kind is not None and kind != SNMP and "type" in interface:
        if details:
            found.append(f"{path}: details ({', '.join(sorted(details))}) belong to an SNMP interface; this one is "
                         f"type {interface.get('type')!r}, which has no settings there (Zabbix would not apply them). "
                         f"For SNMP use type 2. {INTERFACE_HELP}")
        return found
    if kind != SNMP:
        return found            # an update that does not name the type: Zabbix knows it
    allowed = snmp_keys(version)
    if details is None:
        if not update:
            found.append(f"{path}.details: an SNMP interface needs its SNMP settings. {INTERFACE_HELP}")
        return found
    unknown = [k for k in details if k not in allowed]
    if unknown:
        found.append(f"{path}.details: {', '.join(repr(k) for k in unknown)} "
                     f"{'is' if len(unknown) == 1 else 'are'} not an SNMP setting"
                     f"{' on Zabbix ' + version if version else ''}; the keys are {', '.join(allowed)}. {INTERFACE_HELP}")
    if not update or "version" in details:
        snmp_version = str(details.get("version", "")).strip()
        if snmp_version not in _SNMP_VERSIONS:
            found.append(f"{path}.details.version: 1, 2 (SNMPv2c) or 3, got {details.get('version')!r}. {INTERFACE_HELP}")
        elif snmp_version in ("1", "2") and not update and "community" not in details:
            found.append(f"{path}.details.community: {_SNMP_VERSIONS[snmp_version]} needs a community "
                         "(a value or a user macro such as {$SNMP_COMMUNITY}).")
    return found


# What a get answer calls a list that a write calls otherwise (selectHostGroups gives
# "hostgroups", host.create takes "groups"). Zabbix answers 'the parameter "groups" is
# missing', which does not say that the list is there under the other name.
_GET_NAMES: dict[str, dict[str, str]] = {
    "host": {"hostgroups": "groups", "parentTemplates": "templates"},
    "template": {"templategroups": "groups"},
}


def _ids(value: Any, id_field: str) -> list[str]:
    entries = value if isinstance(value, list) else [value]
    return sorted(str(e.get(id_field)) if isinstance(e, dict) else str(e) for e in entries)


def rename_get_lists(api_method: str, params: Any) -> list[str]:
    """A copy of a get answer sent to a create: its "hostgroups" (selectHostGroups) /
    "parentTemplates" / "templategroups" are the lists the create calls "groups" /
    "templates", and a copy means them. Renamed there, when the write name is not given too.

    An update is left as it was: a get name next to the object's ID is an echo of what the
    object has (perhaps cut by limitSelects), and replacing the links with it would unlink
    or regroup without anybody asking. It is dropped by the select echoes / the measured
    contract, and the answer says it was not applied (server._get_names_note)."""
    method = str(api_method).lower()
    names = _GET_NAMES.get(method.split(".")[0], {}) if method.endswith(".create") else {}
    renamed: list[str] = []
    for item in params if isinstance(params, list) else [params]:
        if not isinstance(item, dict):
            continue
        for got, write in names.items():
            if got in item and write not in item:
                item[write] = item.pop(got)
                renamed.append(f"{got} -> {write}")
    return renamed


def get_names_left_out(api_method: str, params: Any) -> list[tuple[str, str]]:
    """The get names an update carries without the write name (they are not applied)."""
    method = str(api_method).lower()
    if not method.endswith(".update"):
        return []
    names = _GET_NAMES.get(method.split(".")[0], {})
    left: list[tuple[str, str]] = []
    for item in params if isinstance(params, list) else [params]:
        if isinstance(item, dict):
            left.extend((got, write) for got, write in names.items()
                        if got in item and write not in item and (got, write) not in left)
    return left


def trim_references(api_method: str, params: Any) -> list[str]:
    """Keep only the ID in each entry of a reference list that has it: a group copied from
    a get answer, {"groupid": "22", "name": "Linux servers", "flags": "0", "uuid": ...}, is
    refused by Zabbix on every release ('unexpected parameter "name"') although the ID alone
    says everything. An entry without its ID is left as it is, for ``problems`` to name."""
    method = str(api_method).lower()
    if method not in _REFERENCE_METHODS:
        return []
    dropped: list[str] = []
    for item in params if isinstance(params, list) else [params]:
        if not isinstance(item, dict):
            continue
        for key, id_field in REFERENCE_LISTS.items():
            value = item.get(key)
            for entry in value if isinstance(value, list) else [value] if isinstance(value, dict) else []:
                if isinstance(entry, dict) and id_field in entry:
                    extra = [k for k in entry if k != id_field]
                    for k in extra:
                        del entry[k]
                    if extra and f"{key}[].{extra[0]}" not in dropped:
                        dropped.extend(f"{key}[].{k}" for k in extra)
    return dropped


def problems(api_method: str, params: Any, version: str | None = None) -> list[str]:
    """What in a write payload Zabbix refuses without saying what is wrong (empty when nothing)."""
    found: list[str] = []
    method = str(api_method).lower()
    items = params if isinstance(params, list) else [params]
    many = isinstance(params, list)
    for n, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        base = f"params[{n}]" if many else "params"
        if method in _REFERENCE_METHODS:
            for key, id_field in REFERENCE_LISTS.items():
                value = item.get(key)
                if isinstance(value, dict):
                    value = [value]
                if not isinstance(value, list):
                    continue
                for i, entry in enumerate(value):
                    if not isinstance(entry, dict):
                        found.append(f"{base}.{key}[{i}]: an object with its ID, {json.dumps({id_field: str(entry)[:40]})}, "
                                     f"not {type(entry).__name__} {json.dumps(entry)[:40]}. Write {key} as "
                                     f"[{{\"{id_field}\": \"<id>\"}}, ...].")
        if method in _NO_TAGS and "tags" in item:
            found.append(f"{base}.tags: {method} takes no tags (Zabbix refuses them). Tags of several "
                         f"hosts or templates: read each one's tags and send the complete list with "
                         f"{method.split('.')[0]}_update, one call per object.")
        if method in _NO_HOSTS and _NO_HOSTS[method] in item:
            how = ("host_massremove with 'hostids' and 'templateids' (or 'templateids_clear' to also "
                   "remove what they brought)" if method.endswith("remove") else "host_massadd with 'hosts' and 'templates'")
            found.append(f"{base}.{_NO_HOSTS[method]}: {method} links no hosts. To link templates to hosts "
                         f"or unlink them, use {how}.")
        found.extend(_release_shape_problems(base, method, item, version))
        update = method.endswith(".update") or method.endswith(".massupdate")
        if method in _INTERFACE_LISTS and isinstance(item.get("interfaces"), (list, dict)):
            interfaces = item["interfaces"] if isinstance(item["interfaces"], list) else [item["interfaces"]]
            for i, interface in enumerate(interfaces):
                found.extend(_interface_problems(f"{base}.interfaces[{i}]", interface, version,
                                                 update=update or (isinstance(interface, dict) and "interfaceid" in interface)))
        if method in _INTERFACE_ITSELF:
            found.extend(_interface_problems(base, item, version, update=method.endswith(".update")))
        found.extend(_enum_problems(base, method, item))
    return found


def _enum_problems(base: str, method: str, item: dict) -> list[str]:
    """A symbolic value of an enum field that is no name of it (item type "web"): Zabbix
    answers "an integer is expected", the right value has to be guessed from that."""
    from zabbix_mcp.server import enum_fields_for, enum_meaning
    found: list[str] = []
    for field, mapping in enum_fields_for(method).items():
        value = item.get(field)
        if not isinstance(value, str) or value.strip().lstrip("-").isdigit() or value.strip().upper() in mapping:
            continue
        allowed = enum_meaning(mapping)
        found.append(f"{base}.{field}: {json.dumps(value)} is no {field} of {method}; give the number or the name: {allowed}.")
    return found


def select_problems(params: Any) -> list[str]:
    """A selectXxx of a read given as one property name ("selectHostGroups": "name"). Zabbix
    takes "extend", "count" or a list of properties; for a single name it answers with a
    wrong path (``"/output": value must be "extend"``) or not at all (an empty response
    for selectInterfaces on 6.4), which a model cannot correct from."""
    if not isinstance(params, dict):
        return []
    found = []
    for key, value in params.items():
        if (isinstance(key, str) and key.startswith("select") and isinstance(value, str)
                and value.strip().lower() not in ("extend", "count")):
            found.append(f"{key}: {json.dumps(value)[:60]} is not a value of it; give a list of properties "
                         f"({key}: {json.dumps([value.strip()])[:60]}), \"extend\" or \"count\".")
    return found


_DASHBOARDS = frozenset({"dashboard.create", "dashboard.update", "templatedashboard.create", "templatedashboard.update"})
_INDEXED = __import__("re").compile(r"^([A-Za-z_]+)\.(\d+)$")


def _release_shape_problems(base: str, method: str, item: dict, version: str | None) -> list[str]:
    """Shapes that changed between releases and that Zabbix takes without a word on the
    wrong one (agent runs on 6.0): a widget field "groupids.0" is stored on 6.x and the
    widget then shows every group; "hostgroup_rights" before 6.2 is refused bare."""
    parsed = parse_version(version)
    if parsed is None:
        return []
    found: list[str] = []
    if method in _DASHBOARDS and tuple(parsed[:2]) < (7, 0):
        def _list(value: Any) -> list:
            return value if isinstance(value, list) else []
        for p, page in enumerate(_list(item.get("pages"))):
            for w, widget in enumerate(_list(page.get("widgets")) if isinstance(page, dict) else []):
                for f, field in enumerate(_list(widget.get("fields")) if isinstance(widget, dict) else []):
                    m = _INDEXED.match(str((field or {}).get("name", ""))) if isinstance(field, dict) else None
                    if m:
                        found.append(f"{base}.pages[{p}].widgets[{w}].fields[{f}].name: \"{m.group(0)}\" is the 7.0+ "
                                     f"form; Zabbix {version} names it \"{m.group(1)}\" (one field per value), "
                                     f"and would store the indexed name without applying it.")
    if method in ("usergroup.create", "usergroup.update") and tuple(parsed[:2]) < (6, 2):
        for key in ("hostgroup_rights", "templategroup_rights"):
            if key in item:
                found.append(f"{base}.{key}: Zabbix {version} has one list 'rights' for host groups "
                             f"([{{\"id\": \"<groupid>\", \"permission\": 2}}]); {key} comes with 6.2.")
    return found
