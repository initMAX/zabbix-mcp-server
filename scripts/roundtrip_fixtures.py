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

"""Create "maximal" fixture objects on a live Zabbix for a get -> update audit.

Every object carries as many optional sub-structures as the release supports
(tags, macros, preprocessing, filters, overrides, shares, ...) so a later audit
can send each ``X.get`` result back into ``X.update`` and learn which returned
fields the server refuses.  Every name starts with ``rt-`` so leftovers are easy
to find.  Nothing is enabled: hosts, actions, discovery rules, web scenarios,
connectors and SLAs are created disabled and the maintenance lies in the past.

Usage: roundtrip_fixtures.py URL USER PASSWORD [--keep | --purge]
Creates everything, prints a summary table and deletes the set again unless
``--keep`` is given; ``--purge`` only deletes what an interrupted run left
behind (every object named ``rt-...``).  Only ``urllib`` is used.
"""

from __future__ import annotations

import json
import secrets
import sys
import urllib.request

PREFIX = "rt-"
PNG_1X1 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)
LINUX_TEMPLATE = "Linux by Zabbix agent"
PAST_FROM = 1577836800  # 2020-01-01 00:00 UTC
PAST_TILL = 1577923200  # 2020-01-02 00:00 UTC
# A throwaway self-signed certificate (CN=rt-saml-idp.example.com, no key kept):
# Zabbix 8.0 requires ``idp_certificate`` on a SAML user directory.
SAML_TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUWi9JjAKjVgYbNjbYvcvKt37PUCIwDQYJKoZIhvcNAQEL
BQAwIjEgMB4GA1UEAwwXcnQtc2FtbC1pZHAuZXhhbXBsZS5jb20wHhcNMjYxMTA1
MTAxMTI4WhcNMzYxMTAyMTAxMTI4WjAiMSAwHgYDVQQDDBdydC1zYW1sLWlkcC5l
eGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMmC/WAD
u630QHhpLIqG/uLBzM4qB10Spa2MCI23e7LetIEWA1fUf+FVor8yfmoJ3lk70l0t
rjp37QseyYOG5BYC19sm1ePxefgbbe6iGCRwK9AfqE4JHE2hwpV9uQLp5wzGRlZ7
fZqyOt/EWot5p8iSG1l/j53qwBGrMmDFT/jQxbdmDFf7w+tXWOBIxyEQehl+a3rL
YV6vovoFF4JzGWjVKoKHF0Merruv3OvNhHbFOgagqx5wmkXrXYCwDe/1Xou+P4Xs
77I5zT05RcK/DGafJlQIaFQNgBN4zVPXr5L4JgF7DbCcnvJ3vOUwu36K3mOU882Q
CP8fQyWOJrO/l7MCAwEAAaNTMFEwHQYDVR0OBBYEFJJlmPiX/Dmy9mkaerz0YzWy
JOBwMB8GA1UdIwQYMBaAFJJlmPiX/Dmy9mkaerz0YzWyJOBwMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBADCJMPpWA2aldo8M3eDZNxY6oDMCAU72
+FLKfAckv5fRONWIsN2ijLHLkMtpRm6iVLKdsSPBZsi/CeDBc+AkdbtJGEe2IT6h
IKwZ3k5wEGWNQ5orRNaDf0fmjRMXJJTnnGsyUG63mPnuXdRryMjoJlfKcbb7W+Ar
8AT2//9GuR6QjnfQmADQYTwkDeUuJNEOcFNObbVsdVrDg25NhwT6XgXx+s/SXvGf
QKJ/11Txhjli5PXo6Of4hs2EHzS3iK1SFsU2g2gJ/49Fzc5nqcLg4nOqElUK3FwE
EjvfApEJD5Xl5dOI5Oyv/aMW0tt8AUez/awHzaxmrhc+fdVM1OAJuEg=
-----END CERTIFICATE-----"""


def at_least(version: str, wanted: str) -> bool:
    """True when ``version`` ("7.0.30") is at least ``wanted`` ("6.2")."""

    def parse(v: str) -> tuple[int, ...]:
        return tuple(int("".join(ch for ch in p if ch.isdigit()) or 0) for p in v.split(".")[:3])

    return parse(version) >= parse(wanted)


class _Ctx:
    """Shared state of one fixture run."""

    def __init__(self, call, version: str) -> None:
        self.call = call
        self.version = version
        self.cleanup: list[tuple[str, list[str]]] = []
        self.summary: dict[str, str] = {}
        self.ids: dict[str, str] = {}

    def v(self, wanted: str) -> bool:
        return at_least(self.version, wanted)

    def create(self, label: str, method: str, params: dict, delete: str, key: str):
        """One create call; on error print ``skip`` and return None."""
        try:
            result = self.call(method, params)
        except RuntimeError as exc:
            print(f"skip {label}: {exc}", file=sys.stderr)
            self.summary[label] = f"skip: {exc}"
            return None
        ids = [str(i) for i in result[key]]
        self.cleanup.insert(0, (delete, ids))  # children were created later
        self.summary[label] = "created"
        return ids[0]

    def lookup(self, method: str, params: dict, key: str):
        try:
            rows = self.call(method, params)
        except RuntimeError:
            return None
        return str(rows[0][key]) if rows else None


def _cep_rules(c: _Ctx) -> None:
    """8.0 complex event processing: one rule of every window type, with
    every condition kind, a window with grouping and tags, and operations
    of several types with their own filter."""
    if not c.v("8.0"):
        return
    conditions = [
        {"type": 3, "operator": 2, "event_name": "rt"},
        {"type": 25, "operator": 0, "tag": "rt"},
        {"type": 26, "operator": 2, "tag": "scope", "tag_value": "rt"},
        {"type": 4, "operator": 5, "severity": 2},
        {"type": 36, "operator": 2, "host_name": "rt"},
        {"type": 37, "operator": 2, "host_group_name": "rt"},
        {"type": 6, "operator": 4, "time_period": "1-5,09:00-18:00"},
    ]
    c.create("ceprule-plain", "ceprule.create", [{
        "name": "rt-cep-plain", "sortorder": 100, "window_type": 0, "description": "rt", "stop": 0,
        "filter": {"evaltype": 0, "conditions": conditions},
        "operations": [
            {"sortorder": 1, "type": 4, "execute_when": 0, "severity": 3},
            {"sortorder": 2, "type": 11, "execute_when": 0, "tag": "rt-added", "tag_value": "1"},
            {"sortorder": 3, "type": 16, "execute_when": 0, "tag": "rt", "new_tag": "rt2"},
            {"sortorder": 4, "type": 7, "execute_when": 0, "suppress_duration": "1h",
             "filter": {"evaltype": 0, "conditions": [{"type": 25, "operator": 0, "tag": "rt"}]}},
        ]}], "ceprule.delete", "cep_ruleids")
    c.create("ceprule-window", "ceprule.create", [{
        "name": "rt-cep-window", "sortorder": 101, "window_type": 1, "status": 1,
        "filter": {"evaltype": 3, "formula": "A and B",
                   "conditions": [{"type": 3, "operator": 2, "event_name": "rt", "formulaid": "A"},
                                  {"type": 4, "operator": 5, "severity": 1, "formulaid": "B"}]},
        "window": {"duration": "30m", "capacity": 10, "group_by_host_group": 1, "group_by_host": 1,
                   "group_by_tags": 1, "tags": ["rt"]},
        "operations": [
            {"sortorder": 1, "type": 2, "execute_when": 2},
            # 8.0.0: an operation can reach beyond the current event (scope) and narrow that with scope_filter
            {"sortorder": 2, "type": 11, "execute_when": 3, "tag": "rt-window", "tag_value": "closed",
             "scope": 2, "scope_filter": {"evaltype": 0, "conditions": [
                 {"type": 25, "operator": 0, "tag": "rt"}, {"type": 33, "operator": 10}]}},
        ]}], "ceprule.delete", "cep_ruleids")


def _groups(c: _Ctx) -> None:
    c.ids["group"] = c.create("hostgroup", "hostgroup.create", {"name": "rt-group"},
                              "hostgroup.delete", "groupids")
    if c.v("6.2"):
        c.ids["tgroup"] = c.create("templategroup", "templategroup.create", {"name": "rt-tgroup"},
                                   "templategroup.delete", "groupids")
    else:
        c.ids["tgroup"] = c.ids["group"]


def _images(c: _Ctx) -> None:
    img = c.create("image", "image.create", {"name": "rt-image", "imagetype": 1, "image": PNG_1X1},
                   "image.delete", "imageids")
    if img is None:
        img = c.lookup("image.get", {"output": ["imageid"], "filter": {"imagetype": 1}, "limit": 1},
                       "imageid")
    c.ids["image"] = img
    regexp = {
        "name": "rt-regexp", "test_string": "abc",
        "expressions": [
            {"expression": "abc", "expression_type": 0, "case_sensitive": 1},
            {"expression": "^a.*$", "expression_type": 3, "case_sensitive": 0},
            {"expression": "a,b", "expression_type": 1, "exp_delimiter": ",", "case_sensitive": 0},
        ]}
    if c.v("8.0"):
        regexp["description"] = "rt"
    c.create("regexp", "regexp.create", regexp, "regexp.delete", "regexpids")
    if img:
        c.create("iconmap", "iconmap.create", {
            "name": "rt-iconmap", "default_iconid": img,
            "mappings": [
                {"inventory_link": 1, "expression": "rt1", "iconid": img},
                {"inventory_link": 2, "expression": "rt2", "iconid": img},
            ]}, "iconmap.delete", "iconmapids")


def _mediatype(c: _Ctx) -> None:
    templates = [{"eventsource": 0, "recovery": r, "subject": f"rt {r}", "message": f"rt body {r}"}
                 for r in (0, 1, 2)]
    c.ids["media"] = c.create("mediatype", "mediatype.create", {
        "name": "rt-media", "type": 4, "status": 1, "script": "return 1;", "timeout": "30s",
        "process_tags": 1, "show_event_menu": 1, "event_menu_url": "http://example.com/{EVENT.ID}",
        "event_menu_name": "rt {EVENT.ID}", "description": "rt webhook",
        "parameters": [{"name": "a", "value": "1"}, {"name": "b", "value": "{ALERT.SUBJECT}"}],
        "message_templates": templates, "maxsessions": 1, "maxattempts": 3,
        "attempt_interval": "10s"}, "mediatype.delete", "mediatypeids")


def _scripts(c: _Ctx) -> None:
    c.ids["script"] = c.create("script", "script.create", {
        "name": "rt-script", "type": 0, "scope": 1, "command": "echo 1", "execute_on": 1,
        "description": "rt"}, "script.delete", "scriptids")
    c.create("script-webhook", "script.create", {
        "name": "rt-script-webhook", "type": 5, "scope": 1, "command": "return 1;",
        "timeout": "30s", "parameters": [{"name": "p", "value": "v"}]},
        "script.delete", "scriptids")
    if c.v("7.0"):
        c.create("script-manual", "script.create", {
            "name": "rt-script-manual", "type": 0, "scope": 2, "command": "echo 2",
            "execute_on": 1, "menu_path": "rt/sub", "confirmation": "Run rt?", "host_access": 2,
            "manualinput": 1, "manualinput_prompt": "Value?", "manualinput_validator_type": 0,
            "manualinput_validator": "^.*$", "manualinput_default_value": "x"},
            "script.delete", "scriptids")


def _users(c: _Ctx) -> None:
    g = c.ids.get("group")
    ug = {"name": "rt-ugroup", "users_status": 1, "gui_access": 0, "debug_mode": 0,
          "tag_filters": [{"groupid": g, "tag": "rt", "value": "1"}]}
    if c.v("6.2"):
        ug["hostgroup_rights"] = [{"id": g, "permission": 2}]
        ug["templategroup_rights"] = [{"id": c.ids.get("tgroup"), "permission": 2}]
    else:
        ug["rights"] = [{"id": g, "permission": 2}]
    c.ids["ugroup"] = c.create("usergroup", "usergroup.create", ug, "usergroup.delete", "usrgrpids")
    c.ids["role"] = c.create("role", "role.create", {
        "name": "rt-role", "type": 1, "rules": {
            "ui": [{"name": "monitoring.dashboard", "status": 1}], "ui.default_access": 1,
            "modules": [], "modules.default_access": 1,
            "api.access": 1, "api.mode": 1, "api": ["host.get"],
            "actions": [{"name": "edit_dashboards", "status": 1}]}},
        "role.delete", "roleids")
    user = {
        "passwd": "Zx9!" + secrets.token_urlsafe(9), "roleid": c.ids.get("role"),
        "usrgrps": [{"usrgrpid": c.ids.get("ugroup")}], "name": "Round", "surname": "Trip",
        "lang": "en_US", "theme": "dark-theme", "autologin": 0, "autologout": "0",
        "refresh": "30s", "rows_per_page": 50, "url": "", "timezone": "UTC",
        "medias": [{"mediatypeid": c.ids.get("media"), "sendto": ["a@b.c"], "active": 0,
                    "severity": 63, "period": "1-7,00:00-24:00"}]}
    user["username" if c.v("5.4") else "alias"] = "rt-user"
    c.ids["user"] = c.create("user", "user.create", user, "user.delete", "userids")
    c.create("globalmacro", "usermacro.createglobal",
             {"macro": "{$RT_GLOBAL}", "value": "1", "description": "rt"},
             "usermacro.deleteglobal", "globalmacroids")
    name_key = "username" if c.v("5.4") else "alias"
    c.ids["admin"] = c.lookup("user.get", {"output": ["userid"], "filter": {name_key: "Admin"}},
                              "userid")


def _prepro() -> list[dict]:
    return [{"type": 1, "params": "2", "error_handler": 0, "error_handler_params": ""},
            {"type": 12, "params": "$.v", "error_handler": 1, "error_handler_params": ""}]


def _gitem(itemid: str, n: int) -> dict:
    return {"itemid": itemid, "color": ["00AA00", "AA0000"][n], "calc_fnc": [2, 4][n],
            "drawtype": n, "sortorder": n, "yaxisside": n}


def _item_family(c: _Ctx, owner: str, tech: str, k: str) -> None:
    """Items, triggers, graph, LLD rule and prototypes on host/template ``owner``.

    ``tech`` is the technical name used in expressions, ``k`` a key infix so the
    template items do not collide with the host ones once inherited."""
    vm = c.create(f"valuemap-{k}", "valuemap.create", {
        "hostid": owner, "name": f"rt-valuemap-{k}",
        "mappings": [{"type": 0, "value": "0", "newvalue": "off"},
                     {"type": 3, "value": "1-9", "newvalue": "some"},
                     {"type": 5, "value": "", "newvalue": "other"}]},
        "valuemap.delete", "valuemapids")
    item = {"hostid": owner, "type": 2, "value_type": 3, "units": "B", "description": "rt",
            "history": "7d", "trends": "30d", "status": 1,
            "tags": [{"tag": "rt", "value": "item"}], "preprocessing": _prepro()}
    if vm:
        item["valuemapid"] = vm
    i1 = c.create(f"item-{k}", "item.create", dict(item, name=f"rt-item-{k}", key_=f"rt.{k}.item"),
                  "item.delete", "itemids")
    i2 = c.create(f"item2-{k}", "item.create",
                  {"hostid": owner, "type": 2, "value_type": 3, "name": f"rt-item2-{k}",
                   "key_": f"rt.{k}.item2", "status": 1}, "item.delete", "itemids")
    if not (i1 and i2):
        return
    tdep = c.create(f"trigger-dep-{k}", "trigger.create", {
        "description": f"rt-trigger-dep-{k}", "expression": f"last(/{tech}/rt.{k}.item2)>0",
        "priority": 1, "status": 1}, "trigger.delete", "triggerids")
    trig = {"description": f"rt-trigger-{k}", "expression": f"last(/{tech}/rt.{k}.item)>0",
            "recovery_mode": 1, "recovery_expression": f"last(/{tech}/rt.{k}.item)<=0",
            "priority": 2, "status": 1, "type": 0, "comments": "rt", "url": "http://example.com",
            "event_name": "rt event {ITEM.VALUE}", "opdata": "{ITEM.LASTVALUE}",
            "correlation_mode": 1, "correlation_tag": "rt", "manual_close": 1,
            "tags": [{"tag": "rt", "value": "trigger"}]}
    if tdep:
        trig["dependencies"] = [{"triggerid": tdep}]
    if c.v("7.0"):
        trig["url_name"] = "rt link"
    t1 = c.create(f"trigger-{k}", "trigger.create", trig, "trigger.delete", "triggerids")
    c.ids[f"trigger-{k}"] = t1
    c.create(f"graph-{k}", "graph.create", {
        "name": f"rt-graph-{k}", "width": 900, "height": 200, "graphtype": 0, "show_legend": 1,
        "show_work_period": 1, "show_triggers": 1, "ymin_type": 0, "ymax_type": 0,
        "gitems": [_gitem(i1, 0), _gitem(i2, 1)]}, "graph.delete", "graphids")
    lld = {"hostid": owner, "name": f"rt-lld-{k}", "key_": f"rt.{k}.lld", "type": 2,
           "lifetime": "30d", "description": "rt", "status": 1,
           "filter": {"evaltype": 3, "formula": "A and B", "conditions": [
               {"macro": "{#A}", "value": "^a", "operator": 8, "formulaid": "A"},
               {"macro": "{#B}", "value": "^b", "operator": 8, "formulaid": "B"}]},
           "lld_macro_paths": [{"lld_macro": "{#A}", "path": "$.a"},
                               {"lld_macro": "{#B}", "path": "$.b"}],
           "preprocessing": [{"type": 12, "params": "$.data", "error_handler": 1,
                              "error_handler_params": ""}],
           "overrides": [{
               "name": "rt-override", "step": 1, "stop": 0,
               "filter": {"evaltype": 0, "conditions": [{"macro": "{#A}", "value": "x", "operator": 8}]},
               "operations": [
                   {"operationobject": 0, "operator": 2, "value": "x", "opstatus": {"status": 1},
                    "opdiscover": {"discover": 0}, "ophistory": {"history": "1d"},
                    "optrends": {"trends": "1d"}, "opperiod": {"delay": "1m"},
                    "optag": [{"tag": "rt", "value": "ov"}]},
                   {"operationobject": 1, "operator": 2, "value": "y", "opseverity": {"severity": 3}},
                   {"operationobject": 3, "operator": 2, "value": "z",
                    "opinventory": {"inventory_mode": 0}}]}]}
    if c.ids.get("linux"):
        lld["overrides"][0]["operations"][2]["optemplate"] = [{"templateid": c.ids["linux"]}]
    if c.v("7.0"):
        lld.update({"lifetime_type": 0, "enabled_lifetime_type": 0, "enabled_lifetime": "7d"})
    rule = c.create(f"lld-{k}", "discoveryrule.create", lld, "discoveryrule.delete", "itemids")
    if not rule:
        return
    proto = {"hostid": owner, "ruleid": rule, "name": f"rt-proto-{k} {{#A}}",
             "key_": f"rt.{k}.proto[{{#A}}]", "type": 2, "value_type": 3, "units": "B",
             "description": "rt", "status": 1, "discover": 0,
             "tags": [{"tag": "rt", "value": "proto"}], "preprocessing": _prepro()}
    if vm:
        proto["valuemapid"] = vm
    ip = c.create(f"itemprototype-{k}", "itemprototype.create", proto,
                  "itemprototype.delete", "itemids")
    if ip:
        tp = {"description": f"rt-tproto-{k} {{#A}}", "priority": 1, "status": 1,
              "expression": f"last(/{tech}/rt.{k}.proto[{{#A}}])>0", "discover": 0,
              "tags": [{"tag": "rt", "value": "tproto"}]}
        if t1:
            tp["dependencies"] = [{"triggerid": t1}]
        c.create(f"triggerprototype-{k}", "triggerprototype.create", tp,
                 "triggerprototype.delete", "triggerids")
        c.create(f"graphprototype-{k}", "graphprototype.create", {
            "name": f"rt-gproto-{k} {{#A}}", "width": 900, "height": 200, "discover": 0,
            "gitems": [_gitem(ip, 0), _gitem(i1, 1)]}, "graphprototype.delete", "graphids")
    hp = {"ruleid": rule, "host": f"rt-hp-{k}-{{#A}}", "name": f"rt-hp-{k}-{{#A}}", "status": 1,
          "discover": 0, "inventory_mode": 0, "groupLinks": [{"groupid": c.ids.get("group")}],
          "groupPrototypes": [{"name": f"rt-gp-{k}-{{#A}}"}],
          "macros": [{"macro": "{$RT_HP}", "value": "1", "description": "d"}],
          "tags": [{"tag": "rt", "value": "hp"}]}
    if c.ids.get("linux"):
        hp["templates"] = [{"templateid": c.ids["linux"]}]
    if c.v("6.0"):
        hp["custom_interfaces"] = 1
        # an agent and an SNMP interface: ``details`` is required on the one
        # and refused on the other, so a row-dependent key shows as such
        hp["interfaces"] = [{"type": 1, "main": 1, "useip": 1, "ip": "127.0.0.1", "dns": "",
                             "port": "10050"},
                            {"type": 2, "main": 1, "useip": 1, "ip": "127.0.0.1", "dns": "",
                             "port": "161", "details": {"version": 2, "community": "{$SNMP_COMMUNITY}",
                                                        "bulk": 1}}]
    c.create(f"hostprototype-{k}", "hostprototype.create", hp, "hostprototype.delete", "hostids")
    if c.v("7.4"):
        c.create(f"lldprototype-{k}", "discoveryruleprototype.create", {
            "hostid": owner, "ruleid": rule, "name": f"rt-lldp-{k} {{#A}}",
            "key_": f"rt.{k}.lldp[{{#A}}]", "type": 2, "lifetime": "30d", "status": 1,
            "filter": {"evaltype": 0, "conditions": [{"macro": "{#C}", "value": "^c",
                                                      "operator": 8}]},
            "lld_macro_paths": [{"lld_macro": "{#C}", "path": "$.c"}]},
            "discoveryruleprototype.delete", "itemids")


def _template(c: _Ctx) -> None:
    c.ids["linux"] = c.lookup("template.get", {"output": ["templateid"],
                                               "filter": {"host": LINUX_TEMPLATE}}, "templateid")
    tid = c.create("template", "template.create", {
        "host": "rt-template", "name": "rt-template", "description": "rt",
        "groups": [{"groupid": c.ids.get("tgroup")}],
        "macros": [{"macro": "{$RT_TSECRET}", "value": "s", "type": 1, "description": "secret"},
                   {"macro": "{$RT_TPLAIN}", "value": "1"}],
        "tags": [{"tag": "rt", "value": "template"}]}, "template.delete", "templateids")
    c.ids["template"] = tid
    if tid:
        _item_family(c, tid, "rt-template", "t")
        # a template that inherits from rt-template: template.get then returns it
        # under ``templates`` of rt-template (the reverse of what update calls so)
        c.create("template-child", "template.create", {
            "host": "rt-template-child", "name": "rt-template-child",
            "groups": [{"groupid": c.ids.get("tgroup")}],
            "templates": [{"templateid": tid}]}, "template.delete", "templateids")


def _host(c: _Ctx) -> None:
    host = {
        "host": "rt-host", "name": "rt-host", "status": 1, "description": "rt",
        "groups": [{"groupid": c.ids.get("group")}],
        "interfaces": [
            {"type": 1, "main": 1, "useip": 0, "ip": "127.0.0.1", "dns": "rt-host.example.com",
             "port": "10050"},
            {"type": 2, "main": 1, "useip": 1, "ip": "127.0.0.2", "dns": "", "port": "161",
             "details": {"version": 2, "community": "public", "bulk": 1}},
            {"type": 3, "main": 1, "useip": 1, "ip": "127.0.0.3", "dns": "", "port": "623"},
            {"type": 4, "main": 1, "useip": 1, "ip": "127.0.0.4", "dns": "", "port": "12345"}],
        "macros": [{"macro": "{$RT_PLAIN}", "value": "1"},
                   {"macro": "{$RT_SECRET}", "value": "s", "type": 1, "description": "secret"},
                   {"macro": "{$RT_DESC}", "value": "2", "description": "desc"}],
        "tags": [{"tag": "rt", "value": "host"}], "inventory_mode": 0,
        "inventory": {"type": "rt-type", "name": "rt-name", "os": "rt-os"},
        "tls_connect": 1, "tls_accept": 1, "ipmi_authtype": -1, "ipmi_privilege": 2,
        "ipmi_username": "ipmi", "ipmi_password": "ipmi"}
    if c.ids.get("template"):
        host["templates"] = [{"templateid": c.ids["template"]}]
    hid = c.create("host", "host.create", host, "host.delete", "hostids")
    c.ids["host"] = hid
    if not hid:
        return
    _item_family(c, hid, "rt-host", "h")
    step = {"headers": [{"name": "X-Rt-Step", "value": "1"}],
            "variables": [{"name": "{s}", "value": "1"}],
            "query_fields": [{"name": "q", "value": "1"}], "required": "ok",
            "status_codes": "200,201", "timeout": "15s"}
    c.create("httptest", "httptest.create", {
        "name": "rt-web", "hostid": hid, "delay": "1m", "retries": 2, "agent": "rt-agent",
        "authentication": 1, "http_user": "u", "http_password": "p", "status": 1,
        "verify_peer": 0, "verify_host": 0,
        "headers": [{"name": "X-Rt", "value": "1"}], "variables": [{"name": "{v}", "value": "1"}],
        "tags": [{"tag": "rt", "value": "web"}],
        "steps": [dict(step, name="rt-step1", no=1, url="http://example.com/a", posts="a=1",
                       follow_redirects=1, retrieve_mode=0),
                  dict(step, name="rt-step2", no=2, url="http://example.com/b", posts="b=2",
                       follow_redirects=0, retrieve_mode=2)]},
        "httptest.delete", "httptestids")


def _maintenance(c: _Ctx) -> None:
    c.create("maintenance", "maintenance.create", {
        "name": "rt-maint", "active_since": PAST_FROM, "active_till": PAST_TILL,
        "maintenance_type": 0, "description": "rt", "tags_evaltype": 0,
        "tags": [{"tag": "rt", "operator": 0, "value": "1"}],
        "hosts": [{"hostid": c.ids.get("host")}], "groups": [{"groupid": c.ids.get("group")}],
        "timeperiods": [
            {"timeperiod_type": 0, "start_date": PAST_FROM, "period": 3600},
            {"timeperiod_type": 2, "every": 1, "start_time": 3600, "period": 3600},
            {"timeperiod_type": 3, "every": 1, "dayofweek": 1, "start_time": 3600, "period": 3600},
            {"timeperiod_type": 4, "month": 1, "day": 1, "start_time": 3600, "period": 3600},
            {"timeperiod_type": 4, "month": 2, "dayofweek": 2, "every": 1, "start_time": 3600,
             "period": 3600}]}, "maintenance.delete", "maintenanceids")


def _zabbix_8_0(c: _Ctx) -> None:
    """What only 8.0 has outside the objects above: a maintenance scoped to
    triggers and event names instead of hosts, a push media type, and
    telemetry queries (an item with a plain filter, an item and an LLD rule
    with a custom expression)."""
    if not c.v("8.0"):
        return
    host = c.ids.get("host")
    triggers = c.call("trigger.get", {"output": ["triggerid"], "hostids": [host], "limit": 2}) if host else []
    if triggers:
        c.create("maintenance-triggers", "maintenance.create", {
            "name": "rt-maint-triggers", "active_since": PAST_FROM, "active_till": PAST_TILL,
            "maintenance_type": 0, "description": "rt", "tags_evaltype": 2,
            "tags": [{"tag": "rt", "operator": 1, "value": "1"}, {"tag": "rt2", "operator": 3, "value": "x"}],
            "triggers": [{"triggerid": t["triggerid"]} for t in triggers],
            "event_names": [{"value": "rt", "operator": 2}, {"value": "noise", "operator": 3}],
            "timeperiods": [{"timeperiod_type": 0, "start_date": PAST_FROM, "period": 3600}]},
            "maintenance.delete", "maintenanceids")
    c.create("mediatype-push", "mediatype.create", {"name": "rt-media-push", "type": 5, "status": 1,
                                                    "description": "rt push"},
             "mediatype.delete", "mediatypeids")
    if host:
        telemetry = {"hostid": host, "type": 24, "value_type": 3, "delay": "1m", "time_shift": "30s",
                     "lookback_limit": "5m", "granularity": "30s"}
        # the query filter is the LLD filter again: eval_formula is read-only,
        # formulaid belongs to a custom expression only
        c.create("item-telemetry", "item.create", dict(
            telemetry, name="rt-item-telemetry", key_="rt.telemetry.item",
            query={"signal_type": 0, "columns": [],
                   "aggregated_columns": [{"function": 4, "alias": "spans"}],
                   "filter": {"evaltype": 0, "conditions": [
                       {"column": "ServiceName", "operator": 0, "value": "rt"}]}}),
            "item.delete", "itemids")
        c.create("item-telemetry-formula", "item.create", dict(
            telemetry, name="rt-item-telemetry-formula", key_="rt.telemetry.formula",
            query={"signal_type": 0, "columns": [],
                   "aggregated_columns": [{"function": 4, "alias": "spans"}],
                   "filter": {"evaltype": 3, "formula": "A and B", "conditions": [
                       {"column": "ServiceName", "operator": 0, "value": "rt", "formulaid": "A"},
                       {"column": "SpanName", "operator": 2, "value": "rt", "formulaid": "B"}]}}),
            "item.delete", "itemids")
        # an LLD rule can be a telemetry query too (8.0.0; not on the reference page)
        lld = {k: v for k, v in telemetry.items() if k != "value_type"}
        c.create("lld-telemetry", "discoveryrule.create", dict(
            lld, name="rt-lld-telemetry", key_="rt.telemetry.lld",
            query={"signal_type": 0, "columns": [],
                   "aggregated_columns": [{"function": 4, "alias": "spans"}],
                   "filter": {"evaltype": 0, "conditions": [
                       {"column": "ServiceName", "operator": 0, "value": "rt"}]}}),
            "discoveryrule.delete", "itemids")
        c.create("lld-telemetry-formula", "discoveryrule.create", dict(
            lld, name="rt-lld-telemetry-formula", key_="rt.telemetry.lld.formula",
            query={"signal_type": 0, "columns": [],
                   "aggregated_columns": [{"function": 4, "alias": "spans"}],
                   "filter": {"evaltype": 3, "formula": "A and B", "conditions": [
                       {"column": "ServiceName", "operator": 0, "value": "rt", "formulaid": "A"},
                       {"column": "SpanName", "operator": 2, "value": "rt", "formulaid": "B"}]}}),
            "discoveryrule.delete", "itemids")


def _msg(c: _Ctx, default: int, to_user: bool = False, **extra) -> dict:
    op = {"operationtype": 0, "opmessage": {"default_msg": default, "mediatypeid": c.ids.get("media")}}
    if default == 0:
        op["opmessage"].update({"subject": "rt subject", "message": "rt message"})
    if to_user:
        op["opmessage_usr"] = [{"userid": c.ids.get("user")}]
    else:
        op["opmessage_grp"] = [{"usrgrpid": c.ids.get("ugroup")}]
    op.update(extra)
    return op


def _actions(c: _Ctx) -> None:
    g, h, t = c.ids.get("group"), c.ids.get("host"), c.ids.get("template")
    trigger = {
        "name": "rt-action-trigger", "eventsource": 0, "status": 1, "esc_period": "1h",
        "pause_suppressed": 1,
        "filter": {"evaltype": 3, "formula": "A and B", "conditions": [
            {"conditiontype": 3, "operator": 2, "value": "rt", "formulaid": "A"},
            {"conditiontype": 4, "operator": 5, "value": "2", "formulaid": "B"}]},
        "operations": [
            _msg(c, 0, esc_step_from=1, esc_step_to=1),
            _msg(c, 1, to_user=True, esc_step_from=2, esc_step_to=2),
            {"operationtype": 1, "opcommand": {"scriptid": c.ids.get("script")},
             "opcommand_hst": [{"hostid": "0"}, {"hostid": h}], "opcommand_grp": [{"groupid": g}],
             "opconditions": [{"conditiontype": 14, "operator": 0, "value": "0"}],
             "esc_step_from": 3, "esc_step_to": 4, "esc_period": "0", "evaltype": 0}],
        "recovery_operations": [_msg(c, 0), {"operationtype": 11, "opmessage": {"default_msg": 1}}],
        "update_operations": [_msg(c, 0), {"operationtype": 12, "opmessage": {"default_msg": 1}}]}
    if c.v("6.4"):
        trigger["notify_if_canceled"] = 1
    if c.v("7.0"):
        trigger["pause_symptoms"] = 1
    c.create("action-trigger", "action.create", trigger, "action.delete", "actionids")
    host_ops = [_msg(c, 0), {"operationtype": 2}, {"operationtype": 4, "opgroup": [{"groupid": g}]},
                {"operationtype": 6, "optemplate": [{"templateid": t}]}, {"operationtype": 8},
                {"operationtype": 10, "opinventory": {"inventory_mode": 0}}]
    if c.v("7.0"):
        host_ops.append({"operationtype": 13, "optag": [{"tag": "rt", "value": "auto"}]})
    c.create("action-discovery", "action.create", {
        "name": "rt-action-discovery", "eventsource": 1, "status": 1,
        "filter": {"evaltype": 0, "conditions": [
            {"conditiontype": 7, "operator": 0, "value": "192.168.250.1-10"},
            {"conditiontype": 10, "operator": 0, "value": "0"}]},
        "operations": host_ops}, "action.delete", "actionids")
    c.create("action-autoreg", "action.create", {
        "name": "rt-action-autoreg", "eventsource": 2, "status": 1,
        "filter": {"evaltype": 0, "conditions": [
            {"conditiontype": 22, "operator": 2, "value": "rt"},
            {"conditiontype": 24, "operator": 2, "value": "rt"}]},
        "operations": host_ops}, "action.delete", "actionids")
    c.create("action-internal", "action.create", {
        "name": "rt-action-internal", "eventsource": 3, "status": 1, "esc_period": "1h",
        "filter": {"evaltype": 0, "conditions": [{"conditiontype": 23, "operator": 0, "value": "0"}]},
        "operations": [_msg(c, 0, esc_step_from=1, esc_step_to=2), _msg(c, 1, to_user=True)],
        "recovery_operations": [_msg(c, 1)]}, "action.delete", "actionids")
    if c.v("6.0"):
        c.create("action-service", "action.create", {
            "name": "rt-action-service", "eventsource": 4, "status": 1, "esc_period": "1h",
            "filter": {"evaltype": 0, "conditions": [
                {"conditiontype": 28, "operator": 2, "value": "rt"},
                {"conditiontype": 25, "operator": 0, "value": "rt"}]},
            "operations": [_msg(c, 0), _msg(c, 1, to_user=True)],
            "recovery_operations": [_msg(c, 0), {"operationtype": 11, "opmessage": {"default_msg": 1}}],
            "update_operations": [_msg(c, 0), {"operationtype": 12, "opmessage": {"default_msg": 1}}]},
            "action.delete", "actionids")


def _correlation(c: _Ctx) -> None:
    c.create("correlation", "correlation.create", {
        "name": "rt-corr", "description": "rt", "status": 1,
        "filter": {"evaltype": 0, "conditions": [{"type": 0, "tag": "rt-old"},
                                                 {"type": 1, "tag": "rt-new"}]},
        "operations": [{"type": 0}, {"type": 1}]}, "correlation.delete", "correlationids")


def _drule(c: _Ctx) -> None:
    icmp = {"type": 12}
    if c.v("7.0"):
        icmp["allow_redirect"] = 0
    rule = {"name": "rt-drule", "iprange": "192.168.250.1-10", "delay": "1h", "status": 1,
            "dchecks": [
                icmp,
                {"type": 9, "key_": "system.uname", "ports": "10050", "uniq": 1,
                 "host_source": 3, "name_source": 3},
                {"type": 11, "key_": "1.3.6.1.2.1.1.1.0", "snmp_community": "public",
                 "ports": "161", "uniq": 0},
                {"type": 3, "ports": "80"}]}
    if c.v("7.0"):
        rule["concurrency_max"] = 2
    c.create("drule", "drule.create", rule, "drule.delete", "druleids")


def _services(c: _Ctx) -> None:
    if not c.v("6.0"):
        return
    c.create("sla", "sla.create", {
        "name": "rt-sla", "period": 1, "slo": "99.9", "effective_date": PAST_FROM,
        "timezone": "UTC", "status": 0, "description": "rt",
        "service_tags": [{"tag": "rt-sla", "operator": 0, "value": "1"}],
        "schedule": [{"period_from": 0, "period_to": 86400},
                     {"period_from": 86400, "period_to": 172800}],
        "excluded_downtimes": [{"name": "rt-dt", "period_from": PAST_FROM,
                                "period_to": PAST_FROM + 3600}]}, "sla.delete", "slaids")
    parent = c.create("service-parent", "service.create", {
        "name": "rt-service-parent", "algorithm": 1, "sortorder": 1, "weight": 0,
        "description": "rt", "tags": [{"tag": "rt-sla", "value": "1"}],
        "status_rules": [{"type": 0, "limit_value": 1, "limit_status": 2, "new_status": 3}]},
        "service.delete", "serviceids")
    child = {"name": "rt-service-child", "algorithm": 0, "sortorder": 2, "weight": 1,
             "propagation_rule": 1, "propagation_value": 1, "description": "rt",
             "problem_tags": [{"tag": "rt", "operator": 0, "value": "1"}],
             "tags": [{"tag": "rt", "value": "child"}]}
    if parent:
        child["parents"] = [{"serviceid": parent}]
    c.create("service-child", "service.create", child, "service.delete", "serviceids")


def _widget_fields(c: _Ctx, kind: str) -> list[dict]:
    """Widget fields; 7.0 renamed multi-value fields (groupids.0, tags.0.tag)."""
    if kind == "clock":
        return [{"type": 0, "name": "time_type", "value": 0}]
    new = c.v("7.0")
    fields = [(0, "show", 1), (2, "groupids.0" if new else "groupids", c.ids.get("group")),
              (1, "problem", "rt"), (1, "tags.0.tag" if new else "tags.tag.0", "rt"),
              (0, "tags.0.operator" if new else "tags.operator.0", 0),
              (1, "tags.0.value" if new else "tags.value.0", "1")]
    if new:
        fields.append((1, "reference", "RTPRB"))
    return [{"type": t, "name": n, "value": v} for t, n, v in fields]


def _page(c: _Ctx, name: str, kinds: list[str]) -> dict:
    w = 36 if c.v("7.0") else 12  # 72-column grid since 7.0, 24 before
    return {"name": name, "display_period": 30, "widgets": [
        {"type": kind, "name": f"rt-{kind}", "x": n * w, "y": 0, "width": w, "height": 5,
         "view_mode": 0, "fields": _widget_fields(c, kind)} for n, kind in enumerate(kinds)]}


def _dashboards(c: _Ctx) -> None:
    shares = {"users": [{"userid": c.ids.get("user"), "permission": 2}],
              "userGroups": [{"usrgrpid": c.ids.get("ugroup"), "permission": 2}]}
    c.ids["dash"] = c.create("dashboard", "dashboard.create", dict(shares, **{
        "name": "rt-dash", "private": 1, "display_period": 30, "auto_start": 1,
        "pages": [_page(c, "rt-page1", ["problems", "clock"]),
                  _page(c, "rt-page2", ["clock"])]}), "dashboard.delete", "dashboardids")
    if c.v("5.2") and c.ids.get("template"):
        c.create("templatedashboard", "templatedashboard.create", {
            "templateid": c.ids["template"], "name": "rt-tdash", "display_period": 30,
            "auto_start": 1, "pages": [_page(c, "rt-tpage", ["clock"])]},
            "templatedashboard.delete", "dashboardids")


def _map(c: _Ctx) -> None:
    img = c.ids.get("image")
    link = {"selementid1": "1", "selementid2": "2", "color": "00CC00", "drawtype": 0,
            "label": "rt-link"}
    if c.ids.get("trigger-h"):
        link["linktriggers"] = [{"triggerid": c.ids["trigger-h"], "color": "DD0000", "drawtype": 2}]
        if c.v("7.4"):
            link["indicator_type"] = 1
    c.create("map", "map.create", {
        "name": "rt-map", "width": 800, "height": 600, "label_format": 1, "expandproblem": 1,
        "highlight": 1, "private": 1, "markelements": 1, "show_unack": 1, "grid_show": 1,
        "selements": [
            {"selementid": "1", "elementtype": 0, "elements": [{"hostid": c.ids.get("host")}],
             "iconid_off": img, "label": "rt-host", "x": 100, "y": 100,
             "urls": [{"name": "rt", "url": "http://example.com"}]},
            {"selementid": "2", "elementtype": 4, "iconid_off": img, "label": "rt-image",
             "x": 300, "y": 100}],
        "links": [link],
        "shapes": [{"type": 0, "x": 10, "y": 10, "width": 100, "height": 50, "text": "rt-shape",
                    "border_type": 1, "font_size": 11}],
        "lines": [{"x1": 0, "y1": 0, "x2": 200, "y2": 200, "line_type": 1, "line_width": 1}],
        "users": [{"userid": c.ids.get("user"), "permission": 2}],
        "userGroups": [{"usrgrpid": c.ids.get("ugroup"), "permission": 2}]},
        "map.delete", "sysmapids")


def _token_report(c: _Ctx) -> None:
    if c.v("5.4") and c.ids.get("user"):
        c.create("token", "token.create", {
            "name": "rt-token", "userid": c.ids["user"], "description": "rt", "expires_at": 0,
            "status": 1}, "token.delete", "tokenids")
    if c.v("5.4") and c.ids.get("dash") and c.ids.get("admin"):
        adm = c.ids["admin"]
        c.create("report", "report.create", {
            "userid": adm, "name": "rt-report", "dashboardid": c.ids["dash"], "period": 1,
            "cycle": 1, "start_time": 43200, "weekdays": 31, "active_since": "2020-01-01",
            "active_till": "2020-12-31", "subject": "rt", "message": "rt body", "status": 1,
            "description": "rt",
            "users": [{"userid": c.ids.get("user"), "access_userid": adm, "exclude": 0}],
            "user_groups": [{"usrgrpid": c.ids.get("ugroup"), "access_userid": adm}]},
            "report.delete", "reportids")


def _connector_proxies(c: _Ctx) -> None:
    if c.v("7.0"):
        c.create("connector", "connector.create", {
            "name": "rt-connector", "url": "http://example.com/receiver", "protocol": 0,
            "data_type": 0, "max_records": 10, "max_senders": 2, "max_attempts": 2,
            "attempt_interval": "5s", "timeout": "5s", "http_proxy": "http://proxy.example.com:3128",
            "authtype": 1, "username": "u", "password": "p", "verify_peer": 1, "verify_host": 1,
            "tags_evaltype": 0, "tags": [{"tag": "rt", "operator": 0, "value": "1"}],
            "status": 0, "description": "rt"}, "connector.delete", "connectorids")
        pg = c.create("proxygroup", "proxygroup.create", {
            "name": "rt-pgroup", "failover_delay": "1m", "min_online": "1", "description": "rt"},
            "proxygroup.delete", "proxy_groupids")
        timeouts = {f"timeout_{k}": "3s" for k in (
            "zabbix_agent", "simple_check", "snmp_agent", "external_check", "db_monitor",
            "http_agent", "ssh_agent", "telnet_agent", "script", "browser")}
        active = {"name": "rt-proxy", "operating_mode": 0, "allowed_addresses": "127.0.0.1",
                  "tls_accept": 1, "description": "rt", "custom_timeouts": 1, **timeouts}
        if pg:
            active.update({"proxy_groupid": pg, "local_address": "127.0.0.1", "local_port": "10051"})
        passive = {"name": "rt-proxy-passive", "operating_mode": 1, "address": "127.0.0.1",
                   "port": "10051", "tls_connect": 1, "description": "rt"}
        if c.v("8.0"):
            # 8.0 requires the telemetry query timeout on an active proxy
            # (and refuses it on a passive one); a proxy can collect OpenTelemetry data
            active["timeout_telemetry_query"] = "5s"
            active["apm"] = {"data_collection_status": 1, "max_messages_per_second": 100,
                             "additional_resource_attributes": [
                                 {"key": "rt.attribute", "value": "1", "signal_type": 0},
                                 {"key": "rt.attribute", "value": "", "signal_type": 2}]}
        c.create("proxy", "proxy.create", active, "proxy.delete", "proxyids")
        proxy = c.create("proxy-passive", "proxy.create", passive, "proxy.delete", "proxyids")
        if c.v("8.0"):
            # 8.0 user group permissions on proxies, proxy groups and APM resource attributes
            extra = {"name": "rt-ugroup-80", "users_status": 1, "proxy_mode": 0, "proxy_group_mode": 0,
                     "apm_filters": [{"key": "service.name", "value": "rt", "signal_type": -1},
                                     {"key": "rt.attribute", "value": "", "signal_type": 0}]}
            if proxy:
                # a proxy outside a proxy group: access to a grouped one is managed by its group
                extra["proxies"] = [{"proxyid": proxy}]
            if pg:
                extra["proxy_groups"] = [{"proxy_groupid": pg}]
            c.create("usergroup-80", "usergroup.create", extra, "usergroup.delete", "usrgrpids")
    else:
        c.create("proxy", "proxy.create", {
            "host": "rt-proxy", "status": 5, "description": "rt", "tls_accept": 1,
            "proxy_address": "127.0.0.1"}, "proxy.delete", "proxyids")
        c.create("proxy-passive", "proxy.create", {
            "host": "rt-proxy-passive", "status": 6, "description": "rt", "tls_connect": 1,
            "interface": {"ip": "127.0.0.1", "dns": "", "useip": 1, "port": "10051"}},
            "proxy.delete", "proxyids")


def _provisioning(c: _Ctx) -> dict:
    media = {"name": "rt-media", "mediatypeid": c.ids.get("media"), "attribute": "mail"}
    if c.v("7.0"):
        media.update({"active": 0, "severity": 63, "period": "1-7,00:00-24:00"})
    return {"provision_status": 1, "group_name": "cn", "user_username": "givenName",
            "user_lastname": "sn", "provision_media": [media],
            "provision_groups": [{"name": "*", "roleid": c.ids.get("role"),
                                  "user_groups": [{"usrgrpid": c.ids.get("ugroup")}]}]}


def _userdirectories(c: _Ctx) -> None:
    if not c.v("6.2"):
        return
    ldap = {"name": "rt-ldap", "host": "ldap.example.com", "port": 389,
            "base_dn": "dc=example,dc=com", "search_attribute": "uid", "bind_dn": "cn=admin",
            "bind_password": "x", "description": "rt", "search_filter": "(%{attr}=%{user})",
            "start_tls": 0}
    if c.v("6.4"):
        ldap.update({"idp_type": 1, "group_basedn": "ou=groups,dc=example,dc=com",
                     "group_member": "member", "group_filter": "(%{groupattr}=%{user})",
                     "group_membership": "memberOf", "user_ref_attr": "uid", **_provisioning(c)})
    c.create("userdirectory-ldap", "userdirectory.create", ldap,
             "userdirectory.delete", "userdirectoryids")
    if c.v("6.4"):
        saml = {
            "idp_type": 2, "idp_entityid": "https://idp.example.com/rt",
            "sso_url": "https://idp.example.com/rt/sso", "slo_url": "https://idp.example.com/rt/slo",
            "username_attribute": "uid", "sp_entityid": "rt-saml",
            "nameid_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "sign_messages": 1, "sign_assertions": 1, "sign_authn_requests": 1,
            "sign_logout_requests": 1, "sign_logout_responses": 1, "encrypt_nameid": 0,
            "encrypt_assertions": 0, "scim_status": 0, **_provisioning(c)}
        created = None
        if c.v("8.0"):
            # 8.0 keeps the SAML certificates in the object when the frontend is
            # configured with $SSO['CERT_STORAGE'] = 'database' (a new installation);
            # with file storage (an upgraded one) the parameter is refused
            # signing is off in this variant: with it on, the service provider's
            # certificate AND private key are required, and a key has no place here
            unsigned = {k: 0 for k in ("sign_messages", "sign_assertions", "sign_authn_requests",
                                       "sign_logout_requests", "sign_logout_responses")}
            created = c.create("userdirectory-saml-cert", "userdirectory.create",
                               dict(saml, idp_certificate=SAML_TEST_CERT, **unsigned),
                               "userdirectory.delete", "userdirectoryids")
        if not created:
            c.create("userdirectory-saml", "userdirectory.create", saml,
                     "userdirectory.delete", "userdirectoryids")
    if c.v("7.0"):
        c.create("mfa", "mfa.create", {"type": 1, "name": "rt-mfa", "hash_function": 1,
                                       "code_length": 6}, "mfa.delete", "mfaids")


def create_fixtures(call, version: str) -> list[tuple[str, list[str]]]:
    """Create the fixture objects. ``call(method, params)`` performs one Zabbix
    API call and returns its result (raises RuntimeError on an API error).
    ``version`` is the server version string ("7.4.14"). Returns the cleanup
    list: (delete_method, ids) tuples in the order they must be deleted
    (children before parents), e.g. [("action.delete", ["12"]), ..., ("host.delete", ["10500"])]."""
    c = _Ctx(call, version)
    for step in (_groups, _images, _mediatype, _scripts, _users, _template, _host, _maintenance,
                 _zabbix_8_0, _actions, _correlation, _drule, _services, _cep_rules, _dashboards, _map,
                 _token_report,
                 _connector_proxies, _userdirectories):
        step(c)
    create_fixtures.last_summary = c.summary  # type: ignore[attr-defined]
    return c.cleanup


def delete_fixtures(call, cleanup: list[tuple[str, list[str]]]) -> int:
    """Delete in the given order; ignore an error on an object that is already
    gone. Returns the number of delete calls that failed for another reason."""
    failed = 0
    for method, ids in cleanup:
        try:
            call(method, ids)
        except RuntimeError as exc:
            if "does not exist" not in str(exc):
                failed += 1
                print(f"cleanup {method} {ids}: {exc}", file=sys.stderr)
    return failed


def deleted_report(failed: int) -> str:
    """What to print after ``delete_fixtures``: the truth, with the way out."""
    if not failed:
        return "fixtures deleted"
    return (f"fixtures NOT all deleted: {failed} delete call(s) failed (see above); "
            f"run roundtrip_fixtures.py URL USER PASSWORD --purge")


# (get method, search field, delete method, id field), parents last. Deleting a
# host or template takes its items, triggers, graphs, LLD rules and web
# scenarios with it; a user group's users go first.
_PURGE_ORDER = (
    ("action.get", "name", "action.delete", "actionid"),
    ("correlation.get", "name", "correlation.delete", "correlationid"),
    ("maintenance.get", "name", "maintenance.delete", "maintenanceid"),
    ("report.get", "name", "report.delete", "reportid"),
    ("sla.get", "name", "sla.delete", "slaid"),
    ("service.get", "name", "service.delete", "serviceid"),
    ("ceprule.get", "name", "ceprule.delete", "cep_ruleid"),
    ("dashboard.get", "name", "dashboard.delete", "dashboardid"),
    ("templatedashboard.get", "name", "templatedashboard.delete", "dashboardid"),
    ("map.get", "name", "map.delete", "sysmapid"),
    ("drule.get", "name", "drule.delete", "druleid"),
    ("host.get", "host", "host.delete", "hostid"),
    ("template.get", "host", "template.delete", "templateid"),
    ("hostgroup.get", "name", "hostgroup.delete", "groupid"),
    ("templategroup.get", "name", "templategroup.delete", "groupid"),
    ("token.get", "name", "token.delete", "tokenid"),
    ("user.get", "username", "user.delete", "userid"),
    ("userdirectory.get", "name", "userdirectory.delete", "userdirectoryid"),   # provisioning refers to group + role
    ("usergroup.get", "name", "usergroup.delete", "usrgrpid"),
    ("role.get", "name", "role.delete", "roleid"),
    ("mediatype.get", "name", "mediatype.delete", "mediatypeid"),
    ("script.get", "name", "script.delete", "scriptid"),
    ("iconmap.get", "name", "iconmap.delete", "iconmapid"),
    ("image.get", "name", "image.delete", "imageid"),
    ("regexp.get", "name", "regexp.delete", "regexpid"),
    ("connector.get", "name", "connector.delete", "connectorid"),
    ("proxy.get", "name", "proxy.delete", "proxyid"),
    ("proxygroup.get", "name", "proxygroup.delete", "proxy_groupid"),
    ("mfa.get", "name", "mfa.delete", "mfaid"),
)


def purge_leftovers(call, version: str) -> int:
    """Delete every object whose name starts with the fixture prefix: what an
    interrupted run left behind. Returns the number of objects deleted."""
    deleted = 0
    for get, field, delete, id_field in _PURGE_ORDER:
        if get == "proxy.get" and not at_least(version, "7.0"):
            field = "host"   # a proxy is named by "host" before 7.0; searching "name" finds nothing
        try:
            rows = call(get, {"output": [id_field, field], "search": {field: PREFIX}, "searchWildcardsEnabled": False})
        except RuntimeError:
            continue   # the method does not exist on this release
        ids = [r[id_field] for r in rows if str(r.get(field, "")).startswith(PREFIX)]
        if get == "user.get" and not ids:
            # the fixture user is called "Round Trip" (Zabbix refuses a password containing "rt")
            rows = call(get, {"output": [id_field, "username"], "search": {"username": "Round Trip"}})
            ids = [r[id_field] for r in rows if r.get("username") == "Round Trip"]
        if get == "userdirectory.get" and at_least(version, "6.4"):
            rows = call(get, {"output": [id_field, "sp_entityid"]})
            ids += [r[id_field] for r in rows if r.get("sp_entityid") == PREFIX + "saml" and r[id_field] not in ids]
        if ids:
            try:
                call(delete, ids)
                deleted += len(ids)
            except RuntimeError as exc:
                print(f"purge {delete} {ids}: {exc}", file=sys.stderr)
    try:
        rows = call("usermacro.get", {"output": ["globalmacroid", "macro"], "globalmacro": True,
                                      "search": {"macro": "{$RT_"}})
        ids = [r["globalmacroid"] for r in rows if r["macro"].startswith("{$RT_")]
        if ids:
            call("usermacro.deleteglobal", ids)
            deleted += len(ids)
    except RuntimeError as exc:
        print(f"purge global macros: {exc}", file=sys.stderr)
    return deleted


def _make_call(url: str):
    """Return ``call(method, params)`` bound to ``url`` plus its auth setter."""
    state = {"auth": None, "bearer": False, "id": 0}

    def call(method: str, params):
        state["id"] += 1
        body = {"jsonrpc": "2.0", "method": method, "params": params, "id": state["id"]}
        headers = {"Content-Type": "application/json-rpc"}
        if state["auth"] and state["bearer"]:
            headers["Authorization"] = f"Bearer {state['auth']}"
        elif state["auth"]:
            body["auth"] = state["auth"]
        req = urllib.request.Request(url.rstrip("/") + "/api_jsonrpc.php",
                                     data=json.dumps(body).encode(), headers=headers)
        with urllib.request.urlopen(req, timeout=120) as resp:
            reply = json.loads(resp.read().decode())
        if "error" in reply:
            err = reply["error"]
            raise RuntimeError(f"{err.get('message', '')} {err.get('data', '')}".strip())
        return reply["result"]

    return call, state


def main(argv: list[str]) -> int:
    args = [a for a in argv if a not in ("--keep", "--purge")]
    if len(args) != 3:
        print("usage: roundtrip_fixtures.py URL USER PASSWORD [--keep | --purge]", file=sys.stderr)
        return 2
    url, user, password = args
    keep = "--keep" in argv
    call, state = _make_call(url)
    version = call("apiinfo.version", {})
    login = {"username" if at_least(version, "5.4") else "user": user, "password": password}
    state["auth"] = call("user.login", login)
    state["bearer"] = at_least(version, "6.4")
    if "--purge" in argv:
        print(f"Zabbix {version} at {url}: purged {purge_leftovers(call, version)} leftover objects")
        return 0
    cleanup = create_fixtures(call, version)
    summary = getattr(create_fixtures, "last_summary", {})
    width = max(len(k) for k in summary) if summary else 10
    created = sum(1 for s in summary.values() if s == "created")
    print(f"Zabbix {version} at {url}: {created} created, {len(summary) - created} skipped")
    for label, status in summary.items():
        print(f"  {label.ljust(width)}  {status}")
    if keep:
        print(f"--keep given, {len(cleanup)} delete calls left undone")
    else:
        failed = delete_fixtures(call, cleanup)
        print(f"deleted ({len(cleanup)} delete calls)" if not failed else deleted_report(failed))
        return 1 if failed else 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
