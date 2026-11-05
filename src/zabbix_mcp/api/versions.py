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

"""Which Zabbix release has which API method.

The tool catalog is one list for every configured server, but the
servers do not all speak the same API: ``proxygroup.*`` arrived in 7.0,
``templategroup.*`` in 6.2, ``host.massupdate`` leaves in 8.0. Without
this table a call to a method the server does not have comes back as a
bare ``Method not found``, and the model has no way to pick the right
tool for the right server up front.

``METHOD_SINCE`` lists the first release that has a method, for every
method that is *not* in 5.0 (the oldest release this server supports);
``METHOD_REMOVED`` lists the first release *without* it and what the
docs say to use instead; ``METHOD_DEPRECATED`` the first release whose
reference calls it deprecated (the legacy objects of 5.0 and 5.2 - applications,
screens, template screens, the old service dependencies - are listed too,
so a raw call on a newer server gets the replacement, not "Method not
found"). Both come from the per-release "API changes"
pages and the object reference pages, checked release by release
(5.0 ... 7.4, 8.0). A method missing from both tables exists on every
supported release.
"""

from __future__ import annotations

import re

# First release that has the method (methods present in 5.0 are not listed).
METHOD_SINCE: dict[str, str] = {
    # Zabbix 5.2
    "authentication.get": "5.2",
    "authentication.update": "5.2",
    "housekeeping.get": "5.2",
    "housekeeping.update": "5.2",
    "role.create": "5.2",
    "role.delete": "5.2",
    "role.get": "5.2",
    "role.update": "5.2",
    "settings.get": "5.2",
    "settings.update": "5.2",
    "templatedashboard.create": "5.2",
    "templatedashboard.delete": "5.2",
    "templatedashboard.get": "5.2",
    "templatedashboard.update": "5.2",
    # Zabbix 5.4
    "configuration.importcompare": "5.4",
    "report.create": "5.4",
    "report.delete": "5.4",
    "report.get": "5.4",
    "report.update": "5.4",
    "token.create": "5.4",
    "token.delete": "5.4",
    "token.generate": "5.4",
    "token.get": "5.4",
    "token.update": "5.4",
    # Zabbix 6.0
    "hanode.get": "6.0",
    "history.clear": "6.0",
    "regexp.create": "6.0",
    "regexp.delete": "6.0",
    "regexp.get": "6.0",
    "regexp.update": "6.0",
    "sla.create": "6.0",
    "sla.delete": "6.0",
    "sla.get": "6.0",
    "sla.getsli": "6.0",
    "sla.update": "6.0",
    "user.unblock": "6.0",
    # Zabbix 6.2
    "hostgroup.propagate": "6.2",
    "templategroup.create": "6.2",
    "templategroup.delete": "6.2",
    "templategroup.get": "6.2",
    "templategroup.massadd": "6.2",
    "templategroup.massremove": "6.2",
    "templategroup.massupdate": "6.2",
    "templategroup.propagate": "6.2",
    "templategroup.update": "6.2",
    "userdirectory.create": "6.2",
    "userdirectory.delete": "6.2",
    "userdirectory.get": "6.2",
    "userdirectory.test": "6.2",
    "userdirectory.update": "6.2",
    # Zabbix 6.0 (module.* is on the reference pages only since 6.4, but
    # the API exists and answers on 6.0.48 and 6.2.9)
    "module.create": "6.0",
    "module.delete": "6.0",
    "module.get": "6.0",
    "module.update": "6.0",
    # Zabbix 6.4
    "connector.create": "6.4",
    "connector.delete": "6.4",
    "connector.get": "6.4",
    "connector.update": "6.4",
    "script.getscriptsbyevents": "6.4",
    "user.provision": "6.4",
    # Zabbix 7.0
    "history.push": "7.0",
    "hostdashboard.get": "7.0",   # undocumented; CHostDashboard.php exists from 7.0
    "mfa.create": "7.0",
    "mfa.delete": "7.0",
    "mfa.get": "7.0",
    "mfa.update": "7.0",
    "proxygroup.create": "7.0",
    "proxygroup.delete": "7.0",
    "proxygroup.get": "7.0",
    "proxygroup.update": "7.0",
    "user.resettotp": "7.0",
    # Zabbix 7.4
    "discoveryruleprototype.create": "7.4",
    "discoveryruleprototype.delete": "7.4",
    "discoveryruleprototype.get": "7.4",
    "discoveryruleprototype.update": "7.4",
    # Zabbix 8.0
    "apmlog.get": "8.0",
    "ceprule.create": "8.0",
    "ceprule.delete": "8.0",
    "ceprule.get": "8.0",
    "ceprule.resettimewindows": "8.0",
    "ceprule.update": "8.0",
    "apmmetric.get": "8.0",
    "apmspan.get": "8.0",
    "apmtrace.get": "8.0",
    "device.get": "8.0",
    "device.offboard": "8.0",
    "serverinfo.get": "8.0",
}

# First release without the method -> (release, what to use instead).
METHOD_REMOVED: dict[str, tuple[str, str]] = {
    # Zabbix 5.2: template screens became template dashboards
    "templatescreen.copy": ("5.2", "templatedashboard.create with the dashboard copied from templatedashboard.get"),
    "templatescreen.create": ("5.2", "templatedashboard.create"),
    "templatescreen.delete": ("5.2", "templatedashboard.delete"),
    "templatescreen.get": ("5.2", "templatedashboard.get"),
    "templatescreen.update": ("5.2", "templatedashboard.update"),
    "templatescreenitem.get": ("5.2", "templatedashboard.get with selectPages"),
    "settings.getglobal": ("5.4", "settings.get"),
    # Zabbix 5.4: applications became item tags, screens became dashboards
    "application.create": ("5.4", "item tags (item.update with tags)"),
    "application.delete": ("5.4", "item tags (item.update with tags)"),
    "application.get": ("5.4", "item.get with tags / selectTags"),
    "application.massadd": ("5.4", "item tags (item.update with tags)"),
    "application.update": ("5.4", "item tags (item.update with tags)"),
    "screen.create": ("5.4", "dashboard.create"),
    "screen.delete": ("5.4", "dashboard.delete"),
    "screen.get": ("5.4", "dashboard.get"),
    "screen.update": ("5.4", "dashboard.update"),
    "screenitem.create": ("5.4", "dashboard.update with pages[].widgets"),
    "screenitem.delete": ("5.4", "dashboard.update with pages[].widgets"),
    "screenitem.get": ("5.4", "dashboard.get with selectPages"),
    "screenitem.update": ("5.4", "dashboard.update with pages[].widgets"),
    "screenitem.updatebyposition": ("5.4", "dashboard.update with pages[].widgets"),
    # Zabbix 6.0: the service model was rewritten (SLA moved to sla.*)
    "service.adddependencies": ("6.0", "service.update with parents / children"),
    "service.addtimes": ("6.0", "sla.create / sla.update with schedule and excluded_downtimes"),
    "service.deletedependencies": ("6.0", "service.update with parents / children"),
    "service.deletetimes": ("6.0", "sla.update with schedule and excluded_downtimes"),
    "service.getsla": ("6.0", "sla.getsli"),
    # Zabbix 6.2
    "trigger.adddependencies": ("6.2", "trigger.update with dependencies"),
    "trigger.deletedependencies": ("6.2", "trigger.update with dependencies"),
    # Zabbix 7.2
    "discoveryrule.copy": ("7.2", "discoveryrule.create with the rule copied from discoveryrule.get"),
    # Zabbix 8.0
    "host.massupdate": ("8.0", "host.update (per host)"),
    "hostgroup.massupdate": ("8.0", "hostgroup.update, hostgroup.massadd or hostgroup.massremove"),
    # 8.0.0 took the write half of the host interface API away (ZBXNEXT-10814;
    # the release candidates still had it): interfaces are edited through
    # the host, whose ``interfaces`` list REPLACES the current one.
    "hostinterface.create": ("8.0", "host.update with the host's full interfaces list plus the new one (host.get with selectInterfaces first; an interface without interfaceid is created)"),
    "hostinterface.delete": ("8.0", "host.update with the host's interfaces list without that interface (every interface not listed is removed)"),
    "hostinterface.massadd": ("8.0", "host.update with the full interfaces list, per host"),
    "hostinterface.massremove": ("8.0", "host.update with the full interfaces list, per host"),
    "hostinterface.replacehostinterfaces": ("8.0", "host.update with interfaces (the list replaces the current one)"),
    "hostinterface.update": ("8.0", "host.update with the host's full interfaces list, the changed interface carrying its interfaceid"),
    "template.massupdate": ("8.0", "template.update, template.massadd or template.massremove"),
    "templategroup.massupdate": ("8.0", "templategroup.update, templategroup.massadd or templategroup.massremove"),
}


# Deprecated but still working: first release whose reference says so ->
# (release, what to use instead). Nothing is refused; ``tools/list`` tells the
# model on which of its servers the method is on its way out.
METHOD_DEPRECATED: dict[str, tuple[str, str]] = {
    "correlation.create": ("8.0", "ceprule.create (complex event processing)"),
    "correlation.delete": ("8.0", "ceprule.delete (complex event processing)"),
    "correlation.get": ("8.0", "ceprule.get (complex event processing)"),
    "correlation.update": ("8.0", "ceprule.update (complex event processing)"),
}


def parse_version(version: str | None) -> tuple[int, int] | None:
    """``"7.4.14"`` -> ``(7, 4)``; ``None`` for anything that is not a version."""
    if not version:
        return None
    try:
        parts = str(version).strip().split(".")
        return int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return None


_PRERELEASE_OF_DOT_ZERO = re.compile(r"^\s*\d+\.\d+\.0\s*-?(alpha|beta|rc)\d*\s*$", re.IGNORECASE)


def is_removed(version: str | None, removed: str | None) -> bool:
    """True when a server running *version* no longer has what release
    *removed* took away.

    A pre-release of that very release (``8.0.0alpha1``, ``8.0.0beta3``,
    ``8.0.0rc2``) is not counted: what it still has is not known from its
    number (8.0.0rc2 had the host interface write methods that 8.0.0
    dropped), and an unknown never blocks a call.
    """
    current = parse_version(version)
    gone = parse_version(removed)
    if current is None or gone is None or current < gone:
        return False
    if current == gone and _PRERELEASE_OF_DOT_ZERO.match(str(version)):
        return False
    return True


def unavailable_reason(api_method: str, version: str | None) -> str | None:
    """Why *api_method* cannot be called on a server running *version*, or ``None``.

    An unknown or unparseable version never blocks a call: the server
    then answers with its own error, as before.
    """
    current = parse_version(version)
    if current is None:
        return None
    method = api_method.lower()
    since = METHOD_SINCE.get(method)
    if since and current < parse_version(since):
        return f"{api_method} requires Zabbix {since} or later (this server runs {version})."
    removed = METHOD_REMOVED.get(method)
    if removed and is_removed(version, removed[0]):
        return (
            f"{api_method} was removed in Zabbix {removed[0]} (this server runs {version}). "
            f"Use {removed[1]} instead."
        )
    return None


def deprecated_reason(api_method: str, version: str | None) -> str | None:
    """Why *api_method* should be avoided on a server running *version*, or
    ``None``. A deprecated method still works; this is advice, not a refusal."""
    current = parse_version(version)
    if current is None:
        return None
    entry = METHOD_DEPRECATED.get(api_method.lower())
    if entry and current >= parse_version(entry[0]):
        return (
            f"{api_method} is deprecated since Zabbix {entry[0]} and may be removed in a later "
            f"release (this server runs {version}). Prefer {entry[1]}."
        )
    return None
