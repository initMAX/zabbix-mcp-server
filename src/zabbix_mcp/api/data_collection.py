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

"""Zabbix API method definitions for the Data Collection category.

Covers hosts, host groups, interfaces, items, triggers, graphs, templates,
discovery (LLD & network), web scenarios, macros, maintenance, correlation,
value maps, and configuration import/export.
"""

from zabbix_mcp.api.types import MethodDef, ParamDef
from zabbix_mcp.api.common import (
    COMMON_GET_PARAMS,
    CREATE_PARAMS,
    UPDATE_PARAMS,
    DELETE_PARAMS,
    MASS_PARAMS,
)

# ---------------------------------------------------------------------------
# host
# ---------------------------------------------------------------------------
_HOST_GET_EXTRA: list[ParamDef] = [
    ParamDef("groupids", "list[str]", "Return only hosts that belong to the given host groups (by group ID)."),
    ParamDef("templateids", "list[str]", "Return only hosts linked to the given templates (by template ID)."),
    ParamDef("hostids", "list[str]", "Return only hosts with the given IDs."),
    ParamDef("proxyids", "list[str]", "Return only hosts monitored by the given proxies (by proxy ID)."),
    ParamDef("with_items", "bool", "Only return hosts that have items."),
    ParamDef("with_triggers", "bool", "Only return hosts that have triggers."),
    ParamDef("with_graphs", "bool", "Only return hosts that have graphs."),
    ParamDef("with_httptests", "bool", "Only return hosts that have web scenarios (HTTP tests)."),
]

_HOST_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="host.get",
        tool_name="host_get",
        description=(
            "Retrieve hosts. Hosts are the core monitored entities in Zabbix - they represent "
            "servers, VMs, network devices, or any other resource you monitor. Each host belongs "
            "to one or more host groups, can be linked to templates, and contains items, triggers, "
            "and graphs that define what is monitored and how."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _HOST_GET_EXTRA,
    ),
    MethodDef(
        api_method="host.create",
        tool_name="host_create",
        description=(
            "Create a new host. At minimum you must supply 'host' (technical name) and 'groups' "
            "(array of host group IDs). You can also attach templates, interfaces, macros, and tags "
            "in the same call. "
            "Interface 'type' accepts symbolic names: AGENT, SNMP, IPMI, JMX."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="host.update",
        tool_name="host_update",
        description=(
            "Update an existing host. The 'hostid' field is required. Any properties you supply "
            "will overwrite the current values. Use this to rename hosts, change their status, "
            "reassign groups or templates, etc."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="host.delete",
        tool_name="host_delete",
        description="Delete hosts by their IDs. This also removes all related items, triggers, and graphs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
    MethodDef(
        api_method="host.massadd",
        tool_name="host_massadd",
        description=(
            "Add groups, templates, macros, or interfaces to multiple hosts at once. "
            "Params must include 'hosts' (array of host IDs) and the objects to add."
        ),
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="host.massremove",
        tool_name="host_massremove",
        description=(
            "Remove groups, templates, macros, or interfaces from multiple hosts at once. "
            "Params must include 'hostids' and the object types to remove."
        ),
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="host.massupdate",
        tool_name="host_massupdate",
        description=(
            "Mass-update properties on multiple hosts at once. Replaces specified properties "
            "for all listed hosts. Params must include 'hosts' (array of host IDs) and the "
            "properties to set."
        ),
        read_only=False,
        params=MASS_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# hostgroup
# ---------------------------------------------------------------------------
_HOSTGROUP_GET_EXTRA: list[ParamDef] = [
    ParamDef("groupids", "list[str]", "Return only host groups with the given IDs."),
    ParamDef("hostids", "list[str]", "Return only host groups that contain the given hosts."),
    ParamDef("with_hosts", "bool", "Only return host groups that contain at least one host."),
    ParamDef("with_monitored_hosts", "bool", "Only return host groups that contain at least one monitored (enabled) host."),
]

_HOSTGROUP_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="hostgroup.get",
        tool_name="hostgroup_get",
        description=(
            "Retrieve host groups. Host groups are used to logically organize hosts and to "
            "control access permissions. Every host must belong to at least one host group. "
            "Groups can also be used to filter when retrieving hosts, items, triggers, etc."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _HOSTGROUP_GET_EXTRA,
    ),
    MethodDef(
        api_method="hostgroup.create",
        tool_name="hostgroup_create",
        description="Create a new host group. Requires the 'name' property.",
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="hostgroup.update",
        tool_name="hostgroup_update",
        description="Update an existing host group. The 'groupid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="hostgroup.delete",
        tool_name="hostgroup_delete",
        description="Delete host groups by their IDs. Hosts in the groups are not deleted.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
    MethodDef(
        api_method="hostgroup.massadd",
        tool_name="hostgroup_massadd",
        description="Add hosts or templates to multiple host groups at once.",
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="hostgroup.massremove",
        tool_name="hostgroup_massremove",
        description="Remove hosts or templates from multiple host groups at once.",
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="hostgroup.massupdate",
        tool_name="hostgroup_massupdate",
        description="Replace all hosts or templates in the specified host groups.",
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="hostgroup.propagate",
        tool_name="hostgroup_propagate",
        description="Propagate permissions to child host groups. Useful after changing permissions on a parent group.",
        read_only=False,
        params=[
            ParamDef(
                "params", "dict",
                "Propagation parameters. Must include 'groups' (array of group IDs) and optionally 'permissions' (bool).",
                required=True,
            ),
        ],
    ),
]

# ---------------------------------------------------------------------------
# hostinterface
# ---------------------------------------------------------------------------
_HOSTINTERFACE_GET_EXTRA: list[ParamDef] = [
    ParamDef("interfaceids", "list[str]", "Return only interfaces with the given IDs."),
    ParamDef("hostids", "list[str]", "Return only interfaces that belong to the given hosts."),
]

_HOSTINTERFACE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="hostinterface.get",
        tool_name="hostinterface_get",
        description=(
            "Retrieve host interfaces. Each host can have multiple interfaces (agent, SNMP, JMX, IPMI) "
            "that define how Zabbix connects to the host for data collection. Items are bound to "
            "specific interfaces."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _HOSTINTERFACE_GET_EXTRA,
    ),
    MethodDef(
        api_method="hostinterface.create",
        tool_name="hostinterface_create",
        description=(
            "Create a new host interface. Requires 'hostid', 'type', 'main' (0/1), "
            "'useip' (0/1), 'ip', 'dns', and 'port'. "
            "Symbolic names accepted for 'type': AGENT, SNMP, IPMI, JMX."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="hostinterface.update",
        tool_name="hostinterface_update",
        description=(
            "Update an existing host interface. The 'interfaceid' field is required. "
            "Symbolic names accepted for 'type': AGENT, SNMP, IPMI, JMX."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="hostinterface.delete",
        tool_name="hostinterface_delete",
        description="Delete host interfaces by their IDs. Cannot delete an interface used by items.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
    MethodDef(
        api_method="hostinterface.massadd",
        tool_name="hostinterface_massadd",
        description="Add interfaces to multiple hosts at once.",
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="hostinterface.massremove",
        tool_name="hostinterface_massremove",
        description="Remove interfaces from multiple hosts at once.",
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="hostinterface.replacehostinterfaces",
        tool_name="hostinterface_replacehostinterfaces",
        description=(
            "Replace all interfaces on a host. Any existing interfaces not present in the request "
            "will be removed. Params must include 'hostid' and 'interfaces' array."
        ),
        read_only=False,
        params=[
            ParamDef(
                "params", "dict",
                "Replacement parameters. Must include 'hostid' and 'interfaces' (array of interface objects).",
                required=True,
            ),
        ],
    ),
]

# ---------------------------------------------------------------------------
# item
# ---------------------------------------------------------------------------
_ITEM_GET_EXTRA: list[ParamDef] = [
    ParamDef("itemids", "list[str]", "Return only items with the given IDs."),
    ParamDef("groupids", "list[str]", "Return only items that belong to hosts in the given host groups."),
    ParamDef("hostids", "list[str]", "Return only items that belong to the given hosts."),
    ParamDef("templateids", "list[str]", "Return only items that belong to the given templates."),
    ParamDef("triggerids", "list[str]", "Return only items used in the given triggers."),
    ParamDef("with_triggers", "bool", "Only return items that are used in at least one trigger."),
    ParamDef("webitems", "bool", "Include web items (items created by web scenarios) in the result."),
]

_ITEM_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="item.get",
        tool_name="item_get",
        description=(
            "Retrieve items. Items are the individual data collection points in Zabbix - each item "
            "gathers a specific metric from a host (CPU usage, memory, disk space, etc.). Items belong "
            "to hosts and are bound to a host interface. Trigger expressions reference items by their "
            "keys to define alerting conditions."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _ITEM_GET_EXTRA,
    ),
    MethodDef(
        api_method="item.create",
        tool_name="item_create",
        description=(
            "Create a new item. Requires 'hostid', 'name', 'key_' (item key), 'type' (collection method), "
            "and 'value_type' (data type). The item is bound to the host and collects data according to "
            "its type and interval. "
            "Symbolic names accepted for 'type': ZABBIX_PASSIVE, TRAPPER, SIMPLE_CHECK, INTERNAL, "
            "ZABBIX_ACTIVE, WEB_ITEM, EXTERNAL_CHECK, DATABASE_MONITOR, IPMI, SSH, TELNET, CALCULATED, "
            "JMX, SNMP_TRAP, DEPENDENT, HTTP_AGENT, SNMP_AGENT, SCRIPT, BROWSER. "
            "Symbolic names for 'value_type': FLOAT, CHAR, LOG, UNSIGNED, TEXT, BINARY, JSON (8.0+). "
            "Preprocessing steps also accept symbolic type names (e.g. JSONPATH, DISCARD_UNCHANGED_HEARTBEAT). "
            "For HTTP_AGENT items, 'authtype' accepts: NONE, BASIC, NTLM, KERBEROS, DIGEST; "
            "'post_type' accepts: RAW, JSON. "
            "Value maps can be assigned by name: \"valuemap\": {\"name\": \"My Map\"} "
            "(the server resolves the ID automatically)."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="item.update",
        tool_name="item_update",
        description=(
            "Update an existing item. The 'itemid' field is required. "
            "Symbolic names accepted for 'type', 'value_type', 'authtype', 'post_type', "
            "and preprocessing step types — same as item_create."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="item.delete",
        tool_name="item_delete",
        description=(
            "Delete items by their IDs. Triggers that reference only the deleted items will also be removed."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# trigger
# ---------------------------------------------------------------------------
_TRIGGER_GET_EXTRA: list[ParamDef] = [
    ParamDef("triggerids", "list[str]", "Return only triggers with the given IDs."),
    ParamDef("groupids", "list[str]", "Return only triggers that belong to hosts in the given host groups."),
    ParamDef("hostids", "list[str]", "Return only triggers that belong to the given hosts."),
    ParamDef("templateids", "list[str]", "Return only triggers that belong to the given templates."),
    ParamDef("only_true", "bool", "Only return triggers that are currently in a problem (PROBLEM) state."),
    ParamDef("min_severity", "int", "Minimum trigger severity to return (0-5: NOT_CLASSIFIED, INFORMATION, WARNING, AVERAGE, HIGH, DISASTER)", required=False),
    ParamDef("with_unacknowledged_events", "bool", "Only return triggers that have unacknowledged problem events."),
    ParamDef("active", "bool", "Only return enabled triggers that belong to enabled hosts."),
    ParamDef("monitored", "bool", "Only return enabled triggers that belong to enabled hosts and contain only enabled items."),
]

_TRIGGER_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="trigger.get",
        tool_name="trigger_get",
        description=(
            "Retrieve triggers. Triggers define conditions (expressions) that evaluate item values "
            "and determine when a problem exists. Each trigger references one or more items via an "
            "expression like 'last(/host/key) > 90'. Triggers have severity levels (0-5) and generate "
            "events when their state changes."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _TRIGGER_GET_EXTRA,
    ),
    MethodDef(
        api_method="trigger.create",
        tool_name="trigger_create",
        description=(
            "Create a new trigger. Requires 'description' (name) and 'expression' that references "
            "items. Example expression: 'last(/myhost/system.cpu.load) > 5'. Optionally set "
            "'priority' and 'status' (0=enabled, 1=disabled). "
            "Symbolic names accepted for 'priority': NOT_CLASSIFIED, INFORMATION, WARNING, "
            "AVERAGE, HIGH, DISASTER."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="trigger.update",
        tool_name="trigger_update",
        description=(
            "Update an existing trigger. The 'triggerid' field is required. "
            "Symbolic names accepted for 'priority' — same as trigger_create."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="trigger.delete",
        tool_name="trigger_delete",
        description="Delete triggers by their IDs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# graph
# ---------------------------------------------------------------------------
_GRAPH_GET_EXTRA: list[ParamDef] = [
    ParamDef("graphids", "list[str]", "Return only graphs with the given IDs."),
    ParamDef("groupids", "list[str]", "Return only graphs that belong to hosts in the given host groups."),
    ParamDef("hostids", "list[str]", "Return only graphs that belong to the given hosts."),
    ParamDef("templateids", "list[str]", "Return only graphs that belong to the given templates."),
]

_GRAPH_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="graph.get",
        tool_name="graph_get",
        description=(
            "Retrieve graphs. Graphs provide visual representations of item data over time. "
            "Each graph contains one or more graph items (data series) that reference Zabbix items. "
            "Graphs belong to hosts or templates."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _GRAPH_GET_EXTRA,
    ),
    MethodDef(
        api_method="graph.create",
        tool_name="graph_create",
        description=(
            "Create a new graph. Requires 'name' and 'gitems' (array of graph item objects, each "
            "referencing an item by 'itemid'). Graphs visualize collected data."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="graph.update",
        tool_name="graph_update",
        description="Update an existing graph. The 'graphid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="graph.delete",
        tool_name="graph_delete",
        description="Delete graphs by their IDs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# graphitem
# ---------------------------------------------------------------------------
_GRAPHITEM_GET_EXTRA: list[ParamDef] = [
    ParamDef("graphids", "list[str]", "Return only graph items that belong to the given graphs."),
    ParamDef("itemids", "list[str]", "Return only graph items that reference the given items."),
]

_GRAPHITEM_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="graphitem.get",
        tool_name="graphitem_get",
        description=(
            "Retrieve graph items (read-only). Graph items are the individual data series within a "
            "graph. Each graph item links a Zabbix item to a graph, specifying color, draw style, "
            "sort order, and Y-axis side."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _GRAPHITEM_GET_EXTRA,
    ),
]

# ---------------------------------------------------------------------------
# template
# ---------------------------------------------------------------------------
_TEMPLATE_GET_EXTRA: list[ParamDef] = [
    ParamDef("templateids", "list[str]", "Return only templates with the given IDs."),
    ParamDef("groupids", "list[str]", "Return only templates that belong to the given template/host groups."),
    ParamDef("hostids", "list[str]", "Return only templates linked to the given hosts."),
    ParamDef("with_items", "bool", "Only return templates that have items."),
    ParamDef("with_triggers", "bool", "Only return templates that have triggers."),
    ParamDef("with_graphs", "bool", "Only return templates that have graphs."),
    ParamDef("with_httptests", "bool", "Only return templates that have web scenarios."),
]

_TEMPLATE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="template.get",
        tool_name="template_get",
        description=(
            "Retrieve templates. Templates are reusable sets of items, triggers, graphs, and "
            "discovery rules that can be linked to one or more hosts. When a template is linked "
            "to a host, all of its entities are automatically applied to that host. Templates "
            "belong to template groups and can be nested (linked to other templates)."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _TEMPLATE_GET_EXTRA,
    ),
    MethodDef(
        api_method="template.create",
        tool_name="template_create",
        description=(
            "Create a new template. Requires 'host' (technical name) and 'groups' (array of "
            "template group IDs). Templates serve as blueprints for monitoring configuration."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="template.update",
        tool_name="template_update",
        description="Update an existing template. The 'templateid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="template.delete",
        tool_name="template_delete",
        description=(
            "Delete templates by their IDs. Entities inherited by hosts from the deleted templates "
            "will be removed from the hosts as well."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
    MethodDef(
        api_method="template.massadd",
        tool_name="template_massadd",
        description="Add groups, hosts, or macros to multiple templates at once.",
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="template.massremove",
        tool_name="template_massremove",
        description="Remove groups, hosts, or macros from multiple templates at once.",
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="template.massupdate",
        tool_name="template_massupdate",
        description="Replace groups, hosts, or macros for multiple templates at once.",
        read_only=False,
        params=MASS_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# templategroup
# ---------------------------------------------------------------------------
_TEMPLATEGROUP_GET_EXTRA: list[ParamDef] = [
    ParamDef("groupids", "list[str]", "Return only template groups with the given IDs."),
    ParamDef("templateids", "list[str]", "Return only template groups that contain the given templates."),
    ParamDef("with_templates", "bool", "Only return template groups that contain at least one template."),
]

_TEMPLATEGROUP_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="templategroup.get",
        tool_name="templategroup_get",
        description=(
            "Retrieve template groups. Template groups organize templates in the same way that "
            "host groups organize hosts. They are used for access control and logical grouping."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _TEMPLATEGROUP_GET_EXTRA,
    ),
    MethodDef(
        api_method="templategroup.create",
        tool_name="templategroup_create",
        description="Create a new template group. Requires the 'name' property.",
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="templategroup.update",
        tool_name="templategroup_update",
        description="Update an existing template group. The 'groupid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="templategroup.delete",
        tool_name="templategroup_delete",
        description="Delete template groups by their IDs. Templates in the groups are not deleted.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
    MethodDef(
        api_method="templategroup.massadd",
        tool_name="templategroup_massadd",
        description="Add templates to multiple template groups at once.",
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="templategroup.massremove",
        tool_name="templategroup_massremove",
        description="Remove templates from multiple template groups at once.",
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="templategroup.massupdate",
        tool_name="templategroup_massupdate",
        description="Replace all templates in the specified template groups.",
        read_only=False,
        params=MASS_PARAMS,
    ),
    MethodDef(
        api_method="templategroup.propagate",
        tool_name="templategroup_propagate",
        description="Propagate permissions to child template groups.",
        read_only=False,
        params=[
            ParamDef(
                "params", "dict",
                "Propagation parameters. Must include 'groups' (array of group IDs) and optionally 'permissions' (bool).",
                required=True,
            ),
        ],
    ),
]

# ---------------------------------------------------------------------------
# discoveryrule (Low-Level Discovery)
# ---------------------------------------------------------------------------
_DISCOVERYRULE_GET_EXTRA: list[ParamDef] = [
    ParamDef("itemids", "list[str]", "Return only LLD rules with the given IDs (LLD rules use item IDs)."),
    ParamDef("hostids", "list[str]", "Return only LLD rules that belong to the given hosts."),
    ParamDef("templateids", "list[str]", "Return only LLD rules that belong to the given templates."),
]

_DISCOVERYRULE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="discoveryrule.get",
        tool_name="discoveryrule_get",
        description=(
            "Retrieve Low-Level Discovery (LLD) rules. LLD rules automatically discover entities "
            "on a host (filesystems, network interfaces, SNMP OIDs, etc.) and create items, triggers, "
            "and graphs from prototypes for each discovered entity. LLD rules are special items that "
            "return JSON describing the discovered entities."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _DISCOVERYRULE_GET_EXTRA,
    ),
    MethodDef(
        api_method="discoveryrule.create",
        tool_name="discoveryrule_create",
        description=(
            "Create a new LLD rule. Requires 'hostid', 'name', 'key_', and 'type'. The rule will "
            "periodically discover entities and create real objects from prototypes. "
            "Symbolic names accepted for 'type': ZABBIX_PASSIVE, TRAPPER, SIMPLE_CHECK, INTERNAL, "
            "ZABBIX_ACTIVE, EXTERNAL_CHECK, DATABASE_MONITOR, IPMI, SSH, TELNET, "
            "HTTP_AGENT, SNMP_AGENT, SCRIPT, DEPENDENT."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="discoveryrule.update",
        tool_name="discoveryrule_update",
        description="Update an existing LLD rule. The 'itemid' field is required (LLD rules use item IDs).",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="discoveryrule.delete",
        tool_name="discoveryrule_delete",
        description="Delete LLD rules by their IDs. All prototypes and discovered objects will also be removed.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# itemprototype
# ---------------------------------------------------------------------------
_ITEMPROTOTYPE_GET_EXTRA: list[ParamDef] = [
    ParamDef("itemids", "list[str]", "Return only item prototypes with the given IDs."),
    ParamDef("discoveryids", "list[str]", "Return only item prototypes belonging to the given LLD rules."),
    ParamDef("hostids", "list[str]", "Return only item prototypes that belong to the given hosts."),
    ParamDef("templateids", "list[str]", "Return only item prototypes that belong to the given templates."),
]

_ITEMPROTOTYPE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="itemprototype.get",
        tool_name="itemprototype_get",
        description=(
            "Retrieve item prototypes. Item prototypes are templates used by LLD rules to create "
            "real items for each discovered entity. For example, a filesystem discovery rule uses "
            "an item prototype to create disk space items for each discovered mount point."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _ITEMPROTOTYPE_GET_EXTRA,
    ),
    MethodDef(
        api_method="itemprototype.create",
        tool_name="itemprototype_create",
        description=(
            "Create a new item prototype. Requires 'hostid', 'ruleid' (the parent LLD rule), "
            "'name', 'key_', 'type', and 'value_type'. The key must contain LLD macros like {#FSNAME}. "
            "Symbolic names accepted for 'type' and 'value_type' — same as item_create."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="itemprototype.update",
        tool_name="itemprototype_update",
        description=(
            "Update an existing item prototype. The 'itemid' field is required. "
            "Symbolic names accepted for 'type' and 'value_type' — same as item_create."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="itemprototype.delete",
        tool_name="itemprototype_delete",
        description="Delete item prototypes by their IDs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# triggerprototype
# ---------------------------------------------------------------------------
_TRIGGERPROTOTYPE_GET_EXTRA: list[ParamDef] = [
    ParamDef("triggerids", "list[str]", "Return only trigger prototypes with the given IDs."),
    ParamDef("discoveryids", "list[str]", "Return only trigger prototypes belonging to the given LLD rules."),
    ParamDef("hostids", "list[str]", "Return only trigger prototypes that belong to the given hosts."),
    ParamDef("templateids", "list[str]", "Return only trigger prototypes that belong to the given templates."),
]

_TRIGGERPROTOTYPE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="triggerprototype.get",
        tool_name="triggerprototype_get",
        description=(
            "Retrieve trigger prototypes. Trigger prototypes are used by LLD rules to create "
            "real triggers for each discovered entity. Their expressions reference item prototypes "
            "and use LLD macros."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _TRIGGERPROTOTYPE_GET_EXTRA,
    ),
    MethodDef(
        api_method="triggerprototype.create",
        tool_name="triggerprototype_create",
        description=(
            "Create a new trigger prototype. Requires 'description' and 'expression' referencing "
            "item prototypes with LLD macros. "
            "Symbolic names accepted for 'priority': NOT_CLASSIFIED, INFORMATION, WARNING, "
            "AVERAGE, HIGH, DISASTER."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="triggerprototype.update",
        tool_name="triggerprototype_update",
        description=(
            "Update an existing trigger prototype. The 'triggerid' field is required. "
            "Symbolic names accepted for 'priority' — same as trigger_create."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="triggerprototype.delete",
        tool_name="triggerprototype_delete",
        description="Delete trigger prototypes by their IDs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# graphprototype
# ---------------------------------------------------------------------------
_GRAPHPROTOTYPE_GET_EXTRA: list[ParamDef] = [
    ParamDef("graphids", "list[str]", "Return only graph prototypes with the given IDs."),
    ParamDef("discoveryids", "list[str]", "Return only graph prototypes belonging to the given LLD rules."),
    ParamDef("hostids", "list[str]", "Return only graph prototypes that belong to the given hosts."),
    ParamDef("templateids", "list[str]", "Return only graph prototypes that belong to the given templates."),
]

_GRAPHPROTOTYPE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="graphprototype.get",
        tool_name="graphprototype_get",
        description=(
            "Retrieve graph prototypes. Graph prototypes are used by LLD rules to create "
            "real graphs for each discovered entity, visualizing data from item prototypes."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _GRAPHPROTOTYPE_GET_EXTRA,
    ),
    MethodDef(
        api_method="graphprototype.create",
        tool_name="graphprototype_create",
        description=(
            "Create a new graph prototype. Requires 'name' and 'gitems' referencing item prototypes."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="graphprototype.update",
        tool_name="graphprototype_update",
        description="Update an existing graph prototype. The 'graphid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="graphprototype.delete",
        tool_name="graphprototype_delete",
        description="Delete graph prototypes by their IDs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# hostprototype
# ---------------------------------------------------------------------------
_HOSTPROTOTYPE_GET_EXTRA: list[ParamDef] = [
    ParamDef("hostids", "list[str]", "Return only host prototypes with the given IDs."),
    ParamDef("discoveryids", "list[str]", "Return only host prototypes belonging to the given LLD rules."),
]

_HOSTPROTOTYPE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="hostprototype.get",
        tool_name="hostprototype_get",
        description=(
            "Retrieve host prototypes. Host prototypes are used by LLD rules to automatically "
            "create new hosts for each discovered entity (e.g., VMware VMs discovered on a hypervisor). "
            "Each host prototype defines the groups, templates, and interfaces for the discovered hosts."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _HOSTPROTOTYPE_GET_EXTRA,
    ),
    MethodDef(
        api_method="hostprototype.create",
        tool_name="hostprototype_create",
        description=(
            "Create a new host prototype. Requires 'host' (technical name with LLD macros), "
            "'ruleid' (parent LLD rule), and 'groupLinks' (host groups for discovered hosts)."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="hostprototype.update",
        tool_name="hostprototype_update",
        description="Update an existing host prototype. The 'hostid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="hostprototype.delete",
        tool_name="hostprototype_delete",
        description="Delete host prototypes by their IDs. Discovered hosts created from these prototypes will also be removed.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# discoveryruleprototype (LLD Rule Prototypes - Zabbix 7.4+)
# ---------------------------------------------------------------------------
_DISCOVERYRULEPROTOTYPE_GET_EXTRA: list[ParamDef] = [
    ParamDef("discoveryids", "list[str]", "Return only LLD rule prototypes with the given IDs."),
    ParamDef("hostids", "list[str]", "Return only LLD rule prototypes that belong to the given hosts."),
]

_DISCOVERYRULEPROTOTYPE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="discoveryruleprototype.get",
        tool_name="discoveryruleprototype_get",
        description=(
            "Retrieve LLD rule prototypes (Zabbix 7.4+). LLD rule prototypes allow discovery rules "
            "to be created on hosts that are themselves discovered by a parent LLD rule, enabling "
            "multi-level (nested) discovery."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _DISCOVERYRULEPROTOTYPE_GET_EXTRA,
    ),
    MethodDef(
        api_method="discoveryruleprototype.create",
        tool_name="discoveryruleprototype_create",
        description=(
            "Create a new LLD rule prototype (Zabbix 7.4+). Requires 'hostid', 'name', 'key_', "
            "and 'type'. The key must include LLD macros from the parent discovery rule. "
            "Symbolic names accepted for 'type' — same as discoveryrule_create."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="discoveryruleprototype.update",
        tool_name="discoveryruleprototype_update",
        description="Update an existing LLD rule prototype. The 'itemid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="discoveryruleprototype.delete",
        tool_name="discoveryruleprototype_delete",
        description="Delete LLD rule prototypes by their IDs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# usermacro
# ---------------------------------------------------------------------------
_USERMACRO_GET_EXTRA: list[ParamDef] = [
    ParamDef("hostids", "list[str]", "Return only macros defined on the given hosts."),
    ParamDef("hostmacroids", "list[str]", "Return only host macros with the given IDs."),
    ParamDef("globalmacroids", "list[str]", "Return only global macros with the given IDs."),
]

_USERMACRO_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="usermacro.get",
        tool_name="usermacro_get",
        description=(
            "Retrieve user macros. User macros are custom variables ({$MACRO}) that can be defined "
            "globally or on individual hosts/templates. They are used in item keys, trigger "
            "expressions, and other places to make configuration reusable and environment-specific. "
            "Host-level macros override global macros of the same name."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _USERMACRO_GET_EXTRA,
    ),
    MethodDef(
        api_method="usermacro.create",
        tool_name="usermacro_create",
        description=(
            "Create a host-level user macro. Requires 'hostid', 'macro' (e.g. '{$MY_MACRO}'), "
            "and 'value'. Symbolic names accepted for 'type': TEXT, SECRET, VAULT."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="usermacro.update",
        tool_name="usermacro_update",
        description="Update a host-level user macro. The 'hostmacroid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="usermacro.delete",
        tool_name="usermacro_delete",
        description="Delete host-level user macros by their IDs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
    MethodDef(
        api_method="usermacro.createglobal",
        tool_name="usermacro_createglobal",
        description=(
            "Create a global user macro. Global macros apply to all hosts unless overridden by "
            "a host-level macro. Requires 'macro' and 'value'."
        ),
        read_only=False,
        params=[
            ParamDef(
                "params", "dict",
                "Global macro properties. Must include 'macro' (e.g. '{$MY_MACRO}') and 'value'.",
                required=True,
            ),
        ],
    ),
    MethodDef(
        api_method="usermacro.updateglobal",
        tool_name="usermacro_updateglobal",
        description="Update a global user macro. The 'globalmacroid' field is required.",
        read_only=False,
        params=[
            ParamDef(
                "params", "dict",
                "Global macro properties to update. Must include 'globalmacroid'.",
                required=True,
            ),
        ],
    ),
    MethodDef(
        api_method="usermacro.deleteglobal",
        tool_name="usermacro_deleteglobal",
        description="Delete global user macros by their IDs.",
        read_only=False,
        array_param="ids",
        params=[
            ParamDef(
                "ids", "list[str]",
                "Array of global macro IDs to delete.",
                required=True,
            ),
        ],
    ),
]

# ---------------------------------------------------------------------------
# valuemap
# ---------------------------------------------------------------------------
_VALUEMAP_GET_EXTRA: list[ParamDef] = [
    ParamDef("valuemapids", "list[str]", "Return only value maps with the given IDs."),
    ParamDef("hostids", "list[str]", "Return only value maps that belong to the given hosts or templates."),
]

_VALUEMAP_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="valuemap.get",
        tool_name="valuemap_get",
        description=(
            "Retrieve value maps. Value maps translate numeric item values into human-readable "
            "strings (e.g., 0 -> 'Down', 1 -> 'Up'). They are defined on hosts or templates "
            "and referenced by items for display purposes."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _VALUEMAP_GET_EXTRA,
    ),
    MethodDef(
        api_method="valuemap.create",
        tool_name="valuemap_create",
        description=(
            "Create a new value map. Requires 'hostid', 'name', and 'mappings' (array of "
            "{'value': '0', 'newvalue': 'Down'} objects)."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="valuemap.update",
        tool_name="valuemap_update",
        description="Update an existing value map. The 'valuemapid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="valuemap.delete",
        tool_name="valuemap_delete",
        description="Delete value maps by their IDs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# maintenance
# ---------------------------------------------------------------------------
_MAINTENANCE_GET_EXTRA: list[ParamDef] = [
    ParamDef("maintenanceids", "list[str]", "Return only maintenance periods with the given IDs."),
    ParamDef("groupids", "list[str]", "Return only maintenance periods that affect the given host groups."),
    ParamDef("hostids", "list[str]", "Return only maintenance periods that affect the given hosts."),
]

_MAINTENANCE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="maintenance.get",
        tool_name="maintenance_get",
        description=(
            "Retrieve maintenance periods. Maintenance windows suppress problem notifications "
            "and optionally pause data collection for specified hosts or host groups during "
            "scheduled downtime (e.g., patching windows)."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _MAINTENANCE_GET_EXTRA,
    ),
    MethodDef(
        api_method="maintenance.create",
        tool_name="maintenance_create",
        description=(
            "Create a new maintenance period. Requires 'name', 'active_since', 'active_till', "
            "'timeperiods', and either 'groupids' or 'hostids' to define which hosts are affected. "
            "Symbolic names accepted for 'maintenance_type': DATA_COLLECTION (with data), NO_DATA (without data)."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="maintenance.update",
        tool_name="maintenance_update",
        description="Update an existing maintenance period. The 'maintenanceid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="maintenance.delete",
        tool_name="maintenance_delete",
        description="Delete maintenance periods by their IDs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# correlation
# ---------------------------------------------------------------------------
_CORRELATION_GET_EXTRA: list[ParamDef] = [
    ParamDef("correlationids", "list[str]", "Return only correlations with the given IDs."),
]

_CORRELATION_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="correlation.get",
        tool_name="correlation_get",
        description=(
            "Retrieve event correlations. Correlations define rules for automatically closing "
            "related problem events. For example, a correlation can close all 'service down' "
            "problems when a 'service up' event is received."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _CORRELATION_GET_EXTRA,
    ),
    MethodDef(
        api_method="correlation.create",
        tool_name="correlation_create",
        description=(
            "Create a new event correlation. Requires 'name', 'filter' (conditions), "
            "and 'operations' (actions to take when conditions match)."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="correlation.update",
        tool_name="correlation_update",
        description="Update an existing event correlation. The 'correlationid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="correlation.delete",
        tool_name="correlation_delete",
        description="Delete event correlations by their IDs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# drule (Network Discovery Rules)
# ---------------------------------------------------------------------------
_DRULE_GET_EXTRA: list[ParamDef] = [
    ParamDef("druleids", "list[str]", "Return only network discovery rules with the given IDs."),
]

_DRULE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="drule.get",
        tool_name="drule_get",
        description=(
            "Retrieve network discovery rules. Network discovery rules define IP ranges and "
            "checks (SNMP, agent, ICMP, etc.) used to automatically find new hosts on the "
            "network. Discovered hosts and services are stored as dhost/dservice objects."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _DRULE_GET_EXTRA,
    ),
    MethodDef(
        api_method="drule.create",
        tool_name="drule_create",
        description=(
            "Create a new network discovery rule. Requires 'name', 'iprange' (e.g. '192.168.1.1-255'), "
            "and 'dchecks' (array of discovery check objects defining what to scan for). "
            "Symbolic names accepted for dcheck 'type': SSH, LDAP, SMTP, FTP, HTTP, POP, NNTP, "
            "IMAP, TCP, ZABBIX_AGENT, SNMPV1, SNMPV2C, ICMP, SNMPV3, HTTPS, TELNET."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="drule.update",
        tool_name="drule_update",
        description="Update an existing network discovery rule. The 'druleid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="drule.delete",
        tool_name="drule_delete",
        description="Delete network discovery rules by their IDs.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# dcheck (Discovery Checks)
# ---------------------------------------------------------------------------
_DCHECK_GET_EXTRA: list[ParamDef] = [
    ParamDef("dcheckids", "list[str]", "Return only discovery checks with the given IDs."),
    ParamDef("druleids", "list[str]", "Return only discovery checks belonging to the given network discovery rules."),
]

_DCHECK_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="dcheck.get",
        tool_name="dcheck_get",
        description=(
            "Retrieve discovery checks (read-only). Discovery checks are the individual tests "
            "(SNMP, agent, ICMP ping, TCP port, etc.) defined within a network discovery rule. "
            "Each discovery rule contains one or more checks."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _DCHECK_GET_EXTRA,
    ),
]

# ---------------------------------------------------------------------------
# dhost (Discovered Hosts)
# ---------------------------------------------------------------------------
_DHOST_GET_EXTRA: list[ParamDef] = [
    ParamDef("dhostids", "list[str]", "Return only discovered hosts with the given IDs."),
    ParamDef("druleids", "list[str]", "Return only discovered hosts found by the given network discovery rules."),
]

_DHOST_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="dhost.get",
        tool_name="dhost_get",
        description=(
            "Retrieve discovered hosts (read-only). Discovered hosts are hosts found by network "
            "discovery rules. Each discovered host may have one or more discovered services "
            "(dservice) representing the checks that succeeded."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _DHOST_GET_EXTRA,
    ),
]

# ---------------------------------------------------------------------------
# dservice (Discovered Services)
# ---------------------------------------------------------------------------
_DSERVICE_GET_EXTRA: list[ParamDef] = [
    ParamDef("dserviceids", "list[str]", "Return only discovered services with the given IDs."),
    ParamDef("dhostids", "list[str]", "Return only discovered services belonging to the given discovered hosts."),
    ParamDef("druleids", "list[str]", "Return only discovered services found by the given network discovery rules."),
]

_DSERVICE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="dservice.get",
        tool_name="dservice_get",
        description=(
            "Retrieve discovered services (read-only). Discovered services represent individual "
            "checks (ports, protocols) that responded on a discovered host. They belong to "
            "discovered hosts (dhost) and are created by network discovery rules (drule)."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _DSERVICE_GET_EXTRA,
    ),
]

# ---------------------------------------------------------------------------
# httptest (Web Scenarios)
# ---------------------------------------------------------------------------
_HTTPTEST_GET_EXTRA: list[ParamDef] = [
    ParamDef("httptestids", "list[str]", "Return only web scenarios with the given IDs."),
    ParamDef("hostids", "list[str]", "Return only web scenarios that belong to the given hosts."),
    ParamDef("groupids", "list[str]", "Return only web scenarios that belong to hosts in the given host groups."),
    ParamDef("templateids", "list[str]", "Return only web scenarios that belong to the given templates."),
]

_HTTPTEST_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="httptest.get",
        tool_name="httptest_get",
        description=(
            "Retrieve web scenarios (HTTP tests). Web scenarios perform multi-step HTTP checks "
            "against web applications, verifying availability, response time, and expected content. "
            "Each scenario contains ordered steps and automatically creates web-monitoring items "
            "on the host."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _HTTPTEST_GET_EXTRA,
    ),
    MethodDef(
        api_method="httptest.create",
        tool_name="httptest_create",
        description=(
            "Create a new web scenario. Requires 'hostid', 'name', and 'steps' (array of HTTP "
            "step objects with 'name', 'url', and 'no' (step order)). Steps can verify status "
            "codes and response content. "
            "Symbolic names accepted for 'authentication': NONE, BASIC, NTLM, KERBEROS, DIGEST."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="httptest.update",
        tool_name="httptest_update",
        description="Update an existing web scenario. The 'httptestid' field is required.",
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="httptest.delete",
        tool_name="httptest_delete",
        description="Delete web scenarios by their IDs. Associated web items will also be removed.",
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# configuration (export / import / importcompare)
# ---------------------------------------------------------------------------
_CONFIGURATION_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="configuration.export",
        tool_name="configuration_export",
        description=(
            "Export Zabbix configuration as YAML, XML, or JSON. Use this to back up or transfer "
            "hosts, templates, and other objects between Zabbix instances. "
            "Params: {\"format\": \"yaml\"|\"xml\"|\"json\", \"options\": {\"hosts\": [\"id\"], "
            "\"templates\": [\"id\"], \"host_groups\": [\"id\"], ...}}"
        ),
        read_only=True,
        params=[
            ParamDef(
                "params", "dict",
                "Export parameters. Required keys: 'format' ('yaml', 'xml', or 'json') and "
                "'options' (object specifying which entities to export by type and ID, e.g. "
                "{\"hosts\": [\"10084\"], \"templates\": [\"10001\"]}).",
                required=True,
            ),
        ],
    ),
    MethodDef(
        api_method="configuration.import",
        tool_name="configuration_import",
        description=(
            "Import configuration into Zabbix from YAML, XML, or JSON. Use this to restore backups "
            "or deploy configuration across instances. "
            "Params: {\"format\": \"yaml\"|\"xml\"|\"json\", \"source\": \"<config data>\", \"rules\": {...}}"
        ),
        read_only=False,
        params=[
            ParamDef(
                "params", "dict",
                "Import parameters. Required keys: 'format' ('yaml', 'xml', or 'json'), "
                "'source' (the serialized configuration data as a string), and 'rules' "
                "(object defining create/update behavior per entity type, e.g. "
                "{\"hosts\": {\"createMissing\": true, \"updateExisting\": true}}).",
                required=True,
            ),
        ],
    ),
    MethodDef(
        api_method="configuration.importcompare",
        tool_name="configuration_importcompare",
        description=(
            "Compare import data with existing Zabbix configuration without applying changes. "
            "Returns a diff showing what would be created, updated, or deleted. Useful for "
            "dry-run validation before an actual import."
        ),
        read_only=True,
        params=[
            ParamDef(
                "params", "dict",
                "Comparison parameters. Same structure as configuration.import: 'format', "
                "'source', and 'rules'.",
                required=True,
            ),
        ],
    ),
]

# ---------------------------------------------------------------------------
# Combined export
# ---------------------------------------------------------------------------
DATA_COLLECTION_METHODS: list[MethodDef] = (
    _HOST_METHODS
    + _HOSTGROUP_METHODS
    + _HOSTINTERFACE_METHODS
    + _ITEM_METHODS
    + _TRIGGER_METHODS
    + _GRAPH_METHODS
    + _GRAPHITEM_METHODS
    + _TEMPLATE_METHODS
    + _TEMPLATEGROUP_METHODS
    + _DISCOVERYRULE_METHODS
    + _ITEMPROTOTYPE_METHODS
    + _TRIGGERPROTOTYPE_METHODS
    + _GRAPHPROTOTYPE_METHODS
    + _HOSTPROTOTYPE_METHODS
    + _DISCOVERYRULEPROTOTYPE_METHODS
    + _USERMACRO_METHODS
    + _VALUEMAP_METHODS
    + _MAINTENANCE_METHODS
    + _CORRELATION_METHODS
    + _DRULE_METHODS
    + _DCHECK_METHODS
    + _DHOST_METHODS
    + _DSERVICE_METHODS
    + _HTTPTEST_METHODS
    + _CONFIGURATION_METHODS
)
