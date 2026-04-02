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

"""Zabbix API method definitions for the Monitoring category.

Covers dashboards, template dashboards, reports, HA nodes, history, trends,
events, problems, maps, tasks, and SLAs.
"""

from zabbix_mcp.api.types import MethodDef, ParamDef
from zabbix_mcp.api.common import (
    COMMON_GET_PARAMS,
    CREATE_PARAMS,
    DELETE_PARAMS,
    UPDATE_PARAMS,
)

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

_DASHBOARD_GET = MethodDef(
    api_method="dashboard.get",
    tool_name="dashboard_get",
    description=(
        "Retrieve dashboards with their widgets, pages, and user/group sharing "
        "settings. Dashboards are the primary visualization surface in Zabbix, "
        "containing pages with widgets that display graphs, maps, problems, "
        "and other monitoring data. Use the 'output' parameter to control which "
        "fields are returned and 'selectPages' / 'selectUsers' / 'selectUserGroups' "
        "in the filter to include related objects."
    ),
    read_only=True,
    params=COMMON_GET_PARAMS + [
        ParamDef(
            "dashboardids", "list[str]",
            "Return only dashboards with the given IDs.",
        ),
        ParamDef(
            "selectPages", "str",
            "Include dashboard pages and their widgets in the output. "
            "Set to 'extend' to return all page/widget fields.",
        ),
    ],
)

_DASHBOARD_CREATE = MethodDef(
    api_method="dashboard.create",
    tool_name="dashboard_create",
    description=(
        "Create a new dashboard. Requires at minimum a 'name' and at least one "
        "page with widgets. Widgets reference items, graphs, maps, or other "
        "Zabbix objects. Params example: {\"name\": \"My Dashboard\", \"pages\": "
        "[{\"widgets\": [{\"type\": \"problems\", \"x\": 0, \"y\": 0, \"width\": 12, "
        "\"height\": 5}]}]}."
    ),
    read_only=False,
    params=CREATE_PARAMS,
)

_DASHBOARD_UPDATE = MethodDef(
    api_method="dashboard.update",
    tool_name="dashboard_update",
    description=(
        "Update an existing dashboard. The params dict must include "
        "'dashboardid'. Any pages or widgets provided will fully replace "
        "the existing ones, so include all desired pages/widgets in the update."
    ),
    read_only=False,
    params=UPDATE_PARAMS,
)

_DASHBOARD_DELETE = MethodDef(
    api_method="dashboard.delete",
    tool_name="dashboard_delete",
    description=(
        "Delete one or more dashboards by their IDs. This permanently removes "
        "the dashboard and all its pages and widgets."
    ),
    read_only=False,
    params=DELETE_PARAMS,
)

# ---------------------------------------------------------------------------
# Template Dashboard
# ---------------------------------------------------------------------------

_TEMPLATEDASHBOARD_GET = MethodDef(
    api_method="templatedashboard.get",
    tool_name="templatedashboard_get",
    description=(
        "Retrieve dashboards that belong to templates. Template dashboards are "
        "defined on templates and automatically appear on hosts linked to those "
        "templates. This is useful for standardising monitoring views across "
        "many hosts. Filter by templateids to find dashboards belonging to "
        "specific templates, or by dashboardids for direct lookup."
    ),
    read_only=True,
    params=COMMON_GET_PARAMS + [
        ParamDef(
            "templateids", "list[str]",
            "Return only dashboards that belong to the given templates.",
        ),
        ParamDef(
            "dashboardids", "list[str]",
            "Return only template dashboards with the given IDs.",
        ),
    ],
)

_TEMPLATEDASHBOARD_CREATE = MethodDef(
    api_method="templatedashboard.create",
    tool_name="templatedashboard_create",
    description=(
        "Create a new template dashboard. Must specify 'templateid' to associate "
        "the dashboard with a template. The dashboard will be inherited by all "
        "hosts linked to that template."
    ),
    read_only=False,
    params=CREATE_PARAMS,
)

_TEMPLATEDASHBOARD_UPDATE = MethodDef(
    api_method="templatedashboard.update",
    tool_name="templatedashboard_update",
    description=(
        "Update a template dashboard. Params must include 'dashboardid'. Changes "
        "propagate to all hosts linked to the parent template."
    ),
    read_only=False,
    params=UPDATE_PARAMS,
)

_TEMPLATEDASHBOARD_DELETE = MethodDef(
    api_method="templatedashboard.delete",
    tool_name="templatedashboard_delete",
    description=(
        "Delete one or more template dashboards by their IDs. The dashboard "
        "will be removed from all hosts linked to the parent template."
    ),
    read_only=False,
    params=DELETE_PARAMS,
)

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

_REPORT_GET = MethodDef(
    api_method="report.get",
    tool_name="report_get",
    description=(
        "Retrieve scheduled reports. Reports are generated from dashboards on a "
        "schedule and delivered to users or user groups via email or other media. "
        "Filter by reportids for direct lookup or by dashboardids to find all "
        "reports generated from specific dashboards."
    ),
    read_only=True,
    params=COMMON_GET_PARAMS + [
        ParamDef(
            "reportids", "list[str]",
            "Return only reports with the given IDs.",
        ),
        ParamDef(
            "dashboardids", "list[str]",
            "Return only reports associated with the given dashboard IDs.",
        ),
    ],
)

_REPORT_CREATE = MethodDef(
    api_method="report.create",
    tool_name="report_create",
    description=(
        "Create a new scheduled report. Requires 'name', 'dashboardid', and a "
        "schedule definition. Reports render a dashboard to PDF and deliver it "
        "to the configured recipients."
    ),
    read_only=False,
    params=CREATE_PARAMS,
)

_REPORT_UPDATE = MethodDef(
    api_method="report.update",
    tool_name="report_update",
    description=(
        "Update a scheduled report. Params must include 'reportid'. Use this to "
        "change the schedule, recipients, or associated dashboard."
    ),
    read_only=False,
    params=UPDATE_PARAMS,
)

_REPORT_DELETE = MethodDef(
    api_method="report.delete",
    tool_name="report_delete",
    description=(
        "Delete one or more scheduled reports by their IDs."
    ),
    read_only=False,
    params=DELETE_PARAMS,
)

# ---------------------------------------------------------------------------
# HA Node
# ---------------------------------------------------------------------------

_HANODE_GET = MethodDef(
    api_method="hanode.get",
    tool_name="hanode_get",
    description=(
        "Retrieve Zabbix server High Availability (HA) cluster nodes. Returns "
        "information about each node's status, address, last access time, and "
        "role (active / standby / stopped / unavailable). Use this to monitor "
        "the health of a Zabbix HA cluster. This is a read-only method; HA "
        "nodes are managed by the Zabbix server process, not via the API."
    ),
    read_only=True,
    params=COMMON_GET_PARAMS + [
        ParamDef(
            "ha_nodeids", "list[str]",
            "Return only HA nodes with the given IDs.",
        ),
    ],
)

# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

_HISTORY_GET = MethodDef(
    api_method="history.get",
    tool_name="history_get",
    description=(
        "Retrieve historical item data (collected metric values). History stores "
        "every collected value and is the most granular data source in Zabbix. "
        "Always specify the 'history' parameter to select the correct data type "
        "(0=numeric float, 1=character/string, 2=log, 3=numeric unsigned, "
        "4=text). Use 'time_from' and 'time_till' (Unix timestamps) to bound "
        "the time range. Combine with 'itemids' or 'hostids' to target specific "
        "metrics. For long time ranges, consider using trend.get instead as it "
        "returns aggregated min/avg/max values and is more efficient."
    ),
    read_only=True,
    params=COMMON_GET_PARAMS + [
        ParamDef(
            "hostids", "list[str]",
            "Return only history for the given host IDs.",
        ),
        ParamDef(
            "itemids", "list[str]",
            "Return only history for the given item IDs.",
        ),
        ParamDef(
            "history", "int",
            "History data type to retrieve: 0=numeric float (default), "
            "1=character/string, 2=log, 3=numeric unsigned, 4=text. "
            "Must match the item's type of information.",
        ),
        ParamDef(
            "time_from", "int",
            "Return only data collected after this Unix timestamp (inclusive).",
        ),
        ParamDef(
            "time_till", "int",
            "Return only data collected before this Unix timestamp (inclusive).",
        ),
    ],
)

_HISTORY_CLEAR = MethodDef(
    api_method="history.clear",
    tool_name="history_clear",
    description=(
        "Clear (delete) history data for the specified items. This permanently "
        "removes all stored historical values for the given items. Use with "
        "caution as this operation cannot be undone. "
        "Note: not supported when TimescaleDB is used for history storage."
    ),
    read_only=False,
    params=[
        ParamDef(
            "itemids", "list[str]",
            "Array of item IDs whose history data should be cleared.",
            required=True,
        ),
    ],
    array_param="itemids",
)

_HISTORY_PUSH = MethodDef(
    api_method="history.push",
    tool_name="history_push",
    description=(
        "Push historical data directly into Zabbix. This allows external systems "
        "to inject metric values. Each entry must include 'itemid', 'clock' "
        "(Unix timestamp), 'ns' (nanoseconds), and 'value'. The item must exist "
        "and be of type 'Zabbix trapper' or 'Dependent item'."
    ),
    read_only=False,
    params=[
        ParamDef(
            "items", "list",
            "Array of history objects to push. Each object must have: "
            "'itemid' (str), 'clock' (int, Unix timestamp), 'ns' (int, nanoseconds), "
            "'value' (str). Example: [{\"itemid\": \"12345\", \"clock\": 1609459200, "
            "\"ns\": 0, \"value\": \"42.5\"}]",
            required=True,
        ),
    ],
    array_param="items",
)

# ---------------------------------------------------------------------------
# Trend
# ---------------------------------------------------------------------------

_TREND_GET = MethodDef(
    api_method="trend.get",
    tool_name="trend_get",
    description=(
        "Retrieve trend data (hourly aggregated min/avg/max values). Trends are "
        "calculated from history and provide a compact, long-term view of metric "
        "behaviour. Each record covers a one-hour period and includes the "
        "minimum, average, and maximum values as well as the number of values "
        "collected. Use trends instead of history for time ranges spanning days "
        "or more to reduce data volume. Filter by 'itemids' and use 'time_from' "
        "/ 'time_till' to bound the time range."
    ),
    read_only=True,
    params=COMMON_GET_PARAMS + [
        ParamDef(
            "itemids", "list[str]",
            "Return only trend data for the given item IDs.",
        ),
        ParamDef(
            "time_from", "int",
            "Return only trend data after this Unix timestamp (inclusive).",
        ),
        ParamDef(
            "time_till", "int",
            "Return only trend data before this Unix timestamp (inclusive).",
        ),
    ],
)

# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------

_EVENT_GET = MethodDef(
    api_method="event.get",
    tool_name="event_get",
    description=(
        "Retrieve events generated by triggers, discovery rules, or "
        "autoregistration. Events form the full audit trail of state changes. "
        "For active/current problems only, prefer problem.get instead. Use "
        "event.get when you need the complete event history including resolved "
        "events, or when you need to correlate PROBLEM and OK events. "
        "Filter by 'source' (0=trigger, 1=discovery, 2=autoregistration, "
        "3=internal) and 'object' to narrow results. Use 'time_from'/'time_till' "
        "for time-bounded queries and 'severity_min' to filter by importance."
    ),
    read_only=True,
    params=COMMON_GET_PARAMS + [
        ParamDef(
            "eventids", "list[str]",
            "Return only events with the given IDs.",
        ),
        ParamDef(
            "groupids", "list[str]",
            "Return only events for hosts belonging to the given host groups.",
        ),
        ParamDef(
            "hostids", "list[str]",
            "Return only events for the given hosts.",
        ),
        ParamDef(
            "objectids", "list[str]",
            "Return only events for the given trigger/item/LLD rule IDs "
            "(depends on the 'object' parameter).",
        ),
        ParamDef(
            "source", "int",
            "Event source: 0=trigger (default), 1=discovery, "
            "2=autoregistration, 3=internal.",
        ),
        ParamDef(
            "object", "int",
            "Event object type: 0=trigger, 1=discovered host, "
            "2=discovered service, 3=autoregistration event, 4=item, "
            "5=LLD rule.",
        ),
        ParamDef(
            "time_from", "int",
            "Return only events generated after this Unix timestamp (inclusive).",
        ),
        ParamDef(
            "time_till", "int",
            "Return only events generated before this Unix timestamp (inclusive).",
        ),
        ParamDef(
            "value", "int",
            "Event value filter: 0=OK (resolved), 1=PROBLEM (active).",
        ),
        ParamDef(
            "severity_min", "int",
            "Return only events with severity greater than or equal to this "
            "value: 0=not classified, 1=information, 2=warning, 3=average, "
            "4=high, 5=disaster.",
        ),
        ParamDef(
            "acknowledged", "bool",
            "If true, return only acknowledged events. If false, only "
            "unacknowledged events.",
        ),
    ],
)

_EVENT_ACKNOWLEDGE = MethodDef(
    api_method="event.acknowledge",
    tool_name="event_acknowledge",
    description=(
        "Acknowledge, close, suppress, or change the severity of events. This "
        "is the primary method for responding to alerts in Zabbix. The 'action' "
        "parameter is a bitmask controlling what happens: 1=close problem, "
        "2=acknowledge, 4=add message, 8=change severity, 16=unacknowledge, "
        "32=suppress, 64=unsuppress, 128=change event rank to cause/symptom. "
        "Combine values to perform multiple actions at once, e.g. action=6 "
        "means acknowledge + add message."
    ),
    read_only=False,
    params=[
        ParamDef(
            "eventids", "list[str]",
            "IDs of the events to update. At least one event ID is required.",
            required=True,
        ),
        ParamDef(
            "action", "int",
            "Acknowledge action bitmask: 1=close problem, 2=acknowledge, "
            "4=add message, 8=change severity, 16=unacknowledge, 32=suppress, "
            "64=unsuppress, 128=change event rank. Combine values for multiple "
            "actions (e.g. 6 = acknowledge + add message).",
            required=True,
        ),
        ParamDef(
            "message", "str",
            "Comment text to attach to the event. Used when action includes "
            "4 (add message).",
        ),
        ParamDef(
            "severity", "int",
            "New trigger severity: 0=not classified, 1=information, 2=warning, "
            "3=average, 4=high, 5=disaster. Used when action includes "
            "8 (change severity).",
        ),
    ],
)

# ---------------------------------------------------------------------------
# Problem
# ---------------------------------------------------------------------------

_PROBLEM_GET = MethodDef(
    api_method="problem.get",
    tool_name="problem_get",
    description=(
        "Retrieve current/active problems (unresolved alerts). This is the "
        "PRIMARY tool for checking what is wrong right now -- it returns only "
        "problems that have not yet been resolved. Use this first when asked "
        "about active alerts, current issues, or ongoing incidents. "
        "For historical events (including resolved), use event.get instead. "
        "Filter by 'hostids' or 'groupids' to scope to specific hosts or "
        "groups, by 'severity_min' to focus on important issues, and by "
        "'acknowledged' or 'suppressed' to filter by operational state. "
        "The 'recent' flag limits results to problems created in the last "
        "30 minutes."
    ),
    read_only=True,
    params=COMMON_GET_PARAMS + [
        ParamDef(
            "eventids", "list[str]",
            "Return only problems with the given event IDs.",
        ),
        ParamDef(
            "groupids", "list[str]",
            "Return only problems for hosts in the given host groups.",
        ),
        ParamDef(
            "hostids", "list[str]",
            "Return only problems for the given hosts.",
        ),
        ParamDef(
            "objectids", "list[str]",
            "Return only problems for the given trigger/item/LLD rule IDs.",
        ),
        ParamDef(
            "source", "int",
            "Problem source: 0=trigger (default), 1=discovery, "
            "2=autoregistration, 3=internal.",
        ),
        ParamDef(
            "object", "int",
            "Problem object type: 0=trigger, 1=discovered host, "
            "2=discovered service, 3=autoregistration, 4=item, 5=LLD rule.",
        ),
        ParamDef(
            "time_from", "int",
            "Return only problems created after this Unix timestamp.",
        ),
        ParamDef(
            "time_till", "int",
            "Return only problems created before this Unix timestamp.",
        ),
        ParamDef(
            "acknowledged", "bool",
            "Filter by acknowledgement state: true=acknowledged only, "
            "false=unacknowledged only.",
        ),
        ParamDef(
            "severity_min", "int",
            "Minimum severity to return: 0=not classified, 1=information, "
            "2=warning, 3=average, 4=high, 5=disaster.",
        ),
        ParamDef(
            "suppressed", "bool",
            "Filter by suppression state. Suppressed problems are silenced "
            "during maintenance windows or by manual suppression.",
        ),
        ParamDef(
            "recent", "bool",
            "Return only recently created problems (within the last 30 "
            "minutes). Useful for detecting new issues quickly.",
        ),
        ParamDef(
            "evaltype", "int",
            "Tag filter evaluation mode: 0=AND/OR (default, all tag "
            "conditions must match), 2=OR (any tag condition may match).",
        ),
    ],
)

# ---------------------------------------------------------------------------
# Map (sysmap)
# ---------------------------------------------------------------------------

_MAP_GET = MethodDef(
    api_method="map.get",
    tool_name="map_get",
    description=(
        "Retrieve network maps (sysmaps). Maps provide a visual topology view "
        "of your infrastructure, showing hosts, host groups, triggers, and the "
        "connections between them. Maps can contain elements (hosts, groups, "
        "images, triggers) and links (connections with status indicators). "
        "Use 'selectElements' and 'selectLinks' in the filter to include "
        "map structure details."
    ),
    read_only=True,
    params=COMMON_GET_PARAMS + [
        ParamDef(
            "sysmapids", "list[str]",
            "Return only maps with the given IDs.",
        ),
    ],
)

_MAP_CREATE = MethodDef(
    api_method="map.create",
    tool_name="map_create",
    description=(
        "Create a new network map. Requires at minimum 'name', 'width', and "
        "'height'. Add elements (hosts, host groups, images) and links "
        "(connections between elements) to build the map topology."
    ),
    read_only=False,
    params=CREATE_PARAMS,
)

_MAP_UPDATE = MethodDef(
    api_method="map.update",
    tool_name="map_update",
    description=(
        "Update an existing network map. Params must include 'sysmapid'. "
        "Any elements or links provided will fully replace the existing ones."
    ),
    read_only=False,
    params=UPDATE_PARAMS,
)

_MAP_DELETE = MethodDef(
    api_method="map.delete",
    tool_name="map_delete",
    description=(
        "Delete one or more network maps by their IDs."
    ),
    read_only=False,
    params=DELETE_PARAMS,
)

# ---------------------------------------------------------------------------
# Task
# ---------------------------------------------------------------------------

_TASK_GET = MethodDef(
    api_method="task.get",
    tool_name="task_get",
    description=(
        "Retrieve tasks. Tasks are internal Zabbix work items such as "
        "diagnostic data collection requests or item value checks. Use this "
        "to monitor the status of previously created tasks."
    ),
    read_only=True,
    params=COMMON_GET_PARAMS + [
        ParamDef(
            "taskids", "list[str]",
            "Return only tasks with the given IDs.",
        ),
    ],
)

_TASK_CREATE = MethodDef(
    api_method="task.create",
    tool_name="task_create",
    description=(
        "Create a new task. Supported task types include requesting a check "
        "now for an item or requesting diagnostic information. "
        "Example for 'check now': {\"type\": 6, \"request\": {\"itemid\": \"12345\"}}. "
        "The task is picked up asynchronously by the Zabbix server or proxy."
    ),
    read_only=False,
    params=[
        ParamDef(
            "params", "dict",
            "Task definition as a JSON dictionary. Must include 'type' and a "
            "'request' object appropriate for the task type.",
            required=True,
        ),
    ],
)

# ---------------------------------------------------------------------------
# SLA (Service Level Agreement) — Zabbix 6.0+
# ---------------------------------------------------------------------------

_SLA_GET = MethodDef(
    api_method="sla.get",
    tool_name="sla_get",
    description=(
        "Retrieve SLA definitions. SLAs measure service availability against "
        "defined targets (e.g. 99.9% uptime). Each SLA has a schedule, SLO "
        "(Service Level Objective) percentage, and is linked to services via "
        "service tags. Use selectServiceTags, selectExcludedDowntimes, and "
        "selectSchedule in extra_params to include related objects."
    ),
    read_only=True,
    params=COMMON_GET_PARAMS + [
        ParamDef(
            "slaids", "list[str]",
            "Return only SLAs with the given IDs.",
        ),
        ParamDef(
            "serviceids", "list[str]",
            "Return only SLAs linked to the given services.",
        ),
    ],
)

_SLA_CREATE = MethodDef(
    api_method="sla.create",
    tool_name="sla_create",
    description=(
        "Create a new SLA. Required fields: 'name', 'slo' (target percentage, "
        "e.g. 99.9), 'period' (reporting period: 0=daily, 1=weekly, 2=monthly, "
        "3=quarterly, 4=annually), 'timezone', and 'service_tags' (array of "
        "tag objects that link this SLA to services). Optionally define "
        "'schedule' and 'excluded_downtimes'."
    ),
    read_only=False,
    params=[
        ParamDef(
            "params", "dict",
            "SLA definition as a JSON dictionary. Required: name, slo, period, "
            "timezone, service_tags.",
            required=True,
        ),
    ],
)

_SLA_UPDATE = MethodDef(
    api_method="sla.update",
    tool_name="sla_update",
    description="Update an existing SLA. The 'slaid' field is required.",
    read_only=False,
    params=UPDATE_PARAMS,
)

_SLA_DELETE = MethodDef(
    api_method="sla.delete",
    tool_name="sla_delete",
    description="Delete SLAs by their IDs.",
    read_only=False,
    params=DELETE_PARAMS,
)

_SLA_GETSLI = MethodDef(
    api_method="sla.getsli",
    tool_name="sla_getsli",
    description=(
        "Get SLA Service Level Indicator (SLI) data — the actual calculated "
        "availability percentages for services covered by an SLA. Returns "
        "period-by-period SLI values showing whether the SLO target was met. "
        "Required: 'slaid'. Optionally filter by 'serviceids' and time range "
        "with 'period_from'/'period_to'."
    ),
    read_only=True,
    params=[
        ParamDef(
            "slaid", "str",
            "ID of the SLA to retrieve SLI data for.",
            required=True,
        ),
        ParamDef(
            "serviceids", "list[str]",
            "Return SLI data only for these service IDs.",
        ),
        ParamDef(
            "period_from", "int",
            "Return SLI data starting from this Unix timestamp.",
        ),
        ParamDef(
            "period_to", "int",
            "Return SLI data up to this Unix timestamp.",
        ),
    ],
)

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

MONITORING_METHODS: list[MethodDef] = [
    # Dashboard
    _DASHBOARD_GET,
    _DASHBOARD_CREATE,
    _DASHBOARD_UPDATE,
    _DASHBOARD_DELETE,
    # Template Dashboard
    _TEMPLATEDASHBOARD_GET,
    _TEMPLATEDASHBOARD_CREATE,
    _TEMPLATEDASHBOARD_UPDATE,
    _TEMPLATEDASHBOARD_DELETE,
    # Report
    _REPORT_GET,
    _REPORT_CREATE,
    _REPORT_UPDATE,
    _REPORT_DELETE,
    # HA Node
    _HANODE_GET,
    # History
    _HISTORY_GET,
    _HISTORY_CLEAR,
    _HISTORY_PUSH,
    # Trend
    _TREND_GET,
    # Event
    _EVENT_GET,
    _EVENT_ACKNOWLEDGE,
    # Problem
    _PROBLEM_GET,
    # Map
    _MAP_GET,
    _MAP_CREATE,
    _MAP_UPDATE,
    _MAP_DELETE,
    # Task
    _TASK_GET,
    _TASK_CREATE,
    # SLA
    _SLA_GET,
    _SLA_CREATE,
    _SLA_UPDATE,
    _SLA_DELETE,
    _SLA_GETSLI,
]
