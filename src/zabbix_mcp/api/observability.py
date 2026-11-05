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


"""Observability and instance objects: Zabbix 8.0 APM data (traces, spans,
logs, metric data points), paired mobile devices, server info, and the
version probe ``apiinfo.version`` that every release has.

The APM methods are read-only queries over OpenTelemetry data the server
ingested; ``time_from`` / ``time_till`` are required and take the same
inputs as every other timestamp parameter (epoch, ISO 8601, ``now-1h``).
"""

from zabbix_mcp.api.common import COMMON_GET_PARAMS, DELETE_PARAMS, UPDATE_PARAMS
from zabbix_mcp.api.types import MethodDef, ParamDef

_OUTPUT = ParamDef(
    "output", "str",
    "Fields to return: 'extend' for every field, 'count' for the count only, "
    "or comma-separated field names.",
)
_LIMIT = ParamDef("limit", "int", "Maximum number of records to return.")
_OFFSET = ParamDef("offset", "int", "Number of records to skip before returning the result (paging).")
_SORTFIELD = ParamDef("sortfield", "str", "Field name(s) to sort by, comma-separated for several.")
_SORTORDER = ParamDef("sortorder", "str", "Sort order: 'ASC' or 'DESC'.")
_FILTER = ParamDef("filter", "dict", "Return only records whose fields exactly match the given values.")
_SEARCH = ParamDef("search", "dict", "Return only records whose string fields match the given pattern (case-insensitive).")
_EXTRA = next(p for p in COMMON_GET_PARAMS if p.name == "extra_params")

_ATTR_DESC = (
    "Attribute conditions as a list of {\"key\": ..., \"value\": ..., \"operator\": ...} objects; "
    "operators: 0 Contains, 1 Equals, 2 Not like, 3 Not equal, 4 Exists, 5 Does not exist. "
    "An empty list returns everything."
)
_EVALTYPE_DESC = "How the conditions in {} combine: 0 = And/Or (default), 2 = Or."


# Every apm*.get of 8.0.0 does this for a caller who is not Super admin
# (CApiUserGroupHelper::getApmFilterResourceAttributes).
_APM_VISIBILITY = (
    " For a user who is not Super admin the result is limited to the data whose resource "
    "attributes match an APM filter of one of the user's groups (usergroup 'apm_filters')."
)


def _time_range(what: str) -> list[ParamDef]:
    return [
        ParamDef(
            "time_from", "timestamp",
            f"Return only {what} at or after this time (required). Unix timestamp, ISO 8601 "
            "date-time or a relative time such as now-1h or now-1d/d.",
            required=True,
        ),
        ParamDef(
            "time_till", "timestamp",
            f"Return only {what} before this time (required). Unix timestamp, ISO 8601 "
            "date-time or a relative time such as now or now/d.",
            required=True,
        ),
    ]


def _attrs(*names: str) -> list[ParamDef]:
    out: list[ParamDef] = []
    for name in names:
        out.append(ParamDef(name, "list", f"{name.replace('_', ' ').capitalize()}: {_ATTR_DESC}"))
        out.append(ParamDef(f"{name}_evaltype", "int", _EVALTYPE_DESC.format(name)))
    return out


# ---------------------------------------------------------------------------
# APM (Zabbix 8.0+)
# ---------------------------------------------------------------------------

_APMTRACE_GET = MethodDef(
    api_method="apmtrace.get",
    tool_name="apmtrace_get",
    description=(
        "Retrieve OpenTelemetry (OTel) APM traces (Zabbix 8.0+): one record per trace, with the "
        "service_name and span_name of its root span, duration in nanoseconds (from the start of "
        "its first span to the end of its last), status_code, span_count, error_count, "
        "has_root_span, resource and span attributes. time_from and time_till are required and "
        "bound the start of the trace: of its root span or, for a trace whose root span is not "
        "stored (has_root_span 0), of its earliest span. Filter by traceids, resource_attributes "
        "/ span_attributes conditions, or min_duration / max_duration. Page with limit and offset. "
        "Use apmspan_get for the spans of a trace and apmlog_get for its log records." + _APM_VISIBILITY
    ),
    read_only=True,
    compact_fields=("timestamp", "traceid", "service_name", "span_name", "duration", "status_code", "span_count"),
    params=_time_range("traces that started") + [
        ParamDef("traceids", "list[str]", "Return only traces with the given IDs."),
        *_attrs("resource_attributes", "span_attributes"),
        ParamDef("min_duration", "int", "Return only traces whose root span (the whole trace, where it has no root span) lasted at least this many nanoseconds."),
        ParamDef("max_duration", "int", "Return only traces whose root span (the whole trace, where it has no root span) lasted less than this many nanoseconds."),
        _OUTPUT, _FILTER, _SEARCH, _SORTFIELD, _SORTORDER, _LIMIT, _OFFSET, _EXTRA,
    ],
)

_APMSPAN_GET = MethodDef(
    api_method="apmspan.get",
    tool_name="apmspan_get",
    description=(
        "Retrieve OpenTelemetry (OTel) APM spans (Zabbix 8.0+): the individual operations inside traces, with "
        "parent_spanid, span_kind, duration in nanoseconds, status, events and links. "
        "time_from and time_till are required and bound the span start. Filter by traceids "
        "(all spans of a trace), spanids, parent_spanids, attribute conditions or duration. "
        "Page with limit and offset." + _APM_VISIBILITY
    ),
    read_only=True,
    compact_fields=("timestamp", "traceid", "spanid", "parent_spanid", "service_name", "span_name", "duration", "status_code"),
    params=_time_range("spans that started") + [
        ParamDef("traceids", "list[str]", "Return only spans that belong to the given traces."),
        ParamDef("spanids", "list[str]", "Return only spans with the given IDs."),
        ParamDef("parent_spanids", "list[str]", "Return only spans whose parent span has one of the given IDs."),
        *_attrs("resource_attributes", "span_attributes"),
        ParamDef("min_duration", "int", "Return only spans that lasted at least this many nanoseconds."),
        ParamDef("max_duration", "int", "Return only spans that lasted less than this many nanoseconds."),
        _OUTPUT, _FILTER, _SEARCH, _SORTFIELD, _SORTORDER, _LIMIT, _OFFSET, _EXTRA,
    ],
)

_APMLOG_GET = MethodDef(
    api_method="apmlog.get",
    tool_name="apmlog_get",
    description=(
        "Retrieve OpenTelemetry (OTel) APM log records (Zabbix 8.0+): logs with severity_text, "
        "severity_number, body, service_name, and the trace / span they were produced in. "
        "time_from and time_till are required. Filter by traceids, spanids, trace flags "
        "(with_flags_on / with_flags_off, sum of flag values), severity_numbers (0 to 24, through "
        "extra_params) or resource / scope / log attribute conditions. Page with limit and offset."
        + _APM_VISIBILITY
    ),
    read_only=True,
    compact_fields=("timestamp", "traceid", "spanid", "service_name", "severity_text", "body"),
    params=_time_range("log records of events that occurred") + [
        ParamDef("traceids", "list[str]", "Return only log records produced during the given traces."),
        ParamDef("spanids", "list[str]", "Return only log records produced during the given spans."),
        ParamDef("with_flags_on", "int", "Return only records that have all of these trace flags set (sum of flag values)."),
        ParamDef("with_flags_off", "int", "Return only records that have none of these trace flags set (sum of flag values)."),
        *_attrs("resource_attributes", "scope_attributes", "log_attributes"),
        _OUTPUT, _FILTER, _SEARCH, _SORTFIELD, _SORTORDER, _LIMIT, _OFFSET, _EXTRA,
    ],
)

_APMMETRIC_GET = MethodDef(
    api_method="apmmetric.get",
    tool_name="apmmetric_get",
    description=(
        "Retrieve OpenTelemetry (OTel) APM metric data points (Zabbix 8.0+): metrics by type "
        "(0 gauge, 1 sum, 2 histogram, 3 exponential histogram) with metric_name, unit, "
        "service_name, value fields and attributes. time_from and time_till are required. "
        "Filter by types, flags (with_flags_on / with_flags_off) or resource / scope / "
        "data point attribute conditions. Page with limit and offset. For Zabbix item "
        "history use history_get instead." + _APM_VISIBILITY
    ),
    read_only=True,
    compact_fields=("time_unix", "type", "service_name", "metric_name", "metric_unit", "value"),
    params=_time_range("data points whose time is") + [
        ParamDef("types", "list[str]", "Return only data points of the given metric types: 0 gauge, 1 sum, 2 histogram, 3 exponential histogram."),
        ParamDef("with_flags_on", "int", "Return only data points that have all of these flags set (sum of flag values)."),
        ParamDef("with_flags_off", "int", "Return only data points that have none of these flags set (sum of flag values)."),
        *_attrs("resource_attributes", "scope_attributes", "attributes"),
        _OUTPUT, _FILTER, _SEARCH, _SORTFIELD, _SORTORDER, _LIMIT, _OFFSET, _EXTRA,
    ],
)

# ---------------------------------------------------------------------------
# Devices (Zabbix 8.0+): mobile app installations paired with users
# ---------------------------------------------------------------------------

_DEVICE_GET = MethodDef(
    api_method="device.get",
    tool_name="device_get",
    description=(
        "Retrieve paired mobile devices (Zabbix 8.0+): the Zabbix mobile app installations "
        "that users onboarded, with the owning userid, device name, status, activated_at and "
        "lastaccess. Filter by deviceids, userids, roleids or usrgrpids. Use device_offboard "
        "to revoke a device."
    ),
    read_only=True,
    compact_fields=("deviceid", "userid", "name", "status", "lastaccess"),
    params=[
        ParamDef("deviceids", "list[str]", "Return only devices with the given IDs."),
        ParamDef("userids", "list[str]", "Return only devices belonging to the given users."),
        ParamDef("roleids", "list[str]", "Return only devices belonging to users with the given roles."),
        ParamDef("usrgrpids", "list[str]", "Return only devices belonging to users in the given user groups."),
        ParamDef("output", "str", "Device properties to return: 'extend' for all, or property names."),
        _FILTER, _SEARCH, _SORTFIELD, _SORTORDER, _LIMIT,
        ParamDef("countOutput", "bool", "Return the count of matching devices instead of the records."),
        _EXTRA,
    ],
)

_DEVICE_OFFBOARD = MethodDef(
    api_method="device.offboard",
    tool_name="device_offboard",
    description=(
        "Offboard (revoke) a paired mobile device by its uuid (Zabbix 8.0+): the app on that "
        "device loses access and must be onboarded again. Pass force=true to remove the "
        "device record even when the device cannot be notified. Get the uuid from device_get."
    ),
    read_only=False,
    params=[
        ParamDef("uuid", "str", "The uuid of the device to offboard (from device_get).", required=True),
        ParamDef("force", "bool", "Remove the device even if it cannot be reached (default false)."),
    ],
)

# ---------------------------------------------------------------------------
# Server info (Zabbix 8.0+) and the version probe (every release)
# ---------------------------------------------------------------------------

_SERVERINFO_GET = MethodDef(
    api_method="serverinfo.get",
    tool_name="serverinfo_get",
    description=(
        "Retrieve information about a Zabbix server instance (Zabbix 8.0+): its serverid and "
        "lastaccess, the time of its last update to the database (for an HA cluster the "
        "active node's). serverid is required: the server's UUIDv7, returned as 'serverid' "
        "by settings_get (8.0+) and shown in the frontend under Reports / System information. "
        "For the API version use apiinfo_version, for HA nodes hanode_get, for queue and "
        "status health_check."
    ),
    read_only=True,
    params=[
        ParamDef("serverid", "str", "ID (UUID) of the Zabbix server to describe.", required=True),
        _OUTPUT,
        _EXTRA,
    ],
)

_APIINFO_VERSION = MethodDef(
    api_method="apiinfo.version",
    tool_name="apiinfo_version",
    description=(
        "Return the version of the Zabbix API, which is the version of the Zabbix frontend "
        "(e.g. '7.4.14'). Takes no parameters. Use it to pick version-specific tools and "
        "parameters; health_check reports the same version for every configured server at once."
    ),
    read_only=True,
    params=[],
)

# ---------------------------------------------------------------------------
# CEP rules (Zabbix 8.0+, complex event processing). Built for v1.41 from
# the frontend's CCepRule.php while 8.0 was a release candidate without a
# reference page; documented since 8.0.0 and checked against that page.
# ---------------------------------------------------------------------------

_CEP_CONDITIONS = (
    "Filter conditions: type 3 event name (event_name), 4 severity (severity), 6 time period "
    "(time_period), 25 tag (tag), 26 tag value (tag + tag_value), 36 host visible name (host_name), "
    "37 host group name (host_group_name); operator 0 equals, 1 does not equal, 2 contains, "
    "3 does not contain, 5 >=, 6 <=, 4 in, 7 not in (time period). evaltype 0 And/Or, 1 And, 2 Or, "
    "3 custom expression (formula + formulaid per condition)."
)
_CEP_OPERATION_CONDITIONS = (
    "An operation's own 'filter' and "
    "'scope_filter' use other condition types: 25 tag name, 26 tag value, and the event flags "
    "30 problem opened, 31 first, 32 last, 33 symptom, 34 cloned, 35 suppressed (operator 10 true, "
    "11 false); an operation with execute_when 0 takes neither 31 nor 32."
)

# CCepRule::validateOperations() and validateWindow() of the 8.0.0 frontend.
# In the description of 'params' for ceprule_create: a client may cut a tool
# description at 2 KB, and tools/list adds a note for a server below 8.0.
_CEP_GOES_TOGETHER = (
    "What goes together in 'operations': execute_when 0 takes types 1-8 and 11-17, 1 takes 1, 2, 4-8 "
    "and 11-18, 2 takes 1, 2 and 4-18, 3 takes 1, 2 and 4-17, 4 takes all, 5 takes 1 and 4-18; "
    "execute_when 0 takes scope 0 only, 3 and 4 take scope 2 only, 1, 2 and 5 take any scope; ordered "
    "by 'sortorder', the operations must be grouped by execute_when in the order 0, 1, 2, 5, 3, 4. "
    "A rule without a window (window_type 0) takes execute_when 0 only, window types 1 to 3 take "
    "0, 1, 2, 3 and 5, a pattern match (4) takes all six and needs at least one operation with "
    "execute_when 4."
)

_CEPRULE_GET = MethodDef(
    api_method="ceprule.get",
    tool_name="ceprule_get",
    description=(
        "Retrieve CEP rules (Zabbix 8.0+ complex event processing): the rules that match incoming "
        "problem events by name, tags, severity, host, host group or time period, collect them in a "
        "time or count window (window_type 0 none, 1 simple window, 2 cause / symptom, 3 simple window "
        "once, 4 pattern match) and run operations on them (close, discard, set or change severity, "
        "suppress, add / set / rename / remove tags, copy as a new event, close the window). Use "
        "selectFilter, selectWindow and selectOperations in extra_params for the full rule; 'error' "
        "carries the server's last processing error. Zabbix 8.0 deprecates event correlation (correlation_*) in favour of these rules."
    ),
    read_only=True,
    compact_fields=("cep_ruleid", "name", "status", "window_type", "stop", "sortorder"),
    params=[
        ParamDef("cep_ruleids", "list[str]", "Return only CEP rules with the given IDs."),
        _OUTPUT, _FILTER, _SEARCH, _SORTFIELD, _SORTORDER, _LIMIT,
        ParamDef("countOutput", "bool", "Return the count of matching rules instead of the records."),
        _EXTRA,
    ],
)

_CEPRULE_CREATE = MethodDef(
    api_method="ceprule.create",
    tool_name="ceprule_create",
    description=(
        "Create a CEP rule (Zabbix 8.0+). Required: 'name', 'sortorder' (evaluation order, 0 and up), "
        "'filter' ({'evaltype', 'conditions': [...]}) and 'operations' (each with 'sortorder', 'type' "
        "1 set name, 2 close event, 3 discard, 4 set severity, 5 increase severity, 6 decrease severity, "
        "7 suppress (suppress_duration), 8 unsuppress, 9 copy first event as new, 10 copy last event "
        "as new, 11 add tag, 12 set tag, 13 set tag value, 14 increase tag value, 15 decrease tag value, "
        "16 rename tag (tag + new_tag), 17 remove tag, 18 close window; 'execute_when' 0 event occurred, "
        "1 event added to window, 2 event evicted, 3 window closed, 4 pattern matched, 5 event closed; "
        "'scope' 0 current event, 1 other events, 2 all events of the window, with an optional "
        "'scope_filter' for scope 1 and 2 and an optional 'filter'). Optional: 'window_type' (0 none, "
        "1 simple window, 2 cause / symptom, 3 simple window once, 4 pattern match) with 'window' ({'duration', 'capacity', 'group_by_host_group', "
        "'group_by_host', 'group_by_tags', 'tags' (tag names), 'event_count_tag' (window type 2 only), "
        "'script' (window type 4 only)}), 'stop' (1 = stop processing further rules), 'description', "
        "'status' (0 enabled, 1 disabled). The conditions a filter takes, which operation type, scope "
        "and window go with which execute_when, and the conditions of an operation's own filters are "
        "in the description of 'params'."
    ),
    read_only=False,
    params=[
        ParamDef(
            "params", "dict",
            "CEP rule definition as a JSON dictionary. Required: name, sortorder, filter, operations. "
            + _CEP_CONDITIONS + " " + _CEP_GOES_TOGETHER + " " + _CEP_OPERATION_CONDITIONS,
            required=True,
        ),
    ],
)

_CEPRULE_UPDATE = MethodDef(
    api_method="ceprule.update",
    tool_name="ceprule_update",
    description=(
        "Update a CEP rule (Zabbix 8.0+). The 'cep_ruleid' field is required; 'filter', 'window' and "
        "'operations' replace the whole structure when given. " + _CEP_CONDITIONS + " " + _CEP_OPERATION_CONDITIONS
    ),
    read_only=False,
    params=UPDATE_PARAMS,
)

_CEPRULE_DELETE = MethodDef(
    api_method="ceprule.delete",
    tool_name="ceprule_delete",
    description="Delete CEP rules by their IDs (Zabbix 8.0+).",
    read_only=False,
    params=DELETE_PARAMS,
)

_CEPRULE_RESETTIMEWINDOWS = MethodDef(
    api_method="ceprule.resettimewindows",
    tool_name="ceprule_resettimewindows",
    description=(
        "Reset the open time windows of a CEP rule on the Zabbix server (Zabbix 8.0+): the events "
        "collected so far are dropped and the windows start again. Takes the rule's cep_ruleid."
    ),
    read_only=False,
    params=[
        ParamDef("cep_ruleid", "str", "ID of the CEP rule whose windows to reset.", required=True),
    ],
)

# ---------------------------------------------------------------------------
# Host dashboards (Zabbix 7.0+): the template dashboards a host inherits,
# as the frontend shows them under Monitoring > Hosts > Dashboards. Not on
# the reference pages; shape from the frontend's CHostDashboard.php.
# ---------------------------------------------------------------------------

_HOSTDASHBOARD_GET = MethodDef(
    api_method="hostdashboard.get",
    tool_name="hostdashboard_get",
    description=(
        "Retrieve the dashboards a host has through its linked templates (Zabbix 7.0+): one record per "
        "host and template dashboard with hostid, dashboardid, name, display_period, auto_start and the "
        "templateid it comes from. 'hostids' is required. Use selectPages in extra_params for the pages "
        "and widgets as resolved for that host. For the template dashboards themselves use "
        "templatedashboard_get, for global dashboards dashboard_get. Not documented in the API reference."
    ),
    read_only=True,
    compact_fields=("hostid", "dashboardid", "name", "templateid"),
    params=[
        ParamDef("hostids", "list[str]", "Return the dashboards of these hosts (required).", required=True),
        ParamDef("dashboardids", "list[str]", "Return only the given template dashboards."),
        ParamDef("output", "str", "'extend' or comma-separated field names (hostid, dashboardid, name, display_period, auto_start, templateid); use countOutput for a count."),
        _FILTER, _SEARCH, _SORTFIELD, _SORTORDER, _LIMIT,
        ParamDef("countOutput", "bool", "Return the count instead of the records."),
        _EXTRA,
    ],
)

OBSERVABILITY_METHODS: list[MethodDef] = [
    _CEPRULE_GET,
    _CEPRULE_CREATE,
    _CEPRULE_UPDATE,
    _CEPRULE_DELETE,
    _CEPRULE_RESETTIMEWINDOWS,
    _HOSTDASHBOARD_GET,
    _APMTRACE_GET,
    _APMSPAN_GET,
    _APMLOG_GET,
    _APMMETRIC_GET,
    _DEVICE_GET,
    _DEVICE_OFFBOARD,
    _SERVERINFO_GET,
    _APIINFO_VERSION,
]
