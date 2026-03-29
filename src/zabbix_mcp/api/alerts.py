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

"""Zabbix API definitions for alerts, actions, media types, and scripts.

This module covers the "Alerts & Actions" domain of the Zabbix API:
- **action**: Automated responses to events (trigger actions, discovery actions,
  autoregistration actions, internal actions, service actions). Actions define
  conditions and operations such as sending notifications or executing scripts.
- **alert**: Read-only log of notifications and remote commands that Zabbix has
  generated as a result of actions. Useful for auditing and troubleshooting
  notification delivery.
- **mediatype**: Notification delivery channels (Email, SMS, Slack, webhook,
  custom scripts, etc.). Media types must be configured before actions can send
  notifications.
- **script**: Global scripts that can be executed on hosts from the frontend,
  API, or as action operations. Includes IPMI, SSH, Telnet, and custom scripts.
"""

from zabbix_mcp.api.types import MethodDef, ParamDef
from zabbix_mcp.api.common import COMMON_GET_PARAMS, CREATE_PARAMS, UPDATE_PARAMS, DELETE_PARAMS

# ---------------------------------------------------------------------------
# action
# ---------------------------------------------------------------------------

_ACTION_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "actionids", "list[str]",
        "Return only actions with the given IDs.",
    ),
    ParamDef(
        "groupids", "list[str]",
        "Return only actions that reference these host group IDs in their conditions.",
    ),
    ParamDef(
        "hostids", "list[str]",
        "Return only actions that reference these host IDs in their conditions.",
    ),
    ParamDef(
        "triggerids", "list[str]",
        "Return only actions that reference these trigger IDs in their conditions.",
    ),
    ParamDef(
        "eventsource", "int",
        "Return only actions with the given event source. "
        "Values: 0 = trigger events, 1 = discovery events, "
        "2 = autoregistration events, 3 = internal events, 4 = service events.",
    ),
]

_ACTION_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="action.get",
        tool_name="action_get",
        description=(
            "Retrieve actions that define automated responses to Zabbix events. "
            "Actions tie conditions (e.g. trigger severity, host group membership) "
            "to operations (e.g. send message, execute script, close problem). "
            "Filter by event source to narrow results: 0=trigger, 1=discovery, "
            "2=autoregistration, 3=internal, 4=service. Use selectOperations, "
            "selectRecoveryOperations, selectUpdateOperations in the output to "
            "include the full operation definitions."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _ACTION_GET_EXTRA,
    ),
    MethodDef(
        api_method="action.create",
        tool_name="action_create",
        description=(
            "Create a new action. Required fields: name, eventsource, and at least "
            "one operation. The params dict should include 'filter' (conditions), "
            "'operations' (what to do when the event occurs), and optionally "
            "'recovery_operations' and 'update_operations'. Set 'status' to 0 "
            "(enabled) or 1 (disabled). "
            "Symbolic names accepted for 'eventsource': TRIGGER, DISCOVERY, "
            "AUTOREGISTRATION, INTERNAL, SERVICE."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="action.update",
        tool_name="action_update",
        description=(
            "Update an existing action. The params dict must include 'actionid'. "
            "Any properties not specified will remain unchanged. Commonly used to "
            "enable/disable actions (set status to 0 or 1), modify conditions, "
            "or change notification recipients."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="action.delete",
        tool_name="action_delete",
        description=(
            "Delete one or more actions by their IDs. This permanently removes the "
            "action definitions and stops any future automated responses they would "
            "have triggered. Already-generated alerts are not affected."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# alert
# ---------------------------------------------------------------------------

_ALERT_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "alertids", "list[str]",
        "Return only alerts with the given IDs.",
    ),
    ParamDef(
        "actionids", "list[str]",
        "Return only alerts generated by the given action IDs.",
    ),
    ParamDef(
        "groupids", "list[str]",
        "Return only alerts for hosts belonging to these host group IDs.",
    ),
    ParamDef(
        "hostids", "list[str]",
        "Return only alerts for the given host IDs.",
    ),
    ParamDef(
        "time_from", "int",
        "Return only alerts generated after this Unix timestamp (inclusive). "
        "Useful for auditing recent notification delivery.",
    ),
    ParamDef(
        "time_till", "int",
        "Return only alerts generated before this Unix timestamp (inclusive).",
    ),
]

_ALERT_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="alert.get",
        tool_name="alert_get",
        description=(
            "Retrieve the alert log -- a read-only record of every notification "
            "and remote command Zabbix has executed as a result of actions. Each "
            "alert entry contains delivery status, retry count, error text (if "
            "failed), and the message body. Use time_from/time_till to scope by "
            "time window. Great for diagnosing 'why didn't I get notified?' issues."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _ALERT_GET_EXTRA,
    ),
]

# ---------------------------------------------------------------------------
# mediatype
# ---------------------------------------------------------------------------

_MEDIATYPE_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "mediatypeids", "list[str]",
        "Return only media types with the given IDs.",
    ),
]

_MEDIATYPE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="mediatype.get",
        tool_name="mediatype_get",
        description=(
            "Retrieve notification media types configured in Zabbix. Media types "
            "define how notifications are delivered: Email, SMS, webhook (Slack, "
            "PagerDuty, Teams, etc.), or custom scripts. Each media type has its "
            "own set of parameters such as SMTP settings, webhook URL, or script "
            "path. Use this to list available notification channels or diagnose "
            "delivery configuration."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _MEDIATYPE_GET_EXTRA,
    ),
    MethodDef(
        api_method="mediatype.create",
        tool_name="mediatype_create",
        description=(
            "Create a new media type (notification channel). Required fields depend "
            "on the type: 'name' and 'type' are always required. "
            "Symbolic names accepted for 'type': EMAIL, SCRIPT, SMS, WEBHOOK. "
            "EMAIL needs smtp_server, smtp_email; SCRIPT needs exec_path; "
            "SMS needs gsm_modem; WEBHOOK needs script and optionally parameters. "
            "Set status to 0 (enabled) or 1 (disabled)."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="mediatype.update",
        tool_name="mediatype_update",
        description=(
            "Update an existing media type. The params dict must include "
            "'mediatypeid'. Commonly used to change SMTP settings, update webhook "
            "URLs or scripts, enable/disable a media type, or adjust retry and "
            "concurrency settings."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="mediatype.delete",
        tool_name="mediatype_delete",
        description=(
            "Delete one or more media types by their IDs. This removes the "
            "notification channel definition. Any actions still referencing the "
            "deleted media type will no longer be able to send notifications "
            "through it. Verify no critical actions depend on the media type "
            "before deletion."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# script
# ---------------------------------------------------------------------------

_SCRIPT_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "scriptids", "list[str]",
        "Return only scripts with the given IDs.",
    ),
    ParamDef(
        "groupids", "list[str]",
        "Return only scripts available for hosts in these host group IDs.",
    ),
    ParamDef(
        "hostids", "list[str]",
        "Return only scripts available for the given host IDs.",
    ),
]

_SCRIPT_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="script.get",
        tool_name="script_get",
        description=(
            "Retrieve global scripts configured in Zabbix. Scripts can be executed "
            "on hosts manually or as action operations. Types include custom script "
            "(0), IPMI (1), SSH (2), Telnet (3), webhook (5). Each script has a "
            "scope (action operation, manual host action, manual event action) and "
            "host group permissions. Use groupids/hostids to find scripts available "
            "for specific targets."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _SCRIPT_GET_EXTRA,
    ),
    MethodDef(
        api_method="script.create",
        tool_name="script_create",
        description=(
            "Create a new global script. Required fields: 'name', 'type', 'command' "
            "(the script body or command to execute), and 'scope'. "
            "Symbolic names accepted for 'type': SCRIPT, IPMI, SSH, TELNET, WEBHOOK, URL. "
            "Symbolic names for 'scope': ACTION_OPERATION, MANUAL_HOST, MANUAL_EVENT. "
            "Symbolic names for 'execute_on' (custom scripts): AGENT, SERVER, SERVER_PROXY."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="script.update",
        tool_name="script_update",
        description=(
            "Update an existing global script. The params dict must include "
            "'scriptid'. Commonly used to change the command, update permissions "
            "(host group scope), or modify execution parameters."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="script.delete",
        tool_name="script_delete",
        description=(
            "Delete one or more global scripts by their IDs. Ensure no actions "
            "reference the script as an operation before deleting, or those action "
            "operations will fail."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
    MethodDef(
        api_method="script.execute",
        tool_name="script_execute",
        description=(
            "Execute a script on a host or in an event context. The script runs "
            "immediately and returns the execution result. For custom scripts "
            "running on the agent, the host must be reachable. Provide either "
            "hostid (for host-scope scripts) or eventid (for event-scope scripts), "
            "or both depending on script configuration."
        ),
        read_only=False,
        params=[
            ParamDef(
                "scriptid", "str",
                "ID of the script to execute.",
                required=True,
            ),
            ParamDef(
                "hostid", "str",
                "Host to run the script on.",
            ),
            ParamDef(
                "eventid", "str",
                "Event context for the script.",
            ),
        ],
    ),
    MethodDef(
        api_method="script.getscriptsbyevents",
        tool_name="script_getscriptsbyevents",
        description=(
            "Get scripts available for the given events. Returns a mapping of "
            "event IDs to the scripts that can be executed in each event's context. "
            "Useful for building dynamic script menus in event detail views."
        ),
        read_only=True,
        params=[
            ParamDef(
                "eventids", "list[str]",
                "Event IDs to get available scripts for.",
                required=True,
            ),
        ],
    ),
    MethodDef(
        api_method="script.getscriptsbyhosts",
        tool_name="script_getscriptsbyhosts",
        description=(
            "Get scripts available for the given hosts. Returns a mapping of host "
            "IDs to the scripts that can be executed on each host. Takes into "
            "account host group permissions and script scope. Useful for building "
            "dynamic script menus in host detail views."
        ),
        read_only=True,
        params=[
            ParamDef(
                "hostids", "list[str]",
                "Host IDs to get available scripts for.",
                required=True,
            ),
        ],
    ),
]

# ---------------------------------------------------------------------------
# Public export
# ---------------------------------------------------------------------------

ALERTS_METHODS: list[MethodDef] = (
    _ACTION_METHODS
    + _ALERT_METHODS
    + _MEDIATYPE_METHODS
    + _SCRIPT_METHODS
)
