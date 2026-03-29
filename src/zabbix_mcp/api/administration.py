"""Zabbix API definitions for server administration and system configuration.

This module covers the "Administration" domain of the Zabbix API:
- **autoregistration**: Settings for automatic host registration when new agents
  connect. Controls PSK encryption and allowed host metadata patterns.
- **iconmap**: Icon mappings used on network maps to automatically assign icons
  to hosts based on inventory fields.
- **image**: Images (icons and backgrounds) used in network maps.
- **settings**: Global Zabbix server settings such as default theme, alert
  timeouts, severity names/colors, and frontend URL.
- **regexp**: Global regular expressions used in LLD rules, triggers, and other
  places. Each regexp can contain multiple test expressions.
- **module**: Frontend (loadable) modules that extend the Zabbix UI with custom
  pages, widgets, or functionality.
- **connector**: Connectors that stream events to external systems in real time
  (e.g. for SIEM integration or custom event processing pipelines).
- **auditlog**: Read-only audit trail of all configuration changes and login
  events. Essential for compliance and forensics.
- **housekeeping**: Settings that control automatic cleanup of old history,
  trends, events, sessions, and audit records.
- **proxy**: Zabbix proxies that collect data on behalf of the server, reducing
  the load on the central server and enabling monitoring across firewalls/NAT.
- **proxygroup**: Logical groupings of proxies for high-availability and
  load-balanced data collection.
- **mfa**: Multi-factor authentication methods (TOTP, Duo) configured globally
  and enforced per user group.
"""

from zabbix_mcp.api.types import MethodDef, ParamDef
from zabbix_mcp.api.common import COMMON_GET_PARAMS, CREATE_PARAMS, UPDATE_PARAMS, DELETE_PARAMS

# ---------------------------------------------------------------------------
# autoregistration
# ---------------------------------------------------------------------------

_AUTOREGISTRATION_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="autoregistration.get",
        tool_name="autoregistration_get",
        description=(
            "Get autoregistration settings. Returns the global configuration for "
            "automatic host registration: the PSK identity and key used for "
            "encrypted autoregistration, and the TLS accept mode. This is a "
            "singleton object with no filtering options."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS,
    ),
    MethodDef(
        api_method="autoregistration.update",
        tool_name="autoregistration_update",
        description=(
            "Update autoregistration settings. Configure the TLS PSK identity and "
            "key for encrypted agent autoregistration, and set the TLS accept mode "
            "(1=unencrypted, 2=PSK, 4=certificate, or bitwise combination). "
            "Changes affect all new agent autoregistration requests."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# iconmap
# ---------------------------------------------------------------------------

_ICONMAP_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "iconmapids", "list[str]",
        "Return only icon maps with the given IDs.",
    ),
]

_ICONMAP_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="iconmap.get",
        tool_name="iconmap_get",
        description=(
            "Retrieve icon maps used on network maps. Icon maps automatically "
            "assign icons to map elements based on host inventory field values. "
            "For example, map a host's 'type' inventory field so that routers, "
            "switches, and servers each display a distinct icon. Use "
            "selectMappings to include the mapping rules in the response."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _ICONMAP_GET_EXTRA,
    ),
    MethodDef(
        api_method="iconmap.create",
        tool_name="iconmap_create",
        description=(
            "Create a new icon map. Required fields: 'name', 'default_iconid' "
            "(fallback icon when no mapping matches), and 'mappings' (array of "
            "mapping rules, each with 'inventory_link', 'expression', and "
            "'iconid'). The inventory_link value corresponds to a host inventory "
            "field number."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="iconmap.update",
        tool_name="iconmap_update",
        description=(
            "Update an existing icon map. The params dict must include "
            "'iconmapid'. Commonly used to add or modify mapping rules, change "
            "the default icon, or rename the icon map."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="iconmap.delete",
        tool_name="iconmap_delete",
        description=(
            "Delete one or more icon maps by their IDs. Network maps referencing "
            "the deleted icon map will revert to using the default icon settings."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# image
# ---------------------------------------------------------------------------

_IMAGE_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "imageids", "list[str]",
        "Return only images with the given IDs.",
    ),
]

_IMAGE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="image.get",
        tool_name="image_get",
        description=(
            "Retrieve images stored in Zabbix. Images are used as icons for map "
            "elements and as backgrounds for network maps. Two types exist: "
            "1 = icon, 2 = background. By default the image data (base64-encoded) "
            "is included in the response; use 'output' to limit returned fields "
            "if you only need metadata."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _IMAGE_GET_EXTRA,
    ),
    MethodDef(
        api_method="image.create",
        tool_name="image_create",
        description=(
            "Upload a new image to Zabbix. Required fields: 'name', 'imagetype' "
            "(1=icon, 2=background), and 'image' (base64-encoded image data). "
            "Supported formats: PNG, JPEG. Icons are typically small (64x64 to "
            "128x128); backgrounds can be larger for map canvases."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="image.update",
        tool_name="image_update",
        description=(
            "Update an existing image. The params dict must include 'imageid'. "
            "Can be used to replace the image data, rename the image, or change "
            "its type. Provide 'image' with new base64-encoded data to replace "
            "the visual content."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="image.delete",
        tool_name="image_delete",
        description=(
            "Delete one or more images by their IDs. Images that are currently "
            "used by icon maps or network map elements should be reassigned first "
            "to avoid broken visuals."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------

_SETTINGS_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="settings.get",
        tool_name="settings_get",
        description=(
            "Get global Zabbix server settings. Returns the singleton settings "
            "object containing: default theme, server name, frontend URL, alert "
            "notification timeout, severity name overrides, severity colors, "
            "custom color settings, login and session parameters, and various "
            "other global defaults. No filtering options -- returns the full object."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS,
    ),
    MethodDef(
        api_method="settings.update",
        tool_name="settings_update",
        description=(
            "Update global Zabbix server settings. Commonly used to change the "
            "frontend URL, set custom severity names and colors, adjust default "
            "theme, configure alert notification timeouts, or update the server "
            "name displayed in the UI. Only include the fields you want to change."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# regexp
# ---------------------------------------------------------------------------

_REGEXP_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "regexpids", "list[str]",
        "Return only regular expressions with the given IDs.",
    ),
]

_REGEXP_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="regexp.get",
        tool_name="regexp_get",
        description=(
            "Retrieve global regular expressions. These named regexp objects are "
            "reusable across Zabbix -- referenced in LLD (Low-Level Discovery) "
            "rules to filter discovered entities, in trigger expressions, and "
            "elsewhere. Each regexp can contain multiple test expressions with "
            "different match types (character string included, result is TRUE/FALSE, "
            "etc.). Use selectExpressions to include the test expressions."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _REGEXP_GET_EXTRA,
    ),
    MethodDef(
        api_method="regexp.create",
        tool_name="regexp_create",
        description=(
            "Create a new global regular expression. Required fields: 'name' and "
            "'expressions' (array of test expression objects, each with "
            "'expression', 'expression_type', and optionally 'case_sensitive'). "
            "expression_type values: 0=character string included, 1=any character "
            "string included, 2=character string not included, 3=result is TRUE, "
            "4=result is FALSE."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="regexp.update",
        tool_name="regexp_update",
        description=(
            "Update an existing global regular expression. The params dict must "
            "include 'regexpid'. Note: providing 'expressions' replaces all "
            "existing test expressions for the regexp."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="regexp.delete",
        tool_name="regexp_delete",
        description=(
            "Delete one or more global regular expressions by their IDs. Ensure "
            "no LLD rules, triggers, or other objects reference the regexp before "
            "deleting, as those references will become invalid."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# module
# ---------------------------------------------------------------------------

_MODULE_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "moduleids", "list[str]",
        "Return only modules with the given IDs.",
    ),
]

_MODULE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="module.get",
        tool_name="module_get",
        description=(
            "Retrieve registered frontend modules. Modules extend the Zabbix web "
            "interface with custom pages, dashboard widgets, or other UI "
            "components. Each module has a status (enabled/disabled) and metadata "
            "about its ID, relative path, and configuration."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _MODULE_GET_EXTRA,
    ),
    MethodDef(
        api_method="module.create",
        tool_name="module_create",
        description=(
            "Register a new frontend module. Required fields: 'id' (unique module "
            "identifier matching the module's manifest), 'relative_path' (path to "
            "the module directory relative to the modules directory). Set 'status' "
            "to 0 (disabled) or 1 (enabled)."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="module.update",
        tool_name="module_update",
        description=(
            "Update an existing frontend module. The params dict must include "
            "'moduleid'. Commonly used to enable or disable a module by setting "
            "'status' to 1 (enabled) or 0 (disabled)."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="module.delete",
        tool_name="module_delete",
        description=(
            "Delete one or more frontend modules by their IDs. This unregisters "
            "the module from the Zabbix frontend but does not delete the module "
            "files from disk."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# connector
# ---------------------------------------------------------------------------

_CONNECTOR_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "connectorids", "list[str]",
        "Return only connectors with the given IDs.",
    ),
]

_CONNECTOR_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="connector.get",
        tool_name="connector_get",
        description=(
            "Retrieve event connectors. Connectors stream Zabbix events to "
            "external systems in real time, enabling SIEM integration, custom "
            "event pipelines, and third-party alerting. Each connector defines "
            "a URL endpoint, data format, authentication, and filtering rules "
            "for which events to forward."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _CONNECTOR_GET_EXTRA,
    ),
    MethodDef(
        api_method="connector.create",
        tool_name="connector_create",
        description=(
            "Create a new event connector. Required fields: 'name', 'url' "
            "(endpoint to send events to), and 'data_type' (0=item values, "
            "1=events). Optional: 'protocol' (0=Zabbix Streaming Protocol), "
            "'max_records', 'max_senders', 'timeout', authentication settings, "
            "and tag-based filtering rules."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="connector.update",
        tool_name="connector_update",
        description=(
            "Update an existing event connector. The params dict must include "
            "'connectorid'. Commonly used to change the target URL, update "
            "authentication credentials, modify event filters, or enable/disable "
            "the connector."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="connector.delete",
        tool_name="connector_delete",
        description=(
            "Delete one or more event connectors by their IDs. Stops event "
            "streaming to the configured endpoints immediately. Events generated "
            "while the connector was active are not affected."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# auditlog
# ---------------------------------------------------------------------------

_AUDITLOG_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "auditids", "list[str]",
        "Return only audit log entries with the given IDs.",
    ),
    ParamDef(
        "userids", "list[str]",
        "Return only audit log entries for actions performed by these user IDs.",
    ),
    ParamDef(
        "time_from", "int",
        "Return only audit log entries created after this Unix timestamp "
        "(inclusive). Use for scoping queries to a specific time window.",
    ),
    ParamDef(
        "time_till", "int",
        "Return only audit log entries created before this Unix timestamp "
        "(inclusive).",
    ),
]

_AUDITLOG_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="auditlog.get",
        tool_name="auditlog_get",
        description=(
            "Retrieve audit log entries (read-only). The audit log records every "
            "configuration change and login/logout event in Zabbix, including who "
            "made the change, when, what object was affected, and the old/new "
            "values. Essential for security auditing, compliance, and forensic "
            "investigation. Use time_from/time_till to limit the time window and "
            "userids to focus on a specific user's activity. Results can be large "
            "-- always use limit or time filters."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _AUDITLOG_GET_EXTRA,
    ),
]

# ---------------------------------------------------------------------------
# housekeeping
# ---------------------------------------------------------------------------

_HOUSEKEEPING_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="housekeeping.get",
        tool_name="housekeeping_get",
        description=(
            "Get housekeeping settings. Returns the global configuration that "
            "controls automatic cleanup of old data: history storage period, "
            "trend storage period, event and alert retention, session cleanup "
            "interval, and audit log retention. This is a singleton object."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS,
    ),
    MethodDef(
        api_method="housekeeping.update",
        tool_name="housekeeping_update",
        description=(
            "Update housekeeping settings. Controls how long Zabbix retains "
            "historical data. Key fields: 'hk_history_global' (override per-item "
            "history retention), 'hk_history' (global history period, e.g. '90d'), "
            "'hk_trends_global' (override per-item trend retention), 'hk_trends' "
            "(global trend period, e.g. '365d'), 'hk_events_mode' (enable event "
            "cleanup), 'hk_audit_mode' (enable audit log cleanup). Increasing "
            "retention periods increases storage requirements."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# proxy
# ---------------------------------------------------------------------------

_PROXY_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "proxyids", "list[str]",
        "Return only proxies with the given IDs.",
    ),
    ParamDef(
        "with_hosts", "bool",
        "Return only proxies that have at least one host assigned to them.",
    ),
]

_PROXY_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="proxy.get",
        tool_name="proxy_get",
        description=(
            "Retrieve Zabbix proxies. Proxies collect monitoring data on behalf "
            "of the Zabbix server, enabling distributed monitoring across network "
            "segments, firewalls, and geographic regions. Each proxy has a mode "
            "(0=active, 1=passive), connection settings, and a list of assigned "
            "hosts. Use selectHosts to include assigned hosts, selectInterface "
            "for connection details. Filter with with_hosts to find proxies that "
            "are actively monitoring hosts."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _PROXY_GET_EXTRA,
    ),
    MethodDef(
        api_method="proxy.create",
        tool_name="proxy_create",
        description=(
            "Create a new proxy. Required fields: 'name' and 'operating_mode' "
            "(0=active proxy that connects to server, 1=passive proxy that "
            "server connects to). For passive proxies, provide 'address' and "
            "'port'. Optional: 'tls_connect' and 'tls_accept' for encryption, "
            "'proxy_groupid' for proxy group membership, 'hosts' to assign "
            "hosts at creation time."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="proxy.update",
        tool_name="proxy_update",
        description=(
            "Update an existing proxy. The params dict must include 'proxyid'. "
            "Commonly used to reassign hosts, change TLS settings, update the "
            "proxy address, or move the proxy to a different proxy group. "
            "Note: changing 'hosts' replaces the entire host assignment list."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="proxy.delete",
        tool_name="proxy_delete",
        description=(
            "Delete one or more proxies by their IDs. Hosts assigned to the "
            "deleted proxy will be set to be monitored directly by the Zabbix "
            "server. Ensure the server can reach those hosts before deleting "
            "their proxy."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# proxygroup
# ---------------------------------------------------------------------------

_PROXYGROUP_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "proxygroupids", "list[str]",
        "Return only proxy groups with the given IDs.",
    ),
]

_PROXYGROUP_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="proxygroup.get",
        tool_name="proxygroup_get",
        description=(
            "Retrieve proxy groups. Proxy groups provide high availability and "
            "load balancing for data collection by grouping multiple proxies. "
            "Hosts assigned to a proxy group are automatically distributed among "
            "the group's proxies, and failover occurs if a proxy becomes "
            "unavailable. Use selectProxies to include the group's member proxies."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _PROXYGROUP_GET_EXTRA,
    ),
    MethodDef(
        api_method="proxygroup.create",
        tool_name="proxygroup_create",
        description=(
            "Create a new proxy group. Required fields: 'name' and "
            "'failover_delay' (time before failover, e.g. '1m'), "
            "'min_online' (minimum number of online proxies for the group to be "
            "considered available, e.g. '1'). Proxies are added to the group by "
            "updating the proxy's proxy_groupid."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="proxygroup.update",
        tool_name="proxygroup_update",
        description=(
            "Update an existing proxy group. The params dict must include "
            "'proxy_groupid'. Commonly used to change failover settings, minimum "
            "online threshold, or rename the group."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="proxygroup.delete",
        tool_name="proxygroup_delete",
        description=(
            "Delete one or more proxy groups by their IDs. Proxies in the group "
            "will be disassociated but not deleted. Hosts assigned to the proxy "
            "group must be reassigned first."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# mfa
# ---------------------------------------------------------------------------

_MFA_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "mfaids", "list[str]",
        "Return only MFA methods with the given IDs.",
    ),
]

_MFA_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="mfa.get",
        tool_name="mfa_get",
        description=(
            "Retrieve multi-factor authentication methods configured in Zabbix. "
            "MFA methods define the second factor required at login: TOTP "
            "(time-based one-time password via apps like Google Authenticator) or "
            "Duo Universal Prompt. MFA methods are assigned to user groups to "
            "enforce per-group MFA requirements. Use this to audit which MFA "
            "methods are available and their configuration."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _MFA_GET_EXTRA,
    ),
    MethodDef(
        api_method="mfa.create",
        tool_name="mfa_create",
        description=(
            "Create a new MFA method. Required fields: 'name' and 'type' "
            "(1=TOTP, 2=Duo Universal Prompt). For TOTP: optionally set "
            "'hash_function' (1=SHA-1, 2=SHA-256, 3=SHA-512) and 'code_length' "
            "(6 or 8). For Duo: 'api_hostname', 'clientid', and 'client_secret' "
            "are required. After creation, assign the MFA method to user groups "
            "via usergroup.update."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="mfa.update",
        tool_name="mfa_update",
        description=(
            "Update an existing MFA method. The params dict must include 'mfaid'. "
            "Commonly used to change TOTP hash function or code length, update "
            "Duo API credentials, rename the method, or reconfigure settings. "
            "Changes affect all user groups using this MFA method."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="mfa.delete",
        tool_name="mfa_delete",
        description=(
            "Delete one or more MFA methods by their IDs. User groups referencing "
            "the deleted MFA method will lose their MFA requirement. Ensure "
            "alternative MFA methods are assigned to affected groups if MFA "
            "enforcement is still needed."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# Public export
# ---------------------------------------------------------------------------

ADMINISTRATION_METHODS: list[MethodDef] = (
    _AUTOREGISTRATION_METHODS
    + _ICONMAP_METHODS
    + _IMAGE_METHODS
    + _SETTINGS_METHODS
    + _REGEXP_METHODS
    + _MODULE_METHODS
    + _CONNECTOR_METHODS
    + _AUDITLOG_METHODS
    + _HOUSEKEEPING_METHODS
    + _PROXY_METHODS
    + _PROXYGROUP_METHODS
    + _MFA_METHODS
)
