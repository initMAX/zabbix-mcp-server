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

"""Zabbix API definitions for user management, authentication, and access control.

This module covers the "Users & Authentication" domain of the Zabbix API:
- **user**: User accounts that can log in to Zabbix. Users are assigned to groups
  and roles that control their permissions and access to host groups and templates.
- **usergroup**: Groups of users that share the same host group permissions and
  frontend/API access settings. Key for permission management.
- **userdirectory**: External authentication directories (LDAP, SAML) for
  centralized user provisioning and single sign-on.
- **role**: RBAC roles that define granular UI element access, API method
  permissions, and allowed actions (e.g. Super admin, Admin, User, Guest).
- **token**: API tokens for non-interactive / service-account access. Tokens
  are bound to a user and inherit that user's permissions.
- **authentication**: Global authentication settings that control login behaviour,
  password policy, LDAP/SAML defaults, HTTP auth, and MFA requirements.
"""

from zabbix_mcp.api.types import MethodDef, ParamDef
from zabbix_mcp.api.common import COMMON_GET_PARAMS, CREATE_PARAMS, UPDATE_PARAMS, DELETE_PARAMS

# ---------------------------------------------------------------------------
# user
# ---------------------------------------------------------------------------

_USER_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "userids", "list[str]",
        "Return only users with the given IDs.",
    ),
    ParamDef(
        "usrgrpids", "list[str]",
        "Return only users belonging to these user group IDs.",
    ),
    ParamDef(
        "mediatypeids", "list[str]",
        "Return only users that use the given media type IDs for notifications.",
    ),
]

_USER_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="user.get",
        tool_name="user_get",
        description=(
            "Retrieve Zabbix user accounts. Each user has a username, role, "
            "assigned user groups, and optionally configured media (notification "
            "addresses). Use selectMedias, selectUsrgrps, selectRole in the output "
            "to include related objects. Filter by usrgrpids to find members of a "
            "specific group, or by mediatypeids to find users reachable via a "
            "particular notification channel."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _USER_GET_EXTRA,
    ),
    MethodDef(
        api_method="user.create",
        tool_name="user_create",
        description=(
            "Create a new Zabbix user. Required fields: 'username', 'passwd' "
            "(or external auth), 'roleid', and 'usrgrps' (array of user group "
            "objects with usrgrpid). Optionally provide 'medias' to set up "
            "notification addresses (email, Slack handle, etc.) at creation time."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="user.update",
        tool_name="user_update",
        description=(
            "Update an existing user. The params dict must include 'userid'. "
            "Commonly used to change passwords, update role assignments, modify "
            "group memberships, or update notification media. Note: updating "
            "'medias' replaces all existing media entries for the user."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="user.delete",
        tool_name="user_delete",
        description=(
            "Delete one or more users by their IDs. The user performing the "
            "deletion cannot delete their own account. Users who are the only "
            "member of a user group or the sole recipient of an action cannot "
            "be deleted until the dependency is resolved."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
    MethodDef(
        api_method="user.login",
        tool_name="user_login",
        description=(
            "Authenticate a user and obtain a session ID (auth token). The "
            "returned token is used for subsequent API calls. If userData is true, "
            "the response also includes the full user object (userid, username, "
            "role, groups, etc.). This is the standard way to start an API session "
            "when not using persistent API tokens."
        ),
        read_only=True,
        params=[
            ParamDef(
                "username", "str",
                "Zabbix username to authenticate.",
                required=True,
            ),
            ParamDef(
                "password", "str",
                "Password for the user.",
                required=True,
            ),
            ParamDef(
                "userData", "bool",
                "Return additional user info (userid, name, role, etc.) "
                "alongside the session token.",
            ),
        ],
    ),
    MethodDef(
        api_method="user.logout",
        tool_name="user_logout",
        description=(
            "Log out the current API session. Invalidates the session token so "
            "it can no longer be used for API calls. Good practice for cleanup "
            "after scripted workflows."
        ),
        read_only=False,
        params=[],
    ),
    MethodDef(
        api_method="user.checkAuthentication",
        tool_name="user_checkauthentication",
        description=(
            "Check whether a session or API token is still valid. If the token is "
            "valid, returns the authenticated user's details. Useful for health "
            "checks or verifying a stored token before making further calls."
        ),
        read_only=True,
        params=[
            ParamDef(
                "token", "str",
                "API token to validate. If omitted, the current session token "
                "is checked.",
            ),
        ],
    ),
    MethodDef(
        api_method="user.provision",
        tool_name="user_provision",
        description=(
            "Provision users from an external directory (LDAP/SAML). This "
            "triggers user synchronization based on the configured user directory "
            "mappings, creating or updating Zabbix user accounts to match the "
            "external source."
        ),
        read_only=False,
        params=[
            ParamDef(
                "params", "dict",
                "User provisioning data. Contains the provisioning parameters "
                "as defined by the configured user directory.",
                required=True,
            ),
        ],
    ),
    MethodDef(
        api_method="user.resettotp",
        tool_name="user_resettotp",
        description=(
            "Reset TOTP secrets for users. This forces the specified users to "
            "re-enroll their TOTP authenticator app on next login. Use when a "
            "user has lost access to their authenticator or when rotating MFA "
            "credentials."
        ),
        read_only=False,
        params=[
            ParamDef(
                "userids", "list[str]",
                "IDs of users whose TOTP secrets should be reset.",
                required=True,
            ),
        ],
        array_param="userids",
    ),
    MethodDef(
        api_method="user.unblock",
        tool_name="user_unblock",
        description=(
            "Unblock users that have been blocked due to too many failed login "
            "attempts. Zabbix auto-blocks accounts after consecutive failures "
            "(configurable). This method re-enables login for the specified users "
            "without requiring a password reset."
        ),
        read_only=False,
        params=[
            ParamDef(
                "userids", "list[str]",
                "IDs of blocked users to unblock.",
                required=True,
            ),
        ],
        array_param="userids",
    ),
]

# ---------------------------------------------------------------------------
# usergroup
# ---------------------------------------------------------------------------

_USERGROUP_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "usrgrpids", "list[str]",
        "Return only user groups with the given IDs.",
    ),
    ParamDef(
        "userids", "list[str]",
        "Return only user groups that contain the given user IDs.",
    ),
    ParamDef(
        "with_users", "bool",
        "Return only user groups that have at least one user.",
    ),
]

_USERGROUP_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="usergroup.get",
        tool_name="usergroup_get",
        description=(
            "Retrieve user groups. User groups are the primary mechanism for "
            "assigning permissions in Zabbix -- each group has a set of host group "
            "permissions (read, read-write, deny) and frontend/API access settings. "
            "Use selectRights to see the permission mappings, selectUsers to include "
            "group members, and selectTagFilters for tag-based permissions."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _USERGROUP_GET_EXTRA,
    ),
    MethodDef(
        api_method="usergroup.create",
        tool_name="usergroup_create",
        description=(
            "Create a new user group. Required field: 'name'. Important optional "
            "fields: 'gui_access' (0=system default, 1=internal auth, 2=LDAP, "
            "3=disabled), 'users_status' (0=enabled, 1=disabled), 'hostgroup_rights' "
            "and 'templategroup_rights' (arrays defining permissions per group)."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="usergroup.update",
        tool_name="usergroup_update",
        description=(
            "Update an existing user group. The params dict must include "
            "'usrgrpid'. Commonly used to change permissions (hostgroup_rights, "
            "templategroup_rights), add or remove users, or modify frontend "
            "access settings."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="usergroup.delete",
        tool_name="usergroup_delete",
        description=(
            "Delete one or more user groups by their IDs. Groups that are the sole "
            "group for any user, or that are referenced by actions, cannot be "
            "deleted until the dependency is resolved."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# userdirectory
# ---------------------------------------------------------------------------

_USERDIRECTORY_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "userdirectoryids", "list[str]",
        "Return only user directories with the given IDs.",
    ),
]

_USERDIRECTORY_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="userdirectory.get",
        tool_name="userdirectory_get",
        description=(
            "Retrieve configured user directories (LDAP or SAML identity providers). "
            "User directories enable centralized authentication and automatic user "
            "provisioning from external identity stores. Each directory defines "
            "connection parameters, attribute mappings, and user group assignments."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _USERDIRECTORY_GET_EXTRA,
    ),
    MethodDef(
        api_method="userdirectory.create",
        tool_name="userdirectory_create",
        description=(
            "Create a new user directory. Required fields depend on the type: "
            "for LDAP -- 'name', 'host', 'port', 'base_dn', 'search_attribute'; "
            "for SAML -- 'name', 'idp_entityid', 'sso_url', 'username_attribute', "
            "'sp_entityid'. Include 'provision_groups' to map external groups to "
            "Zabbix user groups and roles."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="userdirectory.update",
        tool_name="userdirectory_update",
        description=(
            "Update an existing user directory. The params dict must include "
            "'userdirectoryid'. Commonly used to change LDAP connection parameters, "
            "update SAML endpoints, or modify group provisioning mappings."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="userdirectory.delete",
        tool_name="userdirectory_delete",
        description=(
            "Delete one or more user directories by their IDs. Removing a directory "
            "does not delete users that were provisioned from it, but they will no "
            "longer be synchronized or able to authenticate via that directory."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
    MethodDef(
        api_method="userdirectory.test",
        tool_name="userdirectory_test",
        description=(
            "Test an LDAP or SAML directory connection without saving it. Verifies "
            "that Zabbix can connect to the directory server with the provided "
            "parameters and optionally performs a test authentication. Use this "
            "before creating or updating a directory to validate settings."
        ),
        read_only=True,
        params=[
            ParamDef(
                "params", "dict",
                "Test LDAP/SAML directory connection parameters. Include "
                "connection details (host, port, base_dn, etc.) and optionally "
                "test credentials (test_username, test_password).",
                required=True,
            ),
        ],
    ),
]

# ---------------------------------------------------------------------------
# role
# ---------------------------------------------------------------------------

_ROLE_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "roleids", "list[str]",
        "Return only roles with the given IDs.",
    ),
]

_ROLE_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="role.get",
        tool_name="role_get",
        description=(
            "Retrieve user roles. Roles define what a user can do in Zabbix via "
            "granular RBAC rules: which UI sections are visible, which API methods "
            "are allowed, and what actions (acknowledge, close, suppress) are "
            "permitted. Built-in roles: Super admin (type=3), Admin (type=2), "
            "User (type=1), Guest (type=4). Use selectRules to include the full "
            "permission rule set for each role."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _ROLE_GET_EXTRA,
    ),
    MethodDef(
        api_method="role.create",
        tool_name="role_create",
        description=(
            "Create a new user role. Required fields: 'name' and 'type'. "
            "Symbolic names accepted for 'type': USER, ADMIN, SUPER_ADMIN, GUEST. "
            "Provide 'rules' to customize UI element access, API method permissions, "
            "and allowed actions. The type sets the baseline permission level; rules refine it."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="role.update",
        tool_name="role_update",
        description=(
            "Update an existing user role. The params dict must include 'roleid'. "
            "Commonly used to adjust the rules that control UI visibility, API "
            "access, and action permissions. Changes affect all users assigned "
            "to this role."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="role.delete",
        tool_name="role_delete",
        description=(
            "Delete one or more user roles by their IDs. Built-in roles cannot be "
            "deleted. A role cannot be deleted if any users are still assigned to "
            "it -- reassign those users first."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# token
# ---------------------------------------------------------------------------

_TOKEN_GET_EXTRA: list[ParamDef] = [
    ParamDef(
        "tokenids", "list[str]",
        "Return only tokens with the given IDs.",
    ),
]

_TOKEN_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="token.get",
        tool_name="token_get",
        description=(
            "Retrieve API tokens. Tokens provide persistent authentication for "
            "scripts, integrations, and service accounts without requiring "
            "user.login sessions. Each token is bound to a specific user and "
            "inherits that user's permissions. Tokens have optional expiry dates "
            "and can be enabled or disabled independently."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS + _TOKEN_GET_EXTRA,
    ),
    MethodDef(
        api_method="token.create",
        tool_name="token_create",
        description=(
            "Create a new API token. Required fields: 'name' and 'userid' (the "
            "user this token authenticates as). Optional: 'expires_at' (Unix "
            "timestamp for expiry, 0 for no expiry), 'status' (0=enabled, "
            "1=disabled), 'description'. After creation, call token.generate to "
            "obtain the actual authentication string."
        ),
        read_only=False,
        params=CREATE_PARAMS,
    ),
    MethodDef(
        api_method="token.update",
        tool_name="token_update",
        description=(
            "Update an existing API token. The params dict must include 'tokenid'. "
            "Commonly used to enable/disable tokens (status 0/1), change the "
            "expiry date, or update the description. Cannot change the bound user."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
    MethodDef(
        api_method="token.delete",
        tool_name="token_delete",
        description=(
            "Delete one or more API tokens by their IDs. This immediately "
            "invalidates the tokens -- any scripts or integrations using them "
            "will lose access. Consider disabling tokens (status=1) instead of "
            "deleting if you may need to re-enable them later."
        ),
        read_only=False,
        params=DELETE_PARAMS,
    ),
    MethodDef(
        api_method="token.generate",
        tool_name="token_generate",
        description=(
            "Generate authentication strings for API tokens. This must be called "
            "after token.create to obtain the actual secret string used for "
            "authentication. The generated string is only returned once -- store "
            "it securely. Can also be used to regenerate a token's auth string "
            "(the old one becomes invalid)."
        ),
        read_only=False,
        params=[
            ParamDef(
                "tokenids", "list[str]",
                "Token IDs to generate authentication strings for.",
                required=True,
            ),
        ],
        array_param="tokenids",
    ),
]

# ---------------------------------------------------------------------------
# authentication
# ---------------------------------------------------------------------------

_AUTHENTICATION_METHODS: list[MethodDef] = [
    MethodDef(
        api_method="authentication.get",
        tool_name="authentication_get",
        description=(
            "Get the global authentication settings. Returns the server-wide "
            "configuration for authentication methods: internal auth, LDAP "
            "defaults, SAML settings, HTTP authentication, password complexity "
            "requirements, login attempt limits, and MFA enforcement. This is a "
            "singleton object -- there are no IDs to filter by."
        ),
        read_only=True,
        params=COMMON_GET_PARAMS,
    ),
    MethodDef(
        api_method="authentication.update",
        tool_name="authentication_update",
        description=(
            "Update global authentication settings (LDAP, SAML, MFA, etc.). "
            "Controls server-wide login behaviour such as password minimum length, "
            "account lockout after N failed attempts, default authentication type, "
            "SAML SSO toggle, and MFA enforcement. Changes affect all users. "
            "The params dict should include only the fields to change."
        ),
        read_only=False,
        params=UPDATE_PARAMS,
    ),
]

# ---------------------------------------------------------------------------
# Public export
# ---------------------------------------------------------------------------

USERS_METHODS: list[MethodDef] = (
    _USER_METHODS
    + _USERGROUP_METHODS
    + _USERDIRECTORY_METHODS
    + _ROLE_METHODS
    + _TOKEN_METHODS
    + _AUTHENTICATION_METHODS
)
