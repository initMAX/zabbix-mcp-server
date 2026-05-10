# LDAP / Active Directory authentication (admin portal)

Issue [#46](https://github.com/initMAX/zabbix-mcp-server/issues/46).
v1.32+.

The admin portal can bind operators against an LDAP / AD directory
on the same login form as the local-scrypt path. Ordering is
**local-first, LDAP fallback** so a directory outage cannot lock a
local-only admin out of the portal.

## Operator setup

### 1. Install the LDAP client

```
sudo -u zabbix-mcp /opt/zabbix-mcp/venv/bin/pip install ldap3
sudo systemctl restart zabbix-mcp-server
```

`ldap3` is pure Python (no `libldap` system dependency), so the
install is a one-liner.

### 2. Wire up the directory

Edit `/etc/zabbix-mcp/config.toml` and add:

```toml
[admin.ldap]
enabled       = true
display_name  = "Sign in with Active Directory"

# Connection
server            = "ldaps://ad.example.local:636"
start_tls         = true                # cleartext ldap:// + StartTLS upgrade
timeout_seconds   = 5
ca_cert           = ""                  # optional PEM path for private CA

# Service account (anonymous bind = leave bind_dn empty)
bind_dn           = "CN=zabbix-mcp,OU=Service Accounts,DC=example,DC=local"
bind_password     = "service-account-password-here"

# Search
base_dn           = "DC=example,DC=local"
user_search_filter  = "(&(objectClass=person)(sAMAccountName={username}))"
group_search_filter = "(member={user_dn})"

# Group -> role mapping. First match wins; precedence
# admin > operator > viewer > auditor when a user is in multiple
# mapped groups.
[admin.ldap.group_to_role]
"CN=zbx-admin,OU=Groups,DC=example,DC=local"   = "admin"
"CN=zbx-ops,OU=Groups,DC=example,DC=local"     = "operator"
"CN=zbx-readonly,OU=Groups,DC=example,DC=local"= "viewer"

# Default role given to a user that binds OK but is in none of the
# mapped groups. Empty = refuse the login.
default_role = ""
```

Restart:

```
sudo systemctl restart zabbix-mcp-server
```

### 3. Test

```
# Local admin still works (LDAP outage scenario)
curl -X POST -d 'username=admin&password=...' https://your-portal/login

# Directory user
curl -X POST -d 'username=alice&password=...' https://your-portal/login
```

Login attempts land in `audit.log` regardless of source:
- `login_success` with `details.auth = "ldap"` on directory success
- `login_failure` with `details.reason` on bind failure

## Per-directory filter cheatsheet

### Active Directory

```toml
user_search_filter  = "(&(objectClass=person)(sAMAccountName={username}))"
group_search_filter = "(member={user_dn})"
```

`sAMAccountName` is the pre-Windows-2000 login. For UPN-style logins
(`alice@example.local`):

```toml
user_search_filter  = "(&(objectClass=person)(userPrincipalName={username}))"
```

### OpenLDAP / 389-DS (RFC 2307bis schema)

```toml
user_search_filter  = "(&(objectClass=inetOrgPerson)(uid={username}))"
group_search_filter = "(&(objectClass=groupOfNames)(member={user_dn}))"
```

### OpenLDAP (memberUid schema - older deployments)

```toml
user_search_filter  = "(&(objectClass=posixAccount)(uid={username}))"
# group filter uses {username} instead of {user_dn} - currently
# unsupported by the v1.32 implementation. Migrate to groupOfNames.
```

### FreeIPA

```toml
user_search_filter  = "(&(objectClass=person)(uid={username}))"
group_search_filter = "(&(objectClass=groupOfNames)(member={user_dn}))"
```

## TLS

- **ldaps://** = bind-time TLS on port 636. Recommended for cross-
  network connections.
- **ldap://** + `start_tls = true` = cleartext bind on port 389 then
  upgrade to TLS via the StartTLS extended operation. Use when the
  directory does not have port 636 open but does support StartTLS.

Both modes validate the server cert against the system trust store.
Set `ca_cert = "/etc/zabbix-mcp/ldap-ca.pem"` to trust a private CA
(AD with an internal CA / FreeIPA / self-signed staging directory).

## Filter injection defence

The `{username}` placeholder is **escaped per RFC 4515 §3** before
substitution: parentheses, asterisk, backslash, NUL byte. A malicious
username like `*)(uid=*)` is rejected, not interpreted as a wildcard
search. Test coverage in `tests/test_auth_saml_ldap.py`.

## Troubleshooting

- **"service bind failed: ..." in audit log:** `bind_dn` /
  `bind_password` wrong, or the service account lacks search
  permission. Confirm with `ldapsearch -H ldaps://server -D bind_dn
  -w password -b base_dn`.

- **"user not found in directory":** filter does not match. Try the
  same filter manually in `ldapsearch`. Common cause: AD vs OpenLDAP
  schema mismatch (sAMAccountName vs uid).

- **"ambiguous user search (got N matches)":** the filter matched
  multiple entries. Tighten with `(&(objectClass=person)...)`.

- **"user not in any mapped group":** the user's group memberships
  do not match any DN in `[admin.ldap.group_to_role]`. Set
  `default_role = "viewer"` to let them in anyway, or add their
  group to the map.

- **Timeouts on every login:** the directory is unreachable.
  `timeout_seconds = 5` keeps the login form snappy; bump to 10 if
  the LDAP server is across a WAN with high latency.
