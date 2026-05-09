# Admin portal roles

The Zabbix MCP admin portal has three built-in roles. They are checked
at every view entry point - there is no implicit "logged-in = full
access" path. This document is the source of truth for which role can
do what; it is generated from a sweep of `session.role` checks across
`plugins/zabbix/zabbix_mcp/admin/views/*.py` (issue #49 Phase 3 role
parity audit).

## Roles

| Role | Intended use | Can do |
|---|---|---|
| `admin` | Operator who deploys and configures the server. | Everything. Adds/removes Zabbix servers, manages users, edits all settings, deletes tokens, uploads logos, can grant elevated tokens. |
| `operator` | Day-to-day operator. Runs the wizard, mints tokens for clients, reviews audit log. | Token + OAuth client lifecycle, settings edits (most sections), template editing, file uploads. Cannot manage users or Zabbix servers, cannot delete tokens, cannot enable global OAuth. |
| `viewer` | Read-only role for compliance / audit / NOC observers. | View dashboard, audit log, modules page. Cannot mint tokens, cannot edit settings, cannot run the wizard write-side. |

## Permission matrix

The matrix below is built from the explicit `session.role` checks in
the views. `require_auth` alone (without a role check) means "any
authenticated user" - all three roles can reach those routes.

### Authentication & users

| Action | View | admin | operator | viewer |
|---|---|---|---|---|
| Login (`/login`) | `auth.py` | - | - | - |
| List users | `users.py:60` | yes | no | no |
| Create user | `users.py:166` | yes | no | no |
| Edit user | `users.py:284` | yes | no | no |
| Delete user | `users.py:346` | yes | no | no |

### Tokens

| Action | View | admin | operator | viewer |
|---|---|---|---|---|
| List tokens (`/tokens`) | `tokens.py` (require_auth) | yes | yes | yes |
| Create token (`/tokens/create`) | `tokens.py:192` | yes | yes | no |
| Test token | `tokens.py:406` | yes | yes | no |
| Edit / rotate token | `tokens.py:562` | yes | yes | no |
| Set token TTL / scopes | `tokens.py:603` | yes | yes | no |
| **Delete token** | `tokens.py:641` | yes | **no** | no |
| **Bulk delete tokens** | `tokens.py:669` | yes | **no** | no |

### OAuth registered clients

| Action | View | admin | operator | viewer |
|---|---|---|---|---|
| List OAuth clients (`/oauth-clients`) | `oauth_clients.py` (require_auth) | yes | yes | yes |
| Revoke client | `oauth_clients.py:312` | yes | yes | no |
| Edit client scopes | `oauth_clients.py:384` | yes | yes | no |
| Edit allowed_ips / allowed_servers | `oauth_clients.py:647` | yes | yes | no |
| **Enable global OAuth (`/oauth-clients/enable`)** | `oauth_clients.py:526` | yes | no | no |

### Zabbix servers

| Action | View | admin | operator | viewer |
|---|---|---|---|---|
| List servers (`/servers`) | `servers.py` (require_auth) | yes | yes | yes |
| Create server | `servers.py:159` | yes | no | no |
| Edit server | `servers.py:239` | yes | no | no |
| Delete server | `servers.py:401` | yes | no | no |
| Test connection | `servers.py:522` | yes | no | no |
| Set default server | `servers.py:553` | yes | no | no |

### Settings

| Action | View | admin | operator | viewer |
|---|---|---|---|---|
| View settings (`/settings`) | `settings.py` (require_auth) | yes | yes | yes |
| Edit non-admin sections (TLS, OAuth, audit, ...) | `settings.py:258` | yes | yes | no |
| Edit `min_role = "admin"` sections | `settings.py:267` | yes | no | no |

### Templates (report templates)

| Action | View | admin | operator | viewer |
|---|---|---|---|---|
| List templates | `templates.py` (require_auth) | yes | yes | yes |
| Create / edit template | `templates.py:151,263,347` | yes | yes | no |
| Manage templates (move, reorder) | `templates.py:561` | yes | yes | no |
| Delete template | `templates.py:669` | yes | no | no |
| Bulk delete templates | `templates.py:718` | yes | no | no |

### Uploads (logos, signing keys, ...)

| Action | View | admin | operator | viewer |
|---|---|---|---|---|
| List uploads (`/uploads`) | `uploads.py:87` | yes | yes | no |
| Upload file | `uploads.py:87` | yes | yes | no |
| Delete upload | `uploads.py:170` | yes | no | no |
| Bulk delete uploads | `uploads.py:232` | yes | no | no |

### Wizard

| Action | View | admin | operator | viewer |
|---|---|---|---|---|
| Run wizard (`/wizard`) | `wizard.py` (require_auth) | yes | yes | yes |
| Wizard create-token step | `wizard.py:537` | yes | yes | no |

### Audit log

| Action | View | admin | operator | viewer |
|---|---|---|---|---|
| View audit log (`/audit`) | `audit.py:83` (require_auth) | yes | yes | yes |
| Export audit log (`/audit/export`) | `audit.py:157` (require_auth) | yes | yes | yes |

### Modules / dashboard

| Action | View | admin | operator | viewer |
|---|---|---|---|---|
| Dashboard (`/`) | `dashboard.py` (require_auth) | yes | yes | yes |
| Modules list (`/modules`) | `modules.py:35` (require_auth) | yes | yes | yes |

## Notes for reviewers

- **Token create vs delete asymmetry.** Operators can create tokens
  (`tokens.py:192`) but not delete them (`tokens.py:641`). This is
  intentional: token deletion is a destructive cleanup action that an
  admin signs off on; operators day-to-day issue + revoke via OAuth
  Clients (which they CAN do). If your environment treats tokens as
  fully operator-owned, raise the `tokens.py:641` gate to operator.

- **Template delete vs edit asymmetry.** Same shape as tokens:
  operators can edit + manage but not delete report templates. Delete
  is admin-only because losing a template can break a scheduled
  report run.

- **Audit log is viewer-readable.** All three roles can read
  `/audit` and export it. This is by design (the viewer role exists
  exactly for compliance + observability use cases) but operators
  should know there is no "redact for viewer" path - the operator
  log is the same bytes the viewer sees.

- **OAuth enable is admin-only.** Flipping `[oauth].enabled` is a
  global posture change with security implications (introduces a new
  authentication surface), so it stays admin-only even though
  managing clients afterwards is operator-level.

## How to extend

Adding a new role check:

1. Pick the right gate shape:
   - `session.role != "admin"` - admin only
   - `session.role not in ("admin", "operator")` - admin or operator
   - `session.role == "viewer"` - viewer-only block (admin + operator can)
2. Always pair the role gate with `require_auth` first - the role
   check assumes a session object exists.
3. Update the matrix in this file. The matrix is the contract; if a
   PR changes a role gate without updating this file, it is review
   feedback to ask for the matrix entry.
4. Add a row to the audit log explaining the access denial when the
   gate trips - operators rely on the audit log to debug "why was
   user X denied".
