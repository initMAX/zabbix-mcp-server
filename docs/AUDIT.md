# Audit log

The Zabbix MCP server writes two audit streams: an operator-facing log
and a redacted client-facing log. Both are JSON Lines files. This
document is the contract for the schema, redaction rules, and the
sensitive-key denylist.

The audit log is **the** evidence trail for incident review - it
answers "who called what, with what scope, what happened, and what
came back". Every tool invocation, every OAuth event, every admin
portal action lands in `audit.log`. This is issue [#49](https://github.com/initMAX/zabbix-mcp-server/issues/49)
hardening territory.

## File layout

```
/var/log/zabbix-mcp/
├── audit.log              # operator stream (full context)
├── audit.log.1            # rotated backup (50 MB threshold)
├── audit.log.2            # second rotation generation
├── client-audit.log       # redacted client stream
├── client-audit.log.1
└── client-audit.log.2
```

Both files are JSON Lines. Each line is a single complete JSON
object. Append-only writes; rotation is triggered at 50 MB and
preserves the last two rotations (`.1`, `.2`).

## Operator stream (`audit.log`)

Every line is one of two row types: an **admin/OAuth event** or a
**tool invocation**. The schema differs slightly by row type because
admin events carry `target_type` / `target_id` while tool invocations
carry `oauth_subject` / `mapped_zabbix_user` etc.

### Tool invocation row (issue #49 Phase 1)

```json
{
  "timestamp": "2026-05-09 21:43:17",
  "action": "tool.invoke",
  "oauth_subject": "token:CI Pipeline",
  "mapped_zabbix_user": "Admin",
  "mcp_session_id": "f4f1d6e2-2b8c-...",
  "tool_name": "host_get",
  "scopes": ["plugin:zabbix.read"],
  "policy_decision": "allow",
  "denial_reason": null,
  "target": {"hostids": ["10084"]},
  "filters": {"output": "extend"},
  "result_count": 1,
  "ip": "192.168.10.42"
}
```

Fields:

| Field | Meaning |
|---|---|
| `timestamp` | Server-clock UTC, `YYYY-MM-DD HH:MM:SS`. |
| `action` | Always `"tool.invoke"` for tool rows. |
| `oauth_subject` | `token:<name>` for legacy bearer tokens, `oauth:<client_id>:<user>` for OAuth-bound calls, `anonymous` when no token in context. |
| `mapped_zabbix_user` | Operator-set Zabbix user (`[tokens.<id>] zbx_user = "Admin"`). `null` when not configured. Lets a reviewer correlate with the Zabbix-side auditlog. |
| `mcp_session_id` | MCP streamable-HTTP session id (from `mcp-session-id` header). Correlates a sequence of calls inside one client session. |
| `tool_name` | Canonical tool name (e.g. `host_get`, `problem_active_get`, `zabbix_raw_api_call`). The `[server].tool_prefix` is stripped before logging. |
| `scopes` | Granted scopes from the bearer token (`["plugin:zabbix.read"]`, `["monitoring", "alerts"]`, `["*"]`, ...). |
| `policy_decision` | One of `allow`, `deny_scope`, `deny_read_only`, `deny_token_invalid`, `deny_token_expired`, `deny_server`, `deny_ip`, `deny_other`, `error`. |
| `denial_reason` | Operator-readable cause when `policy_decision != "allow"`. `null` on allow. |
| `target` | Bounded resource references the call targeted: `hostid`, `hostids`, `groupid`, `itemid`, `triggerid`, `eventid`, ... See [Bounded `target` keys](#bounded-target-keys). |
| `filters` | Bounded filter flags: `severities`, `monitored`, `active_only`, `recent`, `output`, `limit`, `period`, ... See [Bounded `filters` keys](#bounded-filters-keys). |
| `result_count` | `0`, `1`, or `"N"` for >1 (numeric for the small cases, string `"N"` for many). `null` on deny + when the cardinality cannot be inferred. |
| `ip` | Client IP captured by the ASGI middleware (respects `[server].trusted_proxies` for `X-Forwarded-For`). |

### Admin / OAuth event row

```json
{
  "timestamp": "2026-05-09 21:42:01",
  "action": "consent_granted",
  "user": "admin",
  "target_type": "oauth_client",
  "target_id": "f4f1...",
  "details": {
    "scope": "plugin:zabbix.read",
    "redirect_uri": "https://chatgpt.com/aip/g-...",
    "client_id_short": "f4f1"
  },
  "ip": "192.168.10.42"
}
```

Action types include `login_success`, `login_failed`, `logout`,
`token_create`, `token_revoke`, `oauth_client.revoke`, `consent_granted`,
`token_family_revoked`, `settings_change`, `server_create`, plus more
- see [`audit_writer.py`](../plugins/zabbix/zabbix_mcp/admin/audit_writer.py)
call sites.

The `details` payload routes through the redactor (see
[Redaction rules](#redaction-rules)) so credentials never land here.

## Client stream (`client-audit.log`)

A redacted-twice copy of every `tool.invoke` row. The client stream
exists so an operator can hand the file to the connected AI client
(Claude Desktop, ChatGPT, an automation script) for self-review
without exposing operator-internal details (full denial reasons,
bound IP, mapped Zabbix user).

```json
{
  "timestamp": "2026-05-09 21:43:17",
  "tool": "host_get",
  "decision": "allow",
  "denial_bucket": null,
  "result_count": 1,
  "target": {"hostids": ["10084"]}
}
```

Fields:

| Field | Meaning |
|---|---|
| `timestamp` | Same as operator row. |
| `tool` | Canonical tool name. |
| `decision` | Same as `policy_decision` on operator row. |
| `denial_bucket` | High-level category - `scope`, `read_only`, `auth`, `server`, `other` - or `null` on allow. **Does not** carry the operator-readable `denial_reason`. |
| `result_count` | Same bucketing as operator row. |
| `target` | Same bounded resource references as operator row. |

The client stream **deliberately omits**: `oauth_subject`,
`mapped_zabbix_user`, `mcp_session_id`, full `denial_reason`,
`scopes`, `ip`, `filters`. Those are operator-side context.

## In-memory ring buffer (`audit_self_get` tool)

In addition to the file logs, the server keeps a per-subject
in-memory ring buffer of the last 100 client-audit rows. The
`audit_self_get` MCP tool reads from this buffer so a client can
fetch its own recent activity without the operator handing over the
file.

- Bounded at 100 entries per subject.
- Reset on server restart (no persistence).
- Cross-client isolation enforced by subject key - each token sees
  only its own ring.
- Returns newest-first.

A client asking for longer history asks the operator to share
`client-audit.log` directly.

## Bounded `target` keys

Per issue #49 reviewer feedback (@musaabhasan): every audit row
schema is **fixed and bounded**. The `target` object only ever
carries resource references that are non-sensitive Zabbix object
handles. Anything else (passwords, user macros, command arguments,
custom inventory) is dropped at the extractor before the row is
emitted - even on a denied request.

Recognised target keys (from [`audit_extractors.py`](../plugins/zabbix/zabbix_mcp/audit_extractors.py)):

```
hostid, hostids, host, groupids, groupid, templateids, templateid,
hostinterfaceid, hostinterfaceids, interfaceid, interfaceids,
itemid, itemids, triggerid, triggerids, graphid, graphids,
discoveryruleid, discoveryruleids, ruleid, ruleids,
itemprototypeid, triggerprototypeid, graphprototypeid, hostprototypeid,
eventid, eventids, problemid, problemids, actionid, actionids,
userid, userids, roleid, usrgrpid, usrgrpids,
user_tokenid, tokenid, tokenids, mfaid,
sysmapid, sysmapids, dashboardid, dashboardids, templatedashboardid,
templategroupid, templategroupids,
maintenanceid, maintenanceids, proxyid, proxyids, proxygroupid,
scriptid, scriptids, mediatypeid, mediatypeids,
iconmapid, imageid, regexpid, valuemapid,
connectorid, correlationid, slaid,
reportid, reportids,
server
```

For `zabbix_raw_api_call`, the API method name is surfaced as
`api_method` so a grep can answer "who called `host.create` via the
raw escape hatch?".

## Bounded `filters` keys

```
severities, severity, status, active_only, monitored, recent,
filter, search, searchByAny, searchWildcardsEnabled,
limit, countOutput, output, sortField, sortOrder,
period, time_from, time_till, history, trends,
with_items, with_triggers, with_graphs, with_httptests
```

These describe **what the caller asked for**, not what they sent.
Severity floors, time windows, status flags, search patterns - all
non-secret, all review-relevant.

## Redaction rules

Every audit-bound payload routes through [`audit_redactor.py`](../plugins/zabbix/zabbix_mcp/admin/audit_redactor.py)
at the `write_audit` / `write_tool_audit` boundary. Adding a new
sensitive field type is one edit there, not a sweep through call
sites.

Three layers:

1. **Key denylist** (case-insensitive, substring match). Replaces the
   value with `[REDACTED]`. Drops:
   - `password`, `passwd`, `secret`, `api_key`, `apikey`
   - `code_verifier`, `verifier`, `pkce`
   - `refresh_token`, `access_token`, `auth_token`, `raw_token`, `bearer`
   - `private_key`, `privkey`, `frontend_password`
   - `zbx_session`, `session_cookie`, `cookie`, `csrf`
   - `mfa_code`, `totp`, `otp_code`, `totp_secret`
   - `signature`, `nonce`
   - `tls_psk`, `psk_identity`
   - `snmp_community`, `community`
   - `bind_password`, `smtp_password`, `smtp_secret`
   - `webhook_secret`, `webhook_token`
   - `connect_string`, `connection_string`, `dsn`

2. **Hash-key allowlist**: a few keys legitimately carry SHA-256
   digests, not raw secrets. Their values are kept but truncated to
   the first 16 chars for correlation. Allowed: `token_hash`,
   `password_hash`, `client_secret_hash`, `secret_hash`,
   `oauth_token_hash`, `refresh_token_hash`.

3. **Long-string truncation**: any string >512 chars is truncated
   with `... [truncated, N more chars]`. Keeps the audit log
   readable when an LLM accidentally pastes a large blob.

The redactor is **defensive** - unknown keys pass through
unchanged. The denylist is the only source of truth for what gets
dropped, checked against case-insensitive substring of the lower-cased
key name to catch typos and camelCase variants (`apiKey`, `API_KEY`,
`api_key`).

## Defence in depth: extractor + redactor

The audit pipeline applies redaction at **two** boundaries:

```
tool kwargs
    │
    ▼
audit_extractors.extract()      ◄── drops anything not in TARGET_KEYS / FILTER_KEYS
    │   (target, filters)
    ▼
write_tool_audit()
    │
    ▼
redact()                        ◄── second-pass denylist on what survived extraction
    │
    ▼
operator audit row
    │
    ▼
client_entry (re-built)
    │
    ▼
redact()                        ◄── third-pass on the client-side row
    │
    ▼
client audit row
```

This means a kwarg like `password` on a hypothetical `host_create`
call gets dropped twice: once because it is not in the TARGET / FILTER
key set (extractor), and once because the redactor's denylist would
strip it even if it had been in the key set. Adding a new
secret-bearing field name to the denylist takes a single edit and is
defence-in-depth even if a future extractor change accidentally
includes the key.

## Negative-test contract

Issue #49 ships with negative tests in [`tests/test_audit_negatives.py`](../tests/test_audit_negatives.py)
covering the audit guarantees:

1. **Scope deny gets logged.** A `monitoring`-scope token calling
   `event_acknowledge` produces an audit row with
   `policy_decision = "deny_scope"`.
2. **Severity-bypass is recorded.** A call to raw `problem_get` with
   `severities=[0,1]` is logged with `filters.severities = [0, 1]`
   so the reviewer sees what was actually requested.
3. **Expired tokens fail closed.** An expired bearer returns 401 with
   `WWW-Authenticate: Bearer error="invalid_token"`; the audit row
   carries `policy_decision = "deny_token_invalid"`.
4. **Correlation key holds.** Two calls in the same MCP session share
   the same `oauth_subject` and `mcp_session_id`.
5. **Denied requests do not leak args.** A denied tool call's audit
   row carries `target.<resource_id>` but **not** the raw kwargs -
   the extractor drops everything not in TARGET / FILTER keys, and the
   redactor's denylist provides defence-in-depth.

## Settings -> Audit log admin panel

Mirrors the Zabbix admin-panel "Audit log" UX 1:1 (same field names,
same defaults, same Reset defaults semantics):

| Field | What it does |
|---|---|
| `Enable audit logging` | Master toggle. Off -> no rows are written to either audit.log or client-audit.log; the in-memory ring buffer for `audit_self_get` also stops accepting pushes. The toggle change itself is always recorded (action `audit.toggle`). Disabling requires typing `DISABLE` in a confirmation field. |
| `Log background server events` | Default on. When on, server-side events that happen without an operator action (`housekeeping.cycle`, `forwarder.queue_full`, `forwarder.reconnect`, `system.config_reload`, ...) also land in the audit log. Useful for forensics and to verify the housekeeping daemon is doing its job. Turn off when the operator log is noisy and you only want user-driven actions. |
| `Enable internal housekeeping` | Default on. When on, the server itself does daily rotation + age-based purge. Disable when an external rsyslog / Fluentd / cron job manages rotation. |
| `Data storage period` | Zabbix time period (`31d` default, `90d`, `1y`, `6h`, ...). Files older than this window are deleted by the housekeeping cycle. `0` disables time-based purge (size-based rotation still applies). |
| `Max file size` (MB) | Per-file rotation threshold. When the live audit.log grows past this, it is archived under today's date and a new live file starts. Default 50 MB. |

Persistent danger banner: while audit is disabled, a red banner
appears on every admin-portal page so the operator cannot forget
they are running without an audit trail.

## Daily rotation + retention purge (housekeeping)

When `housekeeping_enabled` is true, a background daemon runs every
60 seconds and performs three steps per audit log file:

1. **Size rotation.** If the live file is larger than `max_file_size_bytes`,
   archive it under today's date as `audit.log.YYYY-MM-DD.gz` (gzip).
2. **Daily rotation.** If the live file has any content and we have not
   archived today yet, do the same archive step. Same-day archives are
   appended (gzip member concatenation, valid per RFC 1952 §2.2).
3. **Age purge.** Walk the directory; delete any
   `audit.log.YYYY-MM-DD.gz` whose mtime is older than
   `retention_seconds`. The live file and the legacy `.1` / `.2`
   rotation backups are left alone.

A summary line is emitted as a `housekeeping.cycle` audit event when
`log_background_events` is on so the operator can see the daemon working.

## External SIEM / syslog forwarder

When `[audit.forward].enabled = true`, every audit row written
locally is also enqueued for shipping to an external SOC / SIEM. The
local audit log files are the **primary** source of truth - a drop
or reconnect on the wire never affects them.

Eleven destination protocols across four wire formats:

| Wire format | Transport | Use case |
|---|---|---|
| `rfc5424_udp` / `_tcp` / `_tls` | Standard syslog | Generic syslog daemon, rsyslog, syslog-ng |
| `cef_udp` / `_tcp` / `_tls` | ArcSight Common Event Format | Splunk Universal Forwarder, Microsoft Sentinel, ArcSight |
| `leef_udp` / `_tcp` / `_tls` | IBM QRadar Log Event Extended Format | IBM QRadar |
| `json_tcp` / `_tls` | Newline-delimited JSON wrapped in syslog framing | ELK, Graylog, generic HTTP receivers, Wazuh |

Connection management:

- **UDP** is fire-and-forget; the OS may drop datagrams silently
  under load. Acceptable on a LAN to a known receiver, less so for
  cross-WAN or cloud SIEM destinations.
- **TCP** delivers in order with octet-counted framing per RFC 6587
  §3.4.1 (length-prefix + space + message). Reconnect with
  exponential backoff (1s, 2s, 4s, ... capped at 60s) on drop.
- **TLS** is TCP with `ssl.create_default_context()`. An optional
  `ca_cert` path lets operators trust a private CA without altering
  the system trust store.

Backpressure: the forwarder maintains a bounded in-memory queue
(default 10,000 rows) between the audit write path and the worker
thread. When the queue fills, the OLDEST entries are dropped first -
recent events matter more for incident review than week-old already-
aged-out ones. A `messages_dropped_queue_full` counter is exposed in
the admin UI status indicator so the operator notices when their SOC
is lagging.

Live status surface in Settings -> External SIEM forwarding:

- Connection state: `connected` / `connecting` / `disconnected` /
  `stopped`
- Queue depth + capacity
- Counters: messages sent, messages failed, queue overflow drops
- Last successful send timestamp + last error message + error
  timestamp

## Auditor role

A new admin-portal role ``auditor`` (alongside admin / operator /
viewer) is scoped to the audit log surface only. The
``_AuditorRoleMiddleware`` bounces any non-/audit URL to /audit
(303). Operators, viewers, and admins who also need to read the
audit log keep their existing access; the auditor role is for SOC /
compliance reviewers who must NOT see token prefixes, OAuth client
metadata, server configuration, or any other admin-sensitive
surface.

Allowed paths for an auditor session:

- `/audit` - audit log viewer + filters
- `/audit/export` - audit log export (CSV)
- `/api/check-updates` - read-only update poll
- `/static/*` - assets
- `/login`, `/logout`, `/admin/health`, `/mcp-status` - infra
- `/` - dashboard

Any other URL redirects to `/audit`.

## See also

- [SECURITY.md](../SECURITY.md) for the broader threat model and
  the OAuth + token-auth posture.
- [OAUTH.md](OAUTH.md) for the OAuth 2.1 flow specifics.
- [`audit_writer.py`](../plugins/zabbix/zabbix_mcp/admin/audit_writer.py)
  + [`audit_redactor.py`](../plugins/zabbix/zabbix_mcp/admin/audit_redactor.py)
  + [`audit_extractors.py`](../plugins/zabbix/zabbix_mcp/audit_extractors.py)
  + [`audit_forwarder.py`](../plugins/zabbix/zabbix_mcp/admin/audit_forwarder.py)
  for the implementation.
- [ROLES.md](ROLES.md) for who can read the audit log via the admin
  portal.
