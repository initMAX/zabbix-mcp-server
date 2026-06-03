# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Zabbix MCP Server, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, contact us directly:

- **Email:** [info@initmax.com](mailto:info@initmax.com)
- **Subject:** `[SECURITY] Zabbix MCP Server — <brief description>`

We will acknowledge your report within 48 hours and work with you on a fix.

## Security Considerations

### MCP Token Authentication

- Multi-token support via `[tokens.*]` sections in `config.toml` — each token is a named entry with independent permissions
- Tokens stored as SHA-256 hashes — raw tokens shown only once at creation, never stored
- **Scopes** — restrict which tool groups a token can access (e.g. `monitoring`, `alerts`)
- **Server binding** — restrict which Zabbix servers a token can reach (`allowed_servers`)
- **IP allowlist** — restrict token usage to specific IPs or CIDR ranges (`allowed_ips`)
- **Expiry** — set `expires_at` (ISO 8601) for automatic token expiration
- **Read-only flag** — per-token write protection independent of server-level `read_only`
- **Revocation** — tokens can be revoked instantly via the admin portal; revoked tokens are rejected immediately
- Legacy `auth_token` automatically migrated to `[tokens.legacy]` on first v1.16 start

### Zabbix API Tokens

- Zabbix API tokens stored in `config.toml` should be protected with file permissions (`chmod 600`)
- The install script sets these permissions automatically — config directory is `chmod 750`
- Use environment variable references (`${ENV_VAR}`) to avoid storing tokens in plain text
- Tokens inherit the permissions of the Zabbix user they belong to — use the principle of least privilege

### Admin Portal Security

- Session-based authentication with scrypt password hashing (n=16384, r=8, p=1)
- Session cookies: `HttpOnly`, `SameSite=Strict`, `Secure` (on HTTPS) - prevents XSS and CSRF
- Login rate limiting: 5 attempts per 5 minutes per IP, 30-second lockout
- POST rate limiting: 30 requests per minute per session
- Password policy: minimum 10 characters, at least one uppercase letter and one digit
- Role-based access control: admin (full), operator (tokens/templates), viewer (read-only)
- Jinja2 autoescape enabled on all templates - prevents XSS
- Config write-back uses atomic file operations with `threading.RLock`

### OAuth 2.1 Authorization Server (v1.28+)

- Authorization Code grant + PKCE S256 (mandatory; non-PKCE clients refused at startup)
- RFC 8707 audience binding: every issued access token's `aud` is bound to `[server].public_url`; tokens issued for one MCP deployment cannot be replayed against another
- Dynamic client registration (RFC 7591) - off via `[oauth].dynamic_registration_enabled = false` if you do not want untrusted callers registering clients
- Login rate limit on `/oauth/login`: 5 failed attempts per IP per 5-minute rolling window (parity with admin portal `/login`)
- Login uses the existing `[admin.users.*]` table (scrypt-hashed) - no second identity store
- Authorization codes are one-shot, 10-minute TTL, in-memory
- Refresh tokens rotated on each use (OAuth 2.1 §4.3.1)
- Issuer URL must be HTTPS for non-localhost bindings (RFC 8414); the framework refuses to start otherwise
- Full setup walkthrough including reverse-proxy patterns (Apache, Nginx, Caddy) in [`docs/OAUTH.md`](docs/OAUTH.md)

### Network Security

- The server binds to `127.0.0.1` (localhost) by default — not accessible from the network
- If you bind to `0.0.0.0`, always configure MCP token authentication to protect the endpoint
- Native TLS support — set `tls_cert_file` and `tls_key_file` in config, or use a reverse proxy (nginx, Caddy)
- IP allowlist — set `allowed_hosts` to restrict access to specific IPs or CIDR ranges
- CORS control — set `cors_origins` to restrict which web origins may access the server; omit to disable CORS entirely
- The `rate_limit` config option protects the Zabbix API from being overwhelmed (default: 300 calls/minute per client)
- SSRF prevention — server test endpoint validates URL scheme and resolves DNS to block private/loopback/reserved IPs

### Origin / Host validation (DNS rebinding protection)

Per the MCP 2025-11-25 spec, the server can reject requests whose `Origin` or `Host` header does not match the operator-declared allowlist (returns HTTP 403 / 421 respectively). This blocks DNS rebinding attacks against an MCP endpoint reachable from a browser context.

**Recommended minimum configuration for production**: set `[server].public_url` to the externally-reachable URL of the server, e.g.

```toml
[server]
public_url = "https://mcp.example.com"
```

The host (`mcp.example.com`) is auto-added to the Host allowlist, the origin (`https://mcp.example.com`) to the Origin allowlist, and DNS-rebinding protection flips on. No further config needed for the typical reverse-proxy deployment.

For additional origins (e.g. an internal admin dashboard at a different URL), populate `[server].allowed_origins`:

```toml
allowed_origins = ["https://app.example.com", "https://office.example.com:*"]
```

When `public_url`, `allowed_origins`, and `allowed_hosts` are all unset on a non-localhost bind, protection stays off (backwards compat) and the server logs a startup warning pointing here.

### Read-Only Mode

- Servers are configured as `read_only = true` by default
- This blocks all write operations (create, update, delete, execute) at the MCP server level, including via the `zabbix_raw_api_call` tool
- Per-token `read_only` flag provides additional write protection
- Two-step action approval (`action_prepare` + `action_confirm`) for write operations — 5-minute confirmation window
- Set `read_only = false` only on servers where you explicitly need write access

### File Access and Uploads

- The `source_file` feature (for `configuration.import`) is disabled by default
- To enable it, configure `allowed_import_dirs` with specific directories from which files may be read
- Path traversal is blocked — only files within configured directories are accessible, validated with `Path.is_relative_to()`
- SVG uploads sanitized: script tags, event handlers, javascript: URLs, and dangerous data URIs stripped
- TLS private keys saved with `0600` permissions; TLS directory `0750`
- Report template preview uses `SandboxedEnvironment` — prevents server-side template injection (SSTI)

### Audit Logging

- All admin portal actions logged to `/var/log/zabbix-mcp/audit.log` (JSON lines)
- Tracked actions: login, logout, token CRUD, user CRUD, server CRUD, settings changes, uploads
- Log rotation at 50 MB with backup scheme
- Audit log viewable and exportable (CSV) via admin portal

#### Tool-level audit logging (v2.0.0, [issue #49](https://github.com/initMAX/zabbix-mcp-server/issues/49))

Every MCP tool invocation writes one structured audit row in addition to the admin-portal events above. The schema is **fixed and bounded** so an incident reviewer can grep for "did anyone call tool X targeting host Y" without reconstructing intent from MCP session logs.

Per-tool audit row fields:

- `oauth_subject` - bearer token name (`token:<name>`) or OAuth identity (`oauth:<client_id>:<user>`)
- `mapped_zabbix_user` - operator-set Zabbix user (`[tokens.<id>].zbx_user`) for cross-correlation with the Zabbix-side auditlog
- `mcp_session_id` - MCP streamable-HTTP session id, correlates a sequence of calls inside one client session
- `tool_name` - canonical tool name (with `[server].tool_prefix` stripped)
- `scopes` - granted scopes from the bearer token
- `policy_decision` - one of `allow`, `deny_scope`, `deny_read_only`, `deny_token_invalid`, `deny_token_expired`, `deny_server`, `deny_ip`, `deny_other`, `error`
- `denial_reason` - operator-readable cause when denied
- `target` - bounded resource references the call targeted (`hostid`, `groupid`, `itemid`, `eventid`, ... - never raw kwargs)
- `filters` - bounded filter flags (`severities`, `monitored`, `active_only`, ...)
- `result_count` - bucketed `0` / `1` / `"N"`
- `ip` - client IP from the ASGI middleware

Two streams: an **operator log** at `/var/log/zabbix-mcp/audit.log` carries the full schema; a **client log** at `/var/log/zabbix-mcp/client-audit.log` is a redacted-twice copy that an operator can hand to a connected AI client (Claude Desktop, ChatGPT) for self-review without exposing operator-internal context. The client log drops `oauth_subject`, `mapped_zabbix_user`, `mcp_session_id`, full `denial_reason`, `scopes`, `ip`, and `filters` - keeping only what the AI client itself already knows.

Defence-in-depth redaction at every audit-bound write boundary ([`audit_redactor.py`](plugins/zabbix/zabbix_mcp/admin/audit_redactor.py)):

- **Bounded extractor** ([`audit_extractors.py`](plugins/zabbix/zabbix_mcp/audit_extractors.py)) is the **first** scrub - it splits a tool's kwargs into `target` and `filters` buckets, dropping anything not in the allow-list of resource-reference keys. Even on a denied request, the audit row gets only the resource references the caller targeted (`hostid`, `eventid`, ...), never the full kwargs. A hypothetical `host_create({password: ..., snmp_community: ..., tls_psk: ...})` cannot leak credentials into the audit row even when the call is denied early.
- **Centralised redactor** is the **second** scrub - substring-match denylist at `write_audit` / `write_tool_audit`. Covers passwords, API keys, OAuth tokens, refresh tokens, code verifiers, PKCE verifiers, CSRF tokens, session cookies, MFA / TOTP secrets, HMAC signatures + nonces, Zabbix-specific credentials (TLS-PSK identity + secret, SNMP community strings, LDAP bind passwords, SMTP / webhook secrets, ODBC connection strings). Hash-bearing keys (`token_hash`, `password_hash`, `client_secret_hash`, ...) bypass the denylist with prefix-only retention for correlation.
- **Long-string truncation** at 512 chars keeps the log readable when an LLM accidentally pastes a large blob into a tool argument.

Self-service activity feed: the `audit_self_get` MCP tool exposes an in-memory ring buffer (max 100 entries per subject) of recent client-audit rows so a connected client can pull its own recent invocations without the operator having to share the log file. Cross-client isolation is enforced server-side - each subject sees only its own ring.

OAuth Clients page surfaces a per-client `Last activity` column derived from a 512 KB tail-scan of the audit log on every page render; clients that registered but never invoked a tool show as "never" - prime revocation candidates. The full schema reference, including the bounded `target` / `filters` key sets and the redaction denylist, is documented in [`docs/AUDIT.md`](docs/AUDIT.md).

Negative-test contract for the audit pipeline lives in [`tests/test_audit_negatives.py`](tests/test_audit_negatives.py): scope-deny rows carry the right `policy_decision`; severity-bypass attempts via raw `problem_get` land in `filters` so a reviewer sees what was actually requested; expired tokens fail closed; same-session calls correlate via `oauth_subject + mcp_session_id`; denied requests expose resource references but never raw kwargs.

#### Enterprise audit panel (v2.0.0)

The Settings -> Audit log admin panel mirrors Zabbix's own audit log panel field for field. Four user-visible knobs:

- **Enable audit logging** - master toggle. Off silences `write_audit` / `write_tool_audit` and the `audit_self_get` ring buffer. The toggle change itself is always recorded (action `audit.toggle`) bypassing the gate. Disabling requires typing `DISABLE` in a confirmation field; the admin portal renders a persistent red banner across every page until audit is re-enabled.
- **Log background server events** - on by default. When on, server-side events that happen without an operator action (`housekeeping.cycle`, `forwarder.queue_full`, `forwarder.reconnect`, `system.config_reload`) also land in the audit log. Useful for forensics and to verify the housekeeping daemon is doing its job; turn off when the operator log is noisy and you only want user-driven actions.
- **Enable internal housekeeping** - default on. Daily rotation to `audit.log.YYYY-MM-DD.gz` plus age-based purge per the data storage period. Disable when an external rsyslog / Fluentd / cron job manages rotation.
- **Data storage period** - Zabbix-style time period (`31d` default, `90d`, `1y`, `6h`, ...). Files older than this window are deleted by the housekeeping cycle.

#### External SIEM / syslog forwarder (v2.0.0)

When `[audit.forward].enabled = true`, every audit row written locally is also enqueued for shipping to an external SOC / SIEM. The local audit log files remain the primary source of truth - a drop on the wire never affects them.

Eleven destination protocols across four wire formats:

- **RFC 5424 syslog** over UDP / TCP / TLS
- **CEF** (ArcSight Common Event Format) over UDP / TCP / TLS - for ArcSight, Splunk, Microsoft Sentinel
- **LEEF** (IBM QRadar Log Event Extended Format) over UDP / TCP / TLS
- **JSON** over TCP / TLS - for ELK, Graylog, generic HTTP receivers, Wazuh

TLS uses `ssl.create_default_context()` with strict server-cert validation; an optional `ca_cert` path lets operators trust a private CA without altering the system trust store. TCP / TLS framing is octet-counted per RFC 6587 §3.4.1 (length-prefix + space + message). Reconnect with exponential backoff (1s, 2s, 4s, ... capped at 60s).

Backpressure: the forwarder maintains a bounded in-memory queue (default 10,000 rows) between the audit write path and the worker. When full, the OLDEST entries are dropped first - recent events matter more for incident review than week-old already-aged-out ones. The `messages_dropped_queue_full` counter exposes "SOC is lagging" status to the admin UI.

#### Auditor role (v2.0.0)

A new admin-portal role `auditor` (alongside admin / operator / viewer) is scoped to the audit log surface only. The `_AuditorRoleMiddleware` bounces any non-/audit URL to `/audit` (303) so a SOC / compliance reviewer reads the audit trail without seeing token prefixes, OAuth client metadata, server configuration, or any other admin-sensitive surface. Allowed paths: `/audit`, `/audit/export`, `/`, `/login`, `/logout`, `/static/*`, `/admin/health`, `/mcp-status`, `/api/check-updates`. Everything else redirects to `/audit`.

#### Conservative OAuth DCR profile (v2.0.0, [issue #49](https://github.com/initMAX/zabbix-mcp-server/issues/49) Track B)

`POST /register` (RFC 7591 dynamic client registration) defaults to `[oauth].dcr_profile = "conservative"` in v2.0.0 (was implicit "permissive" before). The conservative profile silently substitutes the operator-configured default scopes when a client tries to register with wildcard scope (`scope = "*"` is recorded with the substitution logged), enforces exact-string redirect URI matching at `/authorize` (no pattern / wildcard allowed), and short-circuits a few other footguns. Operators who need the v1.30 behaviour can opt back in with `dcr_profile = "permissive"`. The consent screen surfaces a danger-styled warning banner when the operator considers granting wildcard scope so the blast radius is unambiguous.

### Plugin Architecture (forthcoming, design-locked in v2.0.0)

v2.0.0 introduces the user-facing surface for the upcoming plugin system (admin sidebar `MCP Modules` section, `/modules` page, `instructions=` MCP hint). The loader itself is not in v2.0.0 - it ships in a follow-up release tracked under [issue #47](https://github.com/initMAX/zabbix-mcp-server/issues/47). The trust model is locked now so external plugin authors and operators can read against a stable contract:

- **Process isolation, not Python import.** Plugins are standalone MCP servers spoken to over stdio (JSON-RPC `MCP 2025-11-25` protocol on stdin/stdout). Each plugin runs as its own subprocess in its own venv (`/opt/zabbix-mcp/plugins/<id>/venv`). A misbehaving or malicious plugin cannot reach into the host's address space, the host's open Zabbix sessions, the OAuth token store, or the admin portal session table. If a plugin crashes or hangs, the host kills its subprocess and surfaces the failure in the admin portal; the rest of the host stays up.
- **Service-user inheritance.** The plugin subprocess inherits the host's `User=` from the systemd unit (default `zabbix-mcp`). Plugins do not run as root. Plugins do not get a separate Linux account by default - operators who need stronger isolation can configure systemd `DynamicUser=yes` per plugin via the loader's optional sandbox profile, but this is opt-in to keep the default install simple.
- **Authn/authz enforced at the host, not in the plugin.** The host (this server) is the trust anchor. The MCP / OAuth token presented by the AI client is validated by the host before any `tools/list` / `tools/call` request is forwarded to a plugin. Plugins do not see and do not need to validate the caller token. A compromised or malicious plugin cannot impersonate the operator to other plugins because the host serialises all tool routing.
- **Tool prefix is the trust label.** Every plugin declares a `tool_prefix` (e.g. `netbox`, `jira`, `fastspring`) in its `plugin.json`. Tools surface to the AI client with that prefix (`netbox__device_get`, `jira__issue_create`). The bundled Zabbix module's prefix is empty by default for backwards compatibility (`host_get` stays `host_get`); operators running a multi-plugin host can opt into the explicit `[server].tool_prefix = "zabbix"` to namespace bundled tools the same way. The host collects all `tool_prefix` values at boot and refuses to start on a collision rather than silently shadowing.
- **Token scopes extend, not replace.** A `[tokens.X].scopes` list keeps its existing semantics (`monitoring`, `alerts`, `users`, ... = bundled Zabbix tool groups). v2.0.0 adds three new scope shapes that compose with the legacy ones: (a) `tool:<canonical_name>` grants exactly one tool (`tool:host_get`), (b) `plugin:<id>.read` grants the read-only surface of one plugin (`plugin:zabbix.read`), and (c) `plugin:<id>.write` grants the read + write surface of one plugin (`plugin:zabbix.write` - subsumes `.read`). The bare `plugin:<id>` form is equivalent to `.write`. Tokens issued before v2.0.0 continue to work unchanged - they simply cannot reach plugin tools because they do not list any `plugin:` / `tool:` scope. The runtime authorization check (`check_token_authorization`) accepts all four shapes simultaneously; the new consent screen lets the operator mix them in one grant (e.g. `plugin:zabbix.read` + `tool:host_create` to grant read access to everything plus one specific write tool).
- **Read-only enforcement.** Plugins declare `read_tools` and `write_tools` lists in `plugin.json` (self-classification at registration time). A token with `read_only = true` is blocked from invoking anything in the plugin's `write_tools` list - the gate runs at the host before the call is forwarded, so a buggy or hostile plugin cannot bypass it by mis-classifying its own tool. The bundled Zabbix module enforces the same check via `read_only` on `[zabbix.X]` and the per-tool method-name pattern (existing v1.30 logic, unchanged).
- **`allowed_servers` is Zabbix-specific.** The `[tokens.X].allowed_servers` field restricts which `[zabbix.X]` instances a token may reach. It does not apply to non-Zabbix plugins - each plugin owns its own targeting model (e.g. `[plugins.netbox.instances.X]`, FastSpring's single API endpoint, ...). Plugin-level targeting belongs to the plugin's own config schema, parsed by the plugin not by the host. The host only enforces plugin-level scope membership; intra-plugin authorisation is the plugin's responsibility.
- **Plugin config lives in a separate file.** Each plugin's runtime config (API keys, instance URLs, plugin-specific options) goes into `/etc/zabbix-mcp/plugins/<id>.toml` with the same `0640 root:zabbix-mcp` permissions as the main `config.toml`. This keeps plugin churn (install / update / disable / remove) from rewriting the operator's main config and lets the operator set per-plugin file permissions if a plugin needs tighter access control (e.g. mode `0600` for a plugin that holds a payments-API key).
- **Audit log records every lifecycle event.** New action types: `plugin.install`, `plugin.enable`, `plugin.disable`, `plugin.update`, `plugin.remove`, plus per-call `plugin.tool_invoke` carrying the plugin id, tool name, and a SHA-256 hash of the arguments (full args are not logged - the same hashing pattern used today for sensitive bundled tools). Existing audit log retention and rotation rules apply unchanged.
- **Plugin source trust.** v1 of the loader installs plugins from a curated `initmax-mcp` catalog (signed manifests, GitHub Actions release artefacts, version pinning). Loading from arbitrary local paths or arbitrary git URLs is allowed but flagged in the admin portal with an "untrusted source" badge so an operator who installs a community fork sees it before tools are exposed to the AI client. Manifest signature verification is part of the loader release, not v2.0.0.
- **What v2.0.0 already enforces (today, not forthcoming).** The MCP server's `instructions=` field advertises plugin extensibility, and the `/modules` admin page lists installed modules. No plugin tools are loaded yet. Until the loader ships, the only "module" registered with the server is the bundled Zabbix integration. v2.0.0 also moves the bundled Zabbix module's source tree under `plugins/zabbix/zabbix_mcp/` (was `src/zabbix_mcp/`) and ships the manifest at `plugins/zabbix/plugin.json` so the bundled module is structurally a plugin even before the loader ships - same shape as future plugins will use. The trust boundaries above are the contract the loader will land against.
- **Bundled-module disable toggle (forthcoming).** The `[modules.<id>]` config schema is documented in v2.0.0 (`[modules.zabbix].enabled = false`) but the `enabled = false` runtime is part of the loader release. v2.0.0 parses the toggle and logs a single info-level message when an operator sets it; the bundled Zabbix module still registers and exposes its tools regardless. This means an operator who anticipates running the host as a pure plugin loader (no bundled Zabbix) can document their intent in `config.toml` ahead of time without breaking v2.0.0.

## Supported Versions

| Version | Supported |
|---|---|
| 2.0.0 (latest) | Yes |
| 1.31 (LTS / patch line) | Yes |
| 1.30 | Yes |
| 1.29 | Yes |
| 1.28 | Yes |
| 1.27 | Yes |
| 1.26 | Yes |
| 1.25 | Yes |
| 1.24 | Yes |
| < 1.24 | No |
