# Changelog

## v1.12 — (unreleased)

### Security

- **`zabbix_raw_api_call` switched from write-suffix blacklist to read-only whitelist** — previously, the raw API call tool blocked write operations by matching a hardcoded list of write suffixes (`.create`, `.update`, `.delete`, etc.); any new Zabbix API method with an unlisted suffix would bypass `read_only` enforcement; now uses a two-layer whitelist: first checks against known read-only methods from tool definitions (`ALL_METHODS`), then falls back to a conservative suffix whitelist (`.get`, `.export`, etc.); unknown methods are blocked by default on read-only servers
- **`source_file` symlink check reordered** — symlink detection now runs before `Path.resolve()` to prevent following symlinks before rejecting them
- **Config validation hardened** — `log_level`, `port` (1–65535), Zabbix server `url` (must start with `http://` or `https://`), and empty `api_token` after env var resolution are now validated at config load time instead of failing at runtime
- **Removed `log_file` path restriction** — the previous `/var/log`, `/tmp`, home directory limitation was unnecessarily restrictive; administrators can now log to any writable path

### Fixed

- **Blocking I/O in async handlers** — all Zabbix API calls (`client_manager.call`, `get_version`, `check_connection`) are now wrapped in `asyncio.to_thread()` to avoid blocking the event loop on HTTP/SSE transports with concurrent clients
- **`int()` crash in delay auto-fill** — if an unrecognized item type string survived enum normalization, `int(params["type"])` would raise `ValueError`; now caught gracefully
- **Hardcoded `user.checkAuthentication` exception** — default `output: extend` was skipped via a hardcoded method name check; now dynamically checks whether the method's parameter list includes an `output` parameter
- **Integration test `test_health.py`** — removed assertions for `version` and `tools` fields that were dropped from the `health_check` tool in v1.11
- **`_normalize_nested_interfaces` / `_normalize_nested_dchecks`** — removed unnecessary shallow copy of params dict on mutation (interfaces/dchecks are mutated in-place)

### Added

- **Zabbix 8.0 support** — added `JSON` value type (`value_type=6`) to enum mappings for item create/update; updated tool descriptions to list JSON as valid value type; Zabbix 8.0 added to compatibility table as experimental (`skip_version_check = true` required)
- **SLA API** — added `sla.get`, `sla.create`, `sla.update`, `sla.delete`, and `sla.getsli` tools for managing Service Level Agreements and retrieving SLI (Service Level Indicator) data (Zabbix 6.0+); total tool count: 225 across 58 API groups

### Improved

- **Parameter sanitization from production logs** — LLMs copying fields from YAML templates caused recurring Zabbix API rejections; the server now auto-strips: `description` from trigger dependencies, `formulaid` from discovery rule filter conditions, `vendor` from template.update, and clears `error_handler_params` when `error_handler` is DEFAULT (0)
- **Uvicorn access logs suppressed** — uvicorn's built-in access log format (`INFO: 10.0.0.1:port - "POST /mcp..."`) was mixing with the app's structured log format, making log parsing difficult; disabled in favor of the app's own request logging
- **`ClientManager.check_connection()`** — new public method for health checks, replacing direct access to private `_get_client()`
- **Dockerfile** — removed redundant `pip install pip`; added `HEALTHCHECK` instruction for container orchestration
- **`pyproject.toml`** — added `Repository` URL to project metadata

## v1.11 — 2026-04-02

### Security

Full adversarial security audit of the entire codebase ([#2](https://github.com/initMAX/zabbix-mcp-server/issues/2)). All findings fixed:

- **Arbitrary file read via `source_file`** — path traversal allowed reading any file on disk (e.g. `/etc/shadow`, `config.toml` with API tokens); `source_file` feature is now **disabled by default** and requires explicit `allowed_import_dirs` whitelist; paths are resolved and validated with `is_relative_to()` to block `../` traversal and symlink escapes
- **`zabbix_raw_api_call` bypassed `read_only`** — write operations (create/update/delete/execute) sent via the generic raw API call tool were not checked against the server's `read_only` setting; write-suffix detection now enforces `check_write()` on all raw calls
- **Timing attack on bearer token** — Python `==` string comparison leaks token length via response timing differences; replaced with `hmac.compare_digest()` for constant-time comparison
- **`getattr()` chain with user-controlled input** — `_do_call` accepted arbitrary attribute paths (e.g. `__class__.__bases__`), enabling potential access to internal Python objects; strict regex validation `^[a-zA-Z]+\.[a-zA-Z]+$` now rejects anything that isn't a valid Zabbix API method name
- **Rate limiter memory exhaustion** — each unique client ID created an unbounded bucket; an attacker could exhaust server memory by sending requests with random client identifiers; hard cap of 1,000 buckets with LRU eviction added; also fixed `sum(1 for _ in ...)` → `len()`
- **Log file path traversal** — `log_file` config accepted any path without validation (e.g. `/etc/cron.d/exploit`); now restricted to `/var/log`, `/tmp`, or the user's home directory
- **Error messages leaked internals** — unhandled exceptions (stack traces, connection strings, internal paths) were returned to MCP clients; replaced with generic `"API call failed — check server logs"` message; full details logged server-side only
- **Health endpoint information disclosure** — unauthenticated `/health` endpoint returned server version and tool count, aiding reconnaissance; now returns only `{"status": "ok"}`; the `health_check` MCP tool no longer exposes server version, tool count, or Zabbix versions — returns only connectivity status
- **`configuration.importcompare` incorrect write flag** — dry-run comparison method was marked `read_only=False`, blocking it on read-only servers even though it makes no changes; corrected to `read_only=True`
- **`extra_params` key injection** — pass-through dict accepted arbitrary keys including `__proto__` or dunder patterns; now validated with `^[a-zA-Z][a-zA-Z0-9_]*$`
- **Dependency version pinning** — `mcp>=1.1.3` and `zabbix-utils>=2.0.2` had no upper bounds, allowing automatic installation of future major versions with potential breaking changes or supply-chain issues; added `<2.0` and `<3.0` caps
- **Default rate limit mismatch** — `load_config` used a hardcoded default of 60 while `ServerConfig` dataclass and `config.example.toml` documented 300; aligned to 300
- **Incomplete `.dockerignore`** — missing exclusions for `config.toml`, `.env*`, `.mcp.json`, `*.key`, `*.pem`, `*.p12`; sensitive files could leak into Docker image layers
- **Incomplete `.gitignore`** — missing patterns for `*.key`, `*.pem`, `*.p12`, `secrets.*`, `credentials.*`, `.env.*`
- **Dockerfile base image unpinned** — `python:3.13-slim` replaced with `python:3.13.5-slim` to prevent silent base image changes
- **Systemd unit insufficient hardening** — added `PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `RestrictSUIDSGID`, `RestrictNamespaces`
- **`install.sh` silent sed failure** — config modification via `sed` could fail silently; added error checking with user warning
- **Symlink bypass in `source_file`** — symbolic links could bypass `allowed_import_dirs` path validation by resolving to targets outside the allowed boundary; `source_file` now rejects symlinks with a clear error message before path resolution

### Added

- **Native TLS/HTTPS** — new `tls_cert_file` and `tls_key_file` config options; when set, the server listens on HTTPS directly via uvicorn SSL support, eliminating the need for a TLS-terminating reverse proxy in simple deployments
- **CORS control** — new `cors_origins` config option; accepts a list of allowed origin URLs (e.g. `["https://app.example.com"]`); when not set, no CORS headers are sent and cross-origin browser requests are blocked (secure default); warns in the server log when wildcard `*` is used
- **IP allowlist** — new `allowed_hosts` config option; accepts IP addresses and CIDR ranges (e.g. `["10.0.0.0/24", "192.168.1.100"]`); enforced as ASGI middleware returning `403 Forbidden` for unlisted IPs; supports both IPv4 and IPv6
- **File import sandbox** — new `allowed_import_dirs` config option; whitelist of directories from which `source_file` may read files; the feature is disabled when this option is not set (secure by default)
- **Security status summary at startup** — on every start the server logs a full security checklist (auth_token, TLS, IP allowlist, CORS, rate limit, read-only, SSL verification, source_file); disabled features are logged as warnings with a final hint listing the exact config keys to adjust
- **Hidden server names in `health_check`** — Zabbix server identifiers are replaced with generic `server_1`, `server_2` labels to prevent leaking internal infrastructure naming
- **Security test suite** — 27 new tests covering path traversal (dot-dot, absolute path, symlink escape), auth bypass (empty token, partial token, null byte injection, case sensitivity), API method injection (`__class__`, double dot, slash, triple part), `extra_params` key injection (`__proto__`, special characters), read-only enforcement, and IP allowlist middleware (reject/allow/invalid CIDR)

### Fixed

- **Duplicate log lines** — when `log_file` pointed to the same file as systemd `StandardError=append`, every line appeared twice; logging now writes only to file when `log_file` is set (skips stderr), or only to stderr when `log_file` is not set
- **Logging configured on root logger** — `logging.basicConfig` added handlers to the root logger causing propagation duplicates; now configures named `zabbix_mcp` and `mcp` loggers directly with `propagate=False` and silences root logger handlers
- **Security status log level** — all startup security summary lines now use WARNING level so the entire block is visible together when filtering logs by severity; the final "all features configured" message uses INFO

### Improved

- **HTTP transport uses uvicorn directly** — for HTTP and SSE transports, the server now builds the ASGI app from FastMCP and runs uvicorn directly, enabling TLS, CORS middleware, and IP allowlist without patching the framework
- **`SECURITY.md` updated** — documents all new security features (TLS, CORS, IP allowlist, file sandbox, read-only enforcement on raw API calls); version table updated
- **Related Projects section in README** — added link to Zabbix AI Skills
- **`.gitignore`** — added `.DS_Store` exclusion

## v1.10 — 2026-03-31

### Added

- **`skip_version_check` config option** — new per-server setting to bypass `zabbix-utils` API version compatibility check; enables connecting to Zabbix versions newer than what the library has been tested with (e.g. Zabbix 8.0)
- **`disabled_tools` config option** — denylist counterpart to `tools`; exclude specific tool groups or prefixes from registration using the same category names (e.g. `disabled_tools = ["users", "administration"]`); applied after the allowlist when both are set
- **`/health` HTTP endpoint** — unauthenticated `GET /health` endpoint returning server status, version, and tool count as JSON; suitable for Docker healthchecks, load balancers, and uptime monitoring
- **Permission hardening guide** — new section in `config.example.toml` explaining how to combine `tools`, `read_only`, and Zabbix User Roles for fine-grained access control; includes a reference of read vs write operation suffixes

### Fixed

- **Docker healthcheck** — replaced `GET /mcp` (returned 406 Not Acceptable) with `GET /health`; the MCP endpoint only accepts POST, so the previous healthcheck always failed
- **Docker networking** — container now explicitly binds to `0.0.0.0` inside Docker via `--host` override, fixing connectivity issues when `host` in `config.toml` was set to `127.0.0.1` (container loopback, unreachable from host)

### Improved

- **Startup log** — transport, host, and port are now logged on a single line for easier troubleshooting

## v1.9 — 2026-03-30

### Added

- **SSE transport** — new `transport = "sse"` option for MCP clients that do not support Streamable HTTP session management (e.g. n8n); authentication via `auth_token` is supported for both HTTP and SSE transports
- **Tool filtering with categories** — new `tools` config option to limit which tools are exposed via MCP; useful when your LLM has a tool limit (e.g. OpenAI max 128 tools); supports five category names that expand into their tool groups:
  - `"monitoring"` — 77 tools (host, item, trigger, problem, event, history, etc.)
  - `"data_collection"` — 27 tools (template, templategroup, dashboard, valuemap, etc.)
  - `"alerts"` — 16 tools (action, alert, mediatype, script)
  - `"users"` — 39 tools (user, usergroup, role, token, usermacro, etc.)
  - `"administration"` — 59 tools (maintenance, proxy, configuration, settings, etc.)
  - Categories and individual tool prefixes can be mixed: `tools = ["monitoring", "template", "action"]`
  - When not set, all ~220 tools are registered (default)
  - `health_check` and `zabbix_raw_api_call` are always registered regardless of this setting
- **`.mcp.json.example`** — example MCP client configuration for VS Code, Claude Code, Cursor, Windsurf and other editors
- **`selectPages` for `dashboard_get`** — new direct parameter to include dashboard pages and widgets in the output without needing `extra_params`

### Fixed

- **`severity_min` on `event_get` / `problem_get`** — Zabbix 7.x dropped `severity_min` in favor of `severities` (integer array); the server now transparently converts `severity_min=3` to `severities=[3,4,5]` so existing tool calls continue to work
- **Response truncation produces valid JSON** — large API responses (>50KB) are now truncated at the data level (removing list items) instead of slicing the JSON string mid-object; truncated responses include `_truncated`, `_total_count`, and `_returned` metadata
- **Preprocessing `sortorder` auto-stripped** — Zabbix API rejects `sortorder` in preprocessing step objects (order is determined by array position); the server now silently removes it before sending
- **Preprocessing `params` list auto-conversion** — when preprocessing params are passed as a list (e.g. from YAML template format `["pattern", "output"]`), the server auto-converts to the newline-joined string format the API expects
- **Auto-fill `delay` for active polling items** — `item_create` / `itemprototype_create` now auto-fill `delay: "1m"` when not provided for active item types (SNMP_AGENT, HTTP_AGENT, SIMPLE_CHECK, etc.); passive types (TRAPPER, DEPENDENT, CALCULATED) are excluded
- **Valuemap name resolution scoped to template** — `valuemap.get` lookup now filters by host/template ID to prevent returning wrong valuemap when multiple templates use the same name; clear error on ambiguity
- **Structured JSON error responses** — all error returns are now `{"error": true, "message": "...", "type": "ErrorType"}` instead of plain strings, enabling programmatic error handling
- **`script_getscriptsbyhosts`** — fixed array parameter handling; Zabbix 7.x expects `[{"hostid": "..."}]` objects, not plain ID arrays
- **`script_getscriptsbyevents`** — same fix for event ID array format
- **`user_checkauthentication`** — no longer injects `output: "extend"` which this method does not accept
- **`usermacro_deleteglobal`** — fixed routing (`.deleteglobal` was not matched by `.delete` check), added `array_param`, and integer ID conversion

### Improved

- **Rate limit 300 calls/minute per client** — increased from 60, now tracked independently per MCP client session so concurrent clients don't compete for the same budget
- **`trigger_get` `min_severity` description** — updated to list symbolic severity names (NOT_CLASSIFIED, INFORMATION, WARNING, AVERAGE, HIGH, DISASTER)

## v1.8 — 2026-03-29

### Added

- **Valuemap assignment by name** — `item_create` / `item_update` / `itemprototype_create` / `itemprototype_update` now accept `"valuemap": {"name": "My Map"}` (same syntax as Zabbix YAML templates); the server resolves the valuemap ID automatically via `valuemap.get`, saving a manual lookup step

- **Smart preprocessing error_handler** — the server now automatically manages `error_handler` and `error_handler_params` on preprocessing steps:
  - **Auto-fill**: steps that support error handling (JSONPATH, REGEX, MULTIPLIER, etc.) but are missing `error_handler` get `error_handler: 0` and `error_handler_params: ""` added automatically — prevents confusing Zabbix API errors about missing required fields
  - **Auto-strip**: steps that don't support error handling (DISCARD_UNCHANGED, DISCARD_UNCHANGED_HEARTBEAT) have `error_handler` and `error_handler_params` removed automatically — prevents "value must be empty" errors
- **`source_file` for configuration.import** — accept a file path (e.g. `"source_file": "/path/to/template.yaml"`) instead of an inline `source` string; the server reads the file and auto-detects format from extension (.yaml/.yml/.xml/.json)
- **UUID validation for configuration.import** — scans `uuid:` fields in import source and validates UUIDv4 format before sending to Zabbix API; returns a clear error message instead of cryptic Zabbix failures
- **Error handler symbolic name aliases** — `CUSTOM_VALUE` (alias for SET_VALUE/2) and `CUSTOM_ERROR` (alias for SET_ERROR/3) now accepted alongside the existing names

## v1.7 — 2026-03-29

### Added

- **Symbolic name normalization for enum fields** — LLMs and users can now use human-readable names instead of numeric IDs in create/update params; the server translates them before sending to the Zabbix API:
  - **Preprocessing step types** — `"type": "JSONPATH"` instead of `"type": 12`, `"DISCARD_UNCHANGED_HEARTBEAT"` instead of `20`, etc. (all 30 types: MULTIPLIER, RTRIM, LTRIM, TRIM, REGEX, BOOL_TO_DECIMAL, OCTAL_TO_DECIMAL, HEX_TO_DECIMAL, SIMPLE_CHANGE, CHANGE_PER_SECOND, XMLPATH, JSONPATH, IN_RANGE, MATCHES_REGEX, NOT_MATCHES_REGEX, CHECK_JSON_ERROR, CHECK_XML_ERROR, CHECK_REGEX_ERROR, DISCARD_UNCHANGED, DISCARD_UNCHANGED_HEARTBEAT, JAVASCRIPT, PROMETHEUS_PATTERN, PROMETHEUS_TO_JSON, CSV_TO_JSON, STR_REPLACE, CHECK_NOT_SUPPORTED, XML_TO_JSON, SNMP_WALK_VALUE, SNMP_WALK_TO_JSON, SNMP_GET_VALUE)
  - **Preprocessing error handlers** — `"error_handler": "DISCARD_VALUE"` instead of `1` (DEFAULT, DISCARD_VALUE, SET_VALUE, SET_ERROR)
  - **Item / item prototype type** — `"type": "HTTP_AGENT"` instead of `19` (ZABBIX_PASSIVE, TRAPPER, SIMPLE_CHECK, INTERNAL, ZABBIX_ACTIVE, WEB_ITEM, EXTERNAL_CHECK, DATABASE_MONITOR, IPMI, SSH, TELNET, CALCULATED, JMX, SNMP_TRAP, DEPENDENT, HTTP_AGENT, SNMP_AGENT, SCRIPT, BROWSER)
  - **Item / item prototype value_type** — `"value_type": "TEXT"` instead of `4` (FLOAT, CHAR, LOG, UNSIGNED, TEXT, BINARY)
  - **Item / item prototype authtype** — `"authtype": "BASIC"` instead of `1` (NONE, BASIC, NTLM, KERBEROS, DIGEST)
  - **Item / item prototype post_type** — `"post_type": "JSON"` instead of `2` (RAW, JSON)
  - **Trigger / trigger prototype priority** — `"priority": "DISASTER"` instead of `5` (NOT_CLASSIFIED, INFORMATION, WARNING, AVERAGE, HIGH, DISASTER)
  - **Host interface type** — `"type": "SNMP"` instead of `2` (AGENT, SNMP, IPMI, JMX)
  - **Media type type** — `"type": "WEBHOOK"` instead of `4` (EMAIL, SCRIPT, SMS, WEBHOOK)
  - **Script type** — `"type": "SSH"` instead of `2` (SCRIPT, IPMI, SSH, TELNET, WEBHOOK, URL)
  - **Script scope** — `"scope": "MANUAL_HOST"` instead of `2` (ACTION_OPERATION, MANUAL_HOST, MANUAL_EVENT)
  - **Script execute_on** — `"execute_on": "SERVER"` instead of `1` (AGENT, SERVER, SERVER_PROXY)
  - **Action eventsource** — `"eventsource": "TRIGGER"` instead of `0` (TRIGGER, DISCOVERY, AUTOREGISTRATION, INTERNAL, SERVICE)
  - **Proxy operating_mode** — `"operating_mode": "ACTIVE"` instead of `0` (ACTIVE, PASSIVE)
  - **User macro type** — `"type": "SECRET"` instead of `1` (TEXT, SECRET, VAULT)
  - **Connector data_type** — `"data_type": "EVENTS"` instead of `1` (ITEM_VALUES, EVENTS)
  - **Role type** — `"type": "ADMIN"` instead of `2` (USER, ADMIN, SUPER_ADMIN, GUEST)
  - **Httptest authentication** — `"authentication": "BASIC"` instead of `1` (NONE, BASIC, NTLM, KERBEROS, DIGEST)
  - **Discovery check type** — `"type": "ICMP"` instead of `12` in dchecks (SSH, LDAP, SMTP, FTP, HTTP, POP, NNTP, IMAP, TCP, ZABBIX_AGENT, SNMPV1, SNMPV2C, ICMP, SNMPV3, HTTPS, TELNET)
  - **Maintenance type** — `"maintenance_type": "NO_DATA"` instead of `1` (DATA_COLLECTION, NO_DATA)
- **Nested interfaces normalization** — symbolic type names (AGENT, SNMP, IPMI, JMX) are resolved inside the `interfaces` array in `host.create` / `host.update` params
- **Nested dchecks normalization** — symbolic type names (ICMP, HTTP, ZABBIX_AGENT, etc.) are resolved inside the `dchecks` array in `drule.create` / `drule.update` params
- **Auto-wrap single objects into arrays** — when an LLM sends a dict where the Zabbix API expects an array (e.g. `"groups": {"groupid": "1"}` instead of `"groups": [{"groupid": "1"}]`), the server auto-wraps it in a list; applies to `groups`, `templates`, `tags`, `interfaces`, `macros`, `preprocessing`, `dchecks`, `timeperiods`, `steps`, `operations`, and more
- **Default `output` to `"extend"` for get methods** — get methods now return full objects by default instead of just IDs; saves LLMs from having to specify `output: "extend"` on every call; skipped when `countOutput` is set
- **`extra_params` for all get methods** — new optional `extra_params: dict` parameter on every `*.get` tool, merged into the API request as-is; enables `selectXxx` parameters (e.g. `selectPreprocessing`, `selectTags`, `selectInterfaces`, `selectHosts`) and any other Zabbix API parameters not covered by the typed fields
- **ISO 8601 timestamp auto-conversion** — LLMs can now send human-readable datetime strings (e.g. `"active_since": "2026-04-01T08:00:00"`) instead of Unix timestamps; the server auto-converts for known fields: `active_since`, `active_till`, `time_from`, `time_till`, `expires_at`, `clock`; supports formats with/without timezone, T separator, date-only; works in both create/update params and get method parameters
- **Updated tool descriptions** — create/update tools for items, triggers, host interfaces, media types, scripts, actions, proxies, user macros, connectors, roles, web scenarios, discovery rules, and maintenance now list accepted symbolic names in their descriptions, so LLMs use them automatically

## v1.6 — 2026-03-29

### Fixed

- **Array-based API methods broken** — `_do_call` used `obj(**params)` which crashes on list params; `.delete` methods, `history.clear`, `user.unblock`, `user.resettotp`, `token.generate` now correctly pass arrays to the Zabbix API
- **`history.clear`** — changed from `params: dict` to `itemids: list[str]`; added TimescaleDB note in description
- **`history.push`** — changed from `params: dict` to `items: list` (array of history objects)
- **`user.unblock` / `user.resettotp` / `token.generate`** — were sending `{"userids": [...]}` instead of the plain array the API expects

### Added

- `array_param` field on `MethodDef` — declarative way to mark methods that need a plain array passed to the Zabbix API
- `list` type in `_PYTHON_TYPES` for array-of-objects parameters

## v1.5 — 2026-03-29

### Fixed

- **`configuration.import` rules normalization** — LLMs generate inconsistent rule key names; the server now auto-normalizes them to match the Zabbix API:
  - snake_case → camelCase for most keys (e.g. `discovery_rules` → `discoveryRules`)
  - `hostGroups`/`templateGroups` → `host_groups`/`template_groups` (Zabbix >=6.2 expects snake_case for these)
  - Version-aware group handling: `groups` ↔ `host_groups` + `template_groups` based on the target Zabbix server version (split at 6.2)

## v1.3 — 2026-03-29

### Fixed

- **`health_check` serialization error** — `api_version()` returns an `APIVersion` object which is not JSON-serializable; cast to `str` before `json.dumps`

## v1.2 — 2026-03-29

### Fixed

- **Auth startup crash** — FastMCP requires `AuthSettings` alongside `token_verifier`, added missing `issuer_url` and `resource_server_url`
- **`host`/`port` not applied** — parameters were passed to `FastMCP.run()` instead of the constructor, causing them to be ignored
- **systemd unit overriding config** — removed hardcoded `--transport`, `--host`, `--port` flags from the unit file; all settings now come from `config.toml`
- **Log file permissions** — install script already set correct ownership, but running the server as root before the first systemd start could create `server.log` owned by root; documented in troubleshooting
- **Upgrade notice** — update command now confirms config was preserved and hints to check `config.example.toml` for new parameters
- **Duplicate log lines** — logging handlers were being added twice (stderr + file both duplicated)

## v1.1 — 2026-03-29

### Added

- **Rate limiting** — sliding window rate limiter (calls/minute), configurable via `rate_limit` in config (default: 60, set to 0 to disable)
- **Health check** — `health_check` tool to verify MCP server status and Zabbix connectivity
- **Dockerfile** — multi-stage build, non-root user, ready for container deployment
- **Smoke tests** — 25 tests covering config, client, auth, rate limiter, API registry, and tool registration
- **CHANGELOG.md**

### Changed

- Bearer token authentication for HTTP transport
- `install.sh` handles missing systemctl gracefully (containers, WSL)
- Config example: all parameters documented with detailed comments
- README: unified MCP client config section, added ChatGPT widget and Codex

### Fixed

- Version aligned to release tag format (`1.0` → `1.1`)
- Removed unused local social icon files from `.readme/logo/`

## v1.0 — 2026-03-29

Initial release.

### Features

- **219 MCP tools** covering all 57 Zabbix API groups
- **Multi-server support** with separate tokens and read-only settings per server
- **HTTP transport** (Streamable HTTP) as default
- **Generic fallback** — `zabbix_raw_api_call` for any undocumented API method
- **Production deployment** — systemd service, logrotate, dedicated system user
- **One-command install/upgrade** via `deploy/install.sh`
- **TOML configuration** with environment variable references for secrets
- **initMAX branding** — header/footer matching Zabbix-Templates style
- **AGPL-3.0 license**
