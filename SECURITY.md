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
- Session cookies: `HttpOnly`, `SameSite=Strict`, `Secure` (on HTTPS) — prevents XSS and CSRF
- Login rate limiting: 5 attempts per 5 minutes per IP, 30-second lockout
- POST rate limiting: 30 requests per minute per session
- Password policy: minimum 10 characters, at least one uppercase letter and one digit
- Role-based access control: admin (full), operator (tokens/templates), viewer (read-only)
- Jinja2 autoescape enabled on all templates — prevents XSS
- Config write-back uses atomic file operations with `threading.RLock`

### Network Security

- The server binds to `127.0.0.1` (localhost) by default — not accessible from the network
- If you bind to `0.0.0.0`, always configure MCP token authentication to protect the endpoint
- Native TLS support — set `tls_cert_file` and `tls_key_file` in config, or use a reverse proxy (nginx, Caddy)
- IP allowlist — set `allowed_hosts` to restrict access to specific IPs or CIDR ranges
- CORS control — set `cors_origins` to restrict which web origins may access the server; omit to disable CORS entirely
- The `rate_limit` config option protects the Zabbix API from being overwhelmed (default: 300 calls/minute per client)
- SSRF prevention — server test endpoint validates URL scheme and resolves DNS to block private/loopback/reserved IPs

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

## Supported Versions

| Version | Supported |
|---|---|
| 1.21 (latest) | Yes |
| 1.20 | Yes |
| 1.19 | Yes |
| 1.18 | Yes |
| < 1.18 | No |
