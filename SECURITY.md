# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Zabbix MCP Server, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, contact us directly:

- **Email:** [info@initmax.com](mailto:info@initmax.com)
- **Subject:** `[SECURITY] Zabbix MCP Server — <brief description>`

We will acknowledge your report within 48 hours and work with you on a fix.

## Security Considerations

### API Tokens

- Zabbix API tokens stored in `config.toml` should be protected with file permissions (`chmod 600`)
- The install script sets these permissions automatically
- Use environment variable references (`${ENV_VAR}`) to avoid storing tokens in plain text
- Tokens inherit the permissions of the Zabbix user they belong to — use the principle of least privilege

### Network Security

- The server binds to `127.0.0.1` (localhost) by default — not accessible from the network
- If you bind to `0.0.0.0`, always set `auth_token` to protect the endpoint
- Native TLS support — set `tls_cert_file` and `tls_key_file` in config, or use a reverse proxy (nginx, Caddy)
- IP allowlist — set `allowed_hosts` to restrict access to specific IPs or CIDR ranges
- CORS control — set `cors_origins` to restrict which web origins may access the server; omit to disable CORS entirely
- The `rate_limit` config option protects the Zabbix API from being overwhelmed (default: 300 calls/minute per client)

### Read-Only Mode

- Servers are configured as `read_only = true` by default
- This blocks all write operations (create, update, delete, execute) at the MCP server level, including via the `zabbix_raw_api_call` tool
- Set `read_only = false` only on servers where you explicitly need write access

### File Access

- The `source_file` feature (for `configuration.import`) is disabled by default
- To enable it, configure `allowed_import_dirs` with specific directories from which files may be read
- Path traversal is blocked — only files within configured directories are accessible

## Supported Versions

| Version | Supported |
|---|---|
| 1.12 (latest) | Yes |
| 1.11 | Yes |
| < 1.11 | No |
