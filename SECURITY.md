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
- Use a reverse proxy (nginx, Caddy) with TLS for production deployments exposed to the network
- The `rate_limit` config option protects the Zabbix API from being overwhelmed (default: 60 calls/minute)

### Read-Only Mode

- Servers are configured as `read_only = true` by default
- This blocks all write operations (create, update, delete, execute) at the MCP server level
- Set `read_only = false` only on servers where you explicitly need write access

## Supported Versions

| Version | Supported |
|---|---|
| 1.1 (latest) | Yes |
| < 1.1 | No |
