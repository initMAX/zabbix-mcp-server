# Changelog

## v1.0 — 2026-03-29

Initial release.

### Features

- **219 MCP tools** covering all 57 Zabbix API groups
- **Multi-server support** with separate tokens and read-only settings per server
- **HTTP transport** (Streamable HTTP) with optional bearer token authentication
- **Rate limiting** — configurable calls-per-minute to protect Zabbix API
- **Health check** — `health_check` tool to verify server and Zabbix connectivity
- **Generic fallback** — `zabbix_raw_api_call` for any undocumented API method
- **Production deployment** — systemd service, logrotate, dedicated system user
- **One-command install/upgrade** via `deploy/install.sh`
- **Docker support** — multi-stage Dockerfile
- **TOML configuration** with environment variable references for secrets
