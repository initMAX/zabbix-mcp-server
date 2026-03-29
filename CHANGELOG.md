# Changelog

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
