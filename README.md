<!-- *********************************************************************************************************************************** -->
<!-- *** HEADER ************************************************************************************************************************ -->
<!-- *********************************************************************************************************************************** -->
<div align="center">
    <a href="https://www.initmax.com"><img src="./.readme/logo/initMAX_banner.png" alt="initMAX"></a>
    <h3>
        <span>
            Honesty, diligence and MAXimum knowledge of our products is our standard.
        </span>
    </h3>
    <h3>
        <a href="https://www.initmax.com/">
            <img alt="initMAX.com" src="https://img.shields.io/badge/initMAX.com-%20?color=%231f65f4">
        </a>&nbsp;
        <a href="https://www.linkedin.com/company/initmax/">
            <img alt="LinkedIn" src="https://img.shields.io/badge/%20-%20?style=social&logo=linkedin">
        </a>&nbsp;
        <a href="https://www.youtube.com/@initmax1">
            <img alt="YouTube" src="https://img.shields.io/badge/%20-web?style=social&logo=youtube">
        </a>&nbsp;
        <a href="https://www.facebook.com/initmax">
            <img alt="Facebook" src="https://img.shields.io/badge/%20-%20?style=social&logo=facebook">
        </a>&nbsp;
        <a href="https://www.instagram.com/initmax/">
            <img alt="Instagram" src="https://img.shields.io/badge/%20-%20?style=social&logo=instagram">
        </a>&nbsp;
        <a href="https://twitter.com/initmax">
            <img alt="X" src="https://img.shields.io/badge/%20-%20?style=social&logo=x">
        </a>&nbsp;
        <a href="https://github.com/initmax">
            <img alt="GitHub" src="https://img.shields.io/badge/%20-%20?style=social&logo=github">
        </a>
    </h3>
    <h3>
        <a><img src="./.readme/logo/zabbix-premium-partner.png" alt="Zabbix premium partner" width="100"></a>&nbsp;&nbsp;&nbsp;
        <a><img src="./.readme/logo/zabbix-certified-trainer.png" alt="Zabbix certified trainer" width="100"></a>
    </h3>
</div>
<br>
<br>

---
---

<div align="center">
    <h1>
        Zabbix MCP Server
    </h1>
    <h4>
        Production-quality MCP server providing complete coverage of the Zabbix API (219 tools)
    </h4>
</div>
<br>
<br>

## Features

- **Complete API coverage** - Every Zabbix API method (hosts, problems, triggers, templates, users, and 48 more groups) exposed as individual MCP tools
- **Multi-server support** - Configure multiple Zabbix instances (production, staging, etc.) with separate tokens and settings
- **Easy configuration** - Single TOML config file, no scattered env vars
- **Two transports** - stdio (for Claude Desktop / Claude Code) and HTTP (standalone server on a port)
- **Read-only mode** - Per-server write protection to prevent accidental changes
- **Auto-reconnect** - Transparent re-authentication on session expiry
- **Generic fallback** - `zabbix_raw_api_call` tool for any API method not explicitly defined
- **Clean install** - `pip install` / `uvx` / `pipx` - no repo cloning needed

## Quick Start

### 1. Install

```bash
pip install zabbix-mcp-server
```

Or run without installing:

```bash
uvx zabbix-mcp-server --config config.toml
```

### 2. Configure

Create a `config.toml`:

```toml
[server]
transport = "stdio"

[zabbix.production]
url = "https://zabbix.example.com"
api_token = "your-api-token"
read_only = true
verify_ssl = true
```

Get an API token in Zabbix: **User settings > API tokens > Create API token**.

#### Multiple servers

```toml
[zabbix.production]
url = "https://zabbix.example.com"
api_token = "prod-token"
read_only = true

[zabbix.staging]
url = "https://zabbix-staging.example.com"
api_token = "staging-token"
read_only = false
```

#### Environment variable references

```toml
[zabbix.production]
url = "https://zabbix.example.com"
api_token = "${ZABBIX_API_TOKEN}"
```

### 3. Run

**stdio mode** (for Claude Desktop / Claude Code / VS Code / JetBrains):

```bash
zabbix-mcp-server --config config.toml
```

**HTTP mode** (standalone server):

```bash
zabbix-mcp-server --config config.toml --transport http --port 8080
```

## MCP Client Integration

### Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "zabbix": {
      "command": "zabbix-mcp-server",
      "args": ["--config", "/path/to/config.toml"]
    }
  }
}
```

Or with `uvx` (no install needed):

```json
{
  "mcpServers": {
    "zabbix": {
      "command": "uvx",
      "args": ["zabbix-mcp-server", "--config", "/path/to/config.toml"]
    }
  }
}
```

### Claude Code

Add to your Claude Code settings (`.mcp.json` in the project root, or `~/.claude/settings.json` for global):

```json
{
  "mcpServers": {
    "zabbix": {
      "command": "zabbix-mcp-server",
      "args": ["--config", "/path/to/config.toml"]
    }
  }
}
```

### VS Code (Copilot / Continue / Cline)

Add to your VS Code MCP configuration (`.vscode/mcp.json` or the relevant extension settings):

```json
{
  "mcpServers": {
    "zabbix": {
      "command": "zabbix-mcp-server",
      "args": ["--config", "/path/to/config.toml"]
    }
  }
}
```

For HTTP mode, point the extension to:

```
URL: http://localhost:8080/mcp
```

### JetBrains IDEs

Add to your JetBrains MCP configuration:

```json
{
  "mcpServers": {
    "zabbix": {
      "command": "zabbix-mcp-server",
      "args": ["--config", "/path/to/config.toml"]
    }
  }
}
```

For HTTP mode, point the IDE to:

```
URL: http://localhost:8080/mcp
```

### Generic MCP Client

Any MCP-compatible client can connect using one of two transports:

**stdio** - launch the server as a subprocess:

```json
{
  "mcpServers": {
    "zabbix": {
      "command": "zabbix-mcp-server",
      "args": ["--config", "/path/to/config.toml"]
    }
  }
}
```

**HTTP** - connect to a running server:

```
URL: http://localhost:8080/mcp
```

Start the HTTP server with:

```bash
zabbix-mcp-server --config config.toml --transport http --port 8080
```

## Deployment

### Linux Server Deployment with systemd

For production environments, run the MCP server as a systemd service.

#### Install

Use the provided install script to install the server system-wide:

```bash
sudo ./install.sh
```

The install script will:
- Install `zabbix-mcp-server` into a dedicated Python virtual environment
- Place the configuration file at `/etc/zabbix-mcp-server/config.toml`
- Create a systemd service unit
- Set up logrotate

#### systemd Service

After installation, manage the service with standard systemd commands:

```bash
# Start the service
sudo systemctl start zabbix-mcp-server

# Enable on boot
sudo systemctl enable zabbix-mcp-server

# Check status
sudo systemctl status zabbix-mcp-server

# Restart after config changes
sudo systemctl restart zabbix-mcp-server
```

#### Logrotate

The install script configures logrotate automatically. Logs are rotated daily with 14 days of retention. The logrotate configuration is placed at `/etc/logrotate.d/zabbix-mcp-server`.

#### Checking Logs

```bash
# Follow live logs
sudo journalctl -u zabbix-mcp-server -f

# View recent logs
sudo journalctl -u zabbix-mcp-server --since "1 hour ago"

# View logs from the log file (if file logging is configured)
sudo tail -f /var/log/zabbix-mcp-server/zabbix-mcp-server.log
```

## Available Tools

All tools accept an optional `server` parameter to target a specific Zabbix instance (defaults to the first configured server).

### Monitoring
| Tool | Description |
|---|---|
| `problem_get` | Get active problems/alerts (primary alerting tool) |
| `event_get` | Retrieve events |
| `event_acknowledge` | Acknowledge, close, or comment on events |
| `history_get` | Query historical metric data |
| `trend_get` | Query trend (aggregated) data |
| `dashboard_get/create/update/delete` | Manage dashboards |
| `map_get/create/update/delete` | Manage network maps |
| ... | |

### Data Collection
| Tool | Description |
|---|---|
| `host_get/create/update/delete` | Manage monitored hosts |
| `hostgroup_get/create/update/delete` | Manage host groups |
| `item_get/create/update/delete` | Manage data collection items |
| `trigger_get/create/update/delete` | Manage triggers |
| `template_get/create/update/delete` | Manage templates |
| `maintenance_get/create/update/delete` | Manage maintenance periods |
| `configuration_export/import` | Export/import Zabbix configuration |
| ... | |

### Alerts
| Tool | Description |
|---|---|
| `action_get/create/update/delete` | Manage alert actions |
| `alert_get` | Query sent alert history |
| `mediatype_get/create/update/delete` | Manage notification channels |
| `script_execute` | Execute scripts on hosts |
| ... | |

### Users & Access
| Tool | Description |
|---|---|
| `user_get/create/update/delete` | Manage users |
| `usergroup_get/create/update/delete` | Manage user groups |
| `role_get/create/update/delete` | Manage RBAC roles |
| `token_get/create/generate/delete` | Manage API tokens |
| ... | |

### Administration
| Tool | Description |
|---|---|
| `proxy_get/create/update/delete` | Manage proxies |
| `auditlog_get` | Query audit trail |
| `settings_get/update` | Global Zabbix settings |
| `housekeeping_get/update` | Data retention settings |
| ... | |

### Generic
| Tool | Description |
|---|---|
| `zabbix_raw_api_call` | Call any Zabbix API method directly |

## Common tool parameters (get methods)

All `*_get` tools share these parameters:

| Parameter | Description |
|---|---|
| `server` | Target Zabbix server (defaults to first configured) |
| `output` | Fields to return: `extend` (all), or comma-separated names |
| `filter` | Exact match: `{"status": 0}` |
| `search` | Pattern match: `{"name": "web"}` |
| `limit` | Max results |
| `sortfield` | Sort by field |
| `sortorder` | `ASC` or `DESC` |
| `countOutput` | Return count instead of data |

## Configuration Reference

```toml
[server]
transport = "stdio"       # "stdio" or "http"
host = "127.0.0.1"        # HTTP bind address
port = 8080               # HTTP port
log_level = "info"         # debug, info, warning, error

[zabbix.<name>]            # Repeat for each server
url = "https://..."        # Zabbix frontend URL
api_token = "..."          # API token (or "${ENV_VAR}" reference)
read_only = true           # Block write operations (default: true)
verify_ssl = true          # Verify TLS certificates (default: true)
```

## Development

```bash
git clone https://github.com/initmax/zabbix-mcp-server.git
cd zabbix-mcp-server
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Test with MCP Inspector:

```bash
npx @modelcontextprotocol/inspector zabbix-mcp-server --config config.toml
```

## License

AGPL-3.0

<!-- *********************************************************************************************************************************** -->
<!-- *** FOOTER ************************************************************************************************************************ -->
<!-- *********************************************************************************************************************************** -->
<br>
<br>

---
---
<div align="center">
    <h4>
        <a href="https://www.initmax.com/">
            <img alt="initMAX.com" src="https://img.shields.io/badge/initMAX.com-%20?color=%231f65f4">
        </a>&nbsp;&nbsp;
        <a href="tel:+420800244442">
            <img alt="Phone" src="https://img.shields.io/badge/+420%20800%20244%20442-%20?color=%231f65f4">
        </a>&nbsp;&nbsp;
        <a href="mailto:info@initmax.com">
            <img alt="Email" src="https://img.shields.io/badge/info@initmax.com-%20?color=%231f65f4">
        </a>
        <br><br>
        <a href="https://www.linkedin.com/company/initmax/">
            <img alt="LinkedIn" src="https://img.shields.io/badge/%20-%20?style=social&logo=linkedin">
        </a>&nbsp;
        <a href="https://www.youtube.com/@initmax1">
            <img alt="YouTube" src="https://img.shields.io/badge/%20-web?style=social&logo=youtube">
        </a>&nbsp;
        <a href="https://www.facebook.com/initmax">
            <img alt="Facebook" src="https://img.shields.io/badge/%20-%20?style=social&logo=facebook">
        </a>&nbsp;
        <a href="https://www.instagram.com/initmax/">
            <img alt="Instagram" src="https://img.shields.io/badge/%20-%20?style=social&logo=instagram">
        </a>&nbsp;
        <a href="https://twitter.com/initmax">
            <img alt="X" src="https://img.shields.io/badge/%20-%20?style=social&logo=x">
        </a>&nbsp;
        <a href="https://github.com/initmax">
            <img alt="GitHub" src="https://img.shields.io/badge/%20-%20?style=social&logo=github">
        </a>
        <br><br><br>
        <a>
            <img src="./.readme/logo/agplv3.png" width="100">
        </a>
    </h4>
</div>
