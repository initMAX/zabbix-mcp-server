# zabbix-mcp-server

Production-quality [MCP](https://modelcontextprotocol.io) server providing **complete coverage of the Zabbix API** (200+ tools across all 53 API groups).

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

**stdio mode** (for Claude Desktop / Claude Code):

```bash
zabbix-mcp-server --config config.toml
```

**HTTP mode** (standalone server):

```bash
zabbix-mcp-server --config config.toml --transport http --port 8080
```

## Integration with Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

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

## Integration with Claude Code

Add to your Claude Code settings:

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
git clone https://github.com/tomashermanek/zabbix-mcp-server.git
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

MIT
