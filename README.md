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
        <a href="https://www.linkedin.com/company/initmax/">
            <img alt="LinkedIn" src="./.readme/logo/linkedin.png">
        </a>&nbsp;&nbsp;&nbsp;
        <a href="https://www.youtube.com/@initmax1">
            <img alt="YouTube" src="./.readme/logo/youtube.png">
        </a>&nbsp;&nbsp;&nbsp;
        <a href="https://www.facebook.com/initmax">
            <img alt="Facebook" src="./.readme/logo/facebook.png">
        </a>&nbsp;&nbsp;&nbsp;
        <a href="https://www.instagram.com/initmax/">
            <img alt="Instagram" src="./.readme/logo/instagram.png">
        </a>&nbsp;&nbsp;&nbsp;
        <a href="https://x.com/initmax">
            <img alt="X" src="./.readme/logo/x.png">
        </a>&nbsp;&nbsp;&nbsp;
        <a href="https://github.com/initmax">
            <img alt="GitHub" src="./.readme/logo/github.png">
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
        Complete Zabbix API coverage for any MCP-compatible AI assistant (219 tools)
    </h4>
</div>
<br>
<br>

## What is this?

**MCP** ([Model Context Protocol](https://modelcontextprotocol.io)) is an open standard that lets AI assistants (Claude, VS Code Copilot, JetBrains AI, and others) use external tools. This server exposes the **entire Zabbix API** as MCP tools - allowing any compatible AI assistant to query hosts, check problems, manage templates, acknowledge events, and perform any other Zabbix operation.

The server runs as a standalone HTTP service. AI clients connect to it over the network.

## Features

- **Complete API coverage** - All 57 Zabbix API groups (219 tools): hosts, problems, triggers, templates, users, dashboards, and more
- **Multi-server support** - Connect to multiple Zabbix instances (production, staging, ...) with separate tokens
- **Single config file** - One TOML file, no scattered environment variables
- **Read-only mode** - Per-server write protection to prevent accidental changes
- **Auto-reconnect** - Transparent re-authentication on session expiry
- **Production-ready** - systemd service, logrotate, security hardening
- **Generic fallback** - `zabbix_raw_api_call` tool for any API method not explicitly defined

## Quick Start

```bash
git clone https://github.com/initMAX/zabbix-mcp-server.git
cd zabbix-mcp-server
sudo ./deploy/install.sh
sudo nano /etc/zabbix-mcp/config.toml   # fill in your Zabbix URL + API token
sudo systemctl start zabbix-mcp-server
sudo systemctl enable zabbix-mcp-server
```

Done. The server is running on `http://127.0.0.1:8080/mcp`.

## Installation

### Requirements

- Linux server with Python 3.10+
- Network access to your Zabbix server(s)
- Zabbix API token ([User settings > API tokens](https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/user_settings/api_tokens))

### Install

```bash
git clone https://github.com/initMAX/zabbix-mcp-server.git
cd zabbix-mcp-server
sudo ./deploy/install.sh
```

The install script will:
1. Create a dedicated system user `zabbix-mcp` (no login shell)
2. Create a Python virtual environment in `/opt/zabbix-mcp/venv`
3. Install the server and all dependencies
4. Copy the example config to `/etc/zabbix-mcp/config.toml`
5. Install a systemd service unit (`zabbix-mcp-server`)
6. Set up logrotate for `/var/log/zabbix-mcp/*.log` (daily, 30 days retention)

### Upgrade

```bash
cd zabbix-mcp-server
git pull
sudo ./deploy/install.sh update
```

The update command will upgrade the package to the latest version, refresh the systemd unit and logrotate config, and restart the service if it is running.

### Configure

Edit the config file with your Zabbix server details:

```bash
sudo nano /etc/zabbix-mcp/config.toml
```

Minimal configuration - just fill in your Zabbix URL and API token:

```toml
[server]
transport = "http"
host = "127.0.0.1"
port = 8080

[zabbix.production]
url = "https://zabbix.example.com"
api_token = "your-api-token"
read_only = true
verify_ssl = true
```

All available options with detailed descriptions are documented in [`config.example.toml`](config.example.toml).

#### Authentication

The HTTP endpoint can be protected with a bearer token. There are two ways to configure it:

**Option 1** - token directly in config:

```toml
[server]
auth_token = "your-secret-token-here"
```

**Option 2** - token from environment variable (recommended for production):

```toml
[server]
auth_token = "${MCP_AUTH_TOKEN}"
```

When `auth_token` is set, all clients must include it in the `Authorization` header:

```
Authorization: Bearer your-secret-token-here
```

When `auth_token` is not set, the server accepts unauthenticated connections. This is only safe when the server is bound to `127.0.0.1` (default).

#### Multiple Zabbix servers

You can connect to multiple Zabbix instances. Each tool has a `server` parameter to select which one to use (defaults to the first defined):

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

### Start

```bash
sudo systemctl start zabbix-mcp-server
sudo systemctl enable zabbix-mcp-server
```

Verify the server is running:

```bash
sudo systemctl status zabbix-mcp-server
```

### Logs

```bash
# Live log stream
tail -f /var/log/zabbix-mcp/server.log

# Via journalctl
sudo journalctl -u zabbix-mcp-server -f
```

### Manual Installation (pip)

If you prefer to install manually without the deploy script:

```bash
python3 -m venv /opt/zabbix-mcp/venv
/opt/zabbix-mcp/venv/bin/pip install /path/to/zabbix-mcp-server
/opt/zabbix-mcp/venv/bin/zabbix-mcp-server --config /path/to/config.toml
```

## Connecting AI Clients

The server uses the **Streamable HTTP** transport and listens on `http://127.0.0.1:8080/mcp` by default.

**Without authentication:**

```
URL: http://your-server:8080/mcp
```

**With authentication** (when `auth_token` is configured):

```
URL:    http://your-server:8080/mcp
Header: Authorization: Bearer your-secret-token-here
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "zabbix": {
      "url": "http://your-server:8080/mcp"
    }
  }
}
```

### Claude Code

```json
{
  "mcpServers": {
    "zabbix": {
      "url": "http://your-server:8080/mcp"
    }
  }
}
```

### VS Code (Copilot / Continue / Cline)

Add to `.vscode/mcp.json`:

```json
{
  "mcpServers": {
    "zabbix": {
      "url": "http://your-server:8080/mcp"
    }
  }
}
```

### JetBrains IDEs

Add to the MCP server configuration:

```json
{
  "mcpServers": {
    "zabbix": {
      "url": "http://your-server:8080/mcp"
    }
  }
}
```

### Any MCP Client

Any client that supports the MCP Streamable HTTP transport can connect to:

```
http://your-server:8080/mcp
```

## Available Tools

All tools accept an optional `server` parameter to target a specific Zabbix instance (defaults to the first configured server).

### Monitoring
| Tool | Description |
|---|---|
| `problem_get` | Get active problems/alerts (primary alerting tool) |
| `event_get` / `event_acknowledge` | Retrieve and acknowledge events |
| `history_get` / `trend_get` | Query historical and trend data |
| `dashboard_*` / `map_*` | Manage dashboards and network maps |

### Data Collection
| Tool | Description |
|---|---|
| `host_*` / `hostgroup_*` | Manage hosts and host groups |
| `item_*` / `trigger_*` / `graph_*` | Manage items, triggers, graphs |
| `template_*` / `templategroup_*` | Manage templates |
| `maintenance_*` | Manage maintenance periods |
| `discoveryrule_*` / `*prototype_*` | LLD rules and prototypes |
| `configuration_export` / `_import` | Export/import Zabbix configuration |

### Alerts
| Tool | Description |
|---|---|
| `action_*` / `mediatype_*` | Manage actions and notification channels |
| `alert_get` | Query sent alert history |
| `script_execute` | Execute scripts on hosts |

### Users & Access
| Tool | Description |
|---|---|
| `user_*` / `usergroup_*` / `role_*` | Manage users, groups, RBAC roles |
| `token_*` | Manage API tokens |

### Administration
| Tool | Description |
|---|---|
| `proxy_*` / `proxygroup_*` | Manage proxies |
| `auditlog_get` | Query audit trail |
| `settings_get` / `_update` | Global Zabbix settings |

### Generic
| Tool | Description |
|---|---|
| `zabbix_raw_api_call` | Call any Zabbix API method directly |

## Common Parameters (get methods)

| Parameter | Description |
|---|---|
| `server` | Target Zabbix server (defaults to first configured) |
| `output` | Fields to return: `extend` (all), or comma-separated names |
| `filter` | Exact match: `{"status": 0}` |
| `search` | Pattern match: `{"name": "web"}` |
| `limit` | Max results |
| `sortfield` / `sortorder` | Sort by field, `ASC` or `DESC` |
| `countOutput` | Return count instead of data |

## Configuration Reference

```toml
[server]
transport = "http"         # "http" (recommended) or "stdio"
host = "127.0.0.1"        # HTTP bind address
port = 8080               # HTTP port
log_level = "info"         # debug, info, warning, error
log_file = "/var/log/zabbix-mcp/server.log"
# auth_token = "..."      # Bearer token for HTTP auth (or "${ENV_VAR}")

[zabbix.<name>]            # Repeat for each server
url = "https://..."        # Zabbix frontend URL
api_token = "..."          # API token (or "${ENV_VAR}" reference)
read_only = true           # Block write operations (default: true)
verify_ssl = true          # Verify TLS certificates (default: true)
```

## Development

```bash
git clone https://github.com/initMAX/zabbix-mcp-server.git
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

AGPL-3.0 - see [LICENSE](LICENSE).

<!-- *********************************************************************************************************************************** -->
<!-- *** FOOTER ************************************************************************************************************************ -->
<!-- *********************************************************************************************************************************** -->
<br>
<br>

---
---
<div align="center">
    <h4>
        <a href="https://www.initmax.com/" style="display: inline-flex; align-items: center; gap: 5px; color: inherit; text-decoration: none;">
            <img alt="initMAX" src="./.readme/logo/initMAX_symbol_cerne.svg" height="24">
            initMAX.com
        </a>&nbsp;&nbsp;&nbsp;
        <a href="tel:+420800244442" style="display: inline-flex; align-items: center; gap: 5px; color: inherit; text-decoration: none;">
            <img alt="Phone" src="./.readme/logo/phone.svg" height="24">
            +420 800 244 442
        </a>&nbsp;&nbsp;&nbsp;
        <a href="mailto:info@initmax.com" style="display: inline-flex; align-items: center; gap: 5px; color: inherit; text-decoration: none;">
            <img alt="Email" src="./.readme/logo/mail.svg" height="24">
            info@initmax.com
        </a>
        <br><br>
        <a href="https://www.linkedin.com/company/initmax/">
            <img alt="LinkedIn" src="./.readme/logo/linkedin.png">
        </a>&nbsp;
        <a href="https://www.youtube.com/@initmax1">
            <img alt="YouTube" src="./.readme/logo/youtube.png">
        </a>&nbsp;
        <a href="https://www.facebook.com/initmax">
            <img alt="Facebook" src="./.readme/logo/facebook.png">
        </a>&nbsp;
        <a href="https://www.instagram.com/initmax/">
            <img alt="Instagram" src="./.readme/logo/instagram.png">
        </a>&nbsp;
        <a href="https://x.com/initmax">
            <img alt="X" src="./.readme/logo/x.png">
        </a>&nbsp;
        <a href="https://github.com/initmax">
            <img alt="GitHub" src="./.readme/logo/github.png">
        </a>
        <br><br><br>
        <a>
            <img src="./.readme/logo/agplv3.png" width="100">
        </a>
    </h4>
</div>
