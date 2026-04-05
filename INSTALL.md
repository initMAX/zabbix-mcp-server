# Installation Guide

Two ways to deploy the Zabbix MCP Server: **on-prem** (systemd service) or **Docker**.

---

## Prerequisites

Both methods require:

- Network access to your Zabbix server(s)
- A [Zabbix API token](https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/users/api_tokens) (created in Zabbix frontend: **Users → API tokens → Create API token**)

## Option 1: On-Prem Installation (systemd)

### Requirements

- Linux server (RHEL 8+, Ubuntu 20.04+, Debian 11+, or similar)
- Python 3.10 or newer
- Root access (sudo)

### Step 1: Clone the repository

```bash
git clone https://github.com/initMAX/zabbix-mcp-server.git
cd zabbix-mcp-server
```

### Step 2: Run the installer

```bash
sudo ./deploy/install.sh
```

The installer will:

1. Detect the best available Python (>=3.10) — if none found, offers to install it automatically
2. Create a dedicated system user `zabbix-mcp` (no login shell)
3. Create a Python virtual environment in `/opt/zabbix-mcp/venv`
4. Install the server and all dependencies
5. Copy example config to `/etc/zabbix-mcp/config.toml`
6. Install a systemd service (`zabbix-mcp-server`) and logrotate config
7. Check for firewall/SELinux issues and report warnings

> **Tip:** Run `sudo ./deploy/install.sh --dry-run` first to check prerequisites without making any changes.

> **No Python 3.10+?** The installer will ask if you want to install Python automatically. Or use the `--install-python` flag to skip the prompt.

### Step 3: Configure

```bash
sudo nano /etc/zabbix-mcp/config.toml
```

Minimal configuration — fill in your Zabbix URL and API token:

```toml
[server]
transport = "http"
host = "127.0.0.1"
port = 8080

[zabbix.production]
url = "https://zabbix.example.com"
api_token = "your-zabbix-api-token-here"
read_only = true
```

See [`config.example.toml`](config.example.toml) for all available options with detailed descriptions.

### Step 4: Start the service

```bash
sudo systemctl start zabbix-mcp-server
sudo systemctl enable zabbix-mcp-server
```

### Step 5: Verify

```bash
# Check service status
sudo systemctl status zabbix-mcp-server

# Health check
curl http://localhost:8080/health
# → {"status":"ok"}

# View logs
tail -f /var/log/zabbix-mcp/server.log
```

### Upgrade

```bash
cd zabbix-mcp-server
git fetch origin && git reset --hard origin/main
sudo ./deploy/install.sh update
```

The `git fetch + reset` ensures a clean sync with upstream. The update preserves your config, upgrades the package, refreshes the systemd unit, checks file permissions, and restarts the service.

> **Note:** From v1.15+, `sudo ./deploy/install.sh update` handles git sync automatically — the explicit `git fetch + reset` is only needed when upgrading from older versions.

### Uninstall

```bash
sudo ./deploy/install.sh uninstall
```

Complete removal: stops and disables the service, removes the systemd unit, logrotate config, virtualenv, configuration, logs, and the system user. Requires explicit `yes` confirmation.

### Installer CLI reference

```
sudo ./deploy/install.sh [COMMAND] [OPTIONS]
```

| Command / Option | Description |
|---|---|
| `install` | Fresh installation (default) |
| `update` | Update existing installation, preserve config |
| `uninstall` | Complete removal — service, config, logs, virtualenv, system user |
| `--dry-run` | Check prerequisites without installing |
| `set-admin-password` | Reset admin portal password |
| `--install-python` | Auto-install Python 3.12 if no suitable version found |
| `--with-reporting` | Install PDF reporting dependencies (default on fresh install) |
| `--without-reporting` | Skip PDF reporting dependencies |
| `-h`, `--help` | Show full help |

### File paths

| Path | Description |
|---|---|
| `/opt/zabbix-mcp/venv` | Python virtual environment |
| `/etc/zabbix-mcp/config.toml` | Server configuration |
| `/var/log/zabbix-mcp/server.log` | Log file |
| `/etc/systemd/system/zabbix-mcp-server.service` | Systemd unit |
| `/etc/zabbix-mcp/assets/` | Uploaded logos |
| `/etc/zabbix-mcp/tls/` | TLS certificates and keys |
| `/etc/logrotate.d/zabbix-mcp-server` | Logrotate config |

---

## Option 2: Docker

### Requirements

- Docker and Docker Compose
- No Python installation needed — the container uses its own

### Step 1: Clone and configure

```bash
git clone https://github.com/initMAX/zabbix-mcp-server.git
cd zabbix-mcp-server

# Create config from example
cp config.example.toml config.toml
nano config.toml
```

Minimal `config.toml` for Docker — note the transport must be `"http"`:

```toml
[server]
transport = "http"

# When using Docker, host and port are controlled by MCP_HOST/MCP_PORT
# in .env (see below). The values here are ignored.

[zabbix.production]
url = "https://zabbix.example.com"
api_token = "your-zabbix-api-token-here"
read_only = true
```

### Step 2: Configure Docker environment (optional)

```bash
cp .env.example .env
nano .env
```

Available environment variables:

```bash
MCP_HOST=127.0.0.1    # Host interface to bind (default: 127.0.0.1, use 0.0.0.0 for all)
MCP_PORT=8080          # Port inside container and on host (default: 8080)
ADMIN_PORT=9090        # Admin portal port (default: 9090)
MCP_AUTH_TOKEN=...     # Bearer token for authentication (optional but recommended)
```

> **Security:** Docker deployments are often exposed to the network. Set `MCP_AUTH_TOKEN` in `.env` and uncomment `auth_token = "${MCP_AUTH_TOKEN}"` in `config.toml` to require authentication.

### Step 3: Start

```bash
docker compose up -d
```

### Step 4: Verify

```bash
# Check container health
docker compose ps

# Health check
curl http://localhost:8080/health
# → {"status":"ok"}

# View logs
docker compose logs -f
```

### Upgrade

```bash
git pull
docker compose up -d --build
```

### Stop / Remove

```bash
# Stop
docker compose down

# Stop and remove log volume
docker compose down -v
```

### Docker details

- **Base image:** `python:3.13.5-slim` (multi-stage build)
- **Config:** `config.toml` mounted at `/etc/zabbix-mcp/config.toml`
- **Assets/TLS:** stored in Docker named volumes (`assets`, `tls`)
- **Logs:** stored in a Docker named volume (`logs`)
- **Health check:** built-in Docker HEALTHCHECK hitting `/health` every 30s
- **Restart policy:** `unless-stopped`
- **Security:** runs as non-root user `zabbix-mcp`

---

## Manual Installation (pip)

For advanced users who want full control:

```bash
# Create venv
python3 -m venv /opt/zabbix-mcp/venv

# Install
/opt/zabbix-mcp/venv/bin/pip install /path/to/zabbix-mcp-server

# Run
/opt/zabbix-mcp/venv/bin/zabbix-mcp-server --config /path/to/config.toml
```

---

## Post-Installation

### Connect an AI client

The server listens on `http://127.0.0.1:8080/mcp` by default. Configure your MCP client:

```json
{
  "mcpServers": {
    "zabbix": {
      "type": "http",
      "url": "http://your-server:8080/mcp",
      "headers": {
        "Authorization": "Bearer your-auth-token"
      }
    }
  }
}
```

Omit the `headers` block if you didn't set `auth_token`.

### Security checklist

- [ ] `auth_token` set (required when exposed to network)
- [ ] TLS enabled or behind a reverse proxy with HTTPS
- [ ] `read_only = true` for production Zabbix servers
- [ ] Zabbix API token uses least-privilege permissions
- [ ] Firewall allows only necessary traffic to the MCP port

### TLS / HTTPS

For local clients (Claude Code, Cursor), self-signed certificates work fine. For remote MCP connections (Claude Desktop cloud), you need a **publicly trusted certificate** (e.g. Let's Encrypt).

Recommended production setup — reverse proxy with automatic TLS:

```
Client → Caddy/nginx (HTTPS, Let's Encrypt) → MCP Server (HTTP, localhost:8080)
```

See the [TLS / HTTPS section](README.md#tls--https) in README for details.

### Admin Portal

The admin portal provides a web-based interface for managing MCP tokens, users, report templates, and server settings.

**Enable in config.toml:**

```toml
[admin]
enabled = true
port = 9090
host = "127.0.0.1"
```

**First-time setup:**

The installer generates an admin password automatically during `install` or `update`. To reset it:

```bash
sudo ./deploy/install.sh set-admin-password
```

**Access:** Open `http://localhost:9090/` in your browser.

**Features:**
- MCP token management (create, revoke, scope control)
- Admin user management (admin/operator/viewer roles)
- Zabbix server status and connection testing
- Report template editor with live preview
- All config.toml settings editable via UI
- Audit log viewer with CSV export
- Dark/light mode with auto-detection

### Health monitoring

| Method | URL | Auth | Purpose |
|---|---|---|---|
| HTTP endpoint | `GET /health` | No | Load balancer probes, uptime monitoring |
| MCP tool | `health_check` | Yes | Full Zabbix connectivity diagnostics |
