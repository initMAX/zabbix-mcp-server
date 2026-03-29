#!/usr/bin/env bash
#
# Zabbix MCP Server - Install / Update script
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Usage:
#   sudo ./deploy/install.sh          # fresh install
#   sudo ./deploy/install.sh update   # update existing installation
#
set -euo pipefail

INSTALL_DIR="/opt/zabbix-mcp"
CONFIG_DIR="/etc/zabbix-mcp"
LOG_DIR="/var/log/zabbix-mcp"
SERVICE_USER="zabbix-mcp"
SERVICE_NAME="zabbix-mcp-server"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
info()  { echo -e "\e[1;34m>>>\e[0m $*"; }
ok()    { echo -e "\e[1;32m>>>\e[0m $*"; }
warn()  { echo -e "\e[1;33m>>>\e[0m $*"; }
error() { echo -e "\e[1;31m>>>\e[0m $*" >&2; }

need_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (sudo)."
        exit 1
    fi
}

# --------------------------------------------------------------------------- #
# Embedded: systemd unit
# --------------------------------------------------------------------------- #
install_systemd_unit() {
    info "Installing systemd unit..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<'UNIT'
[Unit]
Description=Zabbix MCP Server
Documentation=https://github.com/initMAX/zabbix-mcp-server
After=network.target

[Service]
Type=simple
User=zabbix-mcp
Group=zabbix-mcp

ExecStart=/opt/zabbix-mcp/venv/bin/zabbix-mcp-server \
    --config /etc/zabbix-mcp/config.toml \
    --transport http \
    --host 127.0.0.1 \
    --port 8080

Restart=on-failure
RestartSec=5

# Logging
StandardOutput=append:/var/log/zabbix-mcp/server.log
StandardError=append:/var/log/zabbix-mcp/server.log

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/zabbix-mcp

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
}

# --------------------------------------------------------------------------- #
# Embedded: logrotate
# --------------------------------------------------------------------------- #
install_logrotate() {
    info "Installing logrotate config..."
    cat > "/etc/logrotate.d/${SERVICE_NAME}" <<'LOGROTATE'
/var/log/zabbix-mcp/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    create 0640 zabbix-mcp zabbix-mcp
}
LOGROTATE
}

# --------------------------------------------------------------------------- #
# Install Python package from local git clone
# --------------------------------------------------------------------------- #
install_package() {
    if [[ ! -d "$INSTALL_DIR/venv" ]]; then
        info "Creating virtual environment..."
        python3 -m venv "$INSTALL_DIR/venv"
    fi

    info "Installing zabbix-mcp-server from ${SCRIPT_DIR}..."
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
    "$INSTALL_DIR/venv/bin/pip" install "$SCRIPT_DIR" --quiet

    local version
    version=$("$INSTALL_DIR/venv/bin/zabbix-mcp-server" --version 2>&1 || true)
    ok "Installed: $version"
}

# --------------------------------------------------------------------------- #
# Fresh install
# --------------------------------------------------------------------------- #
do_install() {
    info "=== Zabbix MCP Server - Installation ==="
    echo

    # Verify we're in the repo
    if [[ ! -f "$SCRIPT_DIR/pyproject.toml" ]]; then
        error "Cannot find pyproject.toml in $SCRIPT_DIR"
        error "Run this script from the git repository root: sudo ./deploy/install.sh"
        exit 1
    fi

    # Service user
    if ! id "$SERVICE_USER" &>/dev/null; then
        info "Creating system user '$SERVICE_USER'..."
        useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" "$SERVICE_USER"
    fi

    # Directories
    info "Creating directories..."
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
    chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"

    # Package
    install_package

    # Config
    if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
        info "Copying example config to $CONFIG_DIR/config.toml..."
        cp "$SCRIPT_DIR/config.example.toml" "$CONFIG_DIR/config.toml"
        # Set transport to http for systemd deployment
        sed -i 's/^transport = "stdio"/transport = "http"/' "$CONFIG_DIR/config.toml"
        chmod 600 "$CONFIG_DIR/config.toml"
        chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR/config.toml"
    else
        warn "Config already exists at $CONFIG_DIR/config.toml - not overwriting."
    fi

    # systemd + logrotate
    install_systemd_unit
    install_logrotate

    echo
    ok "=== Installation complete ==="
    echo
    echo "  Next steps:"
    echo "  1. Edit config:      sudo nano $CONFIG_DIR/config.toml"
    echo "  2. Start service:    sudo systemctl start $SERVICE_NAME"
    echo "  3. Enable on boot:   sudo systemctl enable $SERVICE_NAME"
    echo "  4. Check status:     sudo systemctl status $SERVICE_NAME"
    echo "  5. View logs:        tail -f $LOG_DIR/server.log"
    echo
}

# --------------------------------------------------------------------------- #
# Update existing installation
# --------------------------------------------------------------------------- #
do_update() {
    info "=== Zabbix MCP Server - Update ==="
    echo

    if [[ ! -d "$INSTALL_DIR/venv" ]]; then
        error "No existing installation found at $INSTALL_DIR"
        error "Run without 'update' for a fresh install."
        exit 1
    fi

    if [[ ! -f "$SCRIPT_DIR/pyproject.toml" ]]; then
        error "Cannot find pyproject.toml in $SCRIPT_DIR"
        error "Run this script from the git repository root: sudo ./deploy/install.sh update"
        exit 1
    fi

    # Show current version
    local old_version
    old_version=$("$INSTALL_DIR/venv/bin/zabbix-mcp-server" --version 2>&1 || echo "unknown")
    info "Current version: $old_version"

    # Update package
    install_package

    # Update systemd + logrotate (in case they changed)
    install_systemd_unit
    install_logrotate

    # Restart service if running
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Restarting $SERVICE_NAME..."
        systemctl restart "$SERVICE_NAME"
        ok "Service restarted."
    else
        warn "Service is not running. Start with: sudo systemctl start $SERVICE_NAME"
    fi

    echo
    ok "=== Update complete ==="
    echo
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
need_root

case "${1:-install}" in
    update|upgrade)
        do_update
        ;;
    install|"")
        do_install
        ;;
    *)
        echo "Usage: $0 [install|update]"
        exit 1
        ;;
esac
