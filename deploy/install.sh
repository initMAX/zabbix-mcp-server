#!/usr/bin/env bash
set -euo pipefail

# Zabbix MCP Server - Linux deployment script
# Run as root: sudo bash deploy/install.sh

INSTALL_DIR="/opt/zabbix-mcp"
CONFIG_DIR="/etc/zabbix-mcp"
LOG_DIR="/var/log/zabbix-mcp"
SERVICE_USER="zabbix-mcp"

echo "=== Zabbix MCP Server - Installation ==="

# Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating user $SERVICE_USER..."
    useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" "$SERVICE_USER"
fi

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"

# Create virtual environment and install
echo "Installing zabbix-mcp-server..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install zabbix-mcp-server

# Copy config if not exists
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    echo "Copying example config..."
    cp config.example.toml "$CONFIG_DIR/config.toml"
    chmod 600 "$CONFIG_DIR/config.toml"
    chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR/config.toml"
    echo ""
    echo "  >>> IMPORTANT: Edit $CONFIG_DIR/config.toml with your Zabbix server details <<<"
    echo ""
fi

# Install systemd service
echo "Installing systemd service..."
cp deploy/zabbix-mcp-server.service /etc/systemd/system/
systemctl daemon-reload

# Install logrotate
echo "Installing logrotate config..."
cp deploy/zabbix-mcp-server.logrotate /etc/logrotate.d/zabbix-mcp-server

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit config:     sudo nano $CONFIG_DIR/config.toml"
echo "  2. Start service:   sudo systemctl start zabbix-mcp-server"
echo "  3. Enable on boot:  sudo systemctl enable zabbix-mcp-server"
echo "  4. Check status:    sudo systemctl status zabbix-mcp-server"
echo "  5. View logs:       tail -f $LOG_DIR/server.log"
