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
#   sudo ./deploy/install.sh              # fresh install
#   sudo ./deploy/install.sh update       # update existing installation
#   sudo ./deploy/install.sh --dry-run    # check prerequisites without installing
#   ./deploy/install.sh -h                # show help
#
set -euo pipefail

INSTALL_DIR="/opt/zabbix-mcp"
CONFIG_DIR="/etc/zabbix-mcp"
LOG_DIR="/var/log/zabbix-mcp"
SERVICE_USER="zabbix-mcp"
SERVICE_NAME="zabbix-mcp-server"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEFAULT_PORT=8080
PYTHON_BIN=""
DRY_RUN=false
AUTO_INSTALL_PYTHON=false

# --------------------------------------------------------------------------- #
# Read port from config.toml (falls back to DEFAULT_PORT)
# --------------------------------------------------------------------------- #
get_configured_port() {
    local config_file="$CONFIG_DIR/config.toml"
    if [[ -f "$config_file" ]]; then
        local port
        port=$(grep -E '^\s*port\s*=' "$config_file" | head -1 | sed 's/.*=\s*//' | tr -d ' "'\''')
        if [[ -n "$port" && "$port" =~ ^[0-9]+$ ]]; then
            echo "$port"
            return
        fi
    fi
    echo "$DEFAULT_PORT"
}

get_configured_host() {
    local config_file="$CONFIG_DIR/config.toml"
    if [[ -f "$config_file" ]]; then
        local host
        host=$(grep -E '^\s*host\s*=' "$config_file" | head -1 | sed 's/.*=\s*//' | tr -d ' "'\''')
        if [[ -n "$host" ]]; then
            echo "$host"
            return
        fi
    fi
    echo "127.0.0.1"
}

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
info()  { echo -e "\e[1;34m>>>\e[0m $*"; }
ok()    { echo -e "\e[1;32m>>>\e[0m $*"; }
warn()  { echo -e "\e[1;33m>>>\e[0m $*"; }
error() { echo -e "\e[1;31m>>>\e[0m $*" >&2; }

# Run a command with a spinner — usage: spin "message" command [args...]
spin() {
    local msg="$1"; shift
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0

    # Run command in background, capture output
    local tmpfile
    tmpfile=$(mktemp)
    "$@" > "$tmpfile" 2>&1 &
    local pid=$!

    # Animate spinner while command runs
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r\e[1;34m %s \e[0m %s" "${frames[$i]}" "$msg"
        i=$(( (i + 1) % ${#frames[@]} ))
        sleep 0.1
    done

    # Get exit code
    wait "$pid"
    local exit_code=$?

    # Clear spinner line
    printf "\r\e[K"

    if [[ $exit_code -eq 0 ]]; then
        ok "$msg"
    else
        error "$msg — failed!"
        # Show output on failure
        cat "$tmpfile" >&2
    fi

    rm -f "$tmpfile"
    return $exit_code
}

need_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (sudo)."
        exit 1
    fi
}

show_help() {
    cat <<'HELP'
Zabbix MCP Server — Install / Update script

Usage:
  sudo ./deploy/install.sh [COMMAND] [OPTIONS]

Commands:
  install       Fresh installation (default if no command given)
  update        Update existing installation, preserve config

Options:
  --dry-run           Check prerequisites without installing anything
  --install-python    Automatically install Python if no suitable version found
  -h, --help          Show this help message

Examples:
  sudo ./deploy/install.sh                       # fresh install
  sudo ./deploy/install.sh update                # update in place
  sudo ./deploy/install.sh --dry-run             # verify prerequisites
  sudo ./deploy/install.sh --install-python      # auto-install Python if needed
  sudo ./deploy/install.sh install --dry-run     # dry-run for fresh install

What it does:
  install:
    1. Creates system user 'zabbix-mcp'
    2. Detects suitable Python (>=3.10), creates virtualenv
    3. Installs the package from local git clone
    4. Copies config.example.toml → /etc/zabbix-mcp/config.toml
    5. Installs systemd unit and logrotate config
    6. Checks firewall/SELinux and reports warnings

  update:
    1. Reinstalls the package into existing virtualenv
    2. Updates systemd unit and logrotate config
    3. Restarts the service if running

Paths:
  Install dir:  /opt/zabbix-mcp
  Config:       /etc/zabbix-mcp/config.toml
  Logs:         /var/log/zabbix-mcp/server.log
  Service:      zabbix-mcp-server.service
HELP
    exit 0
}

# --------------------------------------------------------------------------- #
# Python detection — find suitable Python >=3.10
# --------------------------------------------------------------------------- #
_try_python_candidates() {
    local candidates=("python3.13" "python3.12" "python3.11" "python3.10" "python3")
    local min_minor=10

    for candidate in "${candidates[@]}"; do
        if command -v "$candidate" &>/dev/null; then
            local version_output minor
            version_output=$("$candidate" --version 2>&1) || continue
            minor=$(echo "$version_output" | sed -n 's/Python 3\.\([0-9]*\)\..*/\1/p')
            if [[ -n "$minor" && "$minor" -ge "$min_minor" ]]; then
                PYTHON_BIN="$candidate"
                info "Using $candidate ($version_output)"
                return 0
            fi
        fi
    done
    return 1
}

_get_install_cmd() {
    # Returns the package manager command to install Python 3.12 + venv
    if [[ -f /etc/redhat-release ]]; then
        echo "dnf install -y python3.12"
    elif [[ -f /etc/debian_version ]]; then
        echo "apt-get update && apt-get install -y python3.12 python3.12-venv"
    else
        echo ""
    fi
}

_install_python() {
    local install_cmd
    install_cmd=$(_get_install_cmd)

    if [[ -z "$install_cmd" ]]; then
        error "Automatic Python installation is not supported on this OS."
        error "Install Python 3.10+ manually using your system package manager."
        exit 1
    fi

    info "Installing Python 3.12..."
    if eval "$install_cmd"; then
        ok "Python 3.12 installed successfully."
    else
        error "Failed to install Python 3.12."
        error "Try installing manually: $install_cmd"
        exit 1
    fi
}

find_python() {
    # First try: find an existing suitable Python
    if _try_python_candidates; then
        return 0
    fi

    # No suitable Python found
    error "No suitable Python interpreter found! Python >=3.10 is required."
    echo
    error "Available Python versions on this system:"
    for cmd in python3 python3.9 python3.10 python3.11 python3.12 python3.13; do
        if command -v "$cmd" &>/dev/null; then
            error "  $cmd → $($cmd --version 2>&1)"
        fi
    done
    echo

    local install_cmd
    install_cmd=$(_get_install_cmd)

    if [[ -z "$install_cmd" ]]; then
        error "Install Python 3.10+ using your system package manager."
        exit 1
    fi

    # Auto-install if --install-python flag was given
    if $AUTO_INSTALL_PYTHON; then
        _install_python
        # Retry detection after install
        if _try_python_candidates; then
            return 0
        fi
        error "Python was installed but still not detected. Check your PATH."
        exit 1
    fi

    # Interactive prompt (only if stdin is a terminal)
    if [[ -t 0 ]]; then
        echo -e "\e[1;33mWould you like to install Python 3.12 automatically?\e[0m"
        echo -e "  Command: \e[1m$install_cmd\e[0m"
        echo
        read -rp "Install now? [y/N] " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            _install_python
            # Retry detection after install
            if _try_python_candidates; then
                return 0
            fi
            error "Python was installed but still not detected. Check your PATH."
            exit 1
        fi
    fi

    # User declined or non-interactive — show manual instructions
    echo
    if [[ -f /etc/redhat-release ]]; then
        error "RHEL/CentOS/Rocky — install Python 3.12:"
        error "  sudo dnf install python3.12"
    elif [[ -f /etc/debian_version ]]; then
        error "Debian/Ubuntu — install Python 3.12:"
        error "  sudo apt update && sudo apt install python3.12 python3.12-venv"
    fi
    error ""
    error "Or re-run with: sudo ./deploy/install.sh --install-python"
    exit 1
}

# --------------------------------------------------------------------------- #
# Firewall & SELinux checks
# --------------------------------------------------------------------------- #
check_firewall_and_selinux() {
    local port="${1:-$DEFAULT_PORT}"
    local warnings=0

    echo

    # --- SELinux ---
    if command -v getenforce &>/dev/null; then
        local selinux_status
        selinux_status=$(getenforce 2>/dev/null || echo "unknown")
        if [[ "$selinux_status" == "Enforcing" ]]; then
            warn "SELinux is ENFORCING — you may need to allow port $port:"
            echo -e "  \e[1;33msudo semanage port -a -t http_port_t -p tcp $port\e[0m"
            echo -e "  \e[1;33msudo restorecon -Rv $INSTALL_DIR\e[0m"
            ((warnings++))
        else
            ok "SELinux: $selinux_status"
        fi
    fi

    # --- Firewall detection ---
    local firewall_detected=false

    # firewalld
    if command -v firewall-cmd &>/dev/null; then
        local fw_state
        fw_state=$(firewall-cmd --state 2>/dev/null || echo "not running")
        if [[ "$fw_state" == "running" ]]; then
            firewall_detected=true
            # Check if port is open
            if firewall-cmd --query-port="${port}/tcp" &>/dev/null; then
                ok "firewalld: port $port/tcp is open"
            else
                error "WARNING: Port $port/tcp is NOT open in firewalld!"
                echo -e "  \e[1;31msudo firewall-cmd --add-port=${port}/tcp --permanent && sudo firewall-cmd --reload\e[0m"
                ((warnings++))
            fi
        fi
    fi

    # ufw
    if command -v ufw &>/dev/null && ! $firewall_detected; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1 || echo "")
        if [[ "$ufw_status" == *"active"* ]]; then
            firewall_detected=true
            if ufw status | grep -qE "^${port}/tcp\s+ALLOW"; then
                ok "ufw: port $port/tcp is allowed"
            else
                error "WARNING: Port $port/tcp may be blocked by ufw!"
                echo -e "  \e[1;31msudo ufw allow ${port}/tcp\e[0m"
                ((warnings++))
            fi
        fi
    fi

    # Port already in use?
    if command -v ss &>/dev/null; then
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            warn "Port $port is already in use by another process!"
            ss -tlnp 2>/dev/null | grep ":${port} " | head -3
            ((warnings++))
        fi
    fi

    if [[ $warnings -eq 0 ]]; then
        ok "No firewall/SELinux issues detected"
    fi
    echo
}

# --------------------------------------------------------------------------- #
# Health check after installation
# --------------------------------------------------------------------------- #
check_health() {
    local port="${1:-$DEFAULT_PORT}"
    local configured_host="${2:-127.0.0.1}"
    # For curl, always use 127.0.0.1 (0.0.0.0 binds all interfaces, including localhost)
    local curl_host="127.0.0.1"
    local url="http://${curl_host}:${port}/health"

    info "Server configured on ${configured_host}:${port}"

    if ! command -v curl &>/dev/null; then
        warn "curl is not installed — skipping health check."
        warn "Install curl and test manually: curl $url"
        return
    fi

    local max_attempts=5
    local attempt=1

    info "Waiting for service to start..."
    sleep 1

    while [[ $attempt -le $max_attempts ]]; do
        if curl -sf --max-time 3 "$url" &>/dev/null; then
            ok "Health check passed: $url → OK"
            return
        fi
        warn "Health check attempt $attempt/$max_attempts failed — retrying..."
        ((attempt++))
        sleep 2
    done

    error "Health check failed after $max_attempts attempts!"
    error "Test manually: curl $url"
    error "Check logs:    tail -f $LOG_DIR/server.log"
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
    --config /etc/zabbix-mcp/config.toml

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
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
ReadWritePaths=/var/log/zabbix-mcp

[Install]
WantedBy=multi-user.target
UNIT
    if command -v systemctl &>/dev/null; then
        spin "Reloading systemd" systemctl daemon-reload
    else
        warn "systemctl not found - skipping daemon-reload (no systemd on this system)."
    fi
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
        spin "Creating virtual environment" "$PYTHON_BIN" -m venv "$INSTALL_DIR/venv"
    fi

    spin "Upgrading pip" "$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
    spin "Installing zabbix-mcp-server from ${SCRIPT_DIR}" "$INSTALL_DIR/venv/bin/pip" install "$SCRIPT_DIR" --quiet

    local version
    version=$("$INSTALL_DIR/venv/bin/zabbix-mcp-server" --version 2>&1 || true)
    ok "Installed: $version"
}

# --------------------------------------------------------------------------- #
# Dry run — check prerequisites only
# --------------------------------------------------------------------------- #
do_dry_run() {
    info "=== Zabbix MCP Server - Dry Run (prerequisite check) ==="
    echo

    # Root check
    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root — install/update would require sudo."
    else
        ok "Running as root"
    fi

    # Repo check
    if [[ -f "$SCRIPT_DIR/pyproject.toml" ]]; then
        ok "Found pyproject.toml in $SCRIPT_DIR"
    else
        error "Cannot find pyproject.toml in $SCRIPT_DIR"
    fi

    # Python detection
    find_python

    # Existing installation?
    if [[ -d "$INSTALL_DIR/venv" ]]; then
        local old_version
        old_version=$("$INSTALL_DIR/venv/bin/zabbix-mcp-server" --version 2>&1 || echo "unknown")
        info "Existing installation found: $old_version"
    else
        info "No existing installation at $INSTALL_DIR"
    fi

    # Config?
    if [[ -f "$CONFIG_DIR/config.toml" ]]; then
        ok "Config exists at $CONFIG_DIR/config.toml"
    else
        info "No config yet — will be created on install"
    fi

    # Firewall & SELinux
    check_firewall_and_selinux "$(get_configured_port)"

    echo
    ok "=== Dry run complete — no changes made ==="
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

    # Find suitable Python
    find_python

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
        if ! sed -i 's/^transport = "stdio"/transport = "http"/' "$CONFIG_DIR/config.toml"; then
            warn "Failed to set transport to http — edit $CONFIG_DIR/config.toml manually."
        fi
        chmod 600 "$CONFIG_DIR/config.toml"
        chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR/config.toml"
    else
        warn "Config already exists at $CONFIG_DIR/config.toml - not overwriting."
    fi

    # systemd + logrotate
    install_systemd_unit
    install_logrotate

    # Firewall & SELinux checks
    local active_port active_host
    active_port=$(get_configured_port)
    active_host=$(get_configured_host)
    check_firewall_and_selinux "$active_port"

    echo
    ok "=== Installation complete ==="
    echo
    echo "  Next steps:"
    echo "  1. Edit config:      sudo nano $CONFIG_DIR/config.toml"
    echo "  2. Start service:    sudo systemctl start $SERVICE_NAME"
    echo "  3. Enable on boot:   sudo systemctl enable $SERVICE_NAME"
    echo "  4. Check status:     sudo systemctl status $SERVICE_NAME"
    echo "  5. View logs:        tail -f $LOG_DIR/server.log"
    echo "  6. Health check:     curl http://localhost:$active_port/health"
    echo
    echo "  Endpoints (from config.toml — ${active_host}:${active_port}):"
    echo "    MCP endpoint:  http://localhost:$active_port/mcp"
    echo "    Health check:  http://localhost:$active_port/health"
    echo
    echo "  Changelog:    https://github.com/initMAX/zabbix-mcp-server/blob/main/CHANGELOG.md"
    echo "  (new features, security fixes, new config options)"
    echo
    echo "  Feedback:     https://github.com/initMAX/zabbix-mcp-server/issues"
    echo "  Discussions:  https://github.com/initMAX/zabbix-mcp-server/discussions"
    echo "  We appreciate bug reports, feature requests, and community feedback!"
    echo
    echo "  Note: This git repository ($SCRIPT_DIR) is not required"
    echo "  for the server to run — it can be moved or removed."
    echo "  To upgrade later, clone the repo again and run:"
    echo "    sudo ./deploy/install.sh update"
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

    # Pull latest code if we're in a git repo
    if [[ -d "$SCRIPT_DIR/.git" ]]; then
        spin "Pulling latest changes from git" git -C "$SCRIPT_DIR" pull --ff-only || \
            warn "Git pull failed — continuing with current local version."
    fi

    # Show current version
    local old_version
    old_version=$("$INSTALL_DIR/venv/bin/zabbix-mcp-server" --version 2>&1 || echo "unknown")
    info "Current version: $old_version"

    # Find suitable Python (in case venv needs recreation)
    find_python

    # Update package
    install_package

    # Config is NOT overwritten — notify about new options
    if [[ -f "$CONFIG_DIR/config.toml" ]]; then
        ok "Config preserved at $CONFIG_DIR/config.toml (not overwritten)."
        info "Check config.example.toml for any new parameters added in this version."
    fi

    # Update systemd + logrotate (in case they changed)
    install_systemd_unit
    install_logrotate

    # Restart service if running
    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            spin "Restarting $SERVICE_NAME" systemctl restart "$SERVICE_NAME"
            # Health check after restart
            check_health "$(get_configured_port)" "$(get_configured_host)"
        else
            warn "Service is not running. Start with: sudo systemctl start $SERVICE_NAME"
        fi
    else
        warn "systemctl not found - restart the server manually."
    fi

    echo
    ok "=== Update complete ==="
    echo
    echo "  Changelog:    https://github.com/initMAX/zabbix-mcp-server/blob/main/CHANGELOG.md"
    echo "  (new features, security fixes, new config options)"
    echo
    echo "  Feedback:     https://github.com/initMAX/zabbix-mcp-server/issues"
    echo "  Discussions:  https://github.com/initMAX/zabbix-mcp-server/discussions"
    echo "  We appreciate bug reports, feature requests, and community feedback!"
    echo
}

# --------------------------------------------------------------------------- #
# Main — parse arguments
# --------------------------------------------------------------------------- #
COMMAND=""
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            show_help
            ;;
        --dry-run)
            DRY_RUN=true
            ;;
        --install-python)
            AUTO_INSTALL_PYTHON=true
            ;;
        install|update|upgrade)
            COMMAND="$arg"
            ;;
        *)
            error "Unknown argument: $arg"
            echo "Run '$0 --help' for usage information."
            exit 1
            ;;
    esac
done

# Default command
COMMAND="${COMMAND:-install}"

# Dry run does not require root
if $DRY_RUN; then
    do_dry_run
    exit 0
fi

# All other commands require root
need_root

case "$COMMAND" in
    update|upgrade)
        do_update
        ;;
    install)
        do_install
        ;;
esac
