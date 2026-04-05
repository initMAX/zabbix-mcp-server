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
INSTALL_REPORTING=auto

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
  install             Fresh installation (default if no command given)
  update              Update existing installation, preserve config
  uninstall           Complete removal of the server and all its data
  set-admin-password  Reset the admin portal password
  generate-token      Generate a new MCP bearer token and add it to config.toml

Options:
  --dry-run           Check prerequisites without installing anything
  --install-python      Automatically install Python if no suitable version found
  --without-reporting   Skip PDF reporting dependencies (weasyprint, jinja2)
  --with-reporting      Force-install PDF reporting even on update without it
  -h, --help            Show this help message

Examples:
  sudo ./deploy/install.sh                       # fresh install (includes reporting)
  sudo ./deploy/install.sh --without-reporting   # fresh install without PDF reports
  sudo ./deploy/install.sh update                # update (keeps reporting if installed)
  sudo ./deploy/install.sh update --with-reporting  # update + add PDF reports
  sudo ./deploy/install.sh uninstall             # complete removal
  sudo ./deploy/install.sh generate-token claude  # generate MCP bearer token
  sudo ./deploy/install.sh --dry-run             # verify prerequisites

What it does:
  install:
    1. Creates system user 'zabbix-mcp'
    2. Detects suitable Python (>=3.10), creates virtualenv
    3. Installs the package from local git clone
    4. Copies config.example.toml → /etc/zabbix-mcp/config.toml
    5. Installs systemd unit and logrotate config
    6. Checks file permissions, firewall/SELinux and reports warnings

  update:
    1. Reinstalls the package into existing virtualenv
    2. Updates systemd unit and logrotate config
    3. Checks and offers to fix file permissions
    4. Restarts the service if running

  uninstall:
    1. Stops and disables the systemd service
    2. Removes systemd unit and logrotate config
    3. Removes /opt/zabbix-mcp (virtualenv, binaries)
    4. Removes /etc/zabbix-mcp (config.toml)
    5. Removes /var/log/zabbix-mcp (logs)
    6. Removes the 'zabbix-mcp' system user

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
            warnings=$((warnings + 1))
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
                warnings=$((warnings + 1))
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
                warnings=$((warnings + 1))
            fi
        fi
    fi

    # Port already in use?
    if command -v ss &>/dev/null; then
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            warn "Port $port is already in use by another process!"
            ss -tlnp 2>/dev/null | grep ":${port} " | head -3
            warnings=$((warnings + 1))
        fi
    fi

    if [[ $warnings -eq 0 ]]; then
        ok "No firewall/SELinux issues detected"
    fi
    echo
}

# --------------------------------------------------------------------------- #
# Permission check — detect and optionally fix ownership issues
# --------------------------------------------------------------------------- #
check_permissions() {
    info "Checking file permissions..."
    local issues=()
    local fix_paths=()
    local fix_mkdir=false

    # Check LOG_DIR ownership
    if [[ -d "$LOG_DIR" ]]; then
        local dir_owner
        dir_owner=$(stat -c '%U:%G' "$LOG_DIR" 2>/dev/null)
        if [[ "$dir_owner" != "$SERVICE_USER:$SERVICE_USER" ]]; then
            issues+=("$LOG_DIR is owned by $dir_owner (expected $SERVICE_USER:$SERVICE_USER)")
            fix_paths+=("$LOG_DIR")
        fi
    else
        issues+=("$LOG_DIR does not exist")
        fix_mkdir=true
    fi

    # Check log file ownership (if it exists)
    local log_file="$LOG_DIR/server.log"
    if [[ -f "$log_file" ]]; then
        local file_owner
        file_owner=$(stat -c '%U:%G' "$log_file" 2>/dev/null)
        if [[ "$file_owner" != "$SERVICE_USER:$SERVICE_USER" ]]; then
            issues+=("$log_file is owned by $file_owner (expected $SERVICE_USER:$SERVICE_USER)")
            fix_paths+=("$log_file")
        fi
    fi

    # Check config ownership
    if [[ -f "$CONFIG_DIR/config.toml" ]]; then
        local config_owner
        config_owner=$(stat -c '%U:%G' "$CONFIG_DIR/config.toml" 2>/dev/null)
        if [[ "$config_owner" != "$SERVICE_USER:$SERVICE_USER" ]]; then
            issues+=("$CONFIG_DIR/config.toml is owned by $config_owner (expected $SERVICE_USER:$SERVICE_USER)")
            fix_paths+=("$CONFIG_DIR/config.toml")
        fi
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        ok "File permissions OK"
        return 0
    fi

    warn "Permission issues found:"
    for issue in "${issues[@]}"; do
        warn "  - $issue"
    done
    echo

    if [[ -t 0 ]]; then
        read -rp "$(echo -e '\e[1;33m>>>\e[0m') Fix permissions now? [Y/n] " answer
        if [[ ! "$answer" =~ ^[Nn]$ ]]; then
            if $fix_mkdir; then
                mkdir -p "$LOG_DIR"
            fi
            for p in "${fix_paths[@]}"; do
                chown "$SERVICE_USER:$SERVICE_USER" "$p"
            done
            ok "Permissions fixed."
        else
            warn "Skipped — fix manually if the service fails to start."
        fi
    else
        warn "Non-interactive mode — fix manually:"
        if $fix_mkdir; then
            warn "  mkdir -p $LOG_DIR"
        fi
        for p in "${fix_paths[@]}"; do
            warn "  chown $SERVICE_USER:$SERVICE_USER $p"
        done
    fi
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
    if [[ ! -d /etc/systemd/system ]]; then
        warn "No systemd detected — skipping unit installation."
        return 0
    fi
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

# Logging — application writes to log_file from config.toml directly.
# Startup errors (before logging init) go to journal:
#   journalctl -u zabbix-mcp-server

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
ReadWritePaths=/var/log/zabbix-mcp /etc/zabbix-mcp

[Install]
WantedBy=multi-user.target
UNIT
    if command -v systemctl &>/dev/null; then
        if spin "Reloading systemd" systemctl daemon-reload; then
            :
        else
            warn "systemctl daemon-reload failed — if running in a container, this is expected."
        fi
    else
        warn "systemctl not found - skipping daemon-reload (no systemd on this system)."
    fi
}

# --------------------------------------------------------------------------- #
# Embedded: logrotate
# --------------------------------------------------------------------------- #
install_logrotate() {
    if [[ ! -d /etc/logrotate.d ]]; then
        warn "No logrotate detected — skipping logrotate configuration."
        return 0
    fi
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
    spin "Installing zabbix-mcp-server from ${SCRIPT_DIR}" "$INSTALL_DIR/venv/bin/pip" install --upgrade "$SCRIPT_DIR" --quiet

    # Resolve "auto" reporting flag:
    #   install: default ON (include reporting)
    #   update:  detect whether reporting is already installed
    if [[ "$INSTALL_REPORTING" == "auto" ]]; then
        if [[ -d "$INSTALL_DIR/venv" ]] && "$INSTALL_DIR/venv/bin/python" -c "import weasyprint" 2>/dev/null; then
            INSTALL_REPORTING=true   # already installed → keep it
        elif [[ "$COMMAND" == "install" ]]; then
            INSTALL_REPORTING=true   # fresh install → include by default
        else
            INSTALL_REPORTING=false  # update without existing reporting → don't add
        fi
    fi

    # Install reporting dependencies
    if [[ "$INSTALL_REPORTING" == "true" ]]; then
        info "Installing PDF reporting system libraries..."
        if [[ -f /etc/redhat-release ]]; then
            dnf install -y cairo pango gdk-pixbuf2 libffi-devel &>/dev/null || \
                warn "Some system libraries for reporting may be missing. Install: dnf install cairo pango gdk-pixbuf2"
        elif [[ -f /etc/debian_version ]]; then
            apt-get update -qq &>/dev/null || true
            apt-get install -y libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev &>/dev/null || \
                warn "Some system libraries for reporting may be missing. Install: apt-get install libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0"
        fi
        spin "Installing PDF reporting dependencies" "$INSTALL_DIR/venv/bin/pip" install --upgrade "$SCRIPT_DIR[reporting]" --quiet
    fi

    local version
    version=$("$INSTALL_DIR/venv/bin/zabbix-mcp-server" --version 2>&1 || true)
    ok "Installed: $version"

    # Check if reporting is available
    if "$INSTALL_DIR/venv/bin/python" -c "import weasyprint, jinja2" 2>/dev/null; then
        ok "PDF reporting: enabled"
    else
        info "PDF reporting: disabled (install with --with-reporting to enable)"
    fi
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

    # Service user + group
    if ! id "$SERVICE_USER" &>/dev/null; then
        info "Creating system user '$SERVICE_USER'..."
        if ! getent group "$SERVICE_USER" &>/dev/null; then
            groupadd --system "$SERVICE_USER"
        fi
        useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" \
            --gid "$SERVICE_USER" "$SERVICE_USER"
    fi

    # Directories
    info "Creating directories..."
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
    mkdir -p "$CONFIG_DIR/assets" "$CONFIG_DIR/tls"
    chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
    chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR" "$CONFIG_DIR/assets" "$CONFIG_DIR/tls"
    chmod 750 "$CONFIG_DIR" "$CONFIG_DIR/tls"
    touch "$LOG_DIR/server.log"
    chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR/server.log"

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

    # Verify permissions (catches issues from re-runs or partial earlier installs)
    check_permissions

    # Firewall & SELinux checks
    local active_port active_host
    active_port=$(get_configured_port)
    active_host=$(get_configured_host)
    check_firewall_and_selinux "$active_port"

    # Setup admin portal (generate password, write [admin] section)
    setup_admin
    migrate_legacy_token

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
    echo "    MCP endpoint:   http://localhost:$active_port/mcp"
    echo "    Health check:   http://localhost:$active_port/health"
    echo "    Admin portal:   http://localhost:9090"
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

    # Pull latest code if we're in a git repo (skip on re-exec — already pulled)
    if [[ -d "$SCRIPT_DIR/.git" ]] && [[ -z "${WMCP_REEXEC:-}" ]]; then
        if command -v git &>/dev/null; then
            local need_reexec=false
            local pull_output
            if pull_output=$(git -C "$SCRIPT_DIR" pull --ff-only 2>&1); then
                if [[ "$pull_output" != *"Already up to date"* ]]; then
                    need_reexec=true
                fi
                ok "Git pull: $pull_output"
            else
                warn "Fast-forward pull failed (diverged history or local changes)."
                local current_branch
                current_branch=$(git -C "$SCRIPT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
                info "Trying: git fetch + reset to origin/${current_branch}..."
                if git -C "$SCRIPT_DIR" fetch origin 2>&1 && \
                   git -C "$SCRIPT_DIR" reset --hard "origin/${current_branch}" 2>&1; then
                    ok "Repository synced to latest origin/${current_branch}."
                    need_reexec=true
                else
                    warn "Git sync failed — continuing with current local version."
                    warn "To fix manually: cd $SCRIPT_DIR && git fetch origin && git reset --hard origin/${current_branch}"
                fi
            fi
            # Re-exec with updated script to ensure new code runs new installer
            if $need_reexec && [[ -z "${WMCP_REEXEC:-}" ]]; then
                info "Re-executing installer from updated source..."
                export WMCP_REEXEC=1
                exec "$SCRIPT_DIR/deploy/install.sh" "${ORIGINAL_ARGS[@]}"
            fi
        else
            warn "git is not installed — skipping pull. Using existing source in $SCRIPT_DIR."
        fi
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

    # Check and fix file permissions (catches issues from failed earlier installs)
    check_permissions

    # Setup admin portal if not yet configured
    setup_admin
    migrate_legacy_token

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
# Uninstall — complete removal
# --------------------------------------------------------------------------- #
do_uninstall() {
    info "=== Zabbix MCP Server - Uninstall ==="
    echo

    warn "This will permanently remove:"
    echo "  - Systemd service:  ${SERVICE_NAME}.service"
    echo "  - Install dir:      $INSTALL_DIR (virtualenv, binaries)"
    echo "  - Config dir:       $CONFIG_DIR (config.toml)"
    echo "  - Log dir:          $LOG_DIR (server.log and rotated logs)"
    echo "  - Logrotate config: /etc/logrotate.d/${SERVICE_NAME}"
    echo "  - System user:      $SERVICE_USER"
    echo

    local answer
    if [[ -t 0 ]]; then
        read -rp "$(echo -e '\e[1;31m>>>\e[0m') Are you sure? Type 'yes' to confirm: " answer
    else
        read -r answer
    fi

    if [[ "$answer" != "yes" ]]; then
        info "Uninstall cancelled."
        exit 0
    fi

    echo

    # Stop and disable service
    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            spin "Stopping $SERVICE_NAME" systemctl stop "$SERVICE_NAME"
        fi
        if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
            spin "Disabling $SERVICE_NAME" systemctl disable "$SERVICE_NAME"
        fi
    fi

    # Remove systemd unit
    if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        ok "Removed systemd unit"
        if command -v systemctl &>/dev/null; then
            systemctl daemon-reload &>/dev/null || true
        fi
    fi

    # Remove logrotate config
    if [[ -f "/etc/logrotate.d/${SERVICE_NAME}" ]]; then
        rm -f "/etc/logrotate.d/${SERVICE_NAME}"
        ok "Removed logrotate config"
    fi

    # Remove install directory (venv, binaries)
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
        ok "Removed $INSTALL_DIR"
    fi

    # Remove config directory
    if [[ -d "$CONFIG_DIR" ]]; then
        rm -rf "$CONFIG_DIR"
        ok "Removed $CONFIG_DIR"
    fi

    # Remove log directory
    if [[ -d "$LOG_DIR" ]]; then
        rm -rf "$LOG_DIR"
        ok "Removed $LOG_DIR"
    fi

    # Remove system user
    if id "$SERVICE_USER" &>/dev/null; then
        if userdel "$SERVICE_USER" 2>/dev/null; then
            ok "Removed system user '$SERVICE_USER'"
        else
            warn "Could not remove user '$SERVICE_USER' — remove manually: userdel $SERVICE_USER"
        fi
    fi

    echo
    ok "=== Uninstall complete ==="
    echo
    echo "  Note: The git repository ($SCRIPT_DIR) was NOT removed."
    echo "  You can safely delete it manually if no longer needed."
    echo
}

# --------------------------------------------------------------------------- #
# Admin portal setup — generate password, write [admin] section
# --------------------------------------------------------------------------- #
_generate_password() {
    # Generate a random 16-char password using Python (always available after install)
    "$INSTALL_DIR/venv/bin/python" -c "
import secrets, string
alphabet = string.ascii_letters + string.digits
print(''.join(secrets.choice(alphabet) for _ in range(16)))
"
}

_hash_password() {
    local password="$1"
    # Pass password via stdin to avoid shell/Python injection via special characters
    printf '%s' "$password" | "$INSTALL_DIR/venv/bin/python" -c "
import hashlib, os, sys
password = sys.stdin.read()
salt = os.urandom(16)
derived = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
print(f'scrypt:16384:8:1\${salt.hex()}\${derived.hex()}')
"
}

setup_admin() {
    # Check if [admin] section already exists in config
    local config_file="$CONFIG_DIR/config.toml"
    if [[ ! -f "$config_file" ]]; then
        return
    fi

    if grep -q '^\[admin\]' "$config_file" 2>/dev/null; then
        # [admin] section exists — check if users are configured
        if grep -q '^\[admin\.users\.' "$config_file" 2>/dev/null; then
            ok "Admin portal already configured"
            return
        fi
    fi

    info "Setting up admin portal..."

    # Generate admin password
    local admin_password
    admin_password=$(_generate_password)
    local password_hash
    password_hash=$(_hash_password "$admin_password")

    # Add admin user to config.toml
    # Use Python to safely write the hash (contains $ which must not be shell-expanded)
    "$INSTALL_DIR/venv/bin/python" -c "
import sys
config_file = sys.argv[1]
password_hash = sys.argv[2]
has_admin = sys.argv[3] == 'true'

with open(config_file, 'r') as f:
    content = f.read()

if has_admin:
    content += '''
[admin.users.admin]
password_hash = \"''' + password_hash + '''\"
role = \"admin\"
'''
else:
    content += '''
# ---------------------------------------------------------------------------
# Admin Portal (auto-generated by installer)
# ---------------------------------------------------------------------------
[admin]
enabled = true
port = 9090

[admin.users.admin]
password_hash = \"''' + password_hash + '''\"
role = \"admin\"
'''

with open(config_file, 'w') as f:
    f.write(content)
" "$config_file" "$password_hash" "$(grep -q '^\[admin\]' "$config_file" 2>/dev/null && echo true || echo false)"

    chown "$SERVICE_USER:$SERVICE_USER" "$config_file"

    echo
    echo -e "  \e[1;32m╔══════════════════════════════════════════════════╗\e[0m"
    echo -e "  \e[1;32m║          Admin Portal Credentials                ║\e[0m"
    echo -e "  \e[1;32m╠══════════════════════════════════════════════════╣\e[0m"
    echo -e "  \e[1;32m║\e[0m  URL:      http://localhost:9090                  \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m  Username: \e[1madmin\e[0m                                 \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m  Password: \e[1m$admin_password\e[0m                      \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m                                                  \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m  Save this password — it will not be shown again \e[1;32m║\e[0m"
    echo -e "  \e[1;32m╚══════════════════════════════════════════════════╝\e[0m"
    echo
}

migrate_legacy_token() {
    # Migrate auth_token to [tokens.legacy] if it exists and no tokens defined
    local config_file="$CONFIG_DIR/config.toml"
    if [[ ! -f "$config_file" ]]; then
        return
    fi

    # Check if auth_token exists and no [tokens.*] sections
    if grep -qE '^\s*auth_token\s*=' "$config_file" && ! grep -q '^\[tokens\.' "$config_file"; then
        local auth_token
        auth_token=$(grep -E '^\s*auth_token\s*=' "$config_file" | head -1 | sed 's/.*=\s*//' | tr -d ' "'\''')
        if [[ -n "$auth_token" && "$auth_token" != '${'* ]]; then
            info "Migrating legacy auth_token to [tokens.legacy]..."
            local token_hash
            # Pass token via stdin to avoid shell injection
            token_hash=$(printf '%s' "$auth_token" | "$INSTALL_DIR/venv/bin/python" -c "
import hashlib, sys
token = sys.stdin.read()
print(f'sha256:{hashlib.sha256(token.encode()).hexdigest()}')
")
            cat >> "$config_file" << 'TOKEN'

# ---------------------------------------------------------------------------
# MCP Tokens (migrated from auth_token by installer)
# ---------------------------------------------------------------------------
[tokens.legacy]
name = "Legacy config.toml token"
TOKEN
            # Append token_hash via echo (contains no shell-special chars — hex only)
            echo "token_hash = \"$token_hash\"" >> "$config_file"
            cat >> "$config_file" << 'TOKEN'
scopes = ["*"]
read_only = false
is_legacy = true
TOKEN
            ok "Legacy auth_token migrated to [tokens.legacy]"
        fi
    fi
}

do_generate_token() {
    info "=== Zabbix MCP Server - Generate MCP Token ==="
    echo

    if [[ ! -d "$INSTALL_DIR/venv" ]]; then
        error "No installation found at $INSTALL_DIR"
        exit 1
    fi

    local config_file="$CONFIG_DIR/config.toml"
    local token_name=""

    # Accept name as argument or prompt
    if [[ -n "${1:-}" ]]; then
        token_name="$1"
    elif [[ -t 0 ]]; then
        read -rp "$(echo -e '\e[1;34m>>>\e[0m') Token name (e.g. claude, ci_pipeline): " token_name
    fi

    if [[ -z "$token_name" ]]; then
        error "Token name is required."
        echo "Usage: sudo ./deploy/install.sh generate-token <name>"
        exit 1
    fi

    # Sanitize name for TOML key
    local token_id
    token_id=$(echo "$token_name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_]/_/g' | cut -c1-50)
    if [[ ! "$token_id" =~ ^[a-z] ]]; then
        token_id="t_${token_id}"
    fi

    # Generate token + hash using Python
    local result
    result=$("$INSTALL_DIR/venv/bin/python" -c "
import secrets, hashlib
raw = 'zmcp_' + secrets.token_hex(32)
hash_str = 'sha256:' + hashlib.sha256(raw.encode()).hexdigest()
print(raw)
print(hash_str)
")
    local raw_token
    raw_token=$(echo "$result" | head -1)
    local token_hash
    token_hash=$(echo "$result" | tail -1)

    # Write to config.toml if it exists
    if [[ -f "$config_file" ]]; then
        # Check for collision
        if grep -q "^\[tokens\.${token_id}\]" "$config_file" 2>/dev/null; then
            error "Token '${token_id}' already exists in config.toml"
            exit 1
        fi

        "$INSTALL_DIR/venv/bin/python" -c "
import sys
config_file = sys.argv[1]
token_id = sys.argv[2]
token_hash = sys.argv[3]
token_name = sys.argv[4]
from datetime import datetime, timezone
created = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

with open(config_file, 'r') as f:
    content = f.read()

content += '''
[tokens.''' + token_id + ''']
name = \"''' + token_name + '''\"
token_hash = \"''' + token_hash + '''\"
scopes = [\"*\"]
read_only = true
created_at = \"''' + created + '''\"
'''

with open(config_file, 'w') as f:
    f.write(content)
" "$config_file" "$token_id" "$token_hash" "$token_name"

        ok "Token written to $config_file as [tokens.${token_id}]"
    fi

    echo
    echo -e "  \e[1;32m╔══════════════════════════════════════════════════════════════════════════════╗\e[0m"
    echo -e "  \e[1;32m║  MCP Token Generated                                                        ║\e[0m"
    echo -e "  \e[1;32m╠══════════════════════════════════════════════════════════════════════════════╣\e[0m"
    echo -e "  \e[1;32m║\e[0m                                                                            \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m  Name:   $token_name"
    echo -e "  \e[1;32m║\e[0m                                                                            \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m  \e[1;33m▸ TOKEN (use in MCP client — copy this!):\e[0m                                 \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m    \e[1;97m$raw_token\e[0m"
    echo -e "  \e[1;32m║\e[0m                                                                            \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m  \e[0;36m▸ HASH (saved to config.toml — do not share):\e[0m                             \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m    \e[0;90m$token_hash\e[0m"
    echo -e "  \e[1;32m║\e[0m                                                                            \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m  \e[1;31m⚠  Save the TOKEN now — it will NOT be shown again!\e[0m                       \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m                                                                            \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m  MCP client config:                                                        \e[1;32m║\e[0m"
    echo -e "  \e[1;32m║\e[0m    \"headers\": {\"Authorization\": \"Bearer \e[1;97m<TOKEN>\e[0m\"}                           \e[1;32m║\e[0m"
    echo -e "  \e[1;32m╚══════════════════════════════════════════════════════════════════════════════╝\e[0m"
    echo

    if command -v systemctl &>/dev/null && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        warn "Restart the service to apply: sudo systemctl restart $SERVICE_NAME"
    fi
}

do_set_admin_password() {
    info "=== Zabbix MCP Server - Set Admin Password ==="
    echo

    if [[ ! -d "$INSTALL_DIR/venv" ]]; then
        error "No installation found at $INSTALL_DIR"
        exit 1
    fi

    local config_file="$CONFIG_DIR/config.toml"
    if [[ ! -f "$config_file" ]]; then
        error "Config file not found at $config_file"
        exit 1
    fi

    local password
    if [[ -t 0 ]]; then
        read -rsp "Enter new admin password (min 10 chars, must include uppercase + digit): " password
        echo
        if [[ ${#password} -lt 10 ]]; then
            error "Password must be at least 10 characters."
            exit 1
        fi
        if ! [[ "$password" =~ [A-Z] ]]; then
            error "Password must contain at least one uppercase letter."
            exit 1
        fi
        if ! [[ "$password" =~ [0-9] ]]; then
            error "Password must contain at least one digit."
            exit 1
        fi
        local confirm
        read -rsp "Confirm password: " confirm
        echo
        if [[ "$password" != "$confirm" ]]; then
            error "Passwords do not match."
            exit 1
        fi
    else
        read -r password
        if [[ ${#password} -lt 10 ]]; then
            error "Password must be at least 10 characters."
            exit 1
        fi
    fi

    local password_hash
    password_hash=$(_hash_password "$password")

    # Update or create [admin.users.admin] in config using Python (safe for $-containing hashes)
    "$INSTALL_DIR/venv/bin/python" -c "
import sys, re
config_file = sys.argv[1]
password_hash = sys.argv[2]

with open(config_file, 'r') as f:
    content = f.read()

if '[admin.users.admin]' in content:
    # Replace existing password_hash line in [admin.users.admin] section
    content = re.sub(
        r'(\[admin\.users\.admin\][^\[]*?)password_hash\s*=\s*\"[^\"]*\"',
        r'\1password_hash = \"' + password_hash + '\"',
        content, count=1, flags=re.DOTALL)
else:
    if '[admin]' not in content:
        content += '\n[admin]\nenabled = true\nport = 9090\nhost = \"127.0.0.1\"\n'
    content += '\n[admin.users.admin]\npassword_hash = \"' + password_hash + '\"\nrole = \"admin\"\n'

with open(config_file, 'w') as f:
    f.write(content)
" "$config_file" "$password_hash"

    ok "Admin password updated successfully."
    info "Restart the server to apply: sudo systemctl restart $SERVICE_NAME"
}

# --------------------------------------------------------------------------- #
# Main — parse arguments
# --------------------------------------------------------------------------- #
COMMAND=""
ORIGINAL_ARGS=("$@")
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
        --with-reporting)
            INSTALL_REPORTING=true
            ;;
        --without-reporting)
            INSTALL_REPORTING=false
            ;;
        install|update|upgrade|uninstall|set-admin-password|generate-token)
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
    uninstall)
        do_uninstall
        ;;
    set-admin-password)
        do_set_admin_password
        ;;
    generate-token)
        do_generate_token "${ORIGINAL_ARGS[@]:1}"
        ;;
    install)
        do_install
        ;;
esac
