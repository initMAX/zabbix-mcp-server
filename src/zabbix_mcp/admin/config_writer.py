#
# Zabbix MCP Server
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

"""Atomic config.toml write-back with comment preservation."""

import os
import signal
import tempfile
import logging
from pathlib import Path

logger = logging.getLogger("zabbix_mcp.admin")

try:
    import tomlkit
    TOMLKIT_AVAILABLE = True
except ImportError:
    TOMLKIT_AVAILABLE = False


def _require_tomlkit() -> None:
    """Raise ImportError if tomlkit is not available."""
    if not TOMLKIT_AVAILABLE:
        raise ImportError(
            "tomlkit is required for config write-back. "
            "Install it with: pip install tomlkit"
        )


def _validate_config_path(config_path: Path) -> Path:
    """Validate that config_path resolves to a real file (no symlink escapes)."""
    resolved = config_path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Config file not found: {resolved}")
    return resolved


def load_config_document(config_path: str | Path) -> "tomlkit.TOMLDocument":
    """Load config.toml as a tomlkit document (preserves comments)."""
    _require_tomlkit()
    path = _validate_config_path(Path(config_path))
    with open(path, "r", encoding="utf-8") as f:
        return tomlkit.load(f)


def save_config_document(config_path: str | Path, doc: "tomlkit.TOMLDocument") -> None:
    """Atomically save a tomlkit document back to config.toml.

    1. Write to temp file in same directory
    2. fsync
    3. os.rename (atomic on same filesystem)
    4. Preserve original file permissions
    """
    _require_tomlkit()
    path = _validate_config_path(Path(config_path))
    parent = path.parent

    # Preserve original permissions
    original_stat = os.stat(path)
    original_mode = original_stat.st_mode

    content = tomlkit.dumps(doc)

    # Try atomic write (temp + rename), fallback to direct write
    # (rename fails on Docker bind mounts / cross-device)
    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".config_", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, original_mode)
        os.rename(tmp_path, str(path))
        tmp_path = None
        logger.info("Config saved atomically: %s", path)
    except OSError:
        # Atomic rename failed (cross-device mount) — fall back to direct write
        if fd is not None:
            os.close(fd)
        if tmp_path is not None and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        logger.info("Config saved (direct write): %s", path)


def update_config_section(config_path: str | Path, section: str, data: dict) -> None:
    """Update a top-level section in config.toml.

    Example: update_config_section(path, "server", {"rate_limit": 500})
    Creates the section if it doesn't exist.
    """
    _require_tomlkit()
    doc = load_config_document(config_path)

    if section not in doc:
        doc.add(section, tomlkit.table())

    for key, value in data.items():
        doc[section][key] = value

    save_config_document(config_path, doc)
    logger.info("Updated config section [%s] with keys: %s", section, list(data.keys()))


def add_config_table(config_path: str | Path, section: str, key: str, data: dict) -> None:
    """Add a sub-table. Example: add_config_table(path, "tokens", "my_token", {...})

    Creates [tokens.my_token] section.
    """
    _require_tomlkit()
    doc = load_config_document(config_path)

    if section not in doc:
        doc.add(section, tomlkit.table())

    sub_table = tomlkit.table()
    for k, v in data.items():
        sub_table.add(k, v)

    doc[section].add(key, sub_table)
    save_config_document(config_path, doc)
    logger.info("Added config table [%s.%s]", section, key)


def remove_config_table(config_path: str | Path, section: str, key: str) -> None:
    """Remove a sub-table. Example: remove_config_table(path, "tokens", "my_token")"""
    _require_tomlkit()
    doc = load_config_document(config_path)

    if section not in doc:
        logger.warning("Section [%s] not found in config, nothing to remove", section)
        return

    if key not in doc[section]:
        logger.warning("Key '%s' not found in [%s], nothing to remove", key, section)
        return

    del doc[section][key]
    save_config_document(config_path, doc)
    logger.info("Removed config table [%s.%s]", section, key)


def signal_reload(pid_file: str | None = None) -> None:
    """Send SIGHUP to the server process for config reload.

    Try to find the PID from a pid file, systemd, or /proc.
    """
    pid = None

    # Try pid file first
    if pid_file:
        pid_path = Path(pid_file)
        if pid_path.is_file():
            try:
                pid = int(pid_path.read_text().strip())
            except (ValueError, OSError) as exc:
                logger.warning("Failed to read PID from %s: %s", pid_file, exc)

    # Try systemd
    if pid is None:
        try:
            import subprocess
            result = subprocess.run(
                ["systemctl", "show", "zabbix-mcp-server", "--property=MainPID", "--value"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip().isdigit():
                candidate = int(result.stdout.strip())
                if candidate > 0:
                    pid = candidate
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    if pid is None:
        logger.warning("Could not determine server PID, skipping reload signal")
        return

    try:
        os.kill(pid, signal.SIGHUP)
        logger.info("Sent SIGHUP to PID %d for config reload", pid)
    except ProcessLookupError:
        logger.warning("Process %d not found, cannot send reload signal", pid)
    except PermissionError:
        logger.warning("Permission denied sending SIGHUP to PID %d", pid)
