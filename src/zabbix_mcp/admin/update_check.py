#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#

"""Background GitHub release polling for the admin-portal update banner.

A daemon thread asks GitHub once an hour whether a newer
zabbix-mcp-server release exists. The result is cached in memory and
persisted to ``/var/lib/zabbix-mcp/.version-cache`` so a restart does
not lose the last known answer (saves a check + survives the case
where GitHub is briefly unreachable).

Privacy note: this is the only outbound request the admin portal
makes. It is documented in config.example.toml and
``[admin].update_check_enabled = false`` disables it cleanly. Failures
(offline, GitHub rate-limited, DNS, TLS) are silent so the banner
never causes a noisy log; we just keep showing the previous result.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

from zabbix_mcp import __version__ as CURRENT_VERSION

logger = logging.getLogger("zabbix_mcp.admin.update_check")

# GitHub releases endpoint - public, no auth, 60 req/h per IP. We hit
# it at most once an hour so the rate limit is not a concern.
RELEASES_URL = "https://api.github.com/repos/initMAX/zabbix-mcp-server/releases/latest"
# Cache lives next to the audit log + config dir which is always
# writable by the service user (chown'd by the installer / Docker
# entrypoint). /var/lib/zabbix-mcp does not exist in the container
# image, so we keep persistent state under /etc/zabbix-mcp/state/.
CACHE_PATH = Path("/etc/zabbix-mcp/state/version-cache.json")
CHECK_INTERVAL_SECONDS = 3600  # 1 hour
HTTP_TIMEOUT_SECONDS = 5


def _parse_version(s: str) -> tuple:
    """Parse a tag name like 'v1.24', '1.23b2', '1.23.1' to a tuple
    suitable for comparison. Pre-release suffixes are stripped so
    '1.23b2' < '1.23' < '1.24'.
    """
    if not s:
        return (0,)
    # Strip leading 'v' and any pre-release suffix.
    s = s.lstrip("v")
    base = ""
    for ch in s:
        if ch.isdigit() or ch == ".":
            base += ch
        else:
            break
    parts = []
    for chunk in base.split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            break
    return tuple(parts) if parts else (0,)


class UpdateChecker:
    """Owns the latest_version state and the background poller thread."""

    def __init__(self) -> None:
        self.current_version: str = CURRENT_VERSION
        self.latest_version: str | None = None
        self.release_url: str | None = None
        self.last_checked: float | None = None
        self.update_available: bool = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._load_cache()

    # ----- public API used by templates -----
    def to_context(self) -> dict:
        """Build the dict consumed by base.html for the banner."""
        return {
            "current": self.current_version,
            "latest": self.latest_version,
            "release_url": self.release_url,
            "available": self.update_available,
            "last_checked": self.last_checked,
        }

    # ----- lifecycle -----
    def start(self, enabled: bool) -> None:
        """Launch the background thread when the feature is enabled."""
        if not enabled:
            logger.info("Update check disabled via [admin].update_check_enabled = false")
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="update-check")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # ----- internals -----
    def _loop(self) -> None:
        # First check immediately so the banner can show up on the
        # first page render after restart, then every CHECK_INTERVAL.
        while not self._stop.is_set():
            try:
                self._check()
            except Exception as exc:  # never let a quirk kill the thread
                logger.debug("Update check failed: %s", exc)
            self._stop.wait(CHECK_INTERVAL_SECONDS)

    def _check(self) -> None:
        req = urllib_request.Request(
            RELEASES_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"zabbix-mcp-server/{CURRENT_VERSION}",
            },
        )
        try:
            with urllib_request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
                payload = json.loads(resp.read())
        except (HTTPError, URLError, json.JSONDecodeError, OSError) as exc:
            logger.debug("Update check request failed: %s", exc)
            return
        # Skip pre-releases entirely - operators who want betas test
        # from the release/v* branch directly. The banner only nags
        # them about stable releases.
        if payload.get("prerelease") or payload.get("draft"):
            return
        latest = payload.get("tag_name") or ""
        if not latest:
            return
        self.latest_version = latest.lstrip("v")
        self.release_url = payload.get("html_url") or None
        self.last_checked = time.time()
        self.update_available = _parse_version(self.latest_version) > _parse_version(self.current_version)
        self._save_cache()

    def _load_cache(self) -> None:
        try:
            if not CACHE_PATH.exists():
                return
            data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
            self.latest_version = data.get("latest")
            self.release_url = data.get("release_url")
            self.last_checked = data.get("last_checked")
            self.update_available = (
                self.latest_version is not None
                and _parse_version(self.latest_version) > _parse_version(self.current_version)
            )
        except (OSError, json.JSONDecodeError, ValueError):
            pass

    def _save_cache(self) -> None:
        try:
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            CACHE_PATH.write_text(
                json.dumps({
                    "latest": self.latest_version,
                    "release_url": self.release_url,
                    "last_checked": self.last_checked,
                }),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.debug("Could not persist version cache: %s", exc)


_global_checker: UpdateChecker | None = None


def get_checker() -> UpdateChecker:
    global _global_checker
    if _global_checker is None:
        _global_checker = UpdateChecker()
    return _global_checker
