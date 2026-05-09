#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#

"""Lazy GitHub release check for the admin-portal update banner.

The check fires:
  1. once at server boot (best-effort so the banner reflects reality
     even before anyone logs in), and
  2. on every successful admin login (see ``AdminApp._login`` ->
     ``trigger_async``), throttled to one outbound call per
     CHECK_INTERVAL_SECONDS so a burst of logins or a reload loop
     won't hammer the public GitHub rate limit (60 unauth req/h/IP).
  3. on demand via ``/api/check-updates`` (admin/operator role) which
     calls ``force_check()`` and bypasses the throttle. Wired to the
     "Check now" button in Settings -> Admin Portal so an operator
     who just upgraded does not have to wait out the throttle to
     confirm they are on the latest version.

The result is cached in memory and persisted to
``/etc/zabbix-mcp/state/version-cache.json`` so a restart does not
lose the last known answer (survives the case where GitHub is
briefly unreachable). Idle deployments with no admin sessions and
no manual checks make zero outbound calls.

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
# Minimum gap between two GitHub polls fired by the login-success or
# boot path. The check runs lazily from successful admin logins so the
# throttle only needs to absorb burst scenarios (browser reload loop,
# two operators logging in within seconds, automated health probes
# hitting /login). 60 seconds is plenty for that and keeps the banner
# fresh after an upgrade - an operator who just bumped the version
# and logs in does not have to wait 30 minutes for the GitHub poll
# to refresh. Manual "Check now" presses bypass this throttle via
# ``force_check()``. Theoretical worst case at 60 sec: 60 polls/hour
# vs the public 60 req/h/IP rate limit - matches but does not exceed.
CHECK_INTERVAL_SECONDS = 60
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
    """Owns the latest_version state and fires throttled lazy polls.

    Single global instance accessed via ``get_checker()``. State
    survives a restart through the on-disk cache. Polls are
    triggered by login (or boot for the very first one), never on
    a permanent background thread.
    """

    def __init__(self) -> None:
        self.current_version: str = CURRENT_VERSION
        self.latest_version: str | None = None
        self.release_url: str | None = None
        self.last_checked: float | None = None
        self.update_available: bool = False
        # Feature toggle - admin login wires this up at boot. False
        # means trigger_async() is a no-op so we never reach out.
        self.enabled: bool = False
        self._busy = threading.Lock()
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
        """Wire up the feature toggle. Replaces the old daemon-thread
        boot path - the actual GitHub poll is now fired lazily from
        successful admin logins (see trigger_async). At boot we still
        kick one async poll so the banner reflects reality even before
        anyone logs in (status checks from a script / health probe)."""
        self.enabled = bool(enabled)
        if not self.enabled:
            logger.info("Update check disabled via [admin].update_check_enabled = false")
            return
        # Boot-time best-effort poll so an admin who logs in within
        # CHECK_INTERVAL of restart does not get stale cache data.
        self.trigger_async()

    def stop(self) -> None:
        # Kept for symmetry with the previous API; nothing to stop now
        # that the daemon thread is gone.
        self.enabled = False

    def trigger_async(self) -> None:
        """Fire a one-shot GitHub poll in a background thread when
        the cache is older than CHECK_INTERVAL_SECONDS. Wired into
        the login-success path so a fresh check happens whenever an
        operator walks back into the portal, but not faster than
        once every CHECK_INTERVAL_SECONDS - a burst of logins won't
        hammer the public GitHub rate limit (60 req / h / IP). No-op
        when the feature is disabled."""
        if not self.enabled:
            return
        import time as _time
        now = _time.time()
        if self.last_checked is not None and (now - self.last_checked) < CHECK_INTERVAL_SECONDS:
            return  # cache still fresh
        # Non-blocking: don't add seconds to the login response.
        if not self._busy.acquire(blocking=False):
            return  # another thread is already in flight
        def _runner() -> None:
            try:
                self._check()
            except Exception as exc:
                logger.debug("Update check failed: %s", exc)
            finally:
                self._busy.release()
        threading.Thread(target=_runner, daemon=True, name="update-check-once").start()

    def force_check(self) -> dict:
        """Synchronous force-refresh that bypasses the throttle.

        Wired to the manual "Check now" button on the admin portal.
        Blocks for up to HTTP_TIMEOUT_SECONDS, returns a dict the
        AJAX endpoint can hand straight back to the browser. Honours
        the feature toggle - returns ``{"ok": False, "reason": "disabled"}``
        when ``[admin].update_check_enabled = false``.
        """
        if not self.enabled:
            return {"ok": False, "reason": "disabled", **self.to_context()}
        # Serialize concurrent force-checks. If another check is
        # already running (login-triggered or earlier "Check now")
        # we wait for it, then re-check whether last_checked has
        # advanced under the lock - if so we reuse that result instead
        # of issuing a duplicate GitHub poll. This prevents a burst of
        # button presses (or a login + button press) from doubling the
        # outbound traffic past the public 60 req/h/IP rate limit.
        import time as _time
        entered_at = _time.time()
        with self._busy:
            if self.last_checked is not None and self.last_checked >= entered_at:
                # Another thread polled while we were waiting on the
                # lock - the result is fresh enough, skip the duplicate.
                return {"ok": True, "reused_in_flight": True, **self.to_context()}
            try:
                self._check()
            except Exception as exc:
                logger.debug("Forced update check failed: %s", exc)
                return {"ok": False, "reason": "request_failed", **self.to_context()}
        return {"ok": True, **self.to_context()}

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
