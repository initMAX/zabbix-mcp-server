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

"""Admin portal authentication: password hashing, sessions, login."""

import hashlib
import hmac
import os
import secrets
import threading
import time
import logging
from dataclasses import dataclass

logger = logging.getLogger("zabbix_mcp.admin")


def hash_password(password: str) -> str:
    """Hash a password with scrypt. Returns 'scrypt:n:r:p$salt_hex$hash_hex'.

    scrypt parameters follow OWASP 2024 recommendations: N=131072, r=8,
    p=1. Older hashes with N=16384 from pre-v1.21 installs still verify
    correctly (the N value is stored in the hash), so existing admin
    users keep working without a forced password reset.
    """
    salt = os.urandom(16)
    derived = hashlib.scrypt(
        password.encode(), salt=salt, n=131072, r=8, p=1, dklen=32, maxmem=1024 * 1024 * 256,
    )
    salt_hex = salt.hex()
    hash_hex = derived.hex()
    return f"scrypt:131072:8:1${salt_hex}${hash_hex}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored scrypt hash. Constant-time comparison."""
    try:
        params_part, salt_hex, hash_hex = stored_hash.split("$")
    except ValueError:
        logger.warning("Invalid stored hash format")
        return False

    # Parse "scrypt:n:r:p"
    try:
        parts = params_part.split(":")
        if parts[0] != "scrypt" or len(parts) != 4:
            logger.warning("Invalid scrypt parameter format")
            return False
        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])
    except (ValueError, IndexError):
        logger.warning("Failed to parse scrypt parameters")
        return False

    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        logger.warning("Invalid hex in stored hash")
        return False

    try:
        # maxmem must grow with N; OWASP 2024's N=131072 needs ~128 MB.
        # Cap at 256 MB to accommodate any future uplift without opening
        # the door to a DoS via attacker-chosen N.
        derived = hashlib.scrypt(
            password.encode(), salt=salt, n=n, r=r, p=p, dklen=len(expected),
            maxmem=1024 * 1024 * 256,
        )
    except (ValueError, OverflowError) as exc:
        logger.warning("scrypt computation failed: %s", exc)
        return False

    return hmac.compare_digest(derived, expected)


def generate_password(length: int = 16) -> str:
    """Generate a random password for initial setup."""
    import string

    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


@dataclass
class Session:
    """Admin portal session."""

    user: str
    role: str
    token: str
    created_at: float
    expires_at: float
    ip: str  # Stored for audit/logging, not validated (users may change IP during session)
    csrf_token: str = ""  # Per-session CSRF token; rotated with the session


class SessionManager:
    """In-memory session store for admin portal."""

    SESSION_DURATION = 8 * 3600  # 8 hours

    def __init__(self, signing_key: str) -> None:
        self._sessions: dict[str, Session] = {}
        self._signing_key = signing_key
        self._lock = threading.RLock()

    def create_session(self, user: str, role: str, ip: str) -> str:
        """Create a new session, return session token."""
        with self._lock:
            self._cleanup_expired_unlocked()

            token = secrets.token_urlsafe(48)
            csrf_token = secrets.token_urlsafe(32)
            now = time.time()
            session = Session(
                user=user,
                role=role,
                token=token,
                created_at=now,
                expires_at=now + self.SESSION_DURATION,
                ip=ip,
                csrf_token=csrf_token,
            )
            self._sessions[token] = session
            logger.info("Created session for user '%s' from %s", user, ip)
            return token

    def validate_session(self, token: str) -> Session | None:
        """Validate a session token. Returns Session if valid."""
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None

            if time.time() > session.expires_at:
                del self._sessions[token]
                return None

            return session

    def destroy_session(self, token: str) -> None:
        """Logout - remove session."""
        with self._lock:
            session = self._sessions.pop(token, None)
            if session is not None:
                logger.info("Destroyed session for user '%s'", session.user)

    def cleanup_expired(self) -> None:
        """Remove expired sessions (public entry — acquires lock)."""
        with self._lock:
            self._cleanup_expired_unlocked()

    def _cleanup_expired_unlocked(self) -> None:
        """Remove expired sessions (caller must hold self._lock)."""
        now = time.time()
        expired = [
            token for token, session in self._sessions.items()
            if now > session.expires_at
        ]
        for token in expired:
            del self._sessions[token]
        if expired:
            logger.debug("Cleaned up %d expired sessions", len(expired))


class LoginRateLimiter:
    """Brute-force protection: sliding-window attempt counter per IP.

    Unlike a lockout-that-resets scheme, we keep every failed-attempt
    timestamp inside the WINDOW. Paced attacks (1 attempt every LOCKOUT+1
    seconds) cannot bypass the counter - once MAX_ATTEMPTS failures
    accumulate inside WINDOW, further attempts are blocked until the
    oldest one falls out of the window.
    """

    MAX_ATTEMPTS = 5
    WINDOW = 300  # 5 minutes rolling window

    def __init__(self) -> None:
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _purge(self, ip: str, now: float) -> list[float]:
        """Return attempts for ip within WINDOW (may mutate in-place)."""
        attempts = [t for t in self._attempts.get(ip, []) if now - t < self.WINDOW]
        if attempts:
            self._attempts[ip] = attempts
        else:
            self._attempts.pop(ip, None)
        return attempts

    def check(self, ip: str) -> bool:
        """Returns True if the IP is allowed to attempt login."""
        with self._lock:
            now = time.time()
            attempts = self._purge(ip, now)
            return len(attempts) < self.MAX_ATTEMPTS

    def record_attempt(self, ip: str) -> None:
        """Record a failed login attempt."""
        with self._lock:
            now = time.time()
            attempts = self._purge(ip, now)
            attempts.append(now)
            self._attempts[ip] = attempts
            # Periodic cleanup: remove stale IPs to prevent memory leak
            if len(self._attempts) > 500:
                stale = [k for k, v in self._attempts.items() if not v or now - v[-1] > self.WINDOW]
                for k in stale:
                    del self._attempts[k]

    def reset(self, ip: str) -> None:
        """Reset attempts after successful login."""
        with self._lock:
            self._attempts.pop(ip, None)
