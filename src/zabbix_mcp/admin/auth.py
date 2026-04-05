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
    """Hash a password with scrypt. Returns 'scrypt:n:r:p$salt_hex$hash_hex'."""
    salt = os.urandom(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    salt_hex = salt.hex()
    hash_hex = derived.hex()
    return f"scrypt:16384:8:1${salt_hex}${hash_hex}"


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
        derived = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=len(expected))
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
            now = time.time()
            session = Session(
                user=user,
                role=role,
                token=token,
                created_at=now,
                expires_at=now + self.SESSION_DURATION,
                ip=ip,
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
    """Brute-force protection: 5 attempts per 5 minutes per IP."""

    MAX_ATTEMPTS = 5
    WINDOW = 300  # 5 minutes
    LOCKOUT = 30  # 30 seconds

    def __init__(self) -> None:
        self._attempts: dict[str, list[float]] = {}

    def check(self, ip: str) -> bool:
        """Returns True if the IP is allowed to attempt login."""
        now = time.time()
        attempts = self._attempts.get(ip, [])

        # Clean old attempts outside the window
        attempts = [t for t in attempts if now - t < self.WINDOW]
        self._attempts[ip] = attempts

        if len(attempts) >= self.MAX_ATTEMPTS:
            # Block if last attempt was less than LOCKOUT seconds ago
            if attempts and now - attempts[-1] < self.LOCKOUT:
                return False
            # Lockout expired — reset attempts so user can try again
            self._attempts[ip] = []
            return True

        return True

    def record_attempt(self, ip: str) -> None:
        """Record a failed login attempt."""
        now = time.time()
        if ip not in self._attempts:
            self._attempts[ip] = []
        self._attempts[ip].append(now)
        # Periodic cleanup: remove stale IPs to prevent memory leak
        if len(self._attempts) > 500:
            stale = [k for k, v in self._attempts.items() if not v or now - v[-1] > self.WINDOW]
            for k in stale:
                del self._attempts[k]

    def reset(self, ip: str) -> None:
        """Reset attempts after successful login."""
        self._attempts.pop(ip, None)
