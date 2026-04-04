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

"""Multi-token authentication for MCP clients.

Reads token definitions from config.toml [tokens.*] sections.
Each token has: name, token_hash, scopes, read_only, allowed_ips, expires_at.
"""

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any

from mcp.server.auth.provider import AccessToken

logger = logging.getLogger("zabbix_mcp.token_store")


@dataclass
class TokenInfo:
    """Parsed token definition from config."""

    id: str  # config key (e.g. "ci_pipeline")
    name: str  # display name
    token_hash: str  # "sha256:hexdigest"
    scopes: list[str]  # ["monitoring", "alerts"] or ["*"]
    read_only: bool = True
    allowed_ips: list[str] | None = None  # CIDR ranges
    expires_at: str | None = None  # ISO 8601
    is_legacy: bool = False
    # Runtime stats (in-memory only, not persisted)
    last_used_at: str | None = None
    last_used_ip: str | None = None
    use_count: int = 0


class TokenStore:
    """In-memory token store loaded from config.

    Supports hot-reload: call load_from_config() to update tokens
    without restart.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, TokenInfo] = {}  # hash -> TokenInfo
        self._by_id: dict[str, TokenInfo] = {}  # id -> TokenInfo

    def load_from_config(self, tokens_config: dict[str, dict]) -> None:
        """Load/reload tokens from the [tokens.*] config sections.

        tokens_config is like:
        {
            "ci_pipeline": {"name": "CI", "token_hash": "sha256:abc...", ...},
            "claude": {"name": "Claude", "token_hash": "sha256:def...", ...},
        }

        Preserves runtime stats (use_count, last_used) for existing tokens.
        """
        new_tokens: dict[str, TokenInfo] = {}
        new_by_id: dict[str, TokenInfo] = {}

        for token_id, cfg in tokens_config.items():
            token_hash = cfg.get("token_hash", "")
            if not token_hash:
                logger.warning("Token '%s' has no token_hash, skipping", token_id)
                continue

            # Parse allowed_ips: accept string (newline/comma separated) or list
            raw_ips = cfg.get("allowed_ips")
            allowed_ips = None
            if raw_ips:
                if isinstance(raw_ips, str):
                    allowed_ips = [
                        s.strip() for s in raw_ips.replace(",", "\n").split("\n")
                        if s.strip()
                    ]
                elif isinstance(raw_ips, list):
                    allowed_ips = raw_ips

            info = TokenInfo(
                id=token_id,
                name=cfg.get("name", token_id),
                token_hash=token_hash,
                scopes=cfg.get("scopes", ["*"]),
                read_only=cfg.get("read_only", True),
                allowed_ips=allowed_ips,
                expires_at=cfg.get("expires_at"),
                is_legacy=cfg.get("is_legacy", False),
            )

            # Preserve runtime stats from existing token
            existing = self._by_id.get(token_id)
            if existing is not None and existing.token_hash == token_hash:
                info.last_used_at = existing.last_used_at
                info.last_used_ip = existing.last_used_ip
                info.use_count = existing.use_count

            new_tokens[token_hash] = info
            new_by_id[token_id] = info

        self._tokens = new_tokens
        self._by_id = new_by_id
        logger.info("Loaded %d tokens from config", len(new_tokens))

    def load_legacy_token(self, auth_token: str) -> None:
        """Import a legacy auth_token (raw value) as a token entry.

        Called during migration when [tokens] section doesn't exist yet.
        """
        token_hash = f"sha256:{hashlib.sha256(auth_token.encode()).hexdigest()}"
        info = TokenInfo(
            id="_legacy",
            name="Legacy Token",
            token_hash=token_hash,
            scopes=["*"],
            read_only=False,
            is_legacy=True,
        )
        self._tokens[token_hash] = info
        self._by_id["_legacy"] = info
        logger.info("Loaded legacy auth token")

    def verify(self, raw_token: str, client_ip: str | None = None) -> TokenInfo | None:
        """Verify a bearer token. Returns TokenInfo if valid, None if invalid.

        Checks:
        1. Hash matches a known token
        2. Token is not expired
        3. Client IP is in allowed_ips (if configured)

        Updates runtime stats on success.
        Uses constant-time comparison via hmac.compare_digest on hashes.
        """
        computed_hash = f"sha256:{hashlib.sha256(raw_token.encode()).hexdigest()}"

        # Look up by hash in dict (O(1) lookup, no timing leak on key presence)
        info = self._tokens.get(computed_hash)
        if info is None:
            return None

        # Constant-time comparison as an extra safety layer
        if not hmac.compare_digest(computed_hash, info.token_hash):
            return None

        # Check expiration
        if info.expires_at:
            try:
                expires = datetime.fromisoformat(info.expires_at)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > expires:
                    logger.warning("Token '%s' has expired (at %s)", info.id, info.expires_at)
                    return None
            except ValueError:
                logger.warning("Token '%s' has invalid expires_at: %s", info.id, info.expires_at)

        # Check allowed IPs
        if info.allowed_ips and client_ip:
            try:
                addr = ip_address(client_ip)
                allowed = False
                for cidr in info.allowed_ips:
                    try:
                        if addr in ip_network(cidr, strict=False):
                            allowed = True
                            break
                    except ValueError:
                        logger.warning("Invalid CIDR in token '%s': %s", info.id, cidr)
                if not allowed:
                    logger.warning(
                        "Token '%s' rejected: IP %s not in allowed_ips", info.id, client_ip
                    )
                    return None
            except ValueError:
                logger.warning("Invalid client IP for token check: %s", client_ip)

        # Update runtime stats
        info.use_count += 1
        info.last_used_at = datetime.now(timezone.utc).isoformat()
        if client_ip:
            info.last_used_ip = client_ip

        return info

    def list_tokens(self) -> list[TokenInfo]:
        """Return all tokens (for admin UI)."""
        return list(self._by_id.values())

    def get_token(self, token_id: str) -> TokenInfo | None:
        """Get a token by its config ID."""
        return self._by_id.get(token_id)

    @property
    def token_count(self) -> int:
        """Number of active tokens."""
        return len(self._by_id)

    @staticmethod
    def generate_token() -> tuple[str, str]:
        """Generate a new token. Returns (raw_token, hash_string).

        Format: zmcp_ + 64 hex chars (32 bytes)
        Hash: sha256:<hexdigest>

        The raw token is shown once to the user. Only the hash is stored.
        """
        import secrets

        raw = "zmcp_" + secrets.token_hex(32)
        hash_str = f"sha256:{hashlib.sha256(raw.encode()).hexdigest()}"
        return raw, hash_str


class MultiTokenVerifier:
    """MCP auth verifier using TokenStore.

    Replaces the old single-token _BearerTokenVerifier.
    Implements the same interface: async verify_token(token) -> AccessToken | None
    """

    def __init__(self, token_store: TokenStore) -> None:
        self._store = token_store

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a bearer token for MCP authentication.

        Returns AccessToken with scopes from the token definition.
        """
        # Note: we don't have client_ip here from the MCP auth flow,
        # IP checking can be done at the middleware level instead.
        info = self._store.verify(token)
        if info is None:
            return None
        return AccessToken(
            token=token,
            client_id=info.name,
            scopes=info.scopes,
            expires_at=int(time.time()) + 86400,
        )
