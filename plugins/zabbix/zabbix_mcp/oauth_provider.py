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

"""OAuth 2.1 Authorization Server provider for the MCP server.

Implements the ``OAuthAuthorizationServerProvider`` protocol from the
MCP framework so that ChatGPT custom apps, Claude Desktop remote
connectors, and any other MCP 2025-11-25 compliant client can finish
their handshake against this server without operators having to bolt
on a separate IdP.

Architecture:

* The MCP server itself is the resource server (RS), the authorization
  server (AS), and the user identity backend, all in one process.
  Tokens are opaque (random hex), held in memory; since AS == RS,
  there is no need for JWT signing or JWKS to bridge a trust boundary.
* User authentication reuses the admin-portal users (scrypt hashes
  in ``/etc/zabbix-mcp/config.toml``).  Operators do not maintain a
  second identity store.
* Dynamic client registration (RFC 7591) is enabled by default;
  registered clients persist in ``[oauth_clients.<client_id>]``
  config sections so they survive a server restart.  Authorization
  codes (10-min TTL) and refresh tokens are in-memory only.
* The ``aud`` (resource indicator, RFC 8707) on every issued access
  token is bound to the canonical MCP URL declared via
  ``[server].public_url`` -- a token issued for one MCP deployment
  cannot be replayed against another.
* The legacy single-token / multi-token bearer mode keeps working:
  ``load_access_token`` first tries the OAuth-issued token cache and
  falls back to the existing ``TokenStore`` so a token configured as
  ``[tokens.<id>]`` can be used as a Bearer credential alongside
  OAuth tokens.

What it does NOT do (deferred):

* No JWT issuance / JWKS endpoint -- not required while AS == RS.
  If we later split the AS off the MCP host, swap opaque tokens for
  RS256 JWTs and add a ``/oauth/jwks.json`` route.
* No token introspection (RFC 7662) -- ``load_access_token`` is the
  in-process equivalent; clients never call introspection because the
  RS is local.
* No PAR (RFC 9126) -- not required by the MCP 2025-11-25 spec; can
  be added later if a client needs it.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections import OrderedDict
from typing import Any
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger("zabbix_mcp.oauth")

# ---------------------------------------------------------------------------
# Lifetime defaults (operator-overridable via [oauth] in config.toml)
# ---------------------------------------------------------------------------

# Authorization codes are short-lived per OAuth 2.1 §4.1.3.
_AUTH_CODE_TTL_SECONDS = 600  # 10 minutes

# Default access-token lifetime (1 hour). Refresh-token rotation gives
# clients a way to extend without forcing the operator to log in again.
_ACCESS_TOKEN_TTL_SECONDS = 3600

# Refresh tokens last 30 days. Each use rotates to a new refresh token
# (per OAuth 2.1 public-client requirements).
_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600

# Bound the in-memory tables so a misbehaving / abusive client cannot
# drive the server out of memory by churning codes or refresh tokens.
_MAX_LIVE_CODES = 10_000
_MAX_LIVE_REFRESH_TOKENS = 50_000
_MAX_LIVE_ACCESS_TOKENS = 50_000


def _new_secret(num_bytes: int = 32) -> str:
    """Cryptographically secure URL-safe token, suitable for codes / tokens."""
    return secrets.token_urlsafe(num_bytes)


class _PendingAuthorization:
    """Holds an /authorize request that is awaiting user login + consent.

    The framework's authorize handler hands us validated AuthorizationParams
    and the resolved client; we stash them keyed by an opaque ``request_id``
    and return a redirect to our login page that carries that request_id.

    Lifecycle states (tracked via ``authenticated_subject``):

    - **Fresh** -- created by ``authorize()``; ``authenticated_subject`` is
      ``None``. The user-agent has been redirected to ``/oauth/login``.
    - **Authenticated, awaiting consent** -- the operator typed valid
      credentials; ``authenticated_subject`` is set to their username.
      The browser is on the consent screen which lists the scopes / tools
      the client is asking for.
    - **Completed** -- ``complete_pending`` consumed the entry, minted an
      authorization code, and 302'd the browser back to the client.

    The two-step (login -> consent) shape is what users expect from
    OAuth: at no point does the operator hand the keys over without
    seeing what the third-party client will be allowed to do.
    """

    __slots__ = ("client", "params", "expires_at", "authenticated_subject", "authenticated_role")

    def __init__(self, client: OAuthClientInformationFull, params: AuthorizationParams, ttl_seconds: int = _AUTH_CODE_TTL_SECONDS) -> None:
        self.client = client
        self.params = params
        self.expires_at = time.time() + ttl_seconds
        self.authenticated_subject: str | None = None
        # Role of the operator who logged in (admin/operator/viewer);
        # caps which scopes this consent step can grant.
        self.authenticated_role: str | None = None


class ZmcpOAuthProvider:
    """OAuth 2.1 AS+RS for the Zabbix MCP server.

    Methods on this class are awaited by the MCP framework's auth
    handlers in ``mcp.server.auth.handlers.*`` -- they implement the
    ``OAuthAuthorizationServerProvider`` Protocol.

    Args:
        public_url: Canonical https URL the MCP server is reachable on
            (e.g. ``https://mcp.example.com``).  Used as the issuer for
            metadata documents and as the ``aud`` value on every issued
            token.
        token_store: Existing legacy bearer-token store.  We never write
            to it; we use it as a fallback in ``load_access_token`` so
            clients that already authenticate with a static
            ``[tokens.<id>]`` bearer keep working when OAuth is enabled.
        login_path: Path on the same host the AS will redirect users to
            for credential entry, e.g. ``"/oauth/login"``.  The login
            view receives ``?request_id=...`` and is responsible for
            calling ``complete_pending`` once the user authenticates.
        registered_clients_loader: Callable returning a dict mapping
            ``client_id -> OAuthClientInformationFull``.  Called once at
            startup; subsequent ``register_client`` calls are persisted
            via ``register_client_persister``.
        register_client_persister: Callable that writes a newly
            registered client back to disk (config.toml).  Receives the
            full client information.
    """

    def __init__(
        self,
        *,
        public_url: str,
        token_store: Any,
        login_path: str = "/oauth/login",
        registered_clients_loader: Any = None,
        register_client_persister: Any = None,
        auth_code_ttl_seconds: int = _AUTH_CODE_TTL_SECONDS,
        access_token_ttl_seconds: int = _ACCESS_TOKEN_TTL_SECONDS,
        refresh_token_ttl_seconds: int = _REFRESH_TOKEN_TTL_SECONDS,
    ) -> None:
        self._public_url = public_url.rstrip("/")
        self._token_store = token_store
        self._login_path = login_path
        self._persist_client = register_client_persister
        self._auth_code_ttl = max(60, int(auth_code_ttl_seconds))
        self._access_token_ttl = max(60, int(access_token_ttl_seconds))
        self._refresh_token_ttl = max(self._access_token_ttl, int(refresh_token_ttl_seconds))

        # client_id -> OAuthClientInformationFull
        self._clients: dict[str, OAuthClientInformationFull] = {}
        if registered_clients_loader is not None:
            try:
                self._clients = dict(registered_clients_loader() or {})
            except Exception as exc:  # pragma: no cover
                logger.exception("Could not load persisted OAuth clients: %s", exc)

        # request_id -> _PendingAuthorization (login-in-flight)
        self._pending: OrderedDict[str, _PendingAuthorization] = OrderedDict()

        # code -> AuthorizationCode (one-shot, 10-min TTL)
        self._codes: OrderedDict[str, AuthorizationCode] = OrderedDict()

        # token -> AccessToken (with subject metadata)
        self._access_tokens: OrderedDict[str, AccessToken] = OrderedDict()

        # refresh -> RefreshToken
        self._refresh_tokens: OrderedDict[str, RefreshToken] = OrderedDict()

        # access_token -> refresh_token (so revoke cascades)
        self._access_to_refresh: dict[str, str] = {}
        # Refresh-token chain bookkeeping for reuse detection (RFC 6819
        # §5.2.2.3).  Each (client_id, subject) login starts a chain;
        # rotating the refresh token via /token bumps it forward.  When
        # an *already-rotated* refresh token is presented, that means
        # the legitimate client and the attacker each hold a copy and
        # one of them is replaying - the safest response is to revoke
        # the entire chain (every access + refresh under that family)
        # and force the operator to re-authorize.
        # consumed_refresh_token -> family_id
        self._consumed_refresh_tokens: OrderedDict[str, str] = OrderedDict()
        # active_refresh_token -> family_id
        self._active_refresh_family: dict[str, str] = {}
        # family_id -> set of token strings (access + refresh) we should
        # nuke when reuse is detected.
        self._family_tokens: dict[str, set[str]] = {}

    # ------------------------------------------------------------------
    # Pending authorization plumbing (called from our /oauth/login view)
    # ------------------------------------------------------------------

    def stash_pending(self, request_id: str, pending: _PendingAuthorization) -> None:
        """Cache an in-flight /authorize -- caller is the framework's authorize handler."""
        self._gc(self._pending, _MAX_LIVE_CODES)
        self._pending[request_id] = pending

    def take_pending(self, request_id: str) -> _PendingAuthorization | None:
        """Pop a pending /authorize -- caller is our login completion view."""
        pending = self._pending.pop(request_id, None)
        if pending is None:
            return None
        if pending.expires_at < time.time():
            return None
        return pending

    def complete_pending(
        self,
        request_id: str,
        granted_scopes: list[str],
        subject: str,
    ) -> str | None:
        """Finalize a logged-in user's consent; mint a code, return the redirect URL.

        Args:
            request_id: Token returned to the login view in ``?request_id=``.
            granted_scopes: Scopes the user actually consented to (subset of
                what the client asked for).
            subject: Username / token id of the authenticated user; embedded
                in issued access tokens so request handlers can attribute
                tool calls back to the operator.

        Returns:
            The full client redirect URL with ``code`` and ``state``
            query params, or ``None`` if the request_id was unknown
            or expired (caller renders an error).
        """
        pending = self.take_pending(request_id)
        if pending is None:
            return None

        code_str = _new_secret(32)
        code = AuthorizationCode(
            code=code_str,
            scopes=list(granted_scopes),
            expires_at=time.time() + self._auth_code_ttl,
            client_id=str(pending.client.client_id or ""),
            code_challenge=pending.params.code_challenge,
            redirect_uri=pending.params.redirect_uri,
            redirect_uri_provided_explicitly=pending.params.redirect_uri_provided_explicitly,
            resource=pending.params.resource,
        )
        # Park the authenticated subject so exchange_authorization_code
        # can carry it onto the access token.
        object.__setattr__(code, "_subject", subject)  # type: ignore[arg-type]
        self._gc(self._codes, _MAX_LIVE_CODES)
        self._codes[code_str] = code

        # Use the framework helper for clean URL composition: it parses
        # the redirect_uri, preserves any existing query params, handles
        # fragments correctly, and re-encodes via urlunparse so we never
        # produce malformed output even when the registered redirect_uri
        # already carries a query string or hash fragment.
        return construct_redirect_uri(
            str(pending.params.redirect_uri),
            code=code_str,
            state=pending.params.state,
        )

    # ------------------------------------------------------------------
    # OAuthAuthorizationServerProvider protocol implementation
    # ------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # Mint client_id if the client did not pre-supply one (RFC 7591 §3.2.1).
        if not client_info.client_id:
            client_info.client_id = _new_secret(16)
        # Public PKCE clients (e.g. Claude Desktop, ChatGPT browser flow)
        # do NOT get a client_secret. A confidential client is granted a
        # secret only when it asked for non-"none" auth.
        if (
            client_info.token_endpoint_auth_method
            and client_info.token_endpoint_auth_method != "none"
            and not client_info.client_secret
        ):
            client_info.client_secret = _new_secret(32)
        client_info.client_id_issued_at = int(time.time())
        self._clients[client_info.client_id] = client_info
        if self._persist_client is not None:
            try:
                self._persist_client(client_info)
            except Exception as exc:  # pragma: no cover
                logger.exception("Could not persist OAuth client %s: %s", client_info.client_id, exc)
        logger.info(
            "OAuth client registered: id=%s name=%r redirect_uris=%s",
            client_info.client_id,
            client_info.client_name,
            [str(u) for u in (client_info.redirect_uris or [])],
        )
        # Audit-log the registration so the operator has a paper trail of
        # which clients dynamically registered themselves and when.  RFC
        # 7591 lets any caller register; without an audit row, an operator
        # has no way to spot a malicious registration after the fact.
        try:
            from zabbix_mcp.admin.audit_writer import write_audit
            from zabbix_mcp.token_store import current_client_ip
            write_audit(
                action="oauth.client_register",
                user="(dynamic registration)",
                target_type="oauth_client",
                target_id=str(client_info.client_id or ""),
                details={
                    "client_name": client_info.client_name or "",
                    "redirect_uris": [str(u) for u in (client_info.redirect_uris or [])],
                    "token_endpoint_auth_method": client_info.token_endpoint_auth_method or "none",
                    "scope": client_info.scope or "",
                },
                ip=current_client_ip.get() or "",
            )
        except Exception:
            logger.exception("Could not write oauth.client_register audit row")

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """Hand the user-agent off to our login form; framework redirects them."""
        request_id = _new_secret(24)
        self.stash_pending(request_id, _PendingAuthorization(client, params, ttl_seconds=self._auth_code_ttl))
        return f"{self._public_url}{self._login_path}?request_id={request_id}"

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        code = self._codes.get(authorization_code)
        if code is None:
            return None
        if code.client_id != (client.client_id or ""):
            return None
        if code.expires_at < time.time():
            self._codes.pop(authorization_code, None)
            return None
        return code

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        # IP allowlist enforcement (parity with [tokens.X].allowed_ips).
        # Read-only on the OAuthClientInformationFull object so the
        # allowlist persists in [oauth_clients.X] config.toml without
        # extending the framework's data model.
        self._enforce_client_ip_allowlist(client)
        # One-shot: code is consumed even on the happy path.
        self._codes.pop(authorization_code.code, None)
        subject = getattr(authorization_code, "_subject", "anonymous")
        # Per-client TTL override (read off OAuthClientInformationFull
        # via the same private-attribute trick we use for subject).
        access_ttl = self._client_access_ttl(client)
        refresh_ttl = self._client_refresh_ttl(client)
        return self._mint_token_pair(
            client_id=str(client.client_id or ""),
            scopes=list(authorization_code.scopes),
            subject=str(subject),
            resource=authorization_code.resource,
            access_ttl_override=access_ttl,
            refresh_ttl_override=refresh_ttl,
        )

    def _enforce_client_ip_allowlist(self, client: OAuthClientInformationFull) -> None:
        """Raise TokenError if the calling IP is outside the client's allowlist.

        The allowlist is stored as a private attribute set in
        ``register_client`` from the optional ``allowed_ips`` field on
        the [oauth_clients.X] config row.  Empty / missing list = no
        restriction.  Same CIDR semantics as ``[tokens.X].allowed_ips``.
        """
        allowed_ips = getattr(client, "_allowed_ips", None) or []
        if not allowed_ips:
            return
        from zabbix_mcp.token_store import current_client_ip
        client_ip = current_client_ip.get()
        if not client_ip:
            raise TokenError("invalid_grant", "client IP allowlist is configured but caller IP is unknown")
        try:
            from ipaddress import ip_address, ip_network
            addr = ip_address(client_ip)
            if not any(addr in ip_network(c, strict=False) for c in allowed_ips):
                raise TokenError("invalid_grant", f"client IP {client_ip} not in allowlist")
        except (ValueError, TypeError) as exc:
            raise TokenError("invalid_grant", f"IP allowlist evaluation failed: {exc}")

    def _client_access_ttl(self, client: OAuthClientInformationFull) -> int:
        v = getattr(client, "_access_ttl", None)
        return int(v) if v else self._access_token_ttl

    def _client_refresh_ttl(self, client: OAuthClientInformationFull) -> int:
        v = getattr(client, "_refresh_ttl", None)
        return int(v) if v else self._refresh_token_ttl

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        # Reuse detection (RFC 6819 §5.2.2.3): if this refresh token has
        # already been consumed in a previous rotation, somebody is
        # replaying.  Nuke the entire family (every access + refresh
        # token derived from the original grant) so the legitimate
        # client is forced to re-authenticate alongside the attacker.
        if refresh_token in self._consumed_refresh_tokens:
            family = self._consumed_refresh_tokens.get(refresh_token)
            if family is not None:
                self._revoke_family(family, reason="refresh_token_reuse_detected")
            return None
        rt = self._refresh_tokens.get(refresh_token)
        if rt is None:
            return None
        if rt.client_id != (client.client_id or ""):
            return None
        if rt.expires_at and rt.expires_at < int(time.time()):
            self._refresh_tokens.pop(refresh_token, None)
            return None
        return rt

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Per OAuth 2.1 §4.3.1, rotate the refresh token; reject any scope
        # the client did not originally hold.
        for s in scopes or []:
            if s not in refresh_token.scopes:
                raise TokenError("invalid_scope", f"scope '{s}' was not in the original grant")
        # Mark the incoming refresh token as consumed BEFORE minting the
        # next pair, so a concurrent replay enters the reuse-detection
        # path in load_refresh_token.
        family = self._active_refresh_family.pop(refresh_token.token, None)
        self._refresh_tokens.pop(refresh_token.token, None)
        if family is not None:
            self._gc(self._consumed_refresh_tokens, _MAX_LIVE_REFRESH_TOKENS)
            self._consumed_refresh_tokens[refresh_token.token] = family
        # Inherit subject from the previous access token for this refresh,
        # if we still have it; otherwise mark anonymous (the user logged
        # in long enough ago that the AT expired).  Also clear the stale
        # _access_to_refresh entry so the back-pointer table does not
        # accumulate dead rows on long-running sessions.
        subject = "anonymous"
        for at_str, at in list(self._access_tokens.items()):
            if self._access_to_refresh.get(at_str) == refresh_token.token:
                subject = getattr(at, "_subject", "anonymous")
                self._access_tokens.pop(at_str, None)
                self._access_to_refresh.pop(at_str, None)
                break
        else:
            # AT was already evicted; sweep any orphan back-pointer.
            for at_str, rt_str in list(self._access_to_refresh.items()):
                if rt_str == refresh_token.token:
                    self._access_to_refresh.pop(at_str, None)
        new_scopes = list(scopes or refresh_token.scopes)
        return self._mint_token_pair(
            client_id=refresh_token.client_id,
            scopes=new_scopes,
            subject=str(subject),
            resource=None,
            family_id=family,  # rotate within the same family
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        # 1. OAuth-issued tokens
        at = self._access_tokens.get(token)
        if at is not None:
            if at.expires_at and at.expires_at < int(time.time()):
                self._access_tokens.pop(token, None)
                return None
            # Audience binding (RFC 8707 §2): refuse a token issued for
            # a different MCP deployment.
            if at.resource and not _audience_matches(at.resource, self._public_url):
                logger.warning(
                    "Rejected access token: aud=%s does not match this MCP server (%s)",
                    at.resource, self._public_url,
                )
                return None
            self._publish_token_to_contextvar(
                token=token,
                client_id=at.client_id,
                scopes=list(at.scopes),
                subject=str(getattr(at, "_subject", "anonymous")),
                read_only=False,
                source="oauth",
            )
            return at

        # 2. Legacy bearer fallback - existing config.toml [tokens.X] entries
        ts = self._token_store
        if ts is None:
            return None
        try:
            verify = ts.verify
        except AttributeError:
            return None
        # Read client IP from contextvar so legacy IP allowlists are honored
        # exactly like the original MultiTokenVerifier did.
        from zabbix_mcp.token_store import current_client_ip, current_token_info
        info = verify(token, client_ip=current_client_ip.get())
        if info is None or info.revoked:
            return None
        current_token_info.set(info)  # parity with MultiTokenVerifier.verify_token
        scopes = list(info.scopes) if info.scopes else ["*"]
        bridged = AccessToken(
            token=token,
            client_id=f"legacy:{info.id}",
            scopes=scopes,
            expires_at=None,
            resource=self._public_url,
        )
        return bridged

    def _publish_token_to_contextvar(
        self,
        *,
        token: str,
        client_id: str,
        scopes: list[str],
        subject: str,
        read_only: bool,
        source: str,
    ) -> None:
        """Bridge an OAuth AccessToken into the legacy ``TokenInfo`` contextvar.

        The downstream tool dispatcher (``_make_tool_handler``) reads
        ``current_token_info`` via ``check_token_authorization`` to enforce
        server-binding, scope, and read-only restrictions.  Without this
        bridge, OAuth-authenticated requests would skip those checks entirely
        because the contextvar would still be ``None``.
        """
        from zabbix_mcp.token_store import current_token_info, TokenInfo
        info = TokenInfo(
            id=f"{source}:{client_id}",
            name=f"{source}:{client_id}:{subject}",
            token_hash="",  # OAuth tokens are opaque, no hash bookkeeping
            token_prefix="",
            scopes=scopes,
            read_only=read_only,
            allowed_ips=None,  # OAuth tokens are not bound to client IPs
            allowed_servers=["*"],
            expires_at=None,
            is_legacy=False,
            revoked=False,
        )
        current_token_info.set(info)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        # Revoke the access + refresh together regardless of which arrived.
        if isinstance(token, AccessToken):
            access_str = token.token
            refresh_str = self._access_to_refresh.pop(access_str, None)
            client_id = token.client_id
            kind = "access_token"
        else:
            refresh_str = token.token
            access_str = None
            client_id = token.client_id
            kind = "refresh_token"
            for a, r in list(self._access_to_refresh.items()):
                if r == refresh_str:
                    access_str = a
                    break
            if access_str is not None:
                self._access_to_refresh.pop(access_str, None)
        if access_str is not None:
            self._access_tokens.pop(access_str, None)
        if refresh_str is not None:
            self._refresh_tokens.pop(refresh_str, None)
        # Audit the client-initiated revocation.  Per-revoke audit lets an
        # operator see when a client signed itself out vs. when an admin
        # nuked the registration from /oauth-clients.
        try:
            from zabbix_mcp.admin.audit_writer import write_audit
            from zabbix_mcp.token_store import current_client_ip
            write_audit(
                action="oauth.token_revoked_by_client",
                user="(oauth client)",
                target_type="oauth_client",
                target_id=str(client_id or ""),
                details={"token_type_hint": kind},
                ip=current_client_ip.get() or "",
            )
        except Exception:
            logger.exception("Could not write oauth.token_revoked_by_client audit row")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _mint_token_pair(
        self,
        *,
        client_id: str,
        scopes: list[str],
        subject: str,
        resource: str | None,
        family_id: str | None = None,
        access_ttl_override: int | None = None,
        refresh_ttl_override: int | None = None,
    ) -> OAuthToken:
        now = int(time.time())
        access_str = _new_secret(32)
        refresh_str = _new_secret(32)
        access_ttl = int(access_ttl_override) if access_ttl_override else self._access_token_ttl
        refresh_ttl = int(refresh_ttl_override) if refresh_ttl_override else self._refresh_token_ttl
        access = AccessToken(
            token=access_str,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + access_ttl,
            resource=resource or self._public_url,
        )
        # Carry subject for downstream auth checks; not part of the
        # OAuth wire model so we attach it as a private attribute.
        object.__setattr__(access, "_subject", subject)  # type: ignore[arg-type]
        refresh = RefreshToken(
            token=refresh_str,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + refresh_ttl,
        )
        self._gc(self._access_tokens, _MAX_LIVE_ACCESS_TOKENS)
        self._gc(self._refresh_tokens, _MAX_LIVE_REFRESH_TOKENS)
        self._access_tokens[access_str] = access
        self._refresh_tokens[refresh_str] = refresh
        self._access_to_refresh[access_str] = refresh_str

        # Track the refresh-token family so a stolen-then-replayed token
        # can be detected (RFC 6819 §5.2.2.3).  A new family_id is minted
        # at the start of each authorization-code grant; refresh-token
        # rotation reuses the parent family.
        if family_id is None:
            family_id = _new_secret(16)
        self._active_refresh_family[refresh_str] = family_id
        self._family_tokens.setdefault(family_id, set()).update({access_str, refresh_str})

        return OAuthToken(
            access_token=access_str,
            token_type="Bearer",
            expires_in=access_ttl,
            refresh_token=refresh_str,
            scope=" ".join(scopes) if scopes else None,
        )

    def _revoke_family(self, family_id: str, reason: str) -> int:
        """Nuke every access + refresh token tied to ``family_id``.

        Returns the count of tokens revoked.  Audited with the supplied
        ``reason`` so an operator can see "refresh-token reuse detected"
        rows in the audit log distinct from regular admin-initiated
        revokes.
        """
        tokens = self._family_tokens.pop(family_id, set())
        n = 0
        for tok in tokens:
            if self._access_tokens.pop(tok, None) is not None:
                n += 1
            if self._refresh_tokens.pop(tok, None) is not None:
                n += 1
            self._access_to_refresh.pop(tok, None)
            self._active_refresh_family.pop(tok, None)
        try:
            from zabbix_mcp.admin.audit_writer import write_audit
            write_audit(
                action="oauth.token_family_revoked",
                user="(automatic)",
                target_type="oauth_family",
                target_id=family_id,
                details={"reason": reason, "tokens_killed": n},
                ip="",
            )
        except Exception:
            logger.exception("Could not write oauth.token_family_revoked audit row")
        return n

    @staticmethod
    def _gc(table: OrderedDict, limit: int) -> None:
        """Bound an in-memory table by evicting the oldest entries when full."""
        while len(table) >= limit:
            try:
                table.popitem(last=False)
            except KeyError:
                return


def _audience_matches(aud: str, expected: str) -> bool:
    """RFC 8707 §2 audience matching.

    Compares scheme+host+port (the canonical resource identity);
    accepts an extra path on the token's audience as long as it is
    a prefix of, or equal to, the expected URL.
    """
    if aud == expected:
        return True
    a = aud.rstrip("/")
    e = expected.rstrip("/")
    if a == e:
        return True
    return a.startswith(e + "/")
