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

"""SAML 2.0 single sign-on for the admin portal (issue #46).

Wraps the OneLogin ``python3-saml`` toolkit. The library is imported
lazily so a deployment that does not need SAML can boot without
``xmlsec1`` system dependency. When ``[admin.saml].enabled = true``,
the login form gains a "Sign in with SAML" button that initiates the
flow:

::

   Browser           Portal                       IdP (Azure AD / Okta / ADFS / Keycloak)
   --------          --------                     ----------------------------------
   GET /saml/login -> build AuthnRequest
                  <- 302 to IdP SSO URL with SAMLRequest base64 in query
   GET IdP SSO ----------------------------------> render login page
                                                   user authenticates
                                                <- 302 to /saml/acs with SAMLResponse POST
   POST /saml/acs -> validate signature
                    extract attributes (email / name / photo)
                    auto-provision local [admin.users.X] entry
                    create session cookie
                  <- 302 to /

Endpoints exposed on the admin portal:

- ``GET /saml/metadata`` - SP metadata XML (operator pastes this URL
  into the IdP "Add application" wizard so the IdP knows our
  EntityID / ACS URL).
- ``GET /saml/login`` - initiator. Builds an AuthnRequest with the
  RelayState pointing at the post-login destination.
- ``POST /saml/acs`` - assertion consumer. Validates signature + audience,
  extracts attributes per the configured mapping, auto-provisions a
  user entry, and creates a session.
- ``GET /saml/slo`` - optional Single Logout endpoint (only when the
  IdP supplies an SLO URL in config).

Mirrors the initmax-portal SAML flow shape (Symfony + python3-saml
share the OneLogin toolkit semantics) so operator docs transfer
near-verbatim from the partners portal SAML guide.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("zabbix_mcp.admin.saml")


@dataclass
class SamlAuthResult:
    """Outcome of a SAML ACS validation."""

    ok: bool
    name_id: str = ""
    email: str = ""
    first_name: str = ""
    last_name: str = ""
    photo_url: str = ""
    role: str = ""
    reason: str = ""
    attributes: dict[str, list[str]] | None = None


def _build_settings(cfg: Any, public_url: str) -> dict:
    """Compose the OneLogin Settings dict from our config dataclass.

    ``public_url`` is the externally-reachable URL of this MCP server
    (``[server].public_url`` or auto-derived). All SAML endpoints
    advertised in metadata + AuthnRequest are anchored at this URL.

    Mirrors the shape SamlSettingsFactory.php builds in the initmax-
    portal so an operator who has the partners SSO running can copy
    most of the IdP-side wiring 1:1.
    """
    base = (public_url or "").rstrip("/")
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": f"{base}/saml/metadata",
            "assertionConsumerService": {
                "url": f"{base}/saml/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": f"{base}/saml/slo",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            "x509cert": "",
            "privateKey": "",
        },
        "idp": {
            "entityId": cfg.idp_entity_id,
            "singleSignOnService": {
                "url": cfg.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": cfg.idp_slo_url or cfg.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": _normalise_cert(cfg.x509_certificate),
        },
        "security": {
            "nameIdEncrypted": False,
            "authnRequestsSigned": False,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "wantNameIdEncrypted": False,
            "requestedAuthnContext": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def _normalise_cert(pem_or_raw: str) -> str:
    """Strip PEM armour + whitespace so OneLogin gets one base64 blob.

    Accepts the certificate in either PEM (-----BEGIN CERTIFICATE-----)
    or raw base64 form; OneLogin's settings parser only wants the
    base64 body.
    """
    if not pem_or_raw:
        return ""
    out = pem_or_raw
    out = out.replace("-----BEGIN CERTIFICATE-----", "")
    out = out.replace("-----END CERTIFICATE-----", "")
    return "".join(out.split())


def _onelogin_request_data(starlette_request: Any) -> dict:
    """Translate a Starlette request into the dict OneLogin expects."""
    url = starlette_request.url
    return {
        "https": "on" if url.scheme == "https" else "off",
        "http_host": url.hostname or "",
        "server_port": url.port or (443 if url.scheme == "https" else 80),
        "script_name": url.path,
        "get_data": dict(starlette_request.query_params),
        "post_data": getattr(starlette_request, "_saml_post_data", {}),
    }


def build_authn_redirect(cfg: Any, public_url: str, request: Any, relay_state: str = "/") -> tuple[str, str]:
    """Return (redirect_url, request_id) for the AuthnRequest.

    Caller stashes the request_id (server-side) so the eventual ACS
    response can be matched to this AuthnRequest.
    """
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError as e:
        raise RuntimeError(
            "python3-saml is not installed. Install with: "
            "pip install python3-saml (requires libxmlsec1 system package)"
        ) from e
    settings = _build_settings(cfg, public_url)
    auth = OneLogin_Saml2_Auth(_onelogin_request_data(request), old_settings=settings)
    redirect = auth.login(return_to=relay_state)
    request_id = auth.get_last_request_id()
    return redirect, request_id


def consume_acs(cfg: Any, public_url: str, request: Any, post_data: dict,
                request_id: str | None = None) -> SamlAuthResult:
    """Validate the SAML response on /saml/acs.

    ``post_data`` is the parsed application/x-www-form-urlencoded body
    (Starlette ``await request.form()`` materialised into a dict).
    ``request_id`` is the AuthnRequest ID we stashed at login start;
    when provided, the toolkit cross-checks the response InResponseTo
    attribute so a replayed assertion targeting a different login
    cannot be reused.
    """
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError:
        return SamlAuthResult(ok=False, reason="python3-saml library missing")
    settings = _build_settings(cfg, public_url)
    # Shove the form into the request shim so _onelogin_request_data picks it up.
    try:
        setattr(request, "_saml_post_data", post_data)
    except Exception:
        pass
    auth = OneLogin_Saml2_Auth(_onelogin_request_data(request), old_settings=settings)
    auth.process_response(request_id=request_id)
    errors = auth.get_errors()
    if errors:
        return SamlAuthResult(
            ok=False,
            reason=", ".join(errors) + f" (last={auth.get_last_error_reason() or 'n/a'})",
        )
    if not auth.is_authenticated():
        return SamlAuthResult(ok=False, reason="SAML response did not authenticate")
    name_id = auth.get_nameid() or ""
    attrs = auth.get_attributes() or {}
    email = _pick_attr(attrs, cfg.email_attribute) or name_id
    first = _pick_attr(attrs, cfg.first_name_attribute) or ""
    last = _pick_attr(attrs, cfg.last_name_attribute) or ""
    photo = ""
    if cfg.photo_url_attribute:
        photo = _pick_attr(attrs, cfg.photo_url_attribute) or ""
    return SamlAuthResult(
        ok=True,
        name_id=name_id,
        email=email,
        first_name=first,
        last_name=last,
        photo_url=photo,
        role=cfg.default_role,  # role assignment via SAML claim is a v1.33 feature
        attributes={k: list(v) if isinstance(v, list) else [str(v)] for k, v in attrs.items()},
    )


def _pick_attr(attrs: dict, key: str) -> str:
    """Return the first value of ``key`` in the SAML attribute set."""
    if not key:
        return ""
    raw = attrs.get(key)
    if not raw:
        return ""
    if isinstance(raw, list):
        return str(raw[0]) if raw else ""
    return str(raw)


def metadata_xml(cfg: Any, public_url: str, request: Any) -> str:
    """Return the SAML SP metadata XML for /saml/metadata.

    Operator pastes the URL into the IdP "Add application" wizard;
    Azure AD / Okta / Keycloak parse the XML and pre-populate the
    EntityID / ACS URL on their side.
    """
    try:
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
    except ImportError:
        return "<!-- python3-saml not installed -->"
    settings_dict = _build_settings(cfg, public_url)
    saml_settings = OneLogin_Saml2_Settings(settings=settings_dict, sp_validation_only=True)
    return saml_settings.get_sp_metadata()


# ----------------------------------------------------------------------
# Microsoft Graph profile photo sync (optional - issue #46 photos)
# ----------------------------------------------------------------------


def fetch_graph_photo(cfg: Any, email: str) -> bytes | None:
    """Fetch a profile photo from Microsoft Graph by user UPN / email.

    Returns the photo bytes (JPEG/PNG) or None when:
    - Graph credentials are not configured
    - the user has no photo
    - the call times out / hits an HTTP error

    Requires application permission ``User.Read.All`` and admin
    consent in Azure AD. Operator wires up graph_client_id / secret
    / tenant_id in [admin.saml].
    """
    if not (cfg.graph_client_id and cfg.graph_client_secret and cfg.graph_tenant_id):
        return None
    if not email:
        return None
    try:
        import json
        import urllib.request
        import urllib.parse
        # 1. client_credentials OAuth token request
        token_url = f"https://login.microsoftonline.com/{cfg.graph_tenant_id}/oauth2/v2.0/token"
        token_body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": cfg.graph_client_id,
            "client_secret": cfg.graph_client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }).encode("utf-8")
        req = urllib.request.Request(
            token_url, data=token_body, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            token_response = json.loads(resp.read())
        access_token = token_response.get("access_token")
        if not access_token:
            return None
        # 2. GET /v1.0/users/{upn}/photo/$value
        photo_url = f"https://graph.microsoft.com/v1.0/users/{urllib.parse.quote(email)}/photo/$value"
        req = urllib.request.Request(
            photo_url, method="GET",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read()
    except Exception:
        logger.exception("Microsoft Graph photo fetch failed for %s", email)
        return None
