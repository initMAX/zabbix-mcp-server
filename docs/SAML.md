# SAML 2.0 single sign-on (admin portal)

Issue [#46](https://github.com/initMAX/zabbix-mcp-server/issues/46).
v1.32+.

The admin portal can authenticate operators against an external SAML
2.0 IdP (Azure AD, Okta, Keycloak, ADFS, Auth0, ...) so a SOC or
ops team does not need a second password store. Local scrypt + LDAP
+ SAML all coexist on the same login page; the order is:

1. **Local scrypt** (`[admin.users.X]`) - tried first so a directory
   outage cannot lock the local-only admin out of the portal.
2. **LDAP / AD bind** - if local fails and `[admin.ldap].enabled =
   true`.
3. **SAML SSO** - operator clicks the "Sign in with SAML" button on
   the login page; the AuthnRequest leaves the portal entirely.

## Operator setup

### 1. Install the SAML toolkit

```
sudo dnf install libxmlsec1-openssl   # or apt: libxmlsec1-openssl
sudo -u zabbix-mcp /opt/zabbix-mcp/venv/bin/pip install python3-saml
sudo systemctl restart zabbix-mcp-server
```

The `xmlsec1` system library is mandatory - `python3-saml` shells out
to it for the XML signature validation step. RHEL / Rocky / Alma ship
`xmlsec1-openssl`; Debian / Ubuntu ship `libxmlsec1-openssl`.

### 2. Wire up the portal -> IdP loop

Three steps from the operator side:

1. Edit `/etc/zabbix-mcp/config.toml` and add the `[admin.saml]`
   section (or open Settings -> SAML 2.0 SSO in the admin portal and
   fill the form):

   ```toml
   [admin.saml]
   enabled            = true
   display_name       = "Sign in with Azure AD"

   # From IdP metadata XML:
   idp_entity_id      = "https://sts.windows.net/<tenant-uuid>/"
   idp_sso_url        = "https://login.microsoftonline.com/<tenant-uuid>/saml2"
   idp_slo_url        = ""                     # optional
   x509_certificate   = """-----BEGIN CERTIFICATE-----
   MIIDxTCCAq2gAwIBAgIQ...
   -----END CERTIFICATE-----"""

   # Attribute mapping (defaults shown - Azure AD / ADFS friendly).
   # Override for Okta / Keycloak / Auth0 which usually emit short
   # claim names ('email', 'given_name', 'family_name').
   email_attribute      = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
   first_name_attribute = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
   last_name_attribute  = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
   photo_url_attribute  = ""                   # optional

   # Role given to a SAML user that has no local [admin.users.X]
   # entry. admin / operator / viewer / auditor.
   default_role         = "viewer"
   ```

2. Hand the IdP the portal endpoints:

   ```
   SP EntityID / Audience: https://<public_url>/saml/metadata
   ACS / Reply URL:        https://<public_url>/saml/acs
   NameID format:          urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
   ```

   Most IdPs accept the metadata URL directly - paste it into the
   "Add application" wizard and it pre-populates the EntityID + ACS
   URL on their side. Restart the MCP service after editing the
   config:

   ```
   sudo systemctl restart zabbix-mcp-server
   ```

3. Test the flow: open the admin portal login page incognito -
   you should see the "Sign in with Azure AD" button (or whatever
   `display_name` you set). Click -> redirected to IdP -> login ->
   redirected back -> session cookie set, dashboard renders.

## Per-IdP attribute mapping cheatsheet

### Azure AD / Microsoft Entra ID

Default attribute URIs ship in `[admin.saml]` defaults. Confirm in
the Azure portal -> Enterprise applications -> your app -> Single
sign-on -> Attributes & Claims that the IdP emits:

| Claim                                                                  | Portal field        |
|------------------------------------------------------------------------|---------------------|
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`   | email_attribute     |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname`      | first_name_attribute|
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname`        | last_name_attribute |

### Okta

Use short claim names. Okta admin -> Applications -> your app ->
General -> SAML Settings -> Edit -> Attribute Statements:

```toml
email_attribute      = "email"
first_name_attribute = "firstName"
last_name_attribute  = "lastName"
```

### Keycloak

Keycloak admin -> Clients -> your client -> Mappers. Add three
"User Property" mappers that emit `email`, `firstName`, `lastName`.

```toml
email_attribute      = "email"
first_name_attribute = "firstName"
last_name_attribute  = "lastName"
```

### ADFS

ADFS Management -> Relying Party Trusts -> your trust -> Edit Claim
Issuance Policy. Add three pass-through transforms emitting the
default `schemas.xmlsoap.org` URIs. Keep the v1.32 defaults.

## Microsoft Graph profile photo sync (optional)

When `graph_client_id / graph_client_secret / graph_tenant_id` are
set in `[admin.saml]`, the portal pulls the operator's profile photo
from Microsoft Graph after a successful SAML login. Requires:

- App registration in Azure AD with API permission `User.Read.All`
  (application permission, NOT delegated)
- Admin consent granted
- Client secret valid (rotate per your secret rotation policy)

Disabled when any of the three is empty.

## Troubleshooting

- **Login fails with "SAML response did not match a pending AuthnRequest":**
  The portal stores the AuthnRequest ID with a 10-minute TTL. Either
  the user took longer than 10 min on the IdP login page, or the IdP
  is sending a stale assertion. Check the IdP-side audit log for the
  `InResponseTo` attribute value.

- **Login fails with "SAML response did not authenticate":**
  Wrong `x509_certificate` in config (the portal cannot verify the
  IdP's signature). Re-copy the cert from the IdP metadata XML.

- **Login succeeds but role is empty:**
  No `default_role` configured AND the user did not match any other
  provisioning rule. Set `default_role = "viewer"` (or higher) to
  let any SAML-authenticated user in.

- **Audit log: `auth.saml_login`:**
  Every SAML login lands in `audit.log` with `action=login_success
  details.auth=saml`. Operational log `mcp.log` has the full
  attribute key list (no values - those can carry PII).
