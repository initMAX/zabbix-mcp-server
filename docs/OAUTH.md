# OAuth 2.1 authentication

`v1.28+` ships an embedded OAuth 2.1 authorization server so MCP clients
that auto-discover authentication (ChatGPT custom apps, Claude Desktop
remote connectors, MCP Inspector, ...) can finish their handshake
without an external IdP. The MCP server is the resource server, the
authorization server, and the user identity backend, all in one
process. Tokens are opaque, held in memory; users authenticate against
the existing admin-portal accounts (`[admin.users.*]`).

The legacy bearer-token mode (`[tokens.X]`) keeps working alongside
OAuth - clients that already authenticate with a static token need no
change.

## When to enable OAuth

Turn it on when:

- You want to expose the MCP server to **ChatGPT custom apps** via the
  "New App" dialog. ChatGPT's "Advanced OAuth settings" auto-detects
  this server's OAuth metadata and runs the full authorize / consent
  flow without the operator copying any client_id / client_secret.
- You want to expose the MCP server to **Claude Desktop remote**,
  **MCP Inspector**, or any other MCP 2025-11-25 client that supports
  OAuth.
- Multiple operators share the deployment and you want each tool
  call attributed back to a named account, not a shared bearer.

If you only access the server from a single CLI / script /
workflow tool (n8n, your own Python automation), stick with
`[tokens.X]` - it is simpler and the wire cost is one HTTP header
instead of an OAuth round-trip per session.

## Do I need a TLS certificate?

**Yes for production, no for localhost.**

OAuth 2.1 (and RFC 8414) mandate HTTPS for the issuer URL. The MCP
framework enforces this at startup - if `public_url` is not HTTPS and
the host is not `localhost` / `127.0.0.1`, the server refuses to boot
the OAuth routes.

| `public_url` | Allowed? | Use for |
|---|---|---|
| `http://localhost:8080` | yes | local development |
| `http://127.0.0.1:8080` | yes | local development |
| `http://192.168.x.y` | NO | rejected at startup |
| `http://mcp.example.com` | NO | rejected at startup |
| `https://mcp.example.com` | yes | production |

For production you have two equally good options:

> **Let's Encrypt one-liner.** If the MCP server itself is going to terminate
> TLS (option 1 below), the installer can grab the cert for you:
>
> ```bash
> sudo ./deploy/install.sh request-tls \
>     --hostname mcp.example.com \
>     --email you@example.com
> ```
>
> The command runs `certbot certonly`, picks `--standalone` if port 80 is
> free or `--webroot` otherwise, symlinks the cert into
> `/etc/zabbix-mcp/tls/`, writes `tls_cert_file` + `tls_key_file` into
> `config.toml`, sets minimum-privilege permissions on the cert files
> (privkey `0440 root:zabbix-mcp`, `live/` + `archive/` directories
> `0710 root:zabbix-mcp` so the service user can read its own privkey
> by full path but cannot enumerate other certs on the box), installs
> a deploy hook at `/etc/letsencrypt/renewal-hooks/deploy/zabbix-mcp-server.sh`
> that re-applies those permissions and reloads the service after each
> renewal, and enables the certbot renewal timer. Re-run any time you
> add or rotate a hostname.
>
> **Pre-flight check:** if your box already runs Apache / nginx / Caddy
> on `:80` with a reverse proxy forwarding to `127.0.0.1:8080`,
> `request-tls` will work (auto-detects webroot mode), but enabling
> the resulting `tls_cert_file` in `[server]` makes the MCP server
> terminate TLS itself - which breaks the existing HTTP-forwarding
> proxy. Pick one termination point: either keep the proxy and have
> it own the cert (option 2 below), or shut the proxy off / re-point
> it to `https://127.0.0.1:8080` and let MCP own TLS (option 1 below).
>
> If you already terminate TLS in a reverse proxy (option 2), let
> Caddy/nginx-proxy/cert-manager/Cloudflare handle the cert there - the
> MCP server only needs `public_url` and `trusted_proxies`.

1. **Native TLS in the MCP server.** Set `tls_cert_file` and
   `tls_key_file` in `[server]`. The server terminates TLS itself
   and the issuer URL points at the same port:

   ```toml
   [server]
   public_url = "https://mcp.example.com"
   tls_cert_file = "/etc/zabbix-mcp/tls/fullchain.pem"
   tls_key_file = "/etc/zabbix-mcp/tls/privkey.pem"
   ```

2. **Reverse proxy in front of MCP** (Caddy, nginx, Cloudflare).
   The MCP server listens HTTP on loopback; the proxy terminates
   TLS and forwards. This is what most production deployments use
   because Caddy and Cloudflare provision Let's Encrypt
   automatically.

   ```toml
   [server]
   host = "127.0.0.1"
   port = 8080
   public_url = "https://mcp.example.com"
   trusted_proxies = ["127.0.0.1"]
   ```

   The same setup works behind any HTTPS-terminating reverse proxy.
   Three battle-tested snippets follow - pick the one matching your
   stack. All three forward `/mcp`, `/authorize`, `/token`, `/register`,
   `/revoke`, `/oauth/login`, `/reports/*`, `/static/*`, and
   `/.well-known/*` to the single MCP backend port.

   > If you graft these onto an existing vhost with a *per-path*
   > `ProxyPass` allowlist instead of the catch-all `/` below, do not
   > forget `/reports/`. Report download links are built from
   > `public_url`, so a missing entry there produces a link that looks
   > right and answers 404. The MCP resource link keeps working either
   > way; only the human-clickable URL depends on the proxy.

   If you also want the admin portal exposed under the same hostname,
   proxy a second backend on a different `Location` / `location` /
   matcher - see "Admin portal under the same hostname" below.

   **Caddy** (Let's Encrypt automatic):

   ```caddy
   mcp.example.com {
       reverse_proxy 127.0.0.1:8080
   }
   ```

   **Nginx** (TLS terminator):

   ```nginx
   server {
       listen 443 ssl http2;
       server_name mcp.example.com;

       ssl_certificate     /etc/letsencrypt/live/mcp.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/mcp.example.com/privkey.pem;
       include /etc/letsencrypt/options-ssl-nginx.conf;

       # Streamable-HTTP MCP framing keeps a connection open for SSE
       # responses, so disable buffering and bump the read timeout.
       proxy_buffering off;
       proxy_read_timeout 600s;
       proxy_http_version 1.1;
       proxy_set_header Connection "";

       proxy_set_header Host              $host;
       proxy_set_header X-Real-IP         $remote_addr;
       proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;

       location / {
           proxy_pass http://127.0.0.1:8080;
       }
   }

   # Optional: redirect HTTP -> HTTPS
   server {
       listen 80;
       server_name mcp.example.com;
       return 301 https://$host$request_uri;
   }
   ```

   **Apache** (`mod_ssl` + `mod_proxy_http`):

   ```apache
   <VirtualHost *:443>
       ServerName mcp.example.com

       SSLEngine on
       SSLCertificateFile    /etc/letsencrypt/live/mcp.example.com/fullchain.pem
       SSLCertificateKeyFile /etc/letsencrypt/live/mcp.example.com/privkey.pem
       Include /etc/letsencrypt/options-ssl-apache.conf

       ProxyPreserveHost On
       ProxyTimeout 600
       RequestHeader set X-Forwarded-Proto "https"

       ProxyPass        / http://127.0.0.1:8080/
       ProxyPassReverse / http://127.0.0.1:8080/
   </VirtualHost>

   <VirtualHost *:80>
       ServerName mcp.example.com
       Redirect permanent / https://mcp.example.com/
   </VirtualHost>
   ```

   You will need `mod_proxy`, `mod_proxy_http`, `mod_ssl`, and
   `mod_headers` loaded; on Rocky / RHEL run `dnf install mod_ssl`
   if missing (mod_proxy / mod_proxy_http / mod_headers ship with the
   base `httpd` package - enable them via `LoadModule` lines under
   `/etc/httpd/conf.modules.d/`).

   Whichever proxy you pick, set `[server].trusted_proxies = ["127.0.0.1"]`
   (or your proxy's IP) in `config.toml` so the OAuth login rate
   limiter and token IP allowlists honour the `X-Forwarded-For` the
   proxy injects.

### Admin portal under the same hostname

If you want to expose the admin portal alongside the MCP endpoint
behind the same TLS hostname (typical for small deployments), add a
second backend route. The admin portal listens on a separate port
(`[admin].port`, default `9090`) so the proxy just routes by path.

   **Nginx** - admin under `/admin/`:

   ```nginx
   location /admin/ {
       proxy_pass http://127.0.0.1:9090/;
       proxy_set_header Host $host;
       proxy_set_header X-Forwarded-Proto https;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   }
   ```

   **Apache** - admin under `/admin/`:

   ```apache
   <Location /admin/>
       ProxyPass        http://127.0.0.1:9090/
       ProxyPassReverse http://127.0.0.1:9090/
   </Location>
   ```

   The admin portal does not currently rewrite asset URLs by prefix,
   so a path-mounted admin portal expects to be served from the
   document root. If you need a sub-path mount, use a separate
   hostname instead (`admin.example.com`) and a second `<VirtualHost>`
   / `server { ... }` block proxying `/` to `127.0.0.1:9090`.

Either way, hit `https://mcp.example.com/.well-known/oauth-authorization-server`
from a browser - if you get JSON with HTTP 200, ChatGPT and Claude
Desktop will be able to discover the server.

## Enable it

In `config.toml`:

```toml
[server]
# REQUIRED when OAuth is enabled - this is the URL ChatGPT / Claude
# will be redirected to during authorize. Must be HTTPS unless host
# is localhost / 127.0.0.1 (see "Do I need a TLS certificate?" above).
public_url = "https://mcp.example.com"

[oauth]
enabled = true
# Optional. Defaults shown.
login_path = "/oauth/login"
dynamic_registration_enabled = true
default_scopes = ["*"]
# Token lifetimes (operator hardening - shorten on high-risk
# deployments at the cost of more /token calls from clients).
auth_code_ttl_seconds      = 600       # 10 min  (OAuth 2.1 §4.1.3)
access_token_ttl_seconds   = 3600      # 1 hour
refresh_token_ttl_seconds  = 2592000   # 30 days, rotated on each use
```

### Per-client overrides

Each `[oauth_clients.<id>]` row may carry its own hardening
fields that override the global `[oauth]` defaults. Edit them
either by hand in `config.toml` or via the OAuth Clients page in
the admin portal (`/oauth-clients/<id>` -> Hardening card):

```toml
[oauth_clients.5d8f...]
client_name = "ChatGPT custom app"
redirect_uris = ["https://chatgpt.com/connector/oauth/..."]
# Optional: stricter than [oauth] defaults
allowed_ips                 = ["203.0.113.0/24"]
access_token_ttl_seconds    = 900     # 15 min for sensitive deployments
refresh_token_ttl_seconds   = 86400   # 1 day
```

The IP allowlist runs at `/token` time, same CIDR semantics as
`[tokens.X].allowed_ips`. The TTL overrides apply both to the
initial code-grant exchange and to subsequent refresh-token
rotations for that client.

Restart the MCP server. The startup log shows:

```
MCP auth: OAuth 2.1 authorization server enabled (issuer https://mcp.example.com,
login at /oauth/login, dynamic registration: yes)
```

That is enough. No keypair, no IdP, no extra service.

## What it exposes

| Endpoint | Standard | Purpose |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | Auth server metadata (endpoints, PKCE methods, grants) |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 | Resource server metadata (issuer pointer, scopes) |
| `POST /register` | RFC 7591 | Dynamic client registration (off if `dynamic_registration_enabled = false`) |
| `GET /authorize`, `POST /authorize` | OAuth 2.1 | Start the authorize flow; redirects user-agent to `/oauth/login` |
| `POST /token` | OAuth 2.1 | Exchange code or refresh token for access token |
| `POST /revoke` | RFC 7009 | Revoke an access or refresh token |
| `GET /oauth/login`, `POST /oauth/login` | this server | Operator login + consent screen |

The 401 response on the MCP endpoint includes an
`WWW-Authenticate: Bearer ... resource_metadata="..."` header so
clients can discover the AS without prior configuration.

## Flow

```
ChatGPT / Claude Desktop                      MCP server
========================                      ==========

POST /mcp                  -->                401 + WWW-Authenticate
                                              (resource_metadata="...")
GET .well-known/...        -->                JSON: authorization_servers=[...]
GET /.well-known/oauth-..  -->                JSON: authorize / token / register
POST /register             -->                {"client_id": "..."}
GET /authorize?...&PKCE    -->                302 to /oauth/login?request_id=...
                                              [user logs in, clicks "Sign in & allow"]
                                              302 to <client redirect_uri>?code=...
POST /token (code+verifier)-->                {"access_token": "...", "refresh_token": "..."}
POST /mcp + Bearer         -->                MCP response
```

## Authentication

Login uses the existing **admin-portal user table** (`[admin.users.*]`
in `config.toml`, scrypt-hashed). Operators do not maintain a second
identity store. If you have an admin user `tomas`, that is the
username they type into ChatGPT's login screen.

Failed logins return HTTP 401 with the form re-rendered. The login
view does not implement rate limiting on its own - the existing
`[server].rate_limit` and the admin portal's POST rate limit cover
brute-force at the transport layer.

## Token binding (RFC 8707)

Every access token issued by this server has its `aud` (resource
indicator) field bound to `[server].public_url`. The MCP server
rejects any token whose `aud` does not match this deployment's
canonical URL. A token issued for `https://mcp.alpha.com` cannot be
replayed against `https://mcp.beta.com` even if both servers share
their token-store key material.

## Operator role cap on consent

The consent screen renders the per-scope checkboxes pre-ticked
according to what the client requested, but the operator cannot
grant a scope wider than their own admin-portal role allows.
This is the OAuth-side expression of "least privilege" the admin
portal already enforces elsewhere.

| Admin portal role | Maximum scope grant |
|---|---|
| `admin`    | `*` (everything, including write operations) |
| `operator` | `monitoring`, `data_collection`, `alerts`, `extensions` |
| `viewer`   | `monitoring`, `extensions` (read-only) |

Rows outside the operator's cap render disabled with a
"not available to your role (<role>); ask an admin" hint.
Server-side check at consent-grant time intersects the form-posted
scope set with the operator's cap and rejects with HTTP 403 if the
result is empty - so a determined operator who edits the disabled
checkbox in the DOM cannot bypass the cap.

## Refresh-token reuse detection

Per RFC 6819 §5.2.2.3, replaying an already-rotated refresh token
is a strong signal that one of the two parties holding it (the
legitimate client and an attacker) is malicious. The server
defends:

1. Each authorization-code grant starts a refresh-token "family"
   identified by an opaque ID.  Refresh-token rotation reuses the
   same family.
2. When a request hits `/token` with a refresh token that the
   server has already consumed (rotated), the entire family is
   revoked: every access token + every refresh token tied to the
   original grant is wiped from memory.
3. An audit row `oauth.token_family_revoked` is written with
   `reason="refresh_token_reuse_detected"` so the operator can
   spot the incident.

Effect on the client side: both the legitimate client and the
attacker get 401 on their next request and have to run the full
authorize flow again. No silent-takeover window.

## Scope catalog

OAuth scopes map 1:1 to the existing `[tokens.X].scopes` system:

| Scope | What the token can call |
|---|---|
| `*` | every tool (default) |
| `monitoring` | `host_*`, `hostgroup_*`, `item_*`, `trigger_*`, `problem_*`, `event_*`, `history_*`, `trend_*`, `graph_*`, `discoveryrule_*`, ... |
| `data_collection` | `template_*`, `templategroup_*`, `valuemap_*`, `dashboard_*` |
| `alerts` | `action_*`, `alert_*`, `mediatype_*`, `script_*` |
| `users` | `user_*`, `usergroup_*`, `role_*`, `mfa_*` |
| `administration` | `settings_*`, `housekeeping_*`, `proxy_*`, `auditlog_*`, ... |
| `extensions` | `graph_render`, `report_generate`, `problem_active_get`, `health_check`, ... |

Individual tool prefixes also work as scopes; e.g. a client granted
`scopes = ["host", "graph_render"]` sees only `host_*` and
`graph_render` in `tools/list` (#38) and is denied any other tool
at runtime.

## Persistence

| What | Where |
|---|---|
| Registered clients | `[oauth_clients.<client_id>]` sections in `config.toml` (survive restart) |
| Authorization codes | in-memory, 10-minute TTL |
| Access tokens | in-memory, 1-hour TTL |
| Refresh tokens | in-memory, 30-day TTL, rotated on each use |

Authorization codes and tokens vanish on server restart. That is by
design - any in-flight session re-authorizes via the MCP client's
auto-refresh logic; clients without refresh just trigger a fresh
login. Refresh tokens are rotated per OAuth 2.1 §4.3.1.

## Disabling OAuth

Set `enabled = false` in `[oauth]` (or remove the section). The
server falls back to legacy bearer auth (`[tokens.X]`) on the next
restart. Existing registered clients in `[oauth_clients.*]` stay in
the config but are not advertised; remove them by hand if you want a
clean slate.

## Security checklist

- `[server].public_url` MUST be HTTPS in production. The framework
  refuses to issue tokens for an HTTP issuer URL outside `localhost`.
- Place the MCP server behind a reverse proxy (nginx, Caddy) that
  terminates TLS and forwards to MCP over loopback. Configure
  `[server].trusted_proxies` so the client IP sent to the OAuth login
  reflects the real caller, not the proxy.
- `dynamic_registration_enabled = false` if you do not want random
  callers registering clients against your server. With the flag off,
  the operator must add `[oauth_clients.<id>]` entries by hand.
- Restrict `allowed_hosts` and `allowed_origins` to the legitimate
  client networks. The MCP server already does this for the `/mcp`
  endpoint; the OAuth endpoints inherit the same allowlist.
- Audit `[oauth_clients.*]` periodically and remove stale entries.
  Each entry is a third-party client that can prompt operators for
  a login.

## Troubleshooting

**ChatGPT shows "OAuth discovery failed"**

The "Advanced OAuth settings" panel needs to reach
`<public_url>/.well-known/oauth-authorization-server` and
`<public_url>/.well-known/oauth-protected-resource`. Hit both URLs
from a browser; both must return JSON with HTTP 200.

If `public_url` is not set, the metadata documents advertise the
literal bind host (e.g. `http://0.0.0.0:8080`) which is not reachable
from ChatGPT's side. Set `public_url` to the externally-visible URL.

**Login redirects to `/oauth/login` then says "expired"**

Authorization codes have a 10-minute TTL. If the user took longer than
that to type their password, the request_id has been evicted. Tell
them to start the connection from ChatGPT again - that issues a fresh
authorize request.

**`401 Unauthorized` on `/mcp` despite a successful login**

Check the access token's `aud` claim against `[server].public_url`.
A common cause is `public_url = "https://example.com"` in config but
the client sees the server at `https://example.com:8080` because of a
reverse proxy mismatch. Set the canonical URL in `public_url` to the
exact form clients use.

**Client metadata for an existing registration changed**

Update the corresponding `[oauth_clients.<id>]` section in
`config.toml` and restart the MCP server. The provider re-loads the
table on boot.

## Reference

- [OAuth 2.1 draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 7591 - Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 8414 - Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 8707 - Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)
- [RFC 9728 - Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [MCP 2025-11-25 Authorization spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OpenAI Apps SDK - Authentication](https://developers.openai.com/apps-sdk/build/auth)
