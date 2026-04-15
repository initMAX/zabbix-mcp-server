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

"""MCP client metadata catalog for the Client Wizard.

Single source of truth for how each AI client wants its MCP server
configured. Used by ``views/wizard.py`` to render copy-paste-ready
config snippets and per-client install instructions.

Each entry shape::

    {
      "name":         human-readable display name,
      "format":       "json" | "toml" | "cli" | "text",
      "transports":   list of supported MCP transports (subset of
                      ["http", "sse", "stdio"]),
      "config_paths": dict of OS -> file path where the snippet goes
                      (or {"cli": "<command>"} for CLI-only clients),
      "template":     Jinja2 template string rendered with context:
                          server_key, transport, url, token, host, port
                      (token may be empty - template should handle that),
      "instructions": list of ordered steps shown next to the snippet,
      "notes":        optional caveats (HTTPS requirement, OS-specific
                      gotchas, etc.),
    }

Adding a new client = append one dict entry. README "Connecting AI
Clients" section is the upstream source of truth for the snippet
shapes; keep them in sync.
"""

from __future__ import annotations

CLIENTS: dict[str, dict] = {
    # =====================================================================
    # Anthropic
    # =====================================================================
    "claude-desktop": {
        "name": "Claude Desktop",
        "vendor": "Anthropic",
        # JSON config via mcp-remote wrapper - this is the ONLY way to
        # connect Claude Desktop to a Bearer-authenticated remote MCP
        # server. The in-app "Custom Connectors" UI (Settings -> Customize
        # -> Connectors -> + Add custom connector) only accepts OAuth 2.0
        # (Client ID + Client Secret); it will not accept a raw
        # Authorization: Bearer header. mcp-remote is a local stdio
        # wrapper that forwards calls to the remote HTTP MCP endpoint and
        # injects the header for us.
        "format": "json",
        "transports": ["http", "sse"],
        "config_paths": {
            "macos": "~/Library/Application Support/Claude/claude_desktop_config.json",
            "windows": "%APPDATA%\\Claude\\claude_desktop_config.json",
            "linux": "~/.config/Claude/claude_desktop_config.json",
        },
        "template": """{
  "mcpServers": {
    "{{ server_key }}": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "{{ url }}"{% if token %},
        "--header",
        "Authorization: Bearer {{ token }}"{% endif %}
      ]
    }
  }
}""",
        "instructions": [
            "Install Node.js 18+ if you do not have it yet (mcp-remote is an `npx` wrapper).",
            "Quit Claude Desktop completely.",
            "Open `{config_path}` in a text editor (create it if it does not exist).",
            "Paste the snippet on the right; if the file already has `mcpServers`, merge the `{server_key}` entry into the existing object.",
            "Save and start Claude Desktop again. The Zabbix tools appear in the tools menu of a new chat.",
            "Alternative (OAuth-backed servers only): Settings -> Customize -> Connectors -> + -> Add custom connector with the URL and OAuth Client ID/Secret. This path does NOT work with Bearer-token auth.",
        ],
        "notes": "Bearer-token remote MCP servers like this one go through the `mcp-remote` local wrapper (https://github.com/geelen/mcp-remote) - the in-app Custom Connectors UI only accepts OAuth 2.0 Client ID / Secret, not Bearer. For Bearer tokens, edit `claude_desktop_config.json` as shown. Publicly-trusted HTTPS is recommended but not strictly required when using mcp-remote (the wrapper runs on your local machine). For local stdio MCP servers, use the `command` + `args` shape directly without mcp-remote.",
    },
    "claude-code": {
        "name": "Claude Code (CLI)",
        "vendor": "Anthropic",
        "format": "cli",
        # SSE is deprecated in the MCP spec and flagged as legacy in Claude
        # Code docs - kept here because the Zabbix MCP server still serves
        # /sse, but HTTP Streamable is preferred.
        "transports": ["http", "sse", "stdio"],
        "config_paths": {
            "cli": "Run the command in any terminal where Claude Code is installed.",
        },
        "template": """{% if transport == "stdio" %}claude mcp add --transport stdio {{ server_key }} -- /opt/zabbix-mcp/venv/bin/zabbix-mcp-server --config /etc/zabbix-mcp/config.toml{% else %}claude mcp add --transport {{ transport }} {{ server_key }} {{ url }}{% if token %} --header "Authorization: Bearer {{ token }}"{% endif %}{% endif %}""",
        "instructions": [
            "Open a terminal where Claude Code is installed.",
            "Run the command on the right.",
            "Verify with `claude mcp list` - `{server_key}` should appear in the list.",
            "Open a Claude Code session and ask a Zabbix question - the tools are auto-loaded.",
        ],
        "notes": "Claude Code is the recommended client for this server: native HTTP MCP support, no HTTPS gymnastics, handles all 231 tools without issues. Requires Claude Pro / Max or Anthropic API credits.",
    },
    # =====================================================================
    # OpenAI
    # =====================================================================
    "codex": {
        "name": "OpenAI Codex (CLI)",
        "vendor": "OpenAI",
        "format": "toml",
        "transports": ["http", "sse"],
        "config_paths": {
            "macos": "~/.codex/config.toml",
            "linux": "~/.codex/config.toml",
            "windows": "%USERPROFILE%\\.codex\\config.toml",
        },
        "template": """[mcp_servers.{{ server_key }}]
url = "{{ url }}"
{%- if token %}
http_headers = { Authorization = "Bearer {{ token }}" }
{%- endif %}""",
        "instructions": [
            "Open `{config_path}` in a text editor (create it if it does not exist).",
            "Append the snippet on the right (or merge into existing `[mcp_servers.*]` table).",
            "Save the file.",
            "Verify with `codex mcp list` or run `codex` and ask a Zabbix question.",
            "Tip: you can also store the token in an environment variable: set `http_headers = { Authorization = \"Bearer ${ZABBIX_MCP_TOKEN}\" }` and `export ZABBIX_MCP_TOKEN=...`",
        ],
        "notes": "Codex CLI ships from OpenAI - MCP examples are in our README. Pay-per-use API (cheap for typical usage).",
    },
    "chatgpt": {
        "name": "ChatGPT (Developer mode MCP)",
        "vendor": "OpenAI",
        "format": "text",
        "transports": ["http", "sse"],
        "config_paths": {
            "web": "ChatGPT Settings -> Apps & Connectors -> Advanced settings -> Developer mode",
        },
        "template": """Name:          {{ server_key }}
URL:           {{ url }}
Transport:     {{ transport }}{% if token %}
Auth header:   Authorization: Bearer {{ token }}{% endif %}""",
        "instructions": [
            "Open ChatGPT Settings (you need a Plus / Pro / Business / Enterprise / Edu plan).",
            "Go to Apps & Connectors -> Advanced settings.",
            "Toggle Developer mode on.",
            "Click + Create (or + New connector) and fill in:",
            "  - Name: `{server_key}`",
            "  - MCP server URL: the URL on the right",
            "  - Authentication: Bearer token - paste the token value",
            "Save. The Zabbix tools appear in the chat tool menu.",
        ],
        "notes": "ChatGPT MCP requires a publicly-trusted HTTPS endpoint - OpenAI's cloud brokers the connection, plain HTTP and self-signed certs are rejected. Use a public HTTPS tunnel (Cloudflare Tunnel / Tailscale Funnel / ngrok) if your MCP server is behind a firewall. Note: ChatGPT's implementation is stricter than Claude / Codex - some MCP servers that work everywhere else can fail here.",
    },
    # =====================================================================
    # IDEs
    # =====================================================================
    "vscode-copilot": {
        "name": "VS Code + GitHub Copilot",
        "vendor": "Microsoft",
        "format": "json",
        "transports": ["http", "sse"],
        "config_paths": {
            "workspace": ".vscode/mcp.json (in your project root)",
        },
        "template": """{
  "servers": {
    "{{ server_key }}": {
      "type": "{{ transport }}",
      "url": "{{ url }}"{% if token %},
      "headers": {
        "Authorization": "Bearer {{ token }}"
      }{% endif %}
    }
  }
}""",
        "instructions": [
            "In your VS Code workspace root, create the file `.vscode/mcp.json` (create the `.vscode` folder first if needed).",
            "Paste the snippet on the right.",
            "Save and reload the VS Code window (Ctrl+Shift+P -> Developer: Reload Window).",
            "Open the Copilot chat panel - the Zabbix tools are now available.",
        ],
        "notes": "Workspace config (per-project). For user-wide config see VS Code MCP documentation.",
    },
    "cursor": {
        "name": "Cursor",
        "vendor": "Cursor",
        "format": "json",
        "transports": ["http", "sse"],
        "config_paths": {
            "macos": "~/.cursor/mcp.json",
            "linux": "~/.cursor/mcp.json",
            "windows": "%USERPROFILE%\\.cursor\\mcp.json",
        },
        "template": """{
  "mcpServers": {
    "{{ server_key }}": {
      "type": "{{ transport }}",
      "url": "{{ url }}"{% if token %},
      "headers": {
        "Authorization": "Bearer {{ token }}"
      }{% endif %}
    }
  }
}""",
        "instructions": [
            "Open `{config_path}` in a text editor (create it if it does not exist).",
            "Paste the snippet on the right (merge with existing `mcpServers` if present).",
            "Save the file and restart Cursor.",
            "The Zabbix tools appear in the Composer chat tool menu.",
        ],
        "notes": "Cursor has a free tier with limits, plus a paid Pro plan. Mature MCP support, works with HTTP MCP servers out of the box.",
    },
    "cline": {
        "name": "Cline (VS Code extension)",
        "vendor": "Cline",
        "format": "json",
        "transports": ["http", "sse"],
        "config_paths": {
            "ui": "Cline panel -> MCP Servers icon -> Configure MCP Servers (cline_mcp_settings.json)",
        },
        "template": """{
  "mcpServers": {
    "{{ server_key }}": {
      "type": "{{ transport }}",
      "url": "{{ url }}"{% if token %},
      "headers": {
        "Authorization": "Bearer {{ token }}"
      }{% endif %}
    }
  }
}""",
        "instructions": [
            "In VS Code, open the Cline panel (extension sidebar).",
            "Click the MCP Servers icon (the plug icon at the top of the Cline panel).",
            "Click `Configure MCP Servers` - opens the `cline_mcp_settings.json` file.",
            "Paste the snippet on the right (merge with existing `mcpServers`).",
            "Save the file. Cline reloads MCP servers automatically.",
        ],
        "notes": "Cline is a free VS Code extension. Bring your own LLM key (works great with free Google Gemini API). Native MCP HTTP support.",
    },
    "jetbrains": {
        "name": "JetBrains AI Assistant",
        "vendor": "JetBrains",
        "format": "json",
        "transports": ["http", "sse"],
        "config_paths": {
            "ui": "Settings -> Tools -> AI Assistant -> Model Context Protocol",
        },
        "template": """{
  "mcpServers": {
    "{{ server_key }}": {
      "type": "{{ transport }}",
      "url": "{{ url }}"{% if token %},
      "headers": {
        "Authorization": "Bearer {{ token }}"
      }{% endif %}
    }
  }
}""",
        "instructions": [
            "Open your JetBrains IDE (IntelliJ IDEA, PyCharm, WebStorm, ...).",
            "Go to Settings (Ctrl+Alt+S) -> Tools -> AI Assistant -> Model Context Protocol.",
            "Click `Add Server` and choose `Edit JSON`.",
            "Paste the snippet on the right.",
            "Click Apply. The server appears in the AI Assistant tool list.",
        ],
        "notes": "Requires a JetBrains AI Assistant subscription (separate from the IDE license).",
    },
    # =====================================================================
    # Standalone desktop apps
    # =====================================================================
    "goose": {
        "name": "Goose (Block)",
        "vendor": "Block",
        # YAML because Goose's config.yaml is the single source of truth -
        # even the Desktop UI "Add Custom Extension" writes to the same
        # file via the Config singleton. SSE transport is deprecated in
        # Goose; canonical value is "streamable_http" (parsed as "sse" for
        # legacy back-compat but not recommended for new installs).
        "format": "yaml",
        "transports": ["http"],
        "config_paths": {
            "macos": "~/.config/goose/config.yaml",
            "linux": "~/.config/goose/config.yaml",
            "windows": "%APPDATA%\\goose\\config.yaml",
        },
        "template": """extensions:
  {{ server_key }}:
    enabled: true
    type: streamable_http
    name: {{ server_key }}
    description: Zabbix MCP server
    uri: {{ url }}
    timeout: 300{% if token %}
    headers:
      Authorization: Bearer {{ token }}{% endif %}""",
        "instructions": [
            "Open `{config_path}` in a text editor (create it and the parent directory if needed).",
            "Merge the snippet on the right under the top-level `extensions:` map.",
            "Save. Restart Goose Desktop (or start a new `goose` session).",
            "Alternative: in Goose Desktop, go to Settings -> Extensions -> Add Custom Extension -> Streaming HTTP, and fill the form fields from the snippet. The Desktop UI writes to the same `config.yaml`.",
            "Tip: for secrets you can store the token in the OS keyring via `goose configure -> Add secret` and reference it with `Authorization: Bearer $ZABBIX_TOKEN`.",
        ],
        "notes": "Goose is open source from Block (Square/Cash). Free, supports any LLM (OpenAI, Anthropic, Gemini, Ollama). Native MCP Streamable HTTP support; SSE transport is deprecated.",
    },
    "open-webui": {
        "name": "Open WebUI",
        "vendor": "Open WebUI",
        # Open WebUI v0.6.31+ has native MCP support - no mcpo bridge
        # required for Streamable HTTP. SSE still needs mcpo. The UI is
        # form-based (Admin -> External Tools -> +), so we emit a text
        # snippet with the field names and values the operator should
        # paste into each form field.
        "format": "text",
        "transports": ["http"],
        "config_paths": {
            "ui": "Open WebUI -> Admin Settings -> External Tools -> +",
        },
        "template": """Type:     MCP (Streamable HTTP)
URL:      {{ url }}
Name:     {{ server_key }}{% if token %}
Auth:     Bearer
Key:      {{ token }}{% else %}
Auth:     None{% endif %}""",
        "instructions": [
            "Open Open WebUI in your browser and sign in with an admin account.",
            "Go to Admin Settings -> External Tools.",
            "Click the + button to add a new server.",
            "Fill the form using the values on the right:",
            "  - Type: `MCP (Streamable HTTP)` - do NOT pick `OpenAPI` (causes an infinite loading screen).",
            "  - URL: the MCP endpoint URL.",
            "  - Name: `{server_key}`.",
            "  - Auth: `Bearer` (or `None` if the server has no auth).",
            "  - Key: paste the raw `zmcp_...` token ONLY - do not prepend `Bearer `, Open WebUI adds it automatically.",
            "Save. Tools appear in the chat composer after a page refresh.",
        ],
        "notes": "Requires Open WebUI v0.6.31 or newer (native MCP support landed then). SSE transport still needs the `mcpo` bridge (https://github.com/open-webui/mcpo) wrapping it as OpenAPI at /openapi.json. Set the `WEBUI_SECRET_KEY` env var on the Open WebUI container, otherwise MCP tool credentials break on restart.",
    },
    "5ire": {
        "name": "5ire",
        "vendor": "5ire",
        "format": "json",
        "transports": ["http", "sse"],
        "config_paths": {
            "ui": "5ire -> Tools -> MCP Servers -> Add Server",
        },
        "template": """{
  "name": "{{ server_key }}",
  "type": "{{ transport }}",
  "url": "{{ url }}"{% if token %},
  "headers": {
    "Authorization": "Bearer {{ token }}"
  }{% endif %}
}""",
        "instructions": [
            "Open 5ire desktop app.",
            "Go to Tools -> MCP Servers.",
            "Click `Add Server`, pick `Remote (HTTP/SSE)`.",
            "Fill in the values from the snippet on the right.",
            "Save. The server appears in the available tools list.",
        ],
        "notes": "5ire is an open source ChatGPT-like desktop client with native MCP support.",
    },
    # =====================================================================
    # CLIs
    # =====================================================================
    "gemini-cli": {
        "name": "Gemini CLI (Google)",
        "vendor": "Google",
        # Gemini CLI distinguishes Streamable HTTP vs SSE by the FIELD NAME:
        # "httpUrl" = Streamable HTTP (current spec, preferred)
        # "url"     = SSE (legacy)
        # The wizard therefore emits the right field name for the picked
        # transport. Format is JSON (not TOML as the old entry said).
        "format": "json",
        "transports": ["http", "sse"],
        "config_paths": {
            "macos": "~/.gemini/settings.json",
            "linux": "~/.gemini/settings.json",
            "windows": "%USERPROFILE%\\.gemini\\settings.json",
        },
        "template": """{
  "mcpServers": {
    "{{ server_key }}": {
      {% if transport == "http" %}"httpUrl": "{{ url }}"{% else %}"url": "{{ url }}"{% endif %}{% if token %},
      "headers": {
        "Authorization": "Bearer {{ token }}"
      }{% endif %}
    }
  }
}""",
        "instructions": [
            "Open `{config_path}` in a text editor (create it and the parent directory if needed).",
            "Paste the snippet on the right (merge with existing `mcpServers`).",
            "Save and start a new `gemini` session in your terminal.",
            "Get a free API key from https://aistudio.google.com/ if you do not have one.",
        ],
        "notes": "Gemini CLI is Google's official terminal AI agent. Free tier on Google AI Studio is generous (1000 requests/day). Closest free equivalent to Codex CLI / Claude Code. Gemini uses `httpUrl` for Streamable HTTP and `url` for SSE (different JSON keys, not a type discriminator).",
    },
    # =====================================================================
    # Workflow tools
    # =====================================================================
    "n8n": {
        "name": "n8n (workflow automation)",
        "vendor": "n8n",
        "format": "text",
        # n8n 1.104.0 (July 2025, PR #15454) added HTTP Streamable support
        # to the MCP Client Tool node - so both transports work now. SSE
        # is still the safer default because of bug #24967 (transport
        # dropdown sometimes ignored), so the wizard picks it when the
        # server transport is SSE.
        "transports": ["http", "sse"],
        "config_paths": {
            "ui": "n8n -> Add Node -> AI -> MCP Client Tool",
        },
        "template": """URL:           {{ url }}
Transport:     {{ transport }}{% if token %}
Auth header:   Authorization: Bearer {{ token }}{% endif %}""",
        "instructions": [
            "In n8n, add a new node.",
            "Search for `MCP Client Tool` (in the AI category).",
            "Select the transport shown in the Transport line of the snippet (HTTP Streamable or SSE).",
            "Set the URL to the value on the right.",
            "If using auth: add a custom header `Authorization` with value `Bearer <token>`.",
            "Test the node - it should list available Zabbix tools.",
        ],
        "notes": "n8n 1.104+ supports both HTTP Streamable and SSE transports for the MCP Client Tool node. Known bug #24967 means the transport dropdown is occasionally ignored - if HTTP fails, try SSE as a workaround.",
    },
    # =====================================================================
    # Generic / catch-all
    # =====================================================================
    "generic": {
        "name": "Other / Generic MCP Client",
        "vendor": "",
        "format": "text",
        "transports": ["http", "sse", "stdio"],
        "config_paths": {
            "any": "Refer to your client's MCP documentation.",
        },
        "template": """URL:           {{ url }}
Transport:     {{ transport }}{% if token %}
Auth header:   Authorization: Bearer {{ token }}{% endif %}""",
        "instructions": [
            "Consult your MCP client's documentation for how to add a remote MCP server.",
            "Use the URL and authentication header from the snippet on the right.",
            "Most MCP clients accept a server URL and optional `Authorization` header.",
        ],
        "notes": "If your specific client is not listed, this generic config has the essentials. The Model Context Protocol specification (https://modelcontextprotocol.io) defines the standard - any compliant client follows it.",
    },
}


def get_client(client_id: str) -> dict | None:
    """Return the metadata dict for a client, or None if unknown."""
    return CLIENTS.get(client_id)


def list_clients() -> list[tuple[str, dict]]:
    """Return [(id, meta), ...] in display order (preserves dict insertion)."""
    return list(CLIENTS.items())
