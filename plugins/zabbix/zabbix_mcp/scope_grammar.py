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

"""v1.31 OAuth / token scope grammar parser.

Single source of truth for the four scope shapes accepted by the
``[tokens.X].scopes`` config field and OAuth-issued access tokens:

- ``"*"`` - full access wildcard
- ``"tool:<canonical_name>"`` - explicit per-tool grant
- ``"plugin:<id>"`` - all tools from one plugin (read + write)
- ``"plugin:<id>.read"`` - read-only tools from one plugin
- ``"plugin:<id>.write"`` - read + write tools from one plugin
- anything else - **legacy** v1.30 bundled tool group / single tool prefix

Lives in its own module so the parsing logic does not have to be
duplicated between ``server.py`` (tools/list filter) and
``token_store.py`` (runtime authorization check); a shared module also
sidesteps the circular-import path that would otherwise have to wire
through one of those two heavy modules.
"""

from __future__ import annotations

# Bundled module identifier - matches plugins/zabbix/plugin.json `id`.
# Once the plugin loader ships and external plugins arrive, this will
# become a registry lookup keyed off the canonical tool name; for v1.31
# every bundled tool belongs to a single fixed plugin.
BUNDLED_PLUGIN_ID = "zabbix"


def parse_token_scopes(scopes: list[str]) -> dict:
    """Parse a token's scope list into the v1.31 grammar.

    Returns a dict with six keys for downstream callers to compose
    checks against:

    - ``wildcard`` (bool) - ``"*"`` was present
    - ``tools`` (set[str]) - explicit per-tool grants (no ``tool:`` prefix)
    - ``plugins_full`` (set[str]) - plugin ids granted ``read + write``
    - ``plugins_read`` (set[str]) - plugin ids granted ``read``
    - ``plugins_write`` (set[str]) - plugin ids granted ``write``
    - ``legacy`` (list[str]) - bundled tool groups / prefixes preserved
      verbatim for the v1.30 ``_expand_tool_groups`` path

    Empty / whitespace-only scope strings are dropped silently. An
    unknown ``plugin:<id>.<suffix>`` (anything other than ``.read`` /
    ``.write``) is treated as a full plugin grant - fail-safe in the
    operator's favour, so a future ``.admin`` suffix the loader adds
    does not accidentally lock the operator out before the new release
    is rolled out everywhere.
    """
    parsed: dict = {
        "wildcard": False,
        "tools": set(),
        "plugins_full": set(),
        "plugins_read": set(),
        "plugins_write": set(),
        "legacy": [],
    }
    for raw in scopes:
        s = str(raw).strip()
        if not s:
            continue
        if s == "*":
            parsed["wildcard"] = True
        elif s.startswith("tool:"):
            parsed["tools"].add(s[len("tool:"):])
        elif s.startswith("plugin:"):
            rest = s[len("plugin:"):]
            if "." in rest:
                pid, suffix = rest.split(".", 1)
                if suffix == "read":
                    parsed["plugins_read"].add(pid)
                elif suffix == "write":
                    parsed["plugins_write"].add(pid)
                else:
                    parsed["plugins_full"].add(pid)
            else:
                parsed["plugins_full"].add(rest)
        else:
            parsed["legacy"].append(s)
    return parsed
