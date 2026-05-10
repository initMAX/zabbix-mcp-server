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

"""Plugin loader skeleton for issue #47.

Discovers MCP plugin manifests in two well-known locations:

* ``<source_tree>/plugins/<id>/plugin.json`` - bundled plugins shipped
  with the host (only ``zabbix`` today; future ``nagios``, ``prtg``,
  ``jira`` will live here too once the loader runtime ships).
* ``/opt/zabbix-mcp/plugins/<id>/plugin.json`` - operator-installed
  plugins managed by ``install.sh add-plugin <id>``.

Validates the manifest shape against the documented schema (id,
name, version, transport, tool_prefix, scope groups) and surfaces
the loaded set to the rest of the server as a list of
:class:`PluginRecord` objects.

**Loader runtime (subprocess spawn + JSON-RPC bridge) ships in a
follow-up release.** This module covers discovery + schema validation
+ enumeration so the admin portal ``/modules`` page can show the
operator what plugins are installed without the host having to grow
the spawn / IPC code at the same time. The bundled Zabbix module
remains in-process for now.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("zabbix_mcp.plugin_loader")


@dataclass
class PluginRecord:
    """A validated plugin manifest + its source path."""

    id: str
    name: str
    version: str
    description: str
    author: str
    transport: str          # stdio (mandatory today)
    tool_prefix: str
    tool_groups: list[str] = field(default_factory=list)
    write_patterns: list[str] = field(default_factory=list)
    report_templates: list[str] = field(default_factory=list)
    audit_target_keys: list[str] = field(default_factory=list)
    bundled: bool = False
    min_host_version: str = ""
    manifest_path: Path = field(default_factory=Path)
    raw: dict[str, Any] = field(default_factory=dict)


class PluginManifestError(ValueError):
    """Raised when a plugin.json fails schema validation.

    Operator-readable; the loader logs the offending plugin path
    alongside the error so the operator can grep their plugin
    inventory without grepping the source tree.
    """


# Schema contract - keep in sync with docs/PLUGIN-DEVELOPMENT.md.
_REQUIRED_FIELDS = ("id", "name", "version", "transport")
_VALID_TRANSPORTS = ("stdio",)
_TOOL_PREFIX_PATTERN = "^[a-z][a-z0-9_]*$"  # validated lazily via re


def _validate_manifest(data: dict, path: Path) -> PluginRecord:
    """Validate ``data`` and return a populated :class:`PluginRecord`.

    Strict validation: a missing required field or a wrong-shape field
    raises :class:`PluginManifestError`. Operators see the error in
    the boot log and the `/modules` admin page renders the offending
    plugin with a red "manifest invalid" badge so they spot the
    typo before it reaches production.
    """
    import re
    if not isinstance(data, dict):
        raise PluginManifestError(f"{path}: manifest must be a JSON object")
    for k in _REQUIRED_FIELDS:
        if k not in data or not data[k]:
            raise PluginManifestError(f"{path}: missing required field {k!r}")
    plugin_id = str(data["id"])
    if not re.match(r"^[a-z][a-z0-9_-]*$", plugin_id):
        raise PluginManifestError(
            f"{path}: id {plugin_id!r} must match ^[a-z][a-z0-9_-]*$"
        )
    if data["transport"] not in _VALID_TRANSPORTS:
        raise PluginManifestError(
            f"{path}: transport {data['transport']!r} not in {_VALID_TRANSPORTS}"
        )
    tool_prefix = str(data.get("tool_prefix", "") or "")
    if tool_prefix and not re.match(_TOOL_PREFIX_PATTERN, tool_prefix):
        raise PluginManifestError(
            f"{path}: tool_prefix {tool_prefix!r} must match {_TOOL_PREFIX_PATTERN}"
        )
    return PluginRecord(
        id=plugin_id,
        name=str(data.get("name", "") or plugin_id),
        version=str(data.get("version", "") or ""),
        description=str(data.get("description", "") or ""),
        author=str(data.get("author", "") or ""),
        transport=str(data["transport"]),
        tool_prefix=tool_prefix,
        tool_groups=list(data.get("tool_groups", []) or []),
        write_patterns=list(data.get("write_patterns", []) or []),
        report_templates=list(data.get("report_templates", []) or []),
        audit_target_keys=list(data.get("audit_target_keys", []) or []),
        bundled=bool(data.get("bundled", False)),
        min_host_version=str(data.get("min_host_version", "") or ""),
        manifest_path=path,
        raw=data,
    )


def _read_manifest(path: Path) -> PluginRecord | None:
    """Read + validate one plugin.json. Returns None on error
    (logged) so a bad plugin does not crash the boot path."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("plugin loader: cannot read %s: %s", path, e)
        return None
    try:
        return _validate_manifest(data, path)
    except PluginManifestError as e:
        logger.warning("plugin loader: %s", e)
        return None


def _discover_in(root: Path) -> list[PluginRecord]:
    """Walk ``root`` for ``<root>/<id>/plugin.json`` entries.

    Skips entries whose id collides with one we've already loaded -
    bundled plugin always wins, operator-installed override is a
    v1.33 follow-up.
    """
    out: list[PluginRecord] = []
    if not root.exists():
        return out
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        manifest = entry / "plugin.json"
        if not manifest.is_file():
            continue
        record = _read_manifest(manifest)
        if record is not None:
            out.append(record)
    return out


def discover() -> list[PluginRecord]:
    """Discover plugins in both well-known locations.

    Returns the union of bundled (source tree) and operator-installed
    (``/opt/zabbix-mcp/plugins/<id>``) plugins. On id collision the
    bundled record wins.

    Discovery is cheap (a directory scan + one JSON parse per
    manifest) - safe to call on every ``/modules`` page render so the
    operator always sees the live inventory rather than a stale boot
    snapshot.
    """
    # Bundled plugins relative to this module's source tree.
    here = Path(__file__).resolve().parent.parent.parent.parent  # repo root
    bundled_root = here / "plugins"
    op_root = Path("/opt/zabbix-mcp/plugins")

    seen_ids: set[str] = set()
    out: list[PluginRecord] = []
    for record in _discover_in(bundled_root):
        if record.id in seen_ids:
            continue
        seen_ids.add(record.id)
        out.append(record)
    for record in _discover_in(op_root):
        if record.id in seen_ids:
            logger.info(
                "plugin loader: operator-installed plugin %r at %s overridden "
                "by bundled manifest with the same id",
                record.id, record.manifest_path,
            )
            continue
        seen_ids.add(record.id)
        out.append(record)
    return out


def find(plugin_id: str) -> PluginRecord | None:
    """Return the plugin record by id, or None when not installed."""
    for record in discover():
        if record.id == plugin_id:
            return record
    return None
