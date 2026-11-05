#!/usr/bin/env python3
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
"""Compare the API a Zabbix frontend really exposes with the tool catalog.

The reference pages are not the whole API. Every method a frontend answers
is declared in the ``ACCESS_RULES`` of its API class, and the classes are
listed in ``CApiServiceFactory``; this script reads both out of a frontend
directory and reports

* a method the frontend exposes that has no tool (undocumented API such as
  ``hostdashboard.get``, or something new),
* a tool the version table offers on that release although the frontend
  does not have the method (removed, renamed, or dated wrong).

    python3 scripts/audit_api_frontend.py /usr/share/zabbix/ui
    python3 scripts/audit_api_frontend.py --docker zabbix-web:/usr/share/zabbix/ui

``--docker CONTAINER:PATH`` copies ``include/classes/api`` and
``include/defines.inc.php`` out of a running container first. The release is
read from ``ZABBIX_API_VERSION``. Exit status 1 when anything differs that
is not listed under ``RAW_ONLY``.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from zabbix_mcp.api import ALL_METHODS  # noqa: E402
from zabbix_mcp.api.versions import METHOD_REMOVED, unavailable_reason  # noqa: E402

# Exposed by the frontend, deliberately without a tool: reachable through
# zabbix_raw_api_call only.
RAW_ONLY = {
    "device.init": "the mobile app's own pairing call",
    "device.onboard": "the mobile app's own pairing call",
}


def _top_level_keys(source: str, const: str) -> list[str]:
    """Keys of the first level of ``public const <const> = [ ... ];``."""
    start = re.search(rf"const\s+{const}\s*=\s*\[", source)
    if not start:
        return []
    depth, i, keys = 1, start.end(), []
    while i < len(source) and depth:
        ch = source[i]
        if ch in "'\"":
            end = source.index(ch, i + 1)
            if depth == 1 and re.match(r"\s*=>", source[end + 1:end + 8]):
                keys.append(source[i + 1:end])
            i = end
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        i += 1
    return keys


def frontend_methods(root: Path) -> tuple[str, dict[str, list[str]]]:
    api = root / "include" / "classes" / "api"
    defines = (root / "include" / "defines.inc.php").read_text(encoding="utf-8", errors="replace")
    version = re.search(r"define\('ZABBIX_API_VERSION',\s*'([^']+)'", defines)
    factory = (api / "CApiServiceFactory.php").read_text(encoding="utf-8", errors="replace")
    out: dict[str, list[str]] = {}
    for name, cls in re.findall(r"'([a-z]+)'\s*=>\s*(C[A-Za-z]+)::class", factory):
        methods = _access_rules(api / "services", cls)
        if methods:
            out[name] = [m.lower() for m in methods]
    return (version.group(1) if version else "unknown"), out


def _access_rules(services: Path, cls: str, depth: int = 0) -> list[str]:
    """``ACCESS_RULES`` of *cls*, or of the nearest parent that declares it
    (``CHost`` and ``CTemplate`` take theirs from ``CHostGeneral``)."""
    path = services / f"{cls}.php"
    if not path.is_file() or depth > 5:
        return []
    source = path.read_text(encoding="utf-8", errors="replace")
    methods = _top_level_keys(source, "ACCESS_RULES")
    if methods:
        return methods
    parent = re.search(rf"class\s+{cls}\s+extends\s+(C[A-Za-z]+)", source)
    return _access_rules(services, parent.group(1), depth + 1) if parent else []


def _from_docker(spec: str) -> Path:
    container, _, path = spec.partition(":")
    tmp = Path(tempfile.mkdtemp(prefix="zbx-frontend-"))
    (tmp / "include" / "classes").mkdir(parents=True)
    for src, dst in ((f"{path}/include/classes/api", tmp / "include" / "classes" / "api"),
                     (f"{path}/include/defines.inc.php", tmp / "include" / "defines.inc.php")):
        subprocess.run(["docker", "cp", f"{container}:{src}", str(dst)], check=True, capture_output=True)
    return tmp


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--docker":
        root = _from_docker(argv[1])
    elif len(argv) == 1 and not argv[0].startswith("--"):
        root = Path(argv[0])
    else:
        raise SystemExit(__doc__)
    version, exposed = frontend_methods(root)
    frontend = {f"{obj}.{m}" for obj, methods in exposed.items() for m in methods}
    tools = {m.api_method.lower() for m in ALL_METHODS}
    offered = {t for t in tools if not unavailable_reason(t, version)}
    issues = []
    for method in sorted(frontend - tools):
        if method in RAW_ONLY:
            print(f"note: {method} has no tool on purpose ({RAW_ONLY[method]})", file=sys.stderr)
        elif method in METHOD_REMOVED:
            # a legacy method of an old release: dated in the version table, raw call only
            print(f"note: {method} is legacy (gone in {METHOD_REMOVED[method][0]}), no tool on purpose", file=sys.stderr)
        else:
            issues.append(f"{method}: exposed by the {version} frontend, no tool")
    for method in sorted(frontend & tools - offered):
        issues.append(f"{method}: exposed by the {version} frontend, the version table says it is not there")
    for method in sorted(offered - frontend):
        # methods the client answers itself or that live outside ACCESS_RULES
        if method in ("apiinfo.version", "user.login", "user.checkauthentication"):
            continue
        issues.append(f"{method}: tool offered on {version}, the frontend does not expose it")
    for issue in issues:
        print(issue)
    print(f"{version}: {len(exposed)} API objects, {len(frontend)} methods, {len(issues)} difference(s)", file=sys.stderr)
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
