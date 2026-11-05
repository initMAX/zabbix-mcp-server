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

"""What does ``false`` mean for a get parameter on a running Zabbix? (read-only)

Zabbix has two kinds of yes/no get parameters. A *boolean* reads its value
(``item.get`` ``templated: false`` returns the items that are not templated).
A *flag* is on as soon as it is present, whatever its value: ``trigger.get``
``only_true: false`` returns the triggers in problem state, exactly like
``true``. A model that fills in ``false`` to say "no" gets the opposite, so
the server does not send ``false`` for a flag
(``contracts.false_means_unset``).

For every flag and boolean parameter of every get method this script counts
the rows with the parameter left out, ``true`` and ``false``, and compares
the answer with what the server does:

* a parameter whose ``false`` is not sent must not have a meaning of its own
  for ``false`` on the live server (the caller would lose it),
* a parameter whose ``false`` is sent must not be switched ON by it.

A parameter that changes nothing on this server's data (all three counts
equal) proves nothing and is counted as such.

Usage: audit_get_flags_live.py URL TOKEN   (or URL USER PASSWORD)  [--all]
``--all`` prints every parameter, not only the ones that fail.
Exit status 1 when a parameter behaves differently from what the server
assumes. Nothing is written to the Zabbix server.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from audit_get_contracts_live import Api  # noqa: E402
from zabbix_mcp.api.contracts import CONTRACTS, false_means_unset  # noqa: E402
from zabbix_mcp.api.versions import unavailable_reason  # noqa: E402


def count(api: Api, method: str, contract, extra: dict):
    try:
        if "countOutput" in contract.common:
            answer = api.call(method, dict({"countOutput": True}, **extra))
            if isinstance(answer, list):
                # groupCount: the count comes as rows, which is "on" whatever they add up to
                return ("rows", sum(int(row.get("rowscount", 0)) for row in answer))
            return int(answer)
        rows = api.call(method, dict({"output": "extend"}, **extra))
        return len(rows)
    except Exception as exc:   # a parameter this server refuses, a method that needs more
        return f"error: {str(exc)[:70]}"


def verdict(base, on, off) -> str:
    if any(isinstance(v, str) for v in (base, on)):
        return "unreadable"
    if isinstance(off, str):
        return "false refused"
    if on == off == base:
        return "no difference"
    if off == on:
        return "false = on"
    if off == base:
        return "false = left out"
    return "false has its own meaning"


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show_all = "--all" in sys.argv
    if len(args) == 2:
        api = Api(args[0], args[1], None, None)
    elif len(args) == 3:
        api = Api(args[0], None, args[1], args[2])
    else:
        raise SystemExit(__doc__)
    version = api.version
    print(f"Zabbix {version}")
    checked = proved = failures = 0
    for method, contract in sorted(CONTRACTS.items()):
        if unavailable_reason(method, version):
            continue
        base = None
        for name, spec in contract.params.items():
            if spec.type not in ("flag", "boolean") or not spec.available(version):
                continue
            if base is None:
                base = count(api, method, contract, {})
            on = count(api, method, contract, {name: True})
            off = count(api, method, contract, {name: False})
            what = verdict(base, on, off)
            dropped = false_means_unset(contract, name)
            checked += 1
            bad = None
            if what == "false has its own meaning" and dropped:
                bad = "false is not sent, and it means something here"
            elif what == "false = on" and not dropped:
                bad = "false is sent, and it switches the parameter on"
            if what not in ("no difference", "unreadable"):
                proved += 1
            if bad:
                failures += 1
            if bad or show_all:
                print(f"  {'FAIL' if bad else 'ok  '} {method} {name} ({spec.type}, false {'not sent' if dropped else 'sent'}): "
                      f"left out {base}, true {on}, false {off} -> {what}" + (f": {bad}" if bad else ""))
    print(f"{version}: {checked} flag / boolean parameters, {proved} told apart by this server's data, "
          f"{failures} behave differently from what the server assumes")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
