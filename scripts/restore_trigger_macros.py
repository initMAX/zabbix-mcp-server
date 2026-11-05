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

"""Find the triggers whose user macros v1.40 / v1.41 replaced by their values, and put the macros back.

Those two releases read a trigger with Zabbix's own expansion
(``expandExpression``), which puts the current value of every user macro into
the expression. A trigger read with ``trigger_get`` and sent back through
``trigger_update`` (or a trigger prototype through its tools) was therefore
stored as ``avg(/host/key,10m)>75`` where it had been
``avg(/host/key,10m)>{$UTIL.MAX}``: it still fires at 75, and no longer
follows the macro.

Zabbix recorded each of those writes in its audit log with the expression
before and after. This script reads the log and lists the updates in which
the only change was a user macro turning into a plain value. With
``--restore`` it writes the earlier expression back, and only where all of
this holds:

* nothing but user macros changed in that update, and each became a plain
  value (not another macro, not a longer expression);
* the trigger was not changed again afterwards: it still has the expression
  that update left behind;
* the values that were written are values those macros have today (the
  macros of the trigger's hosts and templates and the global ones are read).

Everything else is listed with the reason and left alone. A trigger a
template gives to hosts is restored on the template; Zabbix passes it on.

    python3 scripts/restore_trigger_macros.py URL TOKEN [--days N] [--user NAME] [--restore]
    python3 scripts/restore_trigger_macros.py URL USER PASSWORD [--days N] [--user NAME] [--restore]

``--days`` is how far back to read (default 60; the log itself is kept for
31 days by default from Zabbix 7.0 and 365 before). ``--user`` looks only at
updates made by that Zabbix user, for instance the one whose API token the
MCP server uses. Zabbix 6.0 or later: the audit log of earlier releases does
not carry the two values. Without ``--restore`` nothing is written. Exit
status 1 when something is left.
"""

from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from zabbix_mcp.api import trigger_expressions  # noqa: E402

# audit log resource types
TRIGGER, PROTOTYPE = 13, 31
KIND = {TRIGGER: ("trigger", "trigger.get", "trigger.update"),
        PROTOTYPE: ("triggerprototype", "triggerprototype.get", "triggerprototype.update")}
FIELDS = ("expression", "recovery_expression")
PAGE = 2000

_MACRO = re.compile(trigger_expressions.USER_MACRO)
_MACRO_NAME = re.compile(r"\{\$([A-Z0-9_.]+)")
# what a macro may have turned into, by where it stood
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?[KMGTsmhdw]?")
_IN_BRACKETS = re.compile(r'[^,()\[\]"\s]*')
_IN_STRING = re.compile(r'(?:[^"\\]|\\.)*')


def _macros_with_position(text: str) -> list[tuple[re.Match, str]]:
    """Every user macro of *text* with where it stands: in a quoted string, inside the
    brackets of a function or an item key, or at the top level of the expression."""
    found: list[tuple[re.Match, str]] = []
    position, in_string, depth = 0, False, 0
    while position < len(text):
        macro = _MACRO.match(text, position)
        if macro:
            found.append((macro, "string" if in_string else "brackets" if depth else "top"))
            position = macro.end()
            continue
        char = text[position]
        if in_string:
            if char == "\\":
                position += 1
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth = max(0, depth - 1)
        position += 1
    return found


def macros_became_values(old: str, new: str) -> list[tuple[str, str]] | None:
    """The (macro, value) pairs when *new* is *old* with user macros replaced by plain values
    and nothing else changed; None for any other difference.

    A value is what Zabbix's expansion can put there: a number at the top
    level of the expression, a single parameter inside brackets, any text
    inside a quoted string. Another macro, a longer expression or a changed
    context is somebody's edit, not an expansion.
    """
    if old == new:
        return None
    macros = _macros_with_position(old)
    if not macros:
        return None
    pattern, position = "", 0
    for macro, _ in macros:
        pattern += re.escape(old[position:macro.start()]) + "(.*?)"
        position = macro.end()
    pattern += re.escape(old[position:])
    found = re.fullmatch(pattern, new, re.S)
    if not found:
        return None
    changed: list[tuple[str, str]] = []
    for (macro, where), value in zip(macros, found.groups()):
        if value == macro.group(0):
            continue
        shape = {"top": _NUMBER, "brackets": _IN_BRACKETS, "string": _IN_STRING}[where]
        if "{$" in value or not shape.fullmatch(value):
            return None
        changed.append((macro.group(0), value))
    return changed or None


def read_changes(call: Callable[[str, dict], Any], days: int) -> dict[tuple[int, str], dict[str, list[dict]]]:
    """(resource type, triggerid) -> field -> the updates of that field, oldest first."""
    since = int(time.time()) - days * 86400
    seen: set[str] = set()
    out: dict[tuple[int, str], dict[str, list[dict]]] = {}
    while True:
        rows = call("auditlog.get", {
            "output": ["auditid", "clock", "username", "resourcetype", "resourceid", "details"],
            "filter": {"resourcetype": [TRIGGER, PROTOTYPE], "action": 1},
            "time_from": since, "sortfield": ["clock", "auditid"], "sortorder": "ASC", "limit": PAGE,
        })
        fresh = [row for row in rows if row["auditid"] not in seen]
        for row in fresh:
            seen.add(row["auditid"])
            try:
                details = json.loads(row.get("details") or "{}")
            except ValueError:
                continue
            kind = KIND[int(row["resourcetype"])][0]
            for field in FIELDS:
                change = details.get(f"{kind}.{field}")
                if isinstance(change, list) and len(change) == 3 and change[0] == "update":
                    out.setdefault((int(row["resourcetype"]), str(row["resourceid"])), {}).setdefault(field, []).append(
                        {"clock": int(row["clock"]), "user": row.get("username", ""),
                         "old": str(change[2]), "new": str(change[1])})
        if len(rows) < PAGE:
            return out
        # the next page starts in the second the last row is in (rows that share it are
        # told apart by their id); a page that brought nothing new moves on by one second
        newest = int(rows[-1]["clock"])
        since = newest if fresh and newest > since else since + 1


def _expansion(entry: dict) -> list[tuple[str, str]] | None:
    return macros_became_values(entry["old"], entry["new"])


def decide(entries: list[dict], current: str | None, user: str | None = None) -> tuple[str, str | None, list[tuple[str, str]]]:
    """What to do with one field of one trigger: (state, the expression it had, the macros that went).

    *entries* are the recorded updates of the field, oldest first. States:
    ``none`` (no macro was lost here), ``as before`` (it has the expression
    with the macros again), ``changed since`` (something else was done to it
    after the macros went, or it no longer has what the log says), and
    ``restore``: the last thing that happened to it is one or more updates
    that only turned macros into values, and it still has what they left.
    """
    lost_at = [n for n, e in enumerate(entries) if _expansion(e) and (user is None or e["user"] == user)]
    if not lost_at:
        return "none", None, []
    # the run of expansions the newest one belongs to
    start = lost_at[-1]
    while start > 0 and _expansion(entries[start - 1]) and entries[start - 1]["new"] == entries[start]["old"]:
        start -= 1
    end = lost_at[-1]
    while end + 1 < len(entries) and _expansion(entries[end + 1]) and entries[end + 1]["old"] == entries[end]["new"]:
        end += 1
    original = entries[start]["old"]
    lost = macros_became_values(original, entries[end]["new"]) or _expansion(entries[lost_at[-1]]) or []
    if current == original:
        return "as before", None, lost
    if end != len(entries) - 1 or current != entries[end]["new"]:
        return "changed since", original, lost
    return "restore", original, lost


def macro_values(call: Callable[[str, dict], Any], hostids: list[str]) -> dict[str, set[str] | None]:
    """Macro name -> the values it has on these hosts / templates, the templates they inherit
    from, and globally. None when one of them is a secret (its value cannot be read)."""
    todo, known = list(hostids), set(hostids)
    while todo:
        batch, todo = todo[:200], todo[200:]
        for method, key in (("host.get", "hostids"), ("template.get", "templateids")):
            for row in call(method, {key: batch, "output": ["hostid" if method == "host.get" else "templateid"],
                                     "selectParentTemplates": ["templateid"]}):
                for parent in row.get("parentTemplates") or []:
                    if parent["templateid"] not in known:
                        known.add(parent["templateid"])
                        todo.append(parent["templateid"])
    rows = list(call("usermacro.get", {"hostids": sorted(known), "output": ["macro", "value", "type"]}))
    rows += list(call("usermacro.get", {"globalmacro": True, "output": ["macro", "value", "type"]}))
    values: dict[str, set[str] | None] = {}
    for row in rows:
        name = _MACRO_NAME.match(row.get("macro", ""))
        if not name:
            continue
        if "value" not in row or str(row.get("type", "0")) == "1":
            values[name.group(1)] = None
        elif values.get(name.group(1), set()) is not None:
            values.setdefault(name.group(1), set()).add(str(row["value"]))
    return values


def values_are_the_macros(lost: list[tuple[str, str]], values: dict[str, set[str] | None]) -> bool:
    """Whether every value that was written is one the macro has today."""
    for macro, value in lost:
        have = values.get(_MACRO_NAME.match(macro).group(1), set())
        unescaped = re.sub(r"\\(.)", r"\1", value)       # inside a string Zabbix escapes the value
        if not have or (value not in have and unescaped not in have):
            return False
    return True


def current_triggers(call: Callable[[str, dict], Any], method: str, ids: list[str]) -> dict[str, dict]:
    """The triggers as they are stored now, with the expressions in the form the audit log uses."""
    found: dict[str, dict] = {}
    for start in range(0, len(ids), 500):
        rows = call(method, {"triggerids": ids[start:start + 500], "selectHosts": ["hostid"],
                             "output": ["triggerid", "description", "templateid", "flags", *FIELDS]})
        trigger_expressions.rewrite(rows, method, call)
        found.update({str(r["triggerid"]): r for r in rows})
    return found


def run(call: Callable[[str, dict], Any], version: str, *, days: int = 60, user: str | None = None,
        restore: bool = False, out: Callable[[str], None] = print) -> int:
    """List (and with *restore* repair) the triggers that lost macros. Returns how many are left."""
    out(f"Zabbix {version}, the audit log of the last {days} days" + (f", updates by {user}" if user else ""))
    if tuple(int(x) for x in version.split(".")[:2]) < (6, 0):
        out("The audit log of this release does not record the expression before and after; nothing to read.")
        return 0
    changes = read_changes(call, days)
    left = restored = listed = 0
    for resource in (TRIGGER, PROTOTYPE):
        kind, get, update = KIND[resource]
        candidates = {tid: fields for (rtype, tid), fields in changes.items() if rtype == resource
                      and any(decide(entries, None, user)[0] != "none" for entries in fields.values())}
        if not candidates:
            continue
        now = current_triggers(call, get, sorted(candidates))
        for tid, fields in sorted(candidates.items()):
            row = now.get(tid)
            first = min(e["clock"] for entries in fields.values() for e in entries)
            when = datetime.fromtimestamp(first).strftime("%Y-%m-%d %H:%M")
            if row is None:
                out(f"  gone        {kind} {tid} (first changed {when}): it no longer exists")
                continue
            name = str(row.get("description", ""))[:70]
            decisions = {f: decide(entries, row.get(f), user) for f, entries in fields.items()}
            decisions = {f: d for f, d in decisions.items() if d[0] != "none"}
            states = {d[0] for d in decisions.values()}
            if states == {"as before"}:
                continue
            listed += 1
            if "changed since" in states:
                out(f"  SKIPPED     {kind} {tid} '{name}' (first changed {when}): changed again since the macros went; "
                    f"it had: {next(d[1] for d in decisions.values() if d[1])}")
                left += 1
                continue
            if str(row.get("templateid", "0")) != "0":
                out(f"  inherited   {kind} {tid} '{name}': follows its template, which is listed on its own")
                continue
            if str(row.get("flags", "0")) == "4":
                out(f"  discovered  {kind} {tid} '{name}': follows its prototype, which is listed on its own")
                continue
            payload = {"triggerid": tid, **{f: d[1] for f, d in decisions.items() if d[0] == "restore"}}
            lost = [pair for d in decisions.values() if d[0] == "restore" for pair in d[2]]
            verified = values_are_the_macros(lost, macro_values(call, [h["hostid"] for h in row.get("hosts") or []]))
            label = "RESTORE " if restore and verified else "LOST    " if verified else "REVIEW  "
            for field in FIELDS:
                if field in payload:
                    out(f"  {label}    {kind} {tid} '{name}' {field} (first changed {when})\n"
                        f"                now:    {row[field]}\n                before: {payload[field]}")
            if not verified:
                out("                not restored: the values written are not the values these macros have now "
                    "(a secret macro, a macro changed since, or an edit of somebody's own)")
                left += 1
            elif restore:
                try:
                    call(update, payload)
                    restored += 1
                except Exception as exc:   # Zabbix says why
                    out(f"                NOT RESTORED: {str(exc)[:200]}")
                    left += 1
            else:
                left += 1
    if not listed:
        out("No trigger or trigger prototype is without a user macro it had in that time.")
    out(f"{restored} restored, {left} left"
        + ("" if restore or not left else " (--restore writes back what is marked LOST; SKIPPED and REVIEW are yours to look at)"))
    return left


def main() -> int:
    from audit_get_contracts_live import Api
    argv = sys.argv[1:]
    options: dict[str, str] = {}
    for name in ("--days", "--user"):
        if name in argv:
            position = argv.index(name)
            options[name] = argv[position + 1]
            del argv[position:position + 2]
    restore = "--restore" in argv
    args = [a for a in argv if not a.startswith("--")]
    if len(args) == 2:
        api = Api(args[0], args[1], None, None)
    elif len(args) == 3:
        api = Api(args[0], None, args[1], args[2])
    else:
        raise SystemExit(__doc__)
    left = run(api.call, api.version, days=int(options.get("--days", 60)), user=options.get("--user"), restore=restore)
    return 1 if left else 0


if __name__ == "__main__":
    sys.exit(main())
