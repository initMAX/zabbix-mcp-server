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
* each value that was written is what its macro resolves to today for the
  trigger's host or template, looked up in the order Zabbix uses when it
  expands an expression: the macro with the context asked for (or with a
  regular expression that matches it) on the host, on its templates, then
  among the global macros, and only then the macro without a context. Only
  a regular expression plain enough to mean the same here as in Zabbix is
  evaluated; with any other the trigger is left for review.

What it does not restore it lists with the reason and leaves alone:
``SKIPPED`` when the trigger was changed again since, ``REVIEW`` when a value
written is not the macro's (or the macro is a secret or a vault macro), and ``REVIEW`` as well
when a macro went in an update the rule does not cover: one that changed
something else too, which is what a model produces when it is asked to edit
the expression and edits the expanded text, or an earlier one after which
the expression was changed again. A trigger a template gives to hosts is
restored on the template; Zabbix passes it on.

Two things it does not see. One macro put in the place of another with
nothing else changed is somebody's choice and is not listed. And macros are
counted over the whole expression, not place by place: where the same macro
stands in another place of the expression, or is written there in that
update or a later one, a loss in one place can go unnoticed, or be listed
under another update than the one it went in.

    python3 scripts/restore_trigger_macros.py URL TOKEN [--days N] [--user NAME] [--restore]
    python3 scripts/restore_trigger_macros.py URL USER PASSWORD [--days N] [--user NAME] [--restore]

``--days`` is how far back to read (default 60; the log itself is kept for
31 days by default from Zabbix 7.0 and 365 before). ``--user`` looks only at
updates made by that Zabbix user. Give it the user whose API token the MCP
server uses: the log cannot tell a number somebody typed on purpose from the
value an expansion left, when the two are the same. Zabbix 6.0 or later: the
audit log of earlier releases does not carry the two values. Without
``--restore`` nothing is written. A password that begins with a dash: give
the options first, then ``--``, then URL USER PASSWORD.

Exit status 0 when nothing is left, 1 when something is, 2 when the script
could not do its work: an option it does not know, a ``--user`` Zabbix does
not have, Zabbix not reached or refusing a call.
"""

from __future__ import annotations

import json
import re
import sys
import time
import warnings
from collections import Counter
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
_NUMBER = re.compile(r"-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?[KMGTsmhdw]?")
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
    # each macro's place takes the macro itself or a value of the shape that place allows
    shapes = {"top": _NUMBER, "brackets": _IN_BRACKETS, "string": _IN_STRING}
    pattern, position = "", 0
    for macro, where in macros:
        # the macro itself, or a value that is not the macro: with both readings open for a
        # macro that stayed, a trigger with thirty macros would take hours to say "no"
        kept = re.escape(macro.group(0))
        pattern += re.escape(old[position:macro.start()]) + "(" + kept + "|(?!" + kept + ")" + shapes[where].pattern + ")"
        position = macro.end()
    pattern += re.escape(old[position:])
    found = re.fullmatch(pattern, new, re.S)
    if not found:
        return None
    changed: list[tuple[str, str]] = []
    for (macro, where), value in zip(macros, found.groups()):
        if value == macro.group(0):
            continue
        if "{$" in value:
            return None
        # inside a quoted string the macro's own quotes and backslashes are escaped: the macro as it is meant
        text = re.sub(r"\\(.)", r"\1", macro.group(0)) if where == "string" else macro.group(0)
        changed.append((text, value))
    return changed or None


def _macro_count(text: str) -> Counter:
    return Counter(m.group(0) for m in _MACRO.finditer(text))


def macros_gone(old: str, new: str) -> list[str]:
    """The user macros *old* has more often than *new*, each as often as it went.

    Nothing when the two differ only in which macro stands where: one macro
    put in the place of another, with the rest as it was, is somebody's
    choice. Anything else may be an expansion that a further change came
    with: a model that edits the expanded text saw no macro in it, and the
    macros in what it wrote are the ones it added itself.
    """
    if _MACRO.sub("{$}", old) == _MACRO.sub("{$}", new):
        return []
    return sorted((_macro_count(old) - _macro_count(new)).elements())


def read_changes(call: Callable[[str, dict], Any], days: int) -> dict[tuple[int, str], dict[str, list[dict]]]:
    """(resource type, triggerid) -> field -> the updates of that field, oldest first."""
    since = int(time.time()) - days * 86400
    seen: set[str] = set()
    out: dict[tuple[int, str], dict[str, list[dict]]] = {}
    query = {"output": ["auditid", "clock", "username", "resourcetype", "resourceid", "details"],
             "filter": {"resourcetype": [TRIGGER, PROTOTYPE], "action": 1},
             "sortfield": ["clock", "auditid"], "sortorder": "ASC"}

    def take(rows: list[dict]) -> None:
        for row in rows:
            if row["auditid"] in seen:
                continue
            seen.add(row["auditid"])
            try:
                details = json.loads(row.get("details") or "{}")
            except ValueError:
                continue
            if not isinstance(details, dict):
                continue
            kind = KIND[int(row["resourcetype"])][0]
            for field in FIELDS:
                change = details.get(f"{kind}.{field}")
                if isinstance(change, list) and len(change) == 3 and change[0] == "update":
                    out.setdefault((int(row["resourcetype"]), str(row["resourceid"])), {}).setdefault(field, []).append(
                        {"clock": int(row["clock"]), "user": row.get("username", ""),
                         "old": str(change[2]), "new": str(change[1])})

    while True:
        rows = call("auditlog.get", dict(query, time_from=since, limit=PAGE))
        take(rows)
        if len(rows) < PAGE:
            return out
        # A full page may end in the middle of a second. That second is read whole
        # (however many updates it holds), and the next page starts after it.
        newest = int(rows[-1]["clock"])
        take(call("auditlog.get", dict(query, time_from=newest, time_till=newest)))
        since = newest + 1


def _expansion(entry: dict) -> list[tuple[str, str]] | None:
    return macros_became_values(entry["old"], entry["new"])


def _newest_run(entries: list[dict], user: str | None = None) -> tuple[int, int] | None:
    """Where in *entries* the newest update that only turned macros into values stands,
    with the updates of that kind right before it: (first, last).

    With *user* only that user's updates count, and the run ends at an update
    by somebody else: that one is theirs, whatever it looks like.
    """
    def part_of_it(e: dict) -> bool:
        return bool(_expansion(e)) and (user is None or e["user"] == user)

    last = next((n for n in range(len(entries) - 1, -1, -1) if part_of_it(entries[n])), None)
    if last is None:
        return None
    first = last
    while first > 0 and part_of_it(entries[first - 1]) and entries[first - 1]["new"] == entries[first]["old"]:
        first -= 1
    return first, last


def _logged_since(entries: list[dict], position: int, current: str | None) -> list[str]:
    """The expressions the log gives from update *position* on, as far as they can be taken
    for what happened to the trigger: not when the trigger has something else than the log
    ends with (it was changed where the log does not see it, and is judged by what it has).
    None for *current*: the trigger was not read yet."""
    if current is not None and (not entries or current != entries[-1]["new"]):
        return []
    return [later["new"] for later in entries[position:]]


def decide(entries: list[dict], current: str | None, user: str | None = None) -> tuple[str, str | None, list[tuple[str, str]]]:
    """What to do with one field of one trigger: (state, the expression it had, the macros that went).

    *entries* are the recorded updates of the field, oldest first. States:
    ``none`` (no macro was lost here), ``as before`` (it has the expression
    with the macros again), ``changed since`` (something else was done to it
    after the macros went, or it no longer has what the log says), and
    ``restore``: the last thing that happened to it is one or more updates
    that only turned macros into values, and it still has what they left.
    """
    run_of_expansions = _newest_run(entries, user)
    if run_of_expansions is None:
        return "none", None, []
    start, end = run_of_expansions
    original = entries[start]["old"]
    # every value that was written, update by update: each one is checked against its macro
    lost = [pair for e in entries[start:end + 1] for pair in _expansion(e) or []]
    if current == original:
        return "as before", None, lost
    later = _logged_since(entries, end + 1, current)
    if original in later:
        # the macros were put back after that; what was done to the trigger later is
        # another matter (edited_away looks at it)
        return "none", None, []
    if end != len(entries) - 1 or current != entries[end]["new"]:
        # changed again since. When every macro that went has been there again, as often as
        # before, somebody typed them back in an edit of their own: nothing is lost.
        had = _macro_count(original)
        since = [_macro_count(state) for state in later]
        if current is not None:
            since.append(_macro_count(current))
        left_behind = _macro_count(entries[end]["new"])
        went = {macro for macro in had if left_behind[macro] < had[macro]}
        if since and all(any(state[macro] >= had[macro] for state in since) for macro in went):
            return "none", None, []
        return "changed since", original, lost
    return "restore", original, lost


MORE_THAN_THE_MACRO = "went in an update that changed more than the macro"
CHANGED_AFTERWARDS = "went in an earlier update, and the expression was changed again afterwards"


def edited_away(entries: list[dict], current: str | None, user: str | None = None,
                handled: tuple[int, int] | None = None, target: str | None = None) -> tuple[str, list[str], str] | None:
    """The newest update outside *handled* that took user macros out which the expression has
    not had back since: (the expression before that update, the macros, why it is not undone).

    *handled* is the run of updates ``decide`` deals with, as ``_newest_run``
    gives it; *current* is the expression as it is, None before the trigger
    is read; *target* the expression as the restore leaves it, when that is
    another one. Such an update cannot be undone by rule: what else changed in
    it, or after it, may be wanted. It is reported for a person to look at.
    """
    for n in range(len(entries) - 1, -1, -1):
        entry = entries[n]
        if handled is not None and handled[0] <= n <= handled[1]:
            continue
        if user is not None and entry["user"] != user:
            continue
        gone = macros_gone(entry["old"], entry["new"])
        if not gone:
            continue
        # still gone: at no point since has the expression had the macro as often as before that update
        had = _macro_count(entry["old"])
        since = [_macro_count(state) for state in _logged_since(entries, n, current)]
        if target is not None or current is not None:
            since.append(_macro_count(target if target is not None else current))
        missing = sorted(macro for macro in set(gone) if all(state[macro] < had[macro] for state in since))
        if missing:
            return entry["old"], missing, CHANGED_AFTERWARDS if _expansion(entry) else MORE_THAN_THE_MACRO
    return None


_MACRO_PARTS = re.compile(r"\{\$([A-Z0-9_.]+)(?::(.*))?\}", re.S)
_UNSET: Any = object()


class _CannotTell(Exception):
    """A regular expression context that cannot be evaluated here the way Zabbix (PCRE) does."""


def _reads_alike(regex: str) -> bool:
    r"""Whether a regular expression context means the same to Python's ``re`` as to the PCRE
    Zabbix matches with. Left out, to be on the safe side: anything not ASCII, every escape
    but \d \s \w (and \D \S \W), \b \B, \t \n \r and an escaped sign, POSIX classes, ``{,n}``,
    group constructs other than (?: (?= (?!, and a repeated group, which can also take hours
    to say no."""
    if not regex.isascii():
        return False
    if any(not re.fullmatch(r"[dDsSwWbBtnr]|[^A-Za-z0-9]", escape.group(1), re.S)
           for escape in re.finditer(r"\\(.?)", regex, re.S)):
        return False
    without_escapes = re.sub(r"\\.", "", regex, flags=re.S)
    return not re.search(r"\[:|\{,|\(\?(?![:=!])|\)[+*{]", without_escapes)


def _macro_parts(text: str, definition: bool = False) -> tuple[str, str | None, bool] | None:
    """(name, context, whether the context is a regular expression) of a user macro as written,
    read the way Zabbix reads it (CUserMacroParser): spaces before the context do not count,
    a quoted context loses its quotes and the backslash of every \\", an unquoted one is
    taken as it stands. The context is None when the macro has none. ``regex:`` makes a
    regular expression only where a macro is defined (*definition*); in an expression it is
    part of the context."""
    found = _MACRO_PARTS.fullmatch(text)
    if not found:
        return None
    name, context = found.groups()
    if context is None:
        return name, None, False
    regex = re.match(r"\s*regex:", context) if definition else None
    if regex:
        context = context[regex.end():]
    context = context.lstrip(" ")
    if context.startswith('"'):
        quoted = context.rstrip(" ")
        if len(quoted) >= 2 and quoted.endswith('"'):
            context = quoted[1:-1].replace('\\"', '"')
    return name, context, bool(regex)


class MacroValues:
    """What a user macro resolves to for one trigger, in the order the Zabbix frontend uses
    when it expands an expression (CMacrosResolverGeneral::getHostUserMacros):

    1. a macro with a context, on the trigger's hosts, then on their templates, level by
       level: the context itself, or a regular expression that matches it;
    2. the same among the global macros;
    3. the macro without a context, nearest first; 4. the global one.

    Within a level the hosts are taken in the order of their IDs.
    """

    def __init__(self, levels: list[list[dict]], global_macros: list[dict] | tuple = ()):
        """*levels*: the ``usermacro.get`` rows (with ``hostid``) of the trigger's hosts, of
        their templates, of the templates of those and so on. *global_macros*: the global rows."""
        self.levels = [self._by_host(rows) for rows in levels]
        self.global_macros = self._macros(global_macros)

    @staticmethod
    def _macros(rows: Any) -> dict[str, dict]:
        macros: dict[str, dict] = {}
        for row in rows:
            parts = _macro_parts(str(row.get("macro", "")), definition=True)
            if parts is None:
                continue
            name, context, regex = parts
            # None: a secret or a vault macro. Zabbix expands both to a mask, never to the value.
            value = None if "value" not in row or str(row.get("type", "0")) in ("1", "2") else str(row["value"])
            macro = macros.setdefault(name, {"plain": _UNSET, "contexts": {}, "regex": {}})
            if context is None:
                macro["plain"] = value
            else:
                macro["regex" if regex else "contexts"][context] = value
        return macros

    @classmethod
    def _by_host(cls, rows: list[dict]) -> list[dict[str, dict]]:
        hosts: dict[str, list[dict]] = {}
        for row in rows:
            hosts.setdefault(str(row.get("hostid", "")), []).append(row)
        return [cls._macros(hosts[hostid]) for hostid in sorted(hosts, key=lambda i: (len(i), i))]

    @staticmethod
    def _with_context(macro: dict, context: str) -> Any:
        if context in macro["contexts"]:
            return macro["contexts"][context]
        for regex in sorted(macro["regex"]):
            # Zabbix matches with PCRE, on bytes. Only what reads the same here is evaluated.
            if not (context.isascii() and _reads_alike(regex)):
                raise _CannotTell(regex)
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error")
                    matched = re.search(regex, context)
            except (re.error, Warning, RecursionError, OverflowError) as exc:
                raise _CannotTell(regex) from exc
            if matched:
                return macro["regex"][regex]
        return _UNSET

    def _resolve(self, name: str, context: str | None) -> Any:
        default = _UNSET            # the nearest macro without a context: used when no context fits anywhere
        for macros in [macros for hosts in self.levels for macros in hosts] + [self.global_macros]:
            macro = macros.get(name)
            if macro is None:
                continue
            if context is not None:
                value = self._with_context(macro, context)
                if value is not _UNSET:
                    return value
            if macro["plain"] is not _UNSET:
                if context is None:
                    return macro["plain"]
                if default is _UNSET:
                    default = macro["plain"]
        return default

    def of(self, macro: str) -> set[str] | None:
        """What *macro*, as it stands in an expression, resolves to: a set with the one value,
        empty when the macro is not defined, None when the value cannot be known (a secret, or
        a regular expression context that cannot be evaluated here)."""
        parts = _macro_parts(macro)
        if parts is None:
            return set()
        try:
            value = self._resolve(parts[0], parts[1])
        except _CannotTell:
            return None
        if value is _UNSET:
            return set()
        return None if value is None else {value}


def macro_values(call: Callable[[str, dict], Any], hostids: list[str]) -> MacroValues:
    """The macros of these hosts / templates, of the templates they inherit from level by
    level, and the global ones."""
    known, level, levels_of_ids = {str(i) for i in hostids}, [str(i) for i in hostids], []
    while level:
        levels_of_ids.append(level)
        parents: list[str] = []
        for start in range(0, len(level), 200):
            batch = level[start:start + 200]
            for method, key in (("host.get", "hostids"), ("template.get", "templateids")):
                for row in call(method, {key: batch, "output": ["hostid" if method == "host.get" else "templateid"],
                                         "selectParentTemplates": ["templateid"]}):
                    for parent in row.get("parentTemplates") or []:
                        if str(parent["templateid"]) not in known:
                            known.add(str(parent["templateid"]))
                            parents.append(str(parent["templateid"]))
        level = parents
    rows = list(call("usermacro.get", {"hostids": sorted(known), "output": ["hostid", "macro", "value", "type"]})) if known else []
    of_host: dict[str, list[dict]] = {}
    for row in rows:
        of_host.setdefault(str(row.get("hostid")), []).append(row)
    levels = [[row for i in ids for row in of_host.get(i, [])] for ids in levels_of_ids]
    return MacroValues(levels, list(call("usermacro.get", {"globalmacro": True, "output": ["macro", "value", "type"]})))


def values_are_the_macros(lost: list[tuple[str, str]], values: MacroValues) -> bool:
    """Whether every value that was written is what its macro resolves to today."""
    for macro, value in lost:
        have = values.of(macro)
        unescaped = re.sub(r"\\(.)", r"\1", value)       # inside a string Zabbix escapes the value it puts in
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


class NobodyByThatName(Exception):
    """``--user`` names a user Zabbix does not have."""


def _discovered(row: dict) -> bool:
    """Made by a discovery rule: flags 4 for a trigger, 6 for a trigger prototype of a nested rule."""
    try:
        return bool(int(row.get("flags", 0)) & 4)
    except (TypeError, ValueError):
        return False


def run(call: Callable[[str, dict], Any], version: str, *, days: int = 60, user: str | None = None,
        restore: bool = False, out: Callable[[str], None] = print) -> int:
    """List (and with *restore* repair) the triggers that lost macros. Returns how many are left."""
    out(f"Zabbix {version}, the audit log of the last {days} days" + (f", updates by {user}" if user else ""))
    if tuple(int(x) for x in version.split(".")[:2]) < (6, 0):
        out("The audit log of this release does not record the expression before and after; nothing to read.")
        return 0
    changes = read_changes(call, days)
    if user is not None:
        # a name nobody has reads as "nothing lost": say so instead
        names = {e["user"] for fields in changes.values() for entries in fields.values() for e in entries}
        others = f" (triggers were updated in that time by: {', '.join(sorted(names))})" if names else ""
        if user not in names:
            if not call("user.get", {"filter": {"username": user}, "output": ["userid"]}):
                raise NobodyByThatName(f"Zabbix has no user '{user}'{others}")
            out(f"'{user}' updated no trigger in that time{others}")
    restored = listed = 0
    left: set[tuple[int, str]] = set()          # a trigger counts once, whatever is said about it
    for resource in (TRIGGER, PROTOTYPE):
        kind, get, update = KIND[resource]
        candidates = {tid: fields for (rtype, tid), fields in changes.items() if rtype == resource
                      and any(macros_gone(e["old"], e["new"]) for entries in fields.values() for e in entries
                              if user is None or e["user"] == user)}
        if not candidates:
            continue
        now = current_triggers(call, get, sorted(candidates))
        for tid, fields in sorted(candidates.items()):
            row = now.get(tid)
            clocks = [e["clock"] for entries in fields.values() for e in entries if user is None or e["user"] == user]
            when = datetime.fromtimestamp(min(clocks)).strftime("%Y-%m-%d %H:%M")
            if row is None:
                if any(decide(entries, None, user)[0] != "none" or edited_away(entries, None, user) for entries in fields.values()):
                    out(f"  gone        {kind} {tid} (first changed {when}): it no longer exists")
                continue
            name = str(row.get("description", ""))[:70]
            decided = {f: decide(entries, row.get(f), user) for f, entries in fields.items()}
            decisions = {f: d for f, d in decided.items() if d[0] != "none"}
            states = {d[0] for d in decisions.values()}
            own = str(row.get("templateid", "0")) == "0" and not _discovered(row)
            # A macro that went in an update the rule does not undo: never written back,
            # and never passed over in silence either. Looked for in every field, in every
            # update but the run the decision is about, and against the expression as the
            # restore leaves it.
            edits: dict[str, tuple[str, list[str], str]] = {}
            for field, entries in fields.items() if own else ():
                state, original, _ = decided[field]
                found = edited_away(entries, str(row.get(field) or ""), user,
                                    _newest_run(entries, user) if state != "none" else None,
                                    target=original if state == "restore" else None)
                if found:
                    edits[field] = found
            for field, (before, macros, why) in edits.items():
                out(f"  REVIEW      {kind} {tid} '{name}' {field} (first changed {when}): {', '.join(macros)} {why}\n"
                    f"                now:    {row.get(field)}\n                before: {before}")
            if edits:
                listed += 1
                left.add((resource, tid))
            if not states or states == {"as before"}:
                continue
            listed += 0 if edits else 1
            if "changed since" in states:
                out(f"  SKIPPED     {kind} {tid} '{name}' (first changed {when}): changed again since the macros went; "
                    f"it had: {next(d[1] for d in decisions.values() if d[0] == 'changed since')}")
                left.add((resource, tid))
                continue
            if str(row.get("templateid", "0")) != "0":
                out(f"  inherited   {kind} {tid} '{name}': follows its template, which is listed on its own")
                continue
            if _discovered(row):
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
                left.add((resource, tid))
            elif restore:
                try:
                    call(update, payload)
                    restored += 1
                except Exception as exc:   # Zabbix says why
                    out(f"                NOT RESTORED: {str(exc)[:200]}")
                    left.add((resource, tid))
            else:
                left.add((resource, tid))
    if not listed:
        out("No trigger or trigger prototype is without a user macro it had in that time.")
    out(f"{restored} restored, {len(left)} left"
        + ("" if not left else " (--restore writes back what is marked LOST; SKIPPED and REVIEW are yours to look at)"
           if not restore else " (SKIPPED and REVIEW are yours to look at)"))
    return len(left)


def arguments(argv: list[str] | None = None) -> Any:
    """The command line. An option the script does not know is refused, not passed over:
    a ``--user`` that is not taken in would mean a restore over everybody's updates."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="restore_trigger_macros.py", allow_abbrev=False, description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage="%(prog)s URL TOKEN [--days N] [--user NAME] [--restore]\n"
              "       %(prog)s URL USER PASSWORD [--days N] [--user NAME] [--restore]")
    parser.add_argument("url", metavar="URL", help="the Zabbix frontend, as the MCP server has it")
    parser.add_argument("credentials", nargs="+", metavar="CREDENTIALS", help="an API token, or a user name and a password")
    parser.add_argument("--days", type=int, default=60, metavar="N", help="how far back to read (default 60)")
    parser.add_argument("--user", metavar="NAME", help="only the updates made by this Zabbix user")
    parser.add_argument("--restore", action="store_true", help="write the earlier expressions back")
    args = parser.parse_args(argv)
    if len(args.credentials) > 2:
        parser.error("give URL TOKEN, or URL USER PASSWORD")
    if args.days < 1:
        parser.error("--days takes a number of days, 1 or more")
    return args


def main(argv: list[str] | None = None) -> int:
    args = arguments(argv)
    from audit_get_contracts_live import Api
    if len(args.credentials) == 1:
        api = Api(args.url, args.credentials[0], None, None)
    else:
        api = Api(args.url, None, args.credentials[0], args.credentials[1])
    try:
        left = run(api.call, api.version, days=args.days, user=args.user, restore=args.restore)
    except NobodyByThatName as exc:
        print(f"{exc}. Nothing was looked at under that name, and nothing was written.", file=sys.stderr)
        return 2
    return 1 if left else 0


def _main() -> int:
    """``main``, with an error (Zabbix not reached, the login refused, a call refused half way)
    as exit status 2 and one line: status 1 is kept for "something is left"."""
    try:
        return main()
    except Exception as exc:
        print(f"restore_trigger_macros.py: stopped, {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(_main())
