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

"""What a client is told about a tool before it calls it (MCP tool annotations).

A client uses the four hints to decide whether to ask the user first, how
loudly, and whether a call may be repeated after a lost answer:

* ``readOnlyHint``    - the call changes nothing.
* ``destructiveHint`` - the call can overwrite or remove something. ``False``
  only where it does nothing but add (a create, a mass add, a pushed value).
  An update is destructive: it overwrites, and a list property it carries
  (groups, templates, tags, macros, interfaces) replaces the whole list.
* ``idempotentHint``  - sending the same call again changes nothing further.
  A create makes a second object, an acknowledge adds a second message, a
  script runs twice; an update, a delete or an import ends in the same state.
* ``openWorldHint``   - the call makes Zabbix reach for something outside
  itself, named by the caller. Everything else talks to the configured Zabbix
  server and nothing beyond it.

The specification gives the last three a meaning only for a tool that
writes, and defaults that suit an unknown tool (destructive, not idempotent,
open world). A tool left without them is therefore announced as the worst
case, which is what every create tool was until 1.42.
"""

from __future__ import annotations

from typing import Any

# The part of a tool name after the last underscore -> (destructive, idempotent),
# for the tools that write. A verb missing here falls back to the worst case
# and fails tests/test_tool_annotations.py, so a new one is classified on purpose.
WRITE_VERBS: dict[str, tuple[bool, bool]] = {
    # only adds
    "create": (False, False),
    "createglobal": (False, False),
    "push": (False, False),                 # history.push: one more value each time
    "massadd": (False, False),              # an interface is added again on a repeat
    # overwrites what is there
    "update": (True, True),
    "updateglobal": (True, True),
    "massupdate": (True, True),
    "propagate": (True, True),              # permissions and tag filters of the subgroups
    "replacehostinterfaces": (True, True),
    "import": (True, True),                 # updateExisting / deleteMissing
    "provision": (True, True),              # role, groups and media from the directory
    "unblock": (True, True),
    # removes
    "delete": (True, True),
    "deleteglobal": (True, True),
    "massremove": (True, True),
    "clear": (True, True),                  # history.clear
    "logout": (True, True),                 # the session is gone
    "resettotp": (True, True),              # the user enrols again
    "resettimewindows": (True, True),       # what the CEP rule collected so far
    "offboard": (True, True),               # the pairing of the device
    # each call does it once more
    "execute": (True, False),               # script.execute
    "acknowledge": (True, False),           # can close a problem; a message is added every time
    "generate": (True, False),              # token.generate: the previous token string stops working
    # write methods that change nothing in the configuration (since 1.42.2 not open to
    # a read-only token: what they do cannot be called reading)
    "login": (False, False),                # user.login: a session, a password tried against Zabbix
    "test": (False, True),                  # userdirectory.test: Zabbix connects to the server named
}

# Tools the catalog treats as reads (a read-only server and a read-only token
# may call them) that still leave something behind.
_LEAVES_A_TRACE: dict[str, tuple[bool, bool]] = {
}

# Tools whose call makes Zabbix contact what the caller names: a script on a
# host or a URL, a directory server given in the call.
OPEN_WORLD: frozenset[str] = frozenset({
    "script_execute",
    "userdirectory_test",
})


def verb(tool_name: str) -> str:
    return tool_name.rsplit("_", 1)[-1]


def annotations_for(tool_name: str, read_only: bool) -> dict[str, Any]:
    """The hints of a catalog tool, ready for ``ToolAnnotations(**...)``."""
    open_world = tool_name in OPEN_WORLD
    trace = _LEAVES_A_TRACE.get(tool_name)
    if read_only and trace is None:
        return {"readOnlyHint": True, "openWorldHint": open_world}
    destructive, idempotent = trace if trace is not None else WRITE_VERBS.get(verb(tool_name), (True, False))
    return {
        "readOnlyHint": False,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": open_world,
    }


def write_annotations(*, destructive: bool, idempotent: bool, open_world: bool = False) -> dict[str, Any]:
    """The hints of a hand-written tool that writes."""
    return {
        "readOnlyHint": False,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": open_world,
    }


READ_ONLY: dict[str, Any] = {"readOnlyHint": True, "openWorldHint": False}
