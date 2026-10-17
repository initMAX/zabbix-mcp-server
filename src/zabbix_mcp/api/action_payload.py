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

"""Make an action (or correlation) as ``action.get`` returns it acceptable to
``action.update`` / ``action.create``.

The natural model workflow is "read the action, change one thing, write it
back". Zabbix returns a number of properties on read that it refuses on
write, one ``unexpected parameter`` at a time (measured on 6.0.48, 7.0.30 and
7.4.14, identical on all three):

* ``filter.eval_formula`` is read-only; ``filter.formula`` and every
  ``conditions[].formulaid`` are only accepted with ``evaltype`` 3 (custom
  expression), but are returned for every evaluation mode (#99);
* ``conditions[].value2`` is returned as ``""`` for condition types that do
  not have a second value, and refused there;
* ``operations[].operationid`` / ``actionid`` are read-only; ``esc_period``,
  ``esc_step_from``, ``esc_step_to``, ``evaltype`` and ``opconditions`` exist
  only on the main operations of a trigger / internal / service action
  (``evaltype`` / ``opconditions`` on trigger actions only), never on recovery
  or update operations; ``opmessage.subject`` / ``message`` are refused while
  ``default_msg`` is 1 (the media type's text is used); ``opmessage.mediatypeid``
  is refused on a "notify all involved" recovery operation;
* ``esc_period`` applies to trigger, internal and service actions,
  ``pause_suppressed`` / ``pause_symptoms`` / ``notify_if_canceled`` to
  trigger actions only, ``recovery_operations`` to trigger / internal /
  service, ``update_operations`` to trigger / service; the others return
  them anyway and refuse them back.

The documented action object contract also marks the ``opconditions`` entries'
``opconditionid`` / ``operationid`` and command targets' ``opcommand_hstid`` /
``opcommand_grpid`` as read-only. These nested IDs are stripped too, with
offline regression tests covering the write payloads.

``strip_for_write`` removes exactly those, and nothing a caller could have
meant: a non-empty ``value2``, a custom-expression formula, an explicit
``recovery_operations: []`` on a trigger action (which clears them) all stay.
The event source comes from the payload or, on an update that does not
carry it, from a one-field ``action.get`` done by the caller.
"""

from __future__ import annotations

from typing import Any

# eventsource values (action object)
TRIGGER, DISCOVERY, AUTOREGISTRATION, INTERNAL, SERVICE = "0", "1", "2", "3", "4"

_ESC_SOURCES = {TRIGGER, INTERNAL, SERVICE}          # esc_period, operations[].esc_*
_RECOVERY_SOURCES = {TRIGGER, INTERNAL, SERVICE}     # recovery_operations
_UPDATE_SOURCES = {TRIGGER, SERVICE}                 # update_operations
_TRIGGER_ONLY = ("pause_suppressed", "pause_symptoms", "notify_if_canceled")

OP_NOTIFY_ALL_INVOLVED_RECOVERY = "11"


def _s(value: Any) -> str | None:
    """Zabbix returns numbers as strings; callers may send ints."""
    if value is None:
        return None
    return str(value)


def strip_filter(filt: Any) -> Any:
    """Drop what a filter as returned by ``*.get`` cannot carry on write."""
    if not isinstance(filt, dict):
        return filt
    filt.pop("eval_formula", None)
    custom = _s(filt.get("evaltype")) == "3"
    if not custom:
        filt.pop("formula", None)
    conditions = filt.get("conditions")
    if isinstance(conditions, list):
        for cond in conditions:
            if not isinstance(cond, dict):
                continue
            if not custom:
                cond.pop("formulaid", None)
            if cond.get("value2") == "":
                cond.pop("value2")
    return filt


def _strip_operation(op: dict, *, main: bool, source: str | None) -> None:
    op.pop("operationid", None)
    op.pop("actionid", None)
    if not main or (source is not None and source not in _ESC_SOURCES):
        for key in ("esc_period", "esc_step_from", "esc_step_to"):
            op.pop(key, None)
    if not main or (source is not None and source != TRIGGER):
        op.pop("evaltype", None)
        op.pop("opconditions", None)
    for field, read_only in (
        ("opconditions", ("opconditionid", "operationid")),
        ("opcommand_hst", ("opcommand_hstid",)),
        ("opcommand_grp", ("opcommand_grpid",)),
    ):
        rows = op.get(field)
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict):
                    for key in read_only:
                        row.pop(key, None)
    msg = op.get("opmessage")
    if isinstance(msg, dict):
        if _s(msg.get("default_msg")) == "1":
            msg.pop("subject", None)
            msg.pop("message", None)
        if not main and _s(op.get("operationtype")) == OP_NOTIFY_ALL_INVOLVED_RECOVERY:
            msg.pop("mediatypeid", None)


def strip_for_write(params: Any, eventsource: Any = None) -> Any:
    """Strip an ``action.create`` / ``action.update`` payload in place and
    return it. *eventsource* is the action's event source when the payload
    does not carry it (looked up by the caller); ``None`` skips the
    source-specific rules."""
    if not isinstance(params, dict):
        return params
    source = _s(params.get("eventsource", eventsource))

    strip_filter(params.get("filter"))

    if source is not None:
        if source not in _ESC_SOURCES:
            params.pop("esc_period", None)
        if source != TRIGGER:
            for key in _TRIGGER_ONLY:
                params.pop(key, None)
        if source not in _RECOVERY_SOURCES:
            params.pop("recovery_operations", None)
        if source not in _UPDATE_SOURCES:
            params.pop("update_operations", None)

    for key, main in (("operations", True), ("recovery_operations", False), ("update_operations", False)):
        ops = params.get(key)
        if isinstance(ops, list):
            for op in ops:
                if isinstance(op, dict):
                    _strip_operation(op, main=main, source=source)
    return params


def strip_correlation_for_write(params: Any) -> Any:
    """``correlation.get`` returns the same read-only filter fields."""
    if isinstance(params, dict):
        strip_filter(params.get("filter"))
        ops = params.get("operations")
        if isinstance(ops, list):
            for op in ops:
                if isinstance(op, dict):
                    op.pop("corr_operationid", None)
    return params


FILTER_CONTRACT = (
    "filter.evaltype: 0=And/Or, 1=And, 2=Or, 3=custom expression. With evaltype 3 give "
    "'formula' (e.g. \"A and (B or C)\") and a unique upper-case 'formulaid' on every "
    "condition; with 0/1/2 leave both out (the server drops them, and the read-only "
    "'eval_formula', if you copy a filter returned by the get tool). "
    "An omitted 'filter' leaves the filter unchanged on update."
)
