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

"""``scripts/restore_trigger_macros.py`` writes to somebody's Zabbix: it restores only what
is certainly the trace of v1.40 / v1.41, and leaves every edit of somebody's own alone."""

import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import restore_trigger_macros as r  # noqa: E402

M = 'avg(/h/k,10m)>{$MAX:"poller"}'
V = "avg(/h/k,10m)>75"


def entry(clock, old, new, user="mcp"):
    return {"clock": clock, "user": user, "old": old, "new": new}


class TestWhatAnExpansionLooksLike(unittest.TestCase):
    def test_macros_that_became_their_values(self):
        for old, new, pairs in (
            (M, V, [('{$MAX:"poller"}', "75")]),
            ('min(/h/jmx[{#OBJ}, Mem],{$T:"{#B}"})>{$M:"{#B}"}', "min(/h/jmx[{#OBJ}, Mem],5m)>75", None),
            ('count(/h/k,#1,"eq","{$CRIT}")=1', 'count(/h/k,#1,"eq","4")=1', None),
            ('count(/h/k,#1,"eq","{$W:\\"offline\\"}")=1', 'count(/h/k,#1,"eq","2")=1', None),
            ("last(/h/k)>{$A} and last(/h/k)<{$B}", "last(/h/k)>1 and last(/h/k)<{$B}", [("{$A}", "1")]),
            ("last(/h/k)>{$M:{#FS}}", "last(/h/k)>90", None),
            ('last(/h/web.page.get["{$S}://{$H}:{$P}/x"])=0', 'last(/h/web.page.get["http://127.0.0.1:80/x"])=0', None),
            ("last(/h/net.tcp.service[http,{$HOST},{$PORT}])=0", "last(/h/net.tcp.service[http,127.0.0.1,80])=0", None),
            ('find(/h/k,,"like","{$E}")=1', 'find(/h/k,,"like","")=1', [("{$E}", "")]),
            ("max(/h/k,{$T})<{$TEMP_WARN}-3", "max(/h/k,5m)<55-3", [("{$T}", "5m"), ("{$TEMP_WARN}", "55")]),
            ("last(/h/k)>{$A}", "last(/h/k)>-1.5K", None),
        ):
            got = r.macros_became_values(old, new)
            self.assertTrue(got, (old, new))
            if pairs is not None:
                self.assertEqual(got, pairs, (old, new))

    def test_somebody_s_own_edit_is_not_one(self):
        for old, new in (
            ("last(/h/k)>{$A}", "last(/h/k)>{$A}"),                              # nothing changed
            ("last(/h/k)>{$A}", "last(/h/k2)>5"),                               # something else changed too
            ("last(/h/k)>{$A}", "last(/h/k)>{$B}"),                             # another macro
            ("last(/h/k)>{$A}", "last(/h/k)>5 and last(/h/k2)>3"),              # a clause added
            ("last(/h/k)>{$A}", "last(/h/k)>{$A}*2"),
            ("last(/h/k)>{$A}", "last(/h/k)>avg(/h/k,1d)*1.2"),                 # a longer expression
            ('last(/h/k)>{$A:"x"}', 'last(/h/k)>{$A:"y"}'),                     # a changed context
            ("last(/h/k)>5", "last(/h/k)>6"),                                   # no macro before
            ("avg(/h/k,{$T})>1", 'avg(/h/k,5m,"x")>1'),                         # a parameter added
            ('find(/h/k,,"like","{$E}")=1', 'find(/h/k,,"like","a") or find(/h/k,,"like","b")=1'),
            ("last(/h/k)>{$A}", "last(/h/k)>high"),                             # no number where a number belongs
        ):
            self.assertIsNone(r.macros_became_values(old, new), (old, new))

    def test_where_a_macro_stands(self):
        found = r._macros_with_position('max(/h/k[{$A},"{$B}"],{$C})>{$D} and find(/h/k,,"like","x \\" {$E}")=1')
        self.assertEqual([(m.group(0), where) for m, where in found],
                         [("{$A}", "brackets"), ("{$B}", "string"), ("{$C}", "brackets"), ("{$D}", "top"), ("{$E}", "string")])


class TestTheDecision(unittest.TestCase):
    def test_the_trace_of_the_bug_is_restored(self):
        self.assertEqual(r.decide([entry(1, M, V)], V), ("restore", M, [('{$MAX:"poller"}', "75")]))

    def test_macros_lost_in_two_steps(self):
        steps = [entry(1, "a>{$A} and b>{$B}", "a>1 and b>{$B}"), entry(2, "a>1 and b>{$B}", "a>1 and b>2")]
        self.assertEqual(r.decide(steps, "a>1 and b>2"), ("restore", "a>{$A} and b>{$B}", [("{$A}", "1"), ("{$B}", "2")]))

    def test_an_edit_before_the_loss_is_kept(self):
        self.assertEqual(r.decide([entry(0, "avg(/h/k,10m)>{$OLD}", M, "admin"), entry(1, M, V)], V)[:2], ("restore", M))

    def test_an_edit_after_the_loss_is_never_overwritten(self):
        later = entry(2, V, "avg(/h/k,10m)>80 and last(/h/k2)>1", "admin")
        self.assertEqual(r.decide([entry(1, M, V), later], later["new"])[0], "changed since")
        # also when the log does not have that edit (older than what is kept, or made in the database)
        self.assertEqual(r.decide([entry(1, M, V)], "avg(/h/k,10m)>80")[0], "changed since")
        # and when it was restored, lost again and then edited
        self.assertEqual(r.decide([entry(1, M, V), entry(2, V, M, "admin"), entry(3, M, V), entry(4, V, "avg(/h/k,10m)>80", "admin")],
                                  "avg(/h/k,10m)>80")[0], "changed since")

    def test_what_has_its_macros_again_is_left(self):
        self.assertEqual(r.decide([entry(1, M, V), entry(2, V, M, "admin")], M)[0], "as before")
        self.assertEqual(r.decide([entry(1, M, V)], M)[0], "as before")

    def test_restored_and_lost_again(self):
        self.assertEqual(r.decide([entry(1, M, V), entry(2, V, M, "admin"), entry(3, M, V)], V)[:2], ("restore", M))

    def test_no_loss_no_business(self):
        self.assertEqual(r.decide([entry(1, V, "avg(/h/k,10m)>80", "admin")], "avg(/h/k,10m)>80")[0], "none")
        self.assertEqual(r.decide([], V)[0], "none")

    def test_one_user_s_updates_only(self):
        self.assertEqual(r.decide([entry(1, M, V, "mcp")], V, user="mcp")[0], "restore")
        self.assertEqual(r.decide([entry(1, M, V, "admin")], V, user="mcp")[0], "none")


class TestTheValuesAreTheMacros(unittest.TestCase):
    VALUES = {"MAX": {"75", "90"}, "S": {'a "quoted" word'}, "SECRET": None}

    def test_a_value_the_macro_has(self):
        self.assertTrue(r.values_are_the_macros([('{$MAX:"poller"}', "75")], self.VALUES))
        self.assertTrue(r.values_are_the_macros([("{$S}", 'a \\"quoted\\" word')], self.VALUES))     # escaped inside a string

    def test_a_value_it_does_not_have_is_somebody_s_number(self):
        self.assertFalse(r.values_are_the_macros([("{$MAX}", "91")], self.VALUES))
        self.assertFalse(r.values_are_the_macros([("{$MAX}", "75"), ("{$MAX}", "91")], self.VALUES))

    def test_a_secret_or_an_unknown_macro_cannot_be_confirmed(self):
        self.assertFalse(r.values_are_the_macros([("{$SECRET}", "x")], self.VALUES))
        self.assertFalse(r.values_are_the_macros([("{$GONE}", "1")], self.VALUES))


class FakeZabbix:
    """auditlog.get with paging, the triggers as stored, macros, and a record of what was written."""

    def __init__(self, audit=(), triggers=(), prototypes=(), macros=(), global_macros=(), parents=None):
        self.audit = sorted(audit, key=lambda a: (a["clock"], a["auditid"]))
        self.rows = {"trigger.get": {t["triggerid"]: t for t in triggers},
                     "triggerprototype.get": {t["triggerid"]: t for t in prototypes}}
        self.macros, self.global_macros, self.parents = list(macros), list(global_macros), parents or {}
        self.written: list[tuple[str, dict]] = []
        self.pages = 0

    def call(self, method, params):
        if method == "auditlog.get":
            self.pages += 1
            rows = [a for a in self.audit if a["clock"] >= params["time_from"]]
            return rows[:params["limit"]]
        if method in self.rows:
            return [dict(self.rows[method][i]) for i in params["triggerids"] if i in self.rows[method]]
        if method in ("host.get", "template.get"):
            key = "hostids" if method == "host.get" else "templateids"
            idf = "hostid" if method == "host.get" else "templateid"
            return [{idf: i, "parentTemplates": [{"templateid": p} for p in self.parents.get(i, [])]} for i in params[key]]
        if method == "usermacro.get":
            if params.get("globalmacro"):
                return list(self.global_macros)
            return [m for m in self.macros if m["hostid"] in params["hostids"]]
        if method.endswith(".update"):
            self.written.append((method, params))
            return {"triggerids": [params["triggerid"]]}
        raise AssertionError(method)


NOW = int(time.time())


def audit(n, triggerid, old, new, *, field="expression", kind="trigger", user="mcp", clock=None):
    return {"auditid": f"a{n:06d}", "clock": clock if clock is not None else NOW - 3600 + n, "username": user,
            "resourcetype": "13" if kind == "trigger" else "31", "resourceid": triggerid,
            "details": json.dumps({f"{kind}.{field}": ["update", new, old]})}


def trigger(triggerid, expression, *, recovery="", templateid="0", flags="0", hostid="10", name=None):
    return {"triggerid": triggerid, "description": name or f"trigger {triggerid}", "templateid": templateid,
            "flags": flags, "expression": expression, "recovery_expression": recovery, "hosts": [{"hostid": hostid}]}


class TestTheRun(unittest.TestCase):
    MACROS = [{"hostid": "10", "macro": '{$MAX:"poller"}', "value": "75", "type": "0"},
              {"hostid": "20", "macro": "{$MIN}", "value": "65", "type": "0"}]

    def _run(self, zabbix, **kwargs):
        lines: list[str] = []
        left = r.run(zabbix.call, kwargs.pop("version", "7.0.30"), out=lines.append, **kwargs)
        return left, "\n".join(lines)

    def test_listing_writes_nothing(self):
        zabbix = FakeZabbix([audit(1, "1", M, V)], [trigger("1", V)], macros=self.MACROS)
        left, text = self._run(zabbix)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("LOST", text)
        self.assertIn(f"before: {M}", text)

    def test_restore_writes_the_earlier_expression_of_both_fields(self):
        rec_old, rec_new = "avg(/h/k,10m)<{$MIN}", "avg(/h/k,10m)<65"
        zabbix = FakeZabbix([audit(1, "1", M, V), audit(2, "1", rec_old, rec_new, field="recovery_expression")],
                            [trigger("1", V, recovery=rec_new)], macros=self.MACROS, parents={"10": ["20"]})
        left, text = self._run(zabbix, restore=True)
        self.assertEqual(left, 0)
        self.assertEqual(zabbix.written, [("trigger.update", {"triggerid": "1", "expression": M, "recovery_expression": rec_old})])
        self.assertIn("1 restored, 0 left", text)

    def test_a_trigger_prototype_goes_through_its_own_method(self):
        zabbix = FakeZabbix([audit(1, "7", M, V, kind="triggerprototype")], prototypes=[trigger("7", V)], macros=self.MACROS)
        self._run(zabbix, restore=True)
        self.assertEqual(zabbix.written, [("triggerprototype.update", {"triggerid": "7", "expression": M})])

    def test_an_edit_made_afterwards_is_listed_and_left(self):
        zabbix = FakeZabbix([audit(1, "1", M, V), audit(2, "1", V, "avg(/h/k,10m)>80", user="admin")],
                            [trigger("1", "avg(/h/k,10m)>80")], macros=self.MACROS)
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("SKIPPED", text)
        self.assertIn(M, text)

    def test_a_number_that_is_not_the_macro_s_value_is_left_for_a_person(self):
        zabbix = FakeZabbix([audit(1, "1", M, "avg(/h/k,10m)>91", user="admin")], [trigger("1", "avg(/h/k,10m)>91")], macros=self.MACROS)
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("REVIEW", text)
        self.assertIn("not restored: the values written are not the values these macros have now", text)

    def test_a_global_macro_and_a_template_s_macro_count(self):
        zabbix = FakeZabbix([audit(1, "1", "last(/h/k)>{$G} and last(/h/k)<{$MIN}", "last(/h/k)>5 and last(/h/k)<65")],
                            [trigger("1", "last(/h/k)>5 and last(/h/k)<65")], macros=self.MACROS,
                            global_macros=[{"macro": "{$G}", "value": "5", "type": "0"}], parents={"10": ["15"], "15": ["20"]})
        left, _ = self._run(zabbix, restore=True)
        self.assertEqual((left, len(zabbix.written)), (0, 1))

    def test_a_secret_macro_cannot_be_confirmed(self):
        zabbix = FakeZabbix([audit(1, "1", "last(/h/k)>{$S}", "last(/h/k)>5")], [trigger("1", "last(/h/k)>5")],
                            macros=[{"hostid": "10", "macro": "{$S}", "type": "1"}])
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("REVIEW", text)

    def test_inherited_and_discovered_triggers_follow_their_parents(self):
        zabbix = FakeZabbix([audit(1, "1", M, V), audit(2, "2", M, V), audit(3, "3", M, V)],
                            [trigger("1", V), trigger("2", V, templateid="1"), trigger("3", V, flags="4")], macros=self.MACROS)
        left, text = self._run(zabbix, restore=True)
        self.assertEqual([p["triggerid"] for _, p in zabbix.written], ["1"])
        self.assertIn("inherited", text)
        self.assertIn("discovered", text)
        self.assertEqual(left, 0)

    def test_what_is_as_it_was_and_what_is_gone(self):
        zabbix = FakeZabbix([audit(1, "1", M, V), audit(2, "1", V, M, user="admin"), audit(3, "9", M, V)],
                            [trigger("1", M)], macros=self.MACROS)
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (0, []))
        self.assertIn("gone", text)
        self.assertNotIn("trigger 1 ", text)

    def test_nothing_found(self):
        zabbix = FakeZabbix([audit(1, "1", V, "avg(/h/k,10m)>80", user="admin")], [trigger("1", "avg(/h/k,10m)>80")])
        left, text = self._run(zabbix, restore=True)
        self.assertEqual(left, 0)
        self.assertIn("No trigger or trigger prototype is without a user macro it had", text)

    def test_only_one_user_s_updates(self):
        zabbix = FakeZabbix([audit(1, "1", M, V, user="mcp"), audit(2, "2", M, V, user="admin")],
                            [trigger("1", V), trigger("2", V)], macros=self.MACROS)
        self._run(zabbix, restore=True, user="mcp")
        self.assertEqual([p["triggerid"] for _, p in zabbix.written], ["1"])

    def test_a_refusal_by_zabbix_is_reported_not_swallowed(self):
        zabbix = FakeZabbix([audit(1, "1", M, V)], [trigger("1", V)], macros=self.MACROS)
        real = zabbix.call

        def call(method, params):
            if method == "trigger.update":
                raise RuntimeError("Incorrect item key provided for trigger expression")
            return real(method, params)

        lines: list[str] = []
        left = r.run(call, "7.0.30", restore=True, out=lines.append)
        self.assertEqual(left, 1)
        self.assertIn("NOT RESTORED: Incorrect item key", "\n".join(lines))

    def test_before_6_0_there_is_nothing_to_read(self):
        zabbix = FakeZabbix()
        left, text = self._run(zabbix, version="5.0.47")
        self.assertEqual((left, zabbix.pages), (0, 0))
        self.assertIn("does not record the expression before and after", text)


class TestTheAuditLogIsReadWhole(unittest.TestCase):
    def test_rows_that_share_the_second_a_page_ends_in(self):
        # 2005 updates of 2005 triggers, the last ten in one second: a page ends inside it
        rows = [audit(n, str(n), M, V, clock=NOW - 5000 + min(n, 1995)) for n in range(1, 2006)]
        zabbix = FakeZabbix(rows)
        changes = r.read_changes(zabbix.call, days=1)
        self.assertEqual(len(changes), 2005)
        self.assertGreaterEqual(zabbix.pages, 2)

    def test_a_whole_page_in_one_second_does_not_loop(self):
        rows = [audit(n, str(n), M, V, clock=NOW - 100) for n in range(1, r.PAGE + 1)] + [audit(9000, "x", M, V, clock=NOW - 50)]
        zabbix = FakeZabbix(rows)
        changes = r.read_changes(zabbix.call, days=1)
        self.assertEqual(len(changes), r.PAGE + 1)
        self.assertLess(zabbix.pages, 6)

    def test_the_order_within_a_second_is_the_order_of_the_ids(self):
        rows = [audit(2, "1", V, "avg(/h/k,10m)>80", clock=NOW - 10, user="admin"), audit(1, "1", M, V, clock=NOW - 10)]
        changes = r.read_changes(FakeZabbix(rows).call, days=1)
        self.assertEqual([e["new"] for e in changes[(13, "1")]["expression"]], [V, "avg(/h/k,10m)>80"])

    def test_details_that_are_not_what_is_expected_are_skipped(self):
        rows = [audit(1, "1", M, V), dict(audit(2, "2", M, V), details="not json"),
                dict(audit(3, "3", M, V), details=json.dumps({"trigger.expression": ["add", V]})),
                dict(audit(4, "4", M, V), details=json.dumps({"trigger.priority": ["update", "3", "2"]}))]
        self.assertEqual(list(r.read_changes(FakeZabbix(rows).call, days=1)), [(13, "1")])


if __name__ == "__main__":
    unittest.main()
