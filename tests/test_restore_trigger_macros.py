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

import contextlib
import io
import json
import sys
import time
import unittest
import warnings
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
            ("last(/h/k)>{$A}", "last(/h/k)>1e3", None),
            ("last(/h/k)>{$A}", "last(/h/k)>.5", None),
            ("last(/h/k)>{$A}", "last(/h/k)>2.5E-3m", None),
        ):
            got = r.macros_became_values(old, new)
            self.assertTrue(got, (old, new))
            if pairs is not None:
                self.assertEqual(got, pairs, (old, new))

    def test_a_value_is_read_by_the_shape_its_place_allows(self):
        # two macros with a minus between them, and a negative value
        self.assertEqual(r.macros_became_values("x>{$A}-{$B}", "x>-5-3"), [("{$A}", "-5"), ("{$B}", "3")])
        self.assertEqual(r.macros_became_values("x>{$A}-{$B}", "x>{$A}-3"), [("{$B}", "3")])
        # an address with colons of its own
        self.assertEqual(r.macros_became_values('last(/h/web.page.get["{$S}://{$H}:{$P}/x"])=0',
                                                'last(/h/web.page.get["http://[::1]:80/x"])=0'),
                         [("{$S}", "http"), ("{$H}", "[::1]"), ("{$P}", "80")])

    def test_many_macros_that_stayed_do_not_take_long(self):
        # one number changed in a trigger with a hundred macros: read once, not in every combination
        terms = "+".join(f"(last(/h/svc{n})={{$SVC.DOWN}})" for n in range(100))
        quoted = " or ".join(f'find(/h/log{n},,"like","{{$PATTERN}}")=1' for n in range(100))
        started = time.perf_counter()
        self.assertIsNone(r.macros_became_values(terms + ">=3", terms + ">=4"))
        self.assertIsNone(r.macros_became_values(quoted + " or 1=0", quoted + " or 1=1"))
        self.assertEqual(r.macros_became_values(terms + ">={$MIN}", terms + ">=4"), [("{$MIN}", "4")])
        self.assertLess(time.perf_counter() - started, 2)

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


class TestAMacroThatWentWithAnotherChange(unittest.TestCase):
    """What a model produces when it is asked to edit the expression and edits the expanded text."""

    EDIT = entry(1, "avg(/h/k,10m)>{$MAX}", "avg(/h/k,5m)>75")

    def test_it_is_no_expansion_and_is_still_seen(self):
        self.assertIsNone(r.macros_became_values(self.EDIT["old"], self.EDIT["new"]))
        self.assertEqual(r.macros_gone(self.EDIT["old"], self.EDIT["new"]), ["{$MAX}"])
        self.assertEqual(r.edited_away([self.EDIT], "avg(/h/k,5m)>75"), ("avg(/h/k,10m)>{$MAX}", ["{$MAX}"], r.MORE_THAN_THE_MACRO))
        self.assertEqual(r.decide([self.EDIT], "avg(/h/k,5m)>75")[0], "none")       # never written back by rule

    def test_one_macro_in_the_place_of_another_is_somebody_s_choice(self):
        # nothing but the macro differs
        self.assertEqual(r.macros_gone("last(/h/k)>{$A}", "last(/h/k)>{$B}"), [])
        self.assertEqual(r.macros_gone('last(/h/k)>{$A:"x"}', 'last(/h/k)>{$A:"y"}'), [])
        self.assertEqual(r.macros_gone("a>{$A} and b>{$B}", "a>{$B} and b>{$A}"), [])
        self.assertIsNone(r.edited_away([entry(1, "last(/h/k)>{$A}", "last(/h/k)>{$B}")], "last(/h/k)>{$B}"))

    def test_a_macro_that_went_while_another_came_is_not_that(self):
        # the model saw "a>1" and added a clause with a macro of its own: {$A} is lost, not replaced
        self.assertEqual(r.macros_gone("a>{$A}", "a>1 and b>{$B}"), ["{$A}"])
        self.assertEqual(r.edited_away([entry(1, "a>{$A}", "a>1 and b>{$B}")], "a>1 and b>{$B}")[:2], ("a>{$A}", ["{$A}"]))
        # as many macros as before, and the rest changed too: listed, for a person to see which it is
        self.assertEqual(r.macros_gone("last(/h/k)>{$A}", "last(/h/k2)>{$B}"), ["{$A}"])
        self.assertEqual(r.macros_gone("a>{$A} and b>{$A}", "a>{$A} and b>{$B} or c>1"), ["{$A}"])

    def test_one_of_the_two_places_a_macro_stood_in(self):
        edit = entry(1, "a>{$MAX} and b>{$MAX}", "a>75 and b2>{$MAX}")
        self.assertEqual(r.edited_away([edit], "a>75 and b2>{$MAX}")[:2], ("a>{$MAX} and b>{$MAX}", ["{$MAX}"]))
        self.assertIsNone(r.edited_away([edit], "a>{$MAX} and b2>{$MAX}"))          # typed back since
        self.assertIsNotNone(r.edited_away([edit], None))                           # before the trigger is read

    def test_each_macro_as_often_as_it_went(self):
        self.assertEqual(r.macros_gone("a>{$A} and b>{$A} and c>{$B}", "a>1 and b>2 or d>3"), ["{$A}", "{$A}", "{$B}"])

    def test_not_when_the_expression_has_the_macro_again(self):
        self.assertIsNone(r.edited_away([self.EDIT], "avg(/h/k,5m)>{$MAX}"))
        # and the newest such edit is the one that counts
        later = entry(2, "avg(/h/k,5m)>{$MIN} or 1", "avg(/h/k,5m)>5", "admin")
        self.assertEqual(r.edited_away([self.EDIT, later], "avg(/h/k,5m)>5")[1], ["{$MIN}"])

    def test_a_plain_expansion_is_the_other_case(self):
        # the run the decision is about is left to the decision
        plain = [entry(1, M, V)]
        self.assertEqual(r._newest_run(plain), (0, 0))
        self.assertIsNone(r.edited_away(plain, V, handled=(0, 0)))
        self.assertIsNone(r.edited_away(plain, M, handled=(0, 0)))

    def test_an_earlier_expansion_that_was_only_partly_repaired(self):
        # both macros lost; somebody typed {$A} back; {$A} lost again. The newest run is about {$A} only.
        entries = [entry(1, "a>{$A} and b>{$B}", "a>1 and b>2"),
                   entry(2, "a>1 and b>2", "a>{$A} and b>2", "admin"),
                   entry(3, "a>{$A} and b>2", "a>1 and b>2")]
        self.assertEqual(r._newest_run(entries), (2, 2))
        self.assertEqual(r.decide(entries, "a>1 and b>2"), ("restore", "a>{$A} and b>2", [("{$A}", "1")]))
        # against the expression as the restore leaves it: {$B} is still gone, {$A} is not
        self.assertEqual(r.edited_away(entries, "a>{$A} and b>2", handled=(2, 2)),
                         ("a>{$A} and b>{$B}", ["{$B}"], r.CHANGED_AFTERWARDS))
        # a macro that was back at some point since is not that update's loss any more
        back = entries + [entry(4, "a>1 and b>2", "a>{$A} and b>{$B}", "admin"), entry(5, "a>{$A} and b>{$B}", "a>{$A}", "admin")]
        self.assertIsNone(r.edited_away(back, "a>{$A}", user="mcp"))
        self.assertEqual(r.edited_away(back, "a>{$A}")[1:], (["{$B}"], r.MORE_THAN_THE_MACRO))       # the administrator's own edit

    def test_expansions_with_an_edit_between_them(self):
        entries = [entry(1, "a>{$A} and b>{$B}", "a>1 and b>{$B}"),
                   entry(2, "a>1 and b>{$B}", "a>1 and c>{$B}", "admin"),
                   entry(3, "a>1 and c>{$B}", "a>1 and c>2")]
        self.assertEqual(r.decide(entries, "a>1 and c>2")[:2], ("restore", "a>1 and c>{$B}"))
        self.assertEqual(r.edited_away(entries, "a>1 and c>{$B}", handled=r._newest_run(entries))[1:],
                         (["{$A}"], r.CHANGED_AFTERWARDS))

    def test_one_user_s_updates_only(self):
        self.assertIsNone(r.edited_away([dict(self.EDIT, user="admin")], "avg(/h/k,5m)>75", user="mcp"))
        self.assertIsNotNone(r.edited_away([self.EDIT], "avg(/h/k,5m)>75", user="mcp"))


class TestTheDecision(unittest.TestCase):
    def test_the_trace_of_the_bug_is_restored(self):
        self.assertEqual(r.decide([entry(1, M, V)], V), ("restore", M, [('{$MAX:"poller"}', "75")]))

    def test_macros_lost_in_two_steps(self):
        steps = [entry(1, "a>{$A} and b>{$B}", "a>1 and b>{$B}"), entry(2, "a>1 and b>{$B}", "a>1 and b>2")]
        self.assertEqual(r.decide(steps, "a>1 and b>2"), ("restore", "a>{$A} and b>{$B}", [("{$A}", "1"), ("{$B}", "2")]))

    def test_every_value_of_every_step_is_there_to_be_checked(self):
        # read as one change, "x>{$A}-{$B}" to "x>-5-3" does not say which number stood for which macro
        steps = [entry(1, "x>{$A}-{$B}", "x>{$A}-3", "admin"), entry(2, "x>{$A}-3", "x>-5-3")]
        self.assertEqual(r.decide(steps, "x>-5-3"), ("restore", "x>{$A}-{$B}", [("{$B}", "3"), ("{$A}", "-5")]))

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

    def test_macros_typed_back_in_an_edit_of_somebody_s_own(self):
        # lost, then edited, then the macro typed back into the edited expression: nothing is lost
        lost, edited = entry(1, "a>{$A}", "a>1"), entry(2, "a>1", "a>1 and c>0", "admin")
        back = entry(3, "a>1 and c>0", "a>{$A} and c>0", "admin")
        self.assertEqual(r.decide([lost, edited], "a>1 and c>0")[0], "changed since")
        self.assertEqual(r.decide([lost, edited, back], "a>{$A} and c>0")[0], "none")
        self.assertEqual(r.decide([lost, entry(2, "a>1", "a>{$A} and c>0", "admin")], "a>{$A} and c>0")[0], "none")
        self.assertIsNone(r.edited_away([lost, edited, back], "a>{$A} and c>0"))
        # also when it is there again only in the expression as it is now (an edit the log does not have)
        self.assertEqual(r.decide([lost], "a>{$A} and c>0")[0], "none")
        # one of two typed back is not all of them
        two = entry(1, "a>{$A} and b>{$B}", "a>1 and b>2")
        self.assertEqual(r.decide([two, entry(2, "a>1 and b>2", "a>{$A} and b>2 or c>0", "admin")], "a>{$A} and b>2 or c>0")[0],
                         "changed since")

    def test_a_trigger_changed_where_the_log_does_not_see_it_is_judged_by_what_it_has(self):
        # the log says the macro was typed back; the trigger has the value (the log was off, or the database was written)
        lost, back = entry(1, "a>{$A}", "a>1"), entry(2, "a>1", "a>{$A} and c>0", "admin")
        self.assertEqual(r.decide([lost, back], "a>{$A} and c>0")[0], "none")
        self.assertEqual(r.decide([lost, back], "a>1 and c>0")[0], "changed since")
        # the same behind an exact put-back
        self.assertEqual(r.decide([entry(1, M, V), entry(2, V, M, "admin")], V)[0], "changed since")
        # and for a macro that went in a larger edit
        edit, typed = entry(1, "avg(/h/k,10m)>{$A}", "avg(/h/k,5m)>1"), entry(2, "avg(/h/k,5m)>1", "avg(/h/k,5m)>{$A}", "admin")
        self.assertIsNone(r.edited_away([edit, typed], "avg(/h/k,5m)>{$A}"))
        self.assertEqual(r.edited_away([edit, typed], "avg(/h/k,5m)>1")[1], ["{$A}"])

    def test_what_has_its_macros_again_is_left(self):
        self.assertEqual(r.decide([entry(1, M, V), entry(2, V, M, "admin")], M)[0], "as before")
        self.assertEqual(r.decide([entry(1, M, V)], M)[0], "as before")

    def test_what_happened_after_the_macros_were_put_back_is_another_matter(self):
        back = entry(2, V, M, "admin")
        # an ordinary edit that keeps the macro: nothing to report
        kept = entry(3, M, 'avg(/h/k,5m)>{$MAX:"poller"}', "admin")
        self.assertEqual(r.decide([entry(1, M, V), back, kept], kept["new"])[0], "none")
        self.assertIsNone(r.edited_away([entry(1, M, V), back, kept], kept["new"]))
        # a larger edit that took the macro: for review, not "changed since" with an old expression
        took = entry(3, M, "avg(/h/k,5m)>75")
        self.assertEqual(r.decide([entry(1, M, V), back, took], took["new"])[0], "none")
        self.assertEqual(r.edited_away([entry(1, M, V), back, took], took["new"])[:2], (M, ['{$MAX:"poller"}']))

    def test_restored_and_lost_again(self):
        self.assertEqual(r.decide([entry(1, M, V), entry(2, V, M, "admin"), entry(3, M, V)], V)[:2], ("restore", M))

    def test_with_a_user_the_run_ends_at_somebody_else_s_update(self):
        # an administrator typed a number where {$A} was; the MCP server's user then lost {$B}
        theirs = entry(1, "a>{$A} and b>{$B}", "a>1 and b>{$B}", "admin")
        mine = entry(2, "a>1 and b>{$B}", "a>1 and b>2")
        self.assertEqual(r.decide([theirs, mine], "a>1 and b>2", "mcp"), ("restore", "a>1 and b>{$B}", [("{$B}", "2")]))
        # without a user, both are the trace of the bug
        self.assertEqual(r.decide([theirs, mine], "a>1 and b>2")[:2], ("restore", "a>{$A} and b>{$B}"))
        # the other way round: what somebody else did afterwards is a change made since
        mine = entry(1, "a>{$A} and b>{$B}", "a>1 and b>{$B}")
        theirs = entry(2, "a>1 and b>{$B}", "a>1 and b>2", "admin")
        self.assertEqual(r.decide([mine, theirs], "a>1 and b>2", "mcp")[:2], ("changed since", "a>{$A} and b>{$B}"))

    def test_no_loss_no_business(self):
        self.assertEqual(r.decide([entry(1, V, "avg(/h/k,10m)>80", "admin")], "avg(/h/k,10m)>80")[0], "none")
        self.assertEqual(r.decide([], V)[0], "none")

    def test_one_user_s_updates_only(self):
        self.assertEqual(r.decide([entry(1, M, V, "mcp")], V, user="mcp")[0], "restore")
        self.assertEqual(r.decide([entry(1, M, V, "admin")], V, user="mcp")[0], "none")


def macro_rows(pairs, hostid=None):
    """usermacro.get rows from (macro, value) pairs; a value of None is a secret."""
    return [dict({"macro": m, "type": "1"} if v is None else {"macro": m, "value": v, "type": "0"},
                 **({"hostid": hostid} if hostid else {})) for m, v in pairs]


def macros(*levels, global_=()):
    """MacroValues from levels (the trigger's hosts, their templates, ...): a level is the pairs
    of one host, or a dict hostid -> pairs."""
    return r.MacroValues([[row for hostid, pairs in (level.items() if isinstance(level, dict) else [("1", level)])
                           for row in macro_rows(pairs, hostid)] for level in levels], macro_rows(global_))


class TestTheValuesAreTheMacros(unittest.TestCase):
    VALUES = macros([("{$MAX}", "75"), ("{$S}", 'a "quoted" word'), ("{$SECRET}", None)], [("{$MAX}", "90")])

    def test_a_value_the_macro_has(self):
        self.assertTrue(r.values_are_the_macros([('{$MAX:"poller"}', "75")], self.VALUES))
        self.assertTrue(r.values_are_the_macros([("{$S}", 'a \\"quoted\\" word')], self.VALUES))     # escaped inside a string

    def test_the_host_s_macro_before_the_template_s_before_the_global_one(self):
        # 90 is what the template says; on this host the macro is 75
        self.assertFalse(r.values_are_the_macros([("{$MAX}", "90")], self.VALUES))
        self.assertTrue(r.values_are_the_macros([("{$MAX}", "90")], macros([], [("{$MAX}", "90")], global_=[("{$MAX}", "50")])))
        self.assertTrue(r.values_are_the_macros([("{$MAX}", "50")], macros(global_=[("{$MAX}", "50")])))
        self.assertFalse(r.values_are_the_macros([("{$MAX}", "50")], macros([], [("{$MAX}", "90")], global_=[("{$MAX}", "50")])))
        # a trigger on two hosts: the host with the lower ID is asked first, as in Zabbix
        both = macros({"10": [("{$MAX}", "75")], "11": [("{$MAX}", "90")]})
        self.assertEqual(both.of("{$MAX}"), {"75"})
        self.assertFalse(r.values_are_the_macros([("{$MAX}", "90")], both))
        self.assertEqual(macros({"10": [("{$MAX}", "75")], "9": [("{$MAX}", "60")]}).of("{$MAX}"), {"60"})
        self.assertEqual(macros({"10": [("{$OTHER}", "1")], "11": [("{$MAX}", "90")]}).of("{$MAX}"), {"90"})
        # a readable macro on the host is not hidden by a secret further up
        self.assertTrue(r.values_are_the_macros([("{$P}", "x")], macros([("{$P}", "x")], [("{$P}", None)])))
        self.assertFalse(r.values_are_the_macros([("{$P}", "x")], macros([("{$P}", None)], [("{$P}", "x")])))

    def test_the_macro_with_the_context_before_the_one_without(self):
        values = macros([("{$FS.MAX}", "80")], [('{$FS.MAX:"/var"}', "95"), ("{$FS.MAX:/tmp}", "70")])
        # 80 typed where {$FS.MAX:"/var"} stood is not that macro's value, though {$FS.MAX} has it
        self.assertFalse(r.values_are_the_macros([('{$FS.MAX:"/var"}', "80")], values))
        self.assertTrue(r.values_are_the_macros([('{$FS.MAX:"/var"}', "95")], values))
        self.assertTrue(r.values_are_the_macros([("{$FS.MAX:/var}", "95")], values))            # quoted or not
        self.assertTrue(r.values_are_the_macros([('{$FS.MAX:"/tmp"}', "70")], values))
        # a context nobody defined falls back to the nearest macro without one
        self.assertTrue(r.values_are_the_macros([('{$FS.MAX:"/home"}', "80")], values))
        self.assertFalse(r.values_are_the_macros([('{$FS.MAX:"/home"}', "95")], values))
        self.assertTrue(r.values_are_the_macros([('{$FS.MAX:"{#FSNAME}"}', "80")], values))
        # a global macro with the context comes before the host's macro without it
        global_first = macros([("{$FS.MAX}", "80")], global_=[('{$FS.MAX:"/var"}', "95"), ("{$FS.MAX}", "50")])
        self.assertEqual((global_first.of('{$FS.MAX:"/var"}'), global_first.of('{$FS.MAX:"/opt"}'), global_first.of("{$FS.MAX}")),
                         ({"95"}, {"80"}, {"80"}))
        self.assertEqual(macros(global_=[("{$FS.MAX}", "50")]).of('{$FS.MAX:"/var"}'), {"50"})
        self.assertEqual(macros([("{$OTHER}", "1")]).of('{$FS.MAX:"/var"}'), set())

    def test_a_context_given_as_a_regular_expression(self):
        values = macros([("{$FS.MAX}", "80"), ('{$FS.MAX:regex:"^/va"}', "95"), ("{$FS.MAX:regex:^/tmp$}", "70")])
        self.assertEqual((values.of('{$FS.MAX:"/var"}'), values.of("{$FS.MAX:/tmp}"), values.of('{$FS.MAX:"/opt"}'), values.of("{$FS.MAX}")),
                         ({"95"}, {"70"}, {"80"}, {"80"}))
        self.assertFalse(r.values_are_the_macros([('{$FS.MAX:"/opt"}', "95")], values))         # no expression matches /opt
        # on the host the expression counts before the template's macro with that very context
        self.assertEqual(macros([('{$FS.MAX:regex:"^/va"}', "95")], [('{$FS.MAX:"/var"}', "80")]).of('{$FS.MAX:"/var"}'), {"95"})
        # on one host the context itself comes first, and of two expressions the first by name
        self.assertEqual(macros([('{$FS.MAX:regex:"^/va"}', "95"), ('{$FS.MAX:"/var"}', "70")]).of('{$FS.MAX:"/var"}'), {"70"})
        self.assertEqual(macros([('{$FS.MAX:regex:"^/v"}', "1"), ('{$FS.MAX:regex:"^/"}', "2")]).of('{$FS.MAX:"/var"}'), {"2"})
        # what may read differently in PCRE is not guessed at: no value is confirmed
        for unreadable in ('"^[[:alpha:]/]+$"', '"("', '"^/v\\h"', '"^/vár"', '"^([a-z0-9/]+)+$"', '"^/v{,2}ar"',
                           '"^\\u002Fvar"', '"(?i)^/VAR"', '"^(?<p>/var)"', '"^(/v)\\1?ar"'):
            unknown = macros([("{$FS.MAX}", "80"), ("{$FS.MAX:regex:" + unreadable + "}", "95")])
            self.assertIsNone(unknown.of('{$FS.MAX:"/var"}'), unreadable)
            self.assertFalse(r.values_are_the_macros([('{$FS.MAX:"/var"}', "95")], unknown))
            self.assertFalse(r.values_are_the_macros([('{$FS.MAX:"/var"}', "80")], unknown))
            self.assertEqual(unknown.of("{$FS.MAX}"), {"80"})                                   # without a context none is asked

    def test_what_reads_the_same_in_both_is_evaluated(self):
        for readable, context, matches in (('"^/(var|tmp)(/|$)"', "/var/log", True), ('"^/(var|tmp)(/|$)"', "/variable", False),
                                           ('"^eth[0-9]+$"', "eth12", True), ('"\\.log$"', "a.log", True), ('"\\.log$"', "alog", False),
                                           ("^C:\\\\", "C:\\x", True), ('"^(?:sd|vd)[a-z]\\d*$"', "sda1", True),
                                           ('"a\\(b\\)+"', "a(b))", True), ('"^/v\\\\d"', "/v\\d", True),
                                           ('"^\\w+\\s\\w+$"', "two words", True), ('"^(?!lo$)"', "lo", False)):
            values = macros([("{$M}", "80"), ("{$M:regex:" + readable + "}", "95")])
            self.assertEqual(values.of('{$M:"' + context + '"}'), {"95"} if matches else {"80"}, (readable, context))

    def test_a_secret_and_a_vault_macro_are_never_expanded_to_their_value(self):
        # Zabbix puts a mask there; a value where the macro stood was typed by somebody
        vault = r.MacroValues([[{"hostid": "1", "macro": "{$V}", "value": "secret/path:key", "type": "2"},
                                {"hostid": "1", "macro": "{$S}", "type": "1"}]])
        self.assertIsNone(vault.of("{$V}"))
        self.assertIsNone(vault.of("{$S}"))
        self.assertFalse(r.values_are_the_macros([("{$V}", "secret/path:key")], vault))

    def test_a_context_is_read_as_zabbix_reads_it(self):
        self.assertEqual(r._macro_parts("{$M}"), ("M", None, False))
        self.assertEqual(r._macro_parts('{$M: "a b" }'), ("M", "a b", False))
        self.assertEqual(r._macro_parts("{$M: a b }"), ("M", "a b ", False))                    # unquoted: as it stands
        self.assertEqual(r._macro_parts('{$M:"say \\"x\\""}'), ("M", 'say "x"', False))
        self.assertEqual(r._macro_parts('{$M:"C:\\x"}'), ("M", "C:\\x", False))                # only \" is an escape
        self.assertEqual(r._macro_parts("{$M:C:\\x}"), ("M", "C:\\x", False))
        # "regex:" makes a regular expression where the macro is defined; in an expression it is context
        self.assertEqual(r._macro_parts('{$M: regex:"^a"}', definition=True), ("M", "^a", True))
        self.assertEqual(r._macro_parts('{$M:regex:"^a"}'), ("M", 'regex:"^a"', False))
        self.assertEqual(macros([("{$M}", "80"), ('{$M:regex:"x"}', "95")]).of('{$M:regex:"^/v"}'), {"95"})    # "regex" has an x
        self.assertEqual(r._macro_parts("{$M:}"), ("M", "", False))
        self.assertIsNone(r._macro_parts("{HOST.NAME}"))
        # the same macro, quoted in the trigger and unquoted where it is defined
        values = macros([("{$M:C:\\x}", "95"), ("{$M}", "80")])
        self.assertEqual(values.of('{$M:"C:\\x"}'), {"95"})

    def test_a_macro_inside_a_string_of_the_expression(self):
        # there its quotes are escaped; it is the macro {$W:"offline"}
        old, new = 'count(/h/k,#1,"eq","{$W:\\"offline\\"}")=1', 'count(/h/k,#1,"eq","2")=1'
        pairs = r.macros_became_values(old, new)
        self.assertEqual(pairs, [('{$W:"offline"}', "2")])
        self.assertTrue(r.values_are_the_macros(pairs, macros([('{$W:"offline"}', "2"), ("{$W}", "9")])))
        self.assertFalse(r.values_are_the_macros(pairs, macros([('{$W:"offline"}', "3"), ("{$W}", "2")])))

    def test_the_levels_are_read_from_zabbix(self):
        # host 10 -> template 20 -> template 30, and the global macros
        zabbix = FakeZabbix(macros=[{"hostid": "30", "macro": "{$A}", "value": "3", "type": "0"},
                                    {"hostid": "20", "macro": "{$A}", "value": "2", "type": "0"},
                                    {"hostid": "30", "macro": "{$B}", "value": "30", "type": "0"},
                                    {"hostid": "10", "macro": "{$C}", "type": "1"}],
                            global_macros=[{"macro": "{$A}", "value": "0", "type": "0"}, {"macro": "{$G}", "value": "g", "type": "0"}],
                            parents={"10": ["20"], "20": ["30"]})
        values = r.macro_values(zabbix.call, ["10"])
        self.assertEqual((values.of("{$A}"), values.of("{$B}"), values.of("{$C}"), values.of("{$G}"), values.of("{$NONE}")),
                         ({"2"}, {"30"}, None, {"g"}, set()))
        self.assertEqual(r.macro_values(zabbix.call, ["20"]).of("{$A}"), {"2"})
        self.assertEqual(r.macro_values(zabbix.call, ["30"]).of("{$A}"), {"3"})
        self.assertEqual(r.macro_values(zabbix.call, []).of("{$A}"), {"0"})

    def test_a_value_it_does_not_have_is_somebody_s_number(self):
        self.assertFalse(r.values_are_the_macros([("{$MAX}", "91")], self.VALUES))
        self.assertFalse(r.values_are_the_macros([("{$MAX}", "75"), ("{$MAX}", "91")], self.VALUES))
        self.assertFalse(r.values_are_the_macros([("{$B}", "3"), ("{$A}", "-5")], macros([("{$A}", "-5"), ("{$B}", "9")])))

    def test_a_secret_or_an_unknown_macro_cannot_be_confirmed(self):
        self.assertFalse(r.values_are_the_macros([("{$SECRET}", "x")], self.VALUES))
        self.assertFalse(r.values_are_the_macros([("{$GONE}", "1")], self.VALUES))


class FakeZabbix:
    """auditlog.get with paging, the triggers as stored, macros, and a record of what was written."""

    def __init__(self, audit=(), triggers=(), prototypes=(), macros=(), global_macros=(), parents=None, users=("mcp", "admin")):
        self.audit = sorted(audit, key=lambda a: (a["clock"], a["auditid"]))
        self.rows = {"trigger.get": {t["triggerid"]: t for t in triggers},
                     "triggerprototype.get": {t["triggerid"]: t for t in prototypes}}
        self.macros, self.global_macros, self.parents = list(macros), list(global_macros), parents or {}
        self.written: list[tuple[str, dict]] = []
        self.users = list(users)
        self.pages = 0
        self.pieces: dict[str, dict] = {}

    def call(self, method, params):
        if method == "auditlog.get":
            self.pages += 1
            assert params["sortfield"] == ["clock", "auditid"] and params["sortorder"] == "ASC"
            rows = [a for a in self.audit if params["time_from"] <= a["clock"] <= params.get("time_till", a["clock"])]
            return rows[:params["limit"]] if "limit" in params else rows
        if method in self.rows:
            if "selectFunctions" in params:      # the pieces the stored form is rebuilt from
                return [dict(self.pieces[i], triggerid=i) for i in params["triggerids"] if i in self.pieces]
            return [dict(self.rows[method][i]) for i in params["triggerids"] if i in self.rows[method]]
        if method in ("host.get", "template.get"):
            key = "hostids" if method == "host.get" else "templateids"
            idf = "hostid" if method == "host.get" else "templateid"
            return [{idf: i, "parentTemplates": [{"templateid": p} for p in self.parents.get(i, [])]} for i in params[key]]
        if method == "usermacro.get":
            if params.get("globalmacro"):
                return list(self.global_macros)
            return [m for m in self.macros if m["hostid"] in params["hostids"]]
        if method == "user.get":
            return [{"userid": str(n)} for n, name in enumerate(self.users, 1) if name == params["filter"]["username"]]
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

    def test_a_macro_that_went_in_a_larger_edit_is_listed_and_never_written(self):
        # until v1.42 this ended with "No trigger ... is without a user macro" and exit 0
        zabbix = FakeZabbix([audit(1, "1", "avg(/h/k,10m)>{$MAX}", "avg(/h/k,5m)>75")], [trigger("1", "avg(/h/k,5m)>75")], macros=self.MACROS)
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("REVIEW", text)
        self.assertIn("{$MAX} went in an update that changed more than the macro", text)
        self.assertIn("before: avg(/h/k,10m)>{$MAX}", text)
        self.assertNotIn("No trigger or trigger prototype is without", text)
        self.assertIn("0 restored, 1 left (SKIPPED and REVIEW are yours to look at)", text)

    def test_a_larger_edit_and_a_plain_expansion_in_the_same_field(self):
        # the edit took {$A} and left {$B}; then {$B} was expanded. Restoring {$B} must not hide {$A}.
        edited = "a2>1 and b>{$B}"
        zabbix = FakeZabbix([audit(1, "1", "a>{$A} and b>{$B}", edited), audit(2, "1", edited, "a2>1 and b>2")],
                            [trigger("1", "a2>1 and b>2")],
                            macros=[{"hostid": "10", "macro": "{$A}", "value": "1", "type": "0"},
                                    {"hostid": "10", "macro": "{$B}", "value": "2", "type": "0"}])
        left, text = self._run(zabbix, restore=True)
        self.assertEqual(zabbix.written, [("trigger.update", {"triggerid": "1", "expression": edited})])
        self.assertIn("{$A} went in an update that changed more than the macro", text)
        self.assertEqual(left, 1)
        self.assertIn("1 restored, 1 left", text)
        # and it is still said on the next run, when {$B} is back
        zabbix = FakeZabbix([audit(1, "1", "a>{$A} and b>{$B}", edited), audit(2, "1", edited, "a2>1 and b>2"),
                             audit(3, "1", "a2>1 and b>2", edited, user="admin")], [trigger("1", edited)])
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("{$A} went in an update", text)

    def test_with_a_user_another_user_s_number_is_not_taken_back(self):
        audits = [audit(1, "1", "a>{$A} and b>{$B}", "a>1 and b>{$B}", user="admin"),
                  audit(2, "1", "a>1 and b>{$B}", "a>1 and b>2")]
        macros = [{"hostid": "10", "macro": "{$A}", "value": "1", "type": "0"},
                  {"hostid": "10", "macro": "{$B}", "value": "2", "type": "0"}]
        zabbix = FakeZabbix(audits, [trigger("1", "a>1 and b>2")], macros=macros)
        left, text = self._run(zabbix, restore=True, user="mcp")
        self.assertEqual(zabbix.written, [("trigger.update", {"triggerid": "1", "expression": "a>1 and b>{$B}"})])
        self.assertEqual(left, 0)
        self.assertNotIn("{$A}", text.split("before:")[1])

    def test_a_macro_lost_next_to_one_that_was_added_is_listed(self):
        zabbix = FakeZabbix([audit(1, "1", "a>{$A}", "a>1 and b>{$B}")], [trigger("1", "a>1 and b>{$B}")])
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("{$A} went in an update that changed more than the macro", text)
        # one macro in the place of another, nothing else: not listed
        zabbix = FakeZabbix([audit(1, "1", "a>{$A}", "a>{$B}")], [trigger("1", "a>{$B}")])
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (0, []))
        self.assertIn("No trigger or trigger prototype is without", text)

    def test_one_of_two_places_of_the_same_macro_is_listed(self):
        now = "a>75 and b2>{$MAX}"
        zabbix = FakeZabbix([audit(1, "1", "a>{$MAX} and b>{$MAX}", now)], [trigger("1", now)])
        left, text = self._run(zabbix)
        self.assertEqual(left, 1)
        self.assertIn("{$MAX} went in an update", text)

    def test_a_macro_lost_earlier_is_named_next_to_the_restore_of_a_later_one(self):
        audits = [audit(1, "1", "a>{$A} and b>{$B}", "a>1 and b>2"),
                  audit(2, "1", "a>1 and b>2", "a>{$A} and b>2", user="admin"),
                  audit(3, "1", "a>{$A} and b>2", "a>1 and b>2")]
        values = [{"hostid": "10", "macro": "{$A}", "value": "1", "type": "0"},
                  {"hostid": "10", "macro": "{$B}", "value": "2", "type": "0"}]
        for user in (None, "mcp"):
            zabbix = FakeZabbix(audits, [trigger("1", "a>1 and b>2")], macros=values)
            left, text = self._run(zabbix, restore=True, user=user)
            self.assertEqual(zabbix.written, [("trigger.update", {"triggerid": "1", "expression": "a>{$A} and b>2"})])
            self.assertIn("{$B} went in an earlier update, and the expression was changed again afterwards", text)
            self.assertIn("1 restored, 1 left", text)
            # the next run: {$A} is back, {$B} is still named
            zabbix = FakeZabbix(audits + [audit(4, "1", "a>1 and b>2", "a>{$A} and b>2")], [trigger("1", "a>{$A} and b>2")],
                                macros=values)
            left, text = self._run(zabbix, restore=True, user=user)
            self.assertEqual((left, zabbix.written), (1, []))
            self.assertIn("{$B} went in an earlier update", text)

    def test_a_value_of_an_earlier_step_that_is_not_the_macro_s(self):
        audits = [audit(1, "1", "x>{$A}-{$B}", "x>{$A}-3", user="admin"), audit(2, "1", "x>{$A}-3", "x>-5-3")]
        zabbix = FakeZabbix(audits, [trigger("1", "x>-5-3")],
                            macros=[{"hostid": "10", "macro": "{$A}", "value": "-5", "type": "0"},
                                    {"hostid": "10", "macro": "{$B}", "value": "9", "type": "0"}])
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("not restored: the values written are not the values these macros have now", text)

    def test_a_number_that_another_macro_of_that_name_has_is_not_restored(self):
        # 80 typed where {$FS.MAX:"/var"} (95) stood; {$FS.MAX} is 80. Restoring would move the threshold to 95.
        old, new = 'last(/h/vfs.fs.pused[/var])>{$FS.MAX:"/var"}', "last(/h/vfs.fs.pused[/var])>80"
        values = [{"hostid": "10", "macro": '{$FS.MAX:"/var"}', "value": "95", "type": "0"},
                  {"hostid": "10", "macro": "{$FS.MAX}", "value": "80", "type": "0"}]
        zabbix = FakeZabbix([audit(1, "1", old, new)], [trigger("1", new)], macros=values)
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("REVIEW", text)
        # the same for the host's own macro over its template's: 90 typed, the host has 75
        zabbix = FakeZabbix([audit(1, "1", "a>{$CPU.MAX}", "a>90")], [trigger("1", "a>90")], parents={"10": ["20"]},
                            macros=[{"hostid": "10", "macro": "{$CPU.MAX}", "value": "75", "type": "0"},
                                    {"hostid": "20", "macro": "{$CPU.MAX}", "value": "90", "type": "0"}])
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        # and what the expansion did leave is restored
        zabbix = FakeZabbix([audit(1, "1", old, old.replace('{$FS.MAX:"/var"}', "95"))],
                            [trigger("1", old.replace('{$FS.MAX:"/var"}', "95"))], macros=values)
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (0, [("trigger.update", {"triggerid": "1", "expression": old})]))

    def test_the_lines_are_about_the_right_update_and_the_right_field(self):
        # an administrator's edit long before; with --user the date is that of the user's own first update
        early = audit(1, "1", "a>{$OLD}", "a>{$A}", user="admin", clock=NOW - 40 * 86400)
        zabbix = FakeZabbix([early, audit(2, "1", "a>{$A}", "a2>1", clock=NOW - 3600)], [trigger("1", "a2>1")])
        stamp = lambda clock: r.datetime.fromtimestamp(clock).strftime("%Y-%m-%d %H:%M")   # noqa: E731
        self.assertIn(f"(first changed {stamp(NOW - 3600)})", self._run(zabbix, user="mcp")[1])
        self.assertIn(f"(first changed {stamp(NOW - 40 * 86400)})", self._run(zabbix)[1])
        # SKIPPED names the earlier expression of the field that was changed since, not of the other one
        audits = [audit(1, "1", M, V), audit(2, "1", "max(/h/k,10m)<{$MIN}", "max(/h/k,10m)<65", field="recovery_expression"),
                  audit(3, "1", "max(/h/k,10m)<65", "max(/h/k,10m)<60", field="recovery_expression", user="admin")]
        zabbix = FakeZabbix(audits, [trigger("1", V, recovery="max(/h/k,10m)<60")], macros=self.MACROS)
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("it had: max(/h/k,10m)<{$MIN}", text)

    def test_a_macro_the_log_has_back_and_the_trigger_has_not(self):
        audits = [audit(1, "1", "a>{$A}", "a>1"), audit(2, "1", "a>1", "a>{$A} and c>0", user="admin")]
        zabbix = FakeZabbix(audits, [trigger("1", "a>1 and c>0")])
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("SKIPPED", text)
        # as the log says: nothing to report
        zabbix = FakeZabbix(audits, [trigger("1", "a>{$A} and c>0")])
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (0, []))
        self.assertIn("No trigger or trigger prototype is without", text)
        # a trigger that is gone is mentioned when the log alone says something was lost, not otherwise
        self.assertIn("gone", self._run(FakeZabbix(audits[:1], []))[1])
        self.assertNotIn("gone", self._run(FakeZabbix(audits, []))[1])

    def test_a_user_zabbix_does_not_have_is_not_an_all_clear(self):
        zabbix = FakeZabbix([audit(1, "1", M, V)], [trigger("1", V)], macros=self.MACROS)
        with self.assertRaises(r.NobodyByThatName) as refused:
            self._run(zabbix, restore=True, user="Mcp")
        self.assertIn("Zabbix has no user 'Mcp' (triggers were updated in that time by: mcp)", str(refused.exception))
        self.assertEqual(zabbix.written, [])
        # a user Zabbix has, who updated no trigger: that is an answer
        zabbix = FakeZabbix([audit(1, "1", M, V)], [trigger("1", V)], macros=self.MACROS, users=("mcp", "reader"))
        left, text = self._run(zabbix, restore=True, user="reader")
        self.assertEqual((left, zabbix.written), (0, []))
        self.assertIn("updates by reader", text)
        self.assertIn("'reader' updated no trigger in that time (triggers were updated in that time by: mcp)", text)
        # and one who has left since is still in the log
        zabbix = FakeZabbix([audit(1, "1", M, V, user="gone")], [trigger("1", V)], macros=self.MACROS)
        left, text = self._run(zabbix, user="gone")
        self.assertEqual(left, 1)

    def test_a_trigger_counts_once_whatever_is_said_about_it(self):
        # one field skipped, the other with a larger edit
        zabbix = FakeZabbix([audit(1, "1", M, V), audit(2, "1", V, "avg(/h/k,10m)>80", user="admin"),
                             audit(3, "1", "avg(/h/k,10m)<{$MIN}", "avg(/h/k,5m)<65", field="recovery_expression")],
                            [trigger("1", "avg(/h/k,10m)>80", recovery="avg(/h/k,5m)<65")], macros=self.MACROS)
        left, text = self._run(zabbix)
        self.assertEqual(left, 1)
        self.assertIn("SKIPPED", text)
        self.assertIn("{$MIN} went in an update", text)

    def test_a_larger_edit_after_an_earlier_loss_was_repaired(self):
        zabbix = FakeZabbix([audit(1, "1", M, V), audit(2, "1", V, M, user="admin"), audit(3, "1", M, "avg(/h/k,5m)>75")],
                            [trigger("1", "avg(/h/k,5m)>75")], macros=self.MACROS)
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("REVIEW", text)
        self.assertIn("went in an update that changed more than the macro", text)
        self.assertFalse(any(line.startswith("  SKIPPED") for line in text.splitlines()))

    def test_such_an_edit_on_an_inherited_trigger_is_its_template_s(self):
        zabbix = FakeZabbix([audit(1, "2", "avg(/h/k,10m)>{$MAX}", "avg(/h/k,5m)>75")],
                            [trigger("2", "avg(/h/k,5m)>75", templateid="1")], macros=self.MACROS)
        left, text = self._run(zabbix)
        self.assertEqual(left, 0)
        self.assertNotIn("REVIEW", text)

    def test_the_expression_as_zabbix_stores_it_is_rebuilt_before_it_is_compared(self):
        # trigger.get returns {functionid}; the audit log has the written-out form
        zabbix = FakeZabbix([audit(1, "1", "avg(/h/k,10m)>{$MAX:\"poller\"}", "avg(/h/k,10m)>75")],
                            [trigger("1", "{501}>75")], macros=self.MACROS)
        zabbix.pieces["1"] = {"functions": [{"functionid": "501", "itemid": "9", "function": "avg", "parameter": "$,10m"}],
                              "items": [{"itemid": "9", "hostid": "10", "key_": "k"}], "hosts": [{"hostid": "10", "host": "h"}]}
        left, text = self._run(zabbix, restore=True)
        self.assertEqual(left, 0)
        self.assertEqual(zabbix.written, [("trigger.update", {"triggerid": "1", "expression": M})])
        # and a trigger whose pieces are missing keeps the stored form: it matches nothing and is left alone
        zabbix = FakeZabbix([audit(1, "1", M, V)], [trigger("1", "{501}>75")], macros=self.MACROS)
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("SKIPPED", text)

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
        # a trigger prototype made by a nested discovery rule (flags 6) follows its prototype too
        zabbix = FakeZabbix([audit(1, "7", M, V, kind="triggerprototype"), audit(2, "8", M, V, kind="triggerprototype"),
                             audit(3, "8", V, "avg(/h/k,5m)>75", kind="triggerprototype")],
                            prototypes=[trigger("7", V, flags="6"), trigger("8", "avg(/h/k,5m)>75", flags="6")], macros=self.MACROS)
        left, text = self._run(zabbix, restore=True)
        self.assertEqual((left, zabbix.written), (1, []))
        self.assertIn("discovered  triggerprototype 7", text)

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

    def test_more_updates_in_one_second_than_a_page_holds(self):
        # until v1.42 the rows of that second beyond the page were passed over
        for count in (r.PAGE, r.PAGE + 5, 2 * r.PAGE + 500):
            rows = [audit(n, str(n), M, V, clock=NOW - 100) for n in range(1, count + 1)] + [audit(99999, "last", M, V, clock=NOW - 50)]
            zabbix = FakeZabbix(rows)
            changes = r.read_changes(zabbix.call, days=1)
            self.assertEqual(len(changes), count + 1, count)
            self.assertLess(zabbix.pages, 6, count)

    def test_the_order_within_a_second_is_the_order_of_the_ids(self):
        rows = [audit(2, "1", V, "avg(/h/k,10m)>80", clock=NOW - 10, user="admin"), audit(1, "1", M, V, clock=NOW - 10)]
        changes = r.read_changes(FakeZabbix(rows).call, days=1)
        self.assertEqual([e["new"] for e in changes[(13, "1")]["expression"]], [V, "avg(/h/k,10m)>80"])

    def test_details_that_are_not_what_is_expected_are_skipped(self):
        rows = [audit(1, "1", M, V), dict(audit(2, "2", M, V), details="not json"),
                dict(audit(3, "3", M, V), details=json.dumps({"trigger.expression": ["add", V]})),
                dict(audit(4, "4", M, V), details=json.dumps({"trigger.priority": ["update", "3", "2"]})),
                dict(audit(5, "5", M, V), details="[]"), dict(audit(6, "6", M, V), details="null"),
                dict(audit(7, "7", M, V), details='"text"')]
        self.assertEqual(list(r.read_changes(FakeZabbix(rows).call, days=1)), [(13, "1")])


class TestTheScriptItself(unittest.TestCase):
    def test_it_compiles_without_a_warning(self):
        # an invalid escape in a docstring is a SyntaxWarning the first time the script runs on a server
        source = (ROOT / "scripts" / "restore_trigger_macros.py").read_text(encoding="utf-8")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(source, "restore_trigger_macros.py", "exec")


class TestTheCommandLine(unittest.TestCase):
    """An option that is not taken in must stop the script: without ``--user`` the restore
    goes over everybody's updates."""

    def _refused(self, *argv):
        with self.assertRaises(SystemExit) as stopped, contextlib.redirect_stderr(io.StringIO()) as said:
            r.arguments(list(argv))
        self.assertEqual(stopped.exception.code, 2, argv)
        return said.getvalue()

    def test_both_ways_of_writing_an_option(self):
        for argv in (["http://z", "token", "--user", "mcp", "--days", "7", "--restore"],
                     ["--user=mcp", "--days=7", "--restore", "http://z", "token"],
                     ["http://z", "--restore", "token", "--user=mcp", "--days=7"]):
            args = r.arguments(argv)
            self.assertEqual((args.url, args.credentials, args.user, args.days, args.restore),
                             ("http://z", ["token"], "mcp", 7, True), argv)
        args = r.arguments(["http://z", "Admin", "secret"])
        self.assertEqual((args.credentials, args.user, args.days, args.restore), (["Admin", "secret"], None, 60, False))

    def test_what_it_does_not_know_it_refuses(self):
        self.assertIn("--usr", self._refused("http://z", "token", "--usr", "mcp", "--restore"))
        self._refused("http://z", "token", "--restor")              # no guessing at abbreviations
        self._refused("http://z", "token", "--use=mcp")
        self._refused("http://z", "token", "--user")                # the name is missing
        self._refused("http://z", "token", "--days")
        self._refused("http://z", "token", "--days", "x")
        self._refused("http://z", "token", "--days", "0")
        self._refused("http://z")                                   # no credentials
        self._refused("http://z", "a", "b", "c")

    def test_an_error_is_not_something_left(self):
        # exit status 1 says "something is left to restore"; Zabbix not answering is not that
        def unreachable():
            raise ConnectionError("no route to http://z")
        real, r.main = r.main, unreachable
        try:
            with contextlib.redirect_stderr(io.StringIO()) as said:
                self.assertEqual(r._main(), 2)
        finally:
            r.main = real
        self.assertIn("stopped, ConnectionError: no route to http://z", said.getvalue())


if __name__ == "__main__":
    unittest.main()
