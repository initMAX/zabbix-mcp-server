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

"""What a client keeps of a tool description, and what the description says
the server drops from a write.

Two things found while checking 1.42: ``ceprule_create`` had grown to 2575
characters, and clients cut a tool description at 2048; and the sentence
about the keys dropped before a write named ``groups`` and ``tags`` for
``host.update``, although only keys inside their rows are dropped.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zabbix_mcp.api import write_contracts as wc  # noqa: E402
from zabbix_mcp.client import ClientManager  # noqa: E402
from zabbix_mcp.config import AppConfig, ServerConfig, ZabbixServerConfig  # noqa: E402
from zabbix_mcp.server import (  # noqa: E402
    _DESCRIPTION_KEPT, ZabbixMCPServer, _annotate_tools_by_version, _register_tools,
)

RELEASES = ("6.0.48", "6.2.9", "6.4.21", "7.0.30", "7.2.15", "7.4.14", "8.0.0")


def _server(names=("t",), **kwargs):
    cfg = AppConfig(server=ServerConfig(timezone="UTC"),
                    zabbix_servers={n: ZabbixServerConfig(name=n, url="http://localhost", api_token="x", read_only=False)
                                    for n in names})
    mgr = ClientManager(cfg)
    mcp = ZabbixMCPServer(name="test")
    _register_tools(mcp, mgr, **kwargs)
    return mgr, mcp._tool_manager.list_tools()


TOOLS = {t.name: t for t in _server()[1]}


class TestNothingIsCut(unittest.TestCase):
    def test_no_tool_description_is_longer_than_a_client_keeps(self):
        for kwargs in ({}, {"schema_constraints": False}, {"compact_output": False}):
            for tool in _server(**kwargs)[1]:
                self.assertLessEqual(len((tool.description or "").encode()), _DESCRIPTION_KEPT, (tool.name, kwargs))

    def test_nor_with_the_note_tools_list_adds_for_a_mixed_pair_of_servers(self):
        # a 7.4 server next to an 8.0 one: every 8.0 tool gets "not on ...",
        # every tool 8.0 removed or deprecated the other half
        for names, versions in ((("production", "staging"), ("7.4.14", "8.0.0")),
                                (("zabbix-datacenter-prague-01", "zabbix-datacenter-brno-02", "lab"), ("6.0.48", "7.0.30", "8.0.0"))):
            mgr, tools = _server(names)
            mgr._versions.update(dict(zip(names, versions)))
            noted = 0
            for tool in _annotate_tools_by_version(tools, mgr):
                text = tool.description or ""
                noted += "Zabbix version note:" in text
                self.assertLessEqual(len(text.encode()), _DESCRIPTION_KEPT, (tool.name, names))
            self.assertGreater(noted, 20, names)

    def test_a_note_that_would_be_cut_goes_first(self):
        mgr, tools = _server(("old", "new"))
        mgr._versions.update({"old": "7.4.14", "new": "8.0.0"})
        by_name = {t.name: t for t in tools}
        note = "Zabbix version note: not on 'old' - ceprule.create requires Zabbix 8.0 or later (this server runs 7.4.14)."
        usual = {t.name: t for t in _annotate_tools_by_version(tools, mgr)}["ceprule_create"].description
        self.assertTrue(usual.endswith(note))
        long_tool = by_name["ceprule_create"].model_copy(update={"description": "x" * 2000})
        text = _annotate_tools_by_version([long_tool], mgr)[0].description
        self.assertTrue(text.startswith(note + "\n\n"))
        self.assertTrue(text.endswith("x" * 2000))

    def test_the_cep_rules_that_left_the_description_are_in_params(self):
        tool = TOOLS["ceprule_create"]
        params = tool.parameters["properties"]["params"]["description"]
        self.assertIn("are in the description of 'params'", tool.description)
        for text in ("37 host group name (host_group_name)", "What goes together in 'operations'",
                     "grouped by execute_when in the order 0, 1, 2, 5, 3, 4", "a pattern match (4) takes all six",
                     "the event flags 30 problem opened", "an operation with execute_when 0 takes neither 31 nor 32"):
            self.assertIn(text, params)
            self.assertNotIn(text, tool.description)
        # the update tool takes any object: it keeps its own text whole
        for text in ("37 host group name (host_group_name)", "the event flags 30 problem opened"):
            self.assertIn(text, TOOLS["ceprule_update"].description)
        # what a rule is made of stays where the tool is chosen
        for text in ("18 close window", "5 event closed", "2 all events of the window", "4 pattern match"):
            self.assertIn(text, tool.description)
        # room for the note of a server below 8.0
        self.assertLessEqual(len(tool.description.encode()), _DESCRIPTION_KEPT - 300)


def _listed(method: str) -> dict:
    """The four lists of the sentence, as written."""
    text = wc.describe(method)
    out = {"always": [], "inside": [], "dated": [], "twins": []}
    for part in text[text.index("(") + 1:text.rindex(")")].split("; "):
        if part.startswith("inside "):
            out["inside"] = part[len("inside "):].replace(" only the keys refused there", "").split(", ")
        elif " on the releases that refuse " in part:
            out["dated"] = part.split(" on the releases that refuse ")[0].split(", ")
        elif " next to " in part:
            out["twins"] = [tuple(p.split(" next to ")) for p in part.split(", ")]
        else:
            out["always"] = part.split(", ")
    for key in ("always", "inside", "dated"):
        out[key] = [n for n in out[key] if n != "..."]
    return out


def _dropped_alone(method: str, key: str, release: str) -> bool:
    payload = {key: "x"}
    wc.strip_for_write(method, payload, release)
    return key not in payload


class TestWhatTheServerDrops(unittest.TestCase):
    """The sentence against what ``strip_for_write`` does, release by release."""

    def test_every_sentence_is_what_the_server_does(self):
        for method in wc.WRITE_CONTRACTS:
            listed = _listed(method)
            self.assertTrue(any(listed.values()), method)
            for key in listed["always"]:
                for release in RELEASES + (None,):
                    self.assertTrue(_dropped_alone(method, key, release), (method, key, release))
            for key in listed["inside"]:
                # the key itself is sent, on every release
                for release in RELEASES:
                    for value in ([], {}, [{"x": "y"}]):
                        payload = {key: value}
                        wc.strip_for_write(method, payload, release)
                        self.assertIn(key, payload, (method, key, release))
            for key in listed["dated"]:
                # not everywhere: an unmeasured release keeps it
                self.assertFalse(_dropped_alone(method, key, None), (method, key))
            for key, twin in listed["twins"]:
                for release in RELEASES:
                    self.assertFalse(_dropped_alone(method, key, release), (method, key, release))
                dropped_next_to = []
                for release in RELEASES:
                    payload = {key: "x", twin: "y"}
                    wc.strip_for_write(method, payload, release)
                    dropped_next_to.append(key not in payload)
                self.assertTrue(any(dropped_next_to), (method, key, twin))

    def test_no_dropped_key_is_left_out_of_the_sentence(self):
        for method, rules in wc.WRITE_CONTRACTS.items():
            listed = _listed(method)
            named = set(listed["always"]) | set(listed["inside"]) | set(listed["dated"]) | {k for k, _ in listed["twins"]}
            heads = {r.path[0].rstrip("[]") for r in rules}
            if "..." in wc.describe(method):
                self.assertTrue(named <= heads, method)
            else:
                self.assertEqual(named, heads, method)

    def test_the_cases_that_were_wrong(self):
        host = _listed("host.update")
        self.assertEqual(host["inside"], ["groups", "interfaces", "macros", "tags"])
        self.assertNotIn("groups", host["always"])
        # rights alone is a way to give a user group its rights: it is sent
        self.assertEqual(_listed("usergroup.update")["twins"], [("rights", "hostgroup_rights")])
        self.assertEqual(_listed("mediatype.update")["twins"], [("content_type", "message_format")])
        # a template group keeps its uuid on 7.0 and later
        self.assertIn("uuid", _listed("templategroup.update")["dated"])
        self.assertFalse(_dropped_alone("templategroup.update", "uuid", "8.0.0"))
        self.assertEqual(_listed("dashboard.update"), {"always": ["uuid"], "inside": [], "dated": [], "twins": []})

    def test_the_tools_carry_the_sentence(self):
        self.assertIn("inside groups, interfaces, macros, tags only the keys refused there",
                      TOOLS["host_update"].description)
        self.assertIn("rights next to hostgroup_rights", TOOLS["usergroup_update"].description)
        self.assertIn("dashboard.update refuses (uuid).", TOOLS["dashboard_update"].description)


if __name__ == "__main__":
    unittest.main()
