#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""Store behind ``zabbix://reports/<id>`` resource links (issue #68).

The link exists so the PDF never enters the model's context; the store
is what holds the bytes between ``tools/call`` and ``resources/read``.
It must stay bounded - a report nobody fetches has to age out.
"""

from __future__ import annotations

import unittest

from zabbix_mcp.reporting.store import ReportStore

PDF = b"%PDF-1.4 payload"


class TestReportStore(unittest.TestCase):

    def test_put_get_roundtrip(self):
        store = ReportStore()
        rid = store.put(PDF, "report.pdf")
        got = store.get(rid)
        self.assertIsNotNone(got)
        self.assertEqual(got[0], PDF)
        self.assertEqual(got[1], "report.pdf")

    def test_uri_shape(self):
        store = ReportStore()
        rid = store.put(PDF, "r.pdf")
        self.assertEqual(store.uri(rid), f"zabbix://reports/{rid}")

    def test_unknown_id_returns_none(self):
        self.assertIsNone(ReportStore().get("does-not-exist"))

    def test_expired_report_is_dropped(self):
        store = ReportStore(ttl_s=0)
        rid = store.put(PDF, "r.pdf")
        self.assertIsNone(store.get(rid), "a report past its TTL must not be served")
        self.assertEqual(len(store), 0)

    def test_cap_evicts_oldest_not_newest(self):
        # The report just generated matters more than one nobody fetched.
        store = ReportStore(max_reports=2)
        first = store.put(b"first", "1.pdf")
        second = store.put(b"second", "2.pdf")
        third = store.put(b"third", "3.pdf")
        self.assertIsNone(store.get(first))
        self.assertIsNotNone(store.get(second))
        self.assertIsNotNone(store.get(third))
        self.assertEqual(len(store), 2)

    def test_ids_are_unique(self):
        store = ReportStore()
        ids = {store.put(PDF, "r.pdf") for _ in range(5)}
        self.assertEqual(len(ids), 5)


if __name__ == "__main__":
    unittest.main()
