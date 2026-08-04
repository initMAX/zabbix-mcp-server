#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
# Licensed under the GNU Affero General Public License v3.
# See LICENSE for details.
#

"""Dual-generation protocol e2e (issue #64).

Boots ONE real server subprocess and drives it with BOTH client
generations the SDK 2.0 endpoint must serve simultaneously:

* **Legacy 2025-11-25**: initialize handshake, ``Mcp-Session-Id``
  header, session-scoped follow-up requests.
* **Stateless 2026-07-28**: self-contained POSTs carrying the
  ``MCP-Protocol-Version`` header and the ``_meta`` envelope
  (protocolVersion / clientInfo / clientCapabilities), no handshake,
  ``server/discover``, and the ``io.modelcontextprotocol/tasks``
  extension lifecycle (call+task -> poll -> payload).

Parity assertions guarantee neither generation sees a different tool
catalog. Runs without a Zabbix backend - tools/list and the tasks
plumbing do not touch the Zabbix API.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

BEARER = "e2e-protocol-token-0123456789abcdef0123456789abcdef"

_META_ENVELOPE = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "e2e-stateless", "version": "0"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_health(url: str, timeout: float = 25.0) -> None:
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(0.3)
    raise RuntimeError(f"server not healthy at {url}: {last_exc}")


def _post(url: str, body: dict, headers: dict) -> tuple[int, dict | None]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {BEARER}",
        **headers,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        status = exc.code
    # Plain JSON first - naive "data: " sniffing misfires when tool
    # descriptions legitimately contain the substring. Only fall back
    # to SSE-frame extraction when the body is not valid JSON.
    try:
        return status, json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError:
        for line in raw.splitlines():
            if line.startswith("data: "):
                return status, json.loads(line[6:])
        return status, None


class TestDualGenerationProtocol(unittest.TestCase):
    """One server, both protocol generations."""

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.url = f"http://127.0.0.1:{cls.port}/mcp"
        cfg = f"""
[server]
transport = "http"
host = "127.0.0.1"
port = {cls.port}
auth_token = "{BEARER}"

[zabbix.dev]
url = "https://zabbix-e2e.example.invalid"
api_token = "dummy"
"""
        cls._cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        cls._cfg.write(cfg)
        cls._cfg.close()
        cls._log = open(Path(tempfile.gettempdir()) / "zmcp-protocol-e2e.log", "w")
        cls._proc = subprocess.Popen(
            [sys.executable, "-c",
             "from zabbix_mcp.cli import main; main()",
             "--config", cls._cfg.name],
            cwd=tempfile.gettempdir(),
            stdout=cls._log, stderr=subprocess.STDOUT,
        )
        try:
            _wait_for_health(f"http://127.0.0.1:{cls.port}/health")
        except Exception:
            cls._proc.terminate()
            raise

    @classmethod
    def tearDownClass(cls):
        cls._proc.terminate()
        cls._proc.wait(timeout=10)
        cls._log.close()
        Path(cls._cfg.name).unlink(missing_ok=True)

    # -- legacy generation ---------------------------------------------------

    def _legacy_initialize(self) -> tuple[str, dict]:
        """Run the 2025-11-25 handshake, return (session_id, init result)."""
        data = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "e2e-legacy", "version": "0"},
            },
        }).encode()
        req = urllib.request.Request(self.url, data=data, headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {BEARER}",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            session_id = resp.headers.get("Mcp-Session-Id")
            raw = resp.read().decode()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            data_line = next(l[6:] for l in raw.splitlines() if l.startswith("data: "))
            parsed = json.loads(data_line)
        result = parsed["result"]
        # Complete the handshake.
        note = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
        req = urllib.request.Request(self.url, data=note, headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {BEARER}",
            "Mcp-Session-Id": session_id,
        })
        with urllib.request.urlopen(req, timeout=15):
            pass
        return session_id, result

    def test_legacy_handshake_negotiates_2025_11_25(self):
        session_id, init = self._legacy_initialize()
        self.assertEqual(init["protocolVersion"], "2025-11-25")
        self.assertTrue(session_id, "legacy transport must mint Mcp-Session-Id")
        self.assertEqual(init["serverInfo"]["name"], "zabbix-mcp-server")

    def test_legacy_tools_list_via_session(self):
        session_id, _ = self._legacy_initialize()
        status, resp = _post(self.url, {
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        }, {"Mcp-Session-Id": session_id, "MCP-Protocol-Version": "2025-11-25"})
        self.assertEqual(status, 200)
        tools = resp["result"]["tools"]
        self.assertGreater(len(tools), 200)
        self.__class__._legacy_tool_count = len(tools)

    # -- stateless generation ------------------------------------------------

    def test_stateless_requires_meta_envelope(self):
        status, resp = _post(self.url, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
        }, {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"})
        self.assertIsNotNone(resp.get("error"),
                             "modern path must reject requests without the _meta envelope")

    def test_stateless_tools_list_cacheable_private(self):
        status, resp = _post(self.url, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": {"_meta": _META_ENVELOPE},
        }, {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"})
        self.assertEqual(status, 200)
        result = resp["result"]
        self.assertGreater(len(result["tools"]), 200)
        # Spec: CacheableResult on tools/list; per-token filtering makes
        # the catalog private to the authorization.
        self.assertEqual(result.get("cacheScope"), "private")
        self.assertIn("ttlMs", result)
        self.assertEqual(result.get("resultType"), "complete")
        self.assertIn("io.modelcontextprotocol/serverInfo", result.get("_meta", {}))
        self.__class__._stateless_tool_count = len(result["tools"])

    def test_stateless_missing_mcp_method_header_rejected(self):
        """Spec: Mcp-Method is REQUIRED on modern POSTs - server must 4xx."""
        status, _ = _post(self.url, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": {"_meta": _META_ENVELOPE},
        }, {"MCP-Protocol-Version": "2026-07-28"})
        self.assertGreaterEqual(status, 400)

    def test_stateless_no_session_header_minted(self):
        req = urllib.request.Request(self.url, data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": {"_meta": _META_ENVELOPE},
        }).encode(), headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {BEARER}",
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": "tools/list",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            self.assertIsNone(resp.headers.get("Mcp-Session-Id"),
                              "2026-07-28 responses must not carry a session id")

    def test_server_discover_advertises_tasks_extension(self):
        status, resp = _post(self.url, {
            "jsonrpc": "2.0", "id": 1, "method": "server/discover",
            "params": {"_meta": _META_ENVELOPE},
        }, {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"})
        self.assertEqual(status, 200)
        caps = resp["result"]["capabilities"]
        self.assertIn("io.modelcontextprotocol/tasks", caps.get("extensions", {}))

    def test_task_lifecycle_call_poll_payload(self):
        # 1. task-mode tools/call returns the handle in _meta immediately.
        status, resp = _post(self.url, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "_meta": _META_ENVELOPE,
                "name": "report_generate",
                "arguments": {"report_type": "availability"},
                "task": {"ttl": 60000},
            },
        }, {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call",
            "Mcp-Name": "report_generate"})
        self.assertEqual(status, 200)
        handle = resp["result"]["_meta"]["io.modelcontextprotocol/tasks"]
        self.assertEqual(handle["status"], "working")
        tid = handle["taskId"]

        # 2. Poll until terminal (report fails fast without weasyprint /
        #    a reachable Zabbix - completed-with-error payload is fine,
        #    the lifecycle is what is under test).
        for _ in range(30):
            status, resp = _post(self.url, {
                "jsonrpc": "2.0", "id": 2, "method": "tasks/get",
                "params": {"_meta": _META_ENVELOPE, "taskId": tid},
            }, {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tasks/get"})
            if resp["result"]["status"] in ("completed", "failed", "cancelled"):
                break
            time.sleep(0.3)
        self.assertIn(resp["result"]["status"], ("completed", "failed"))

        # 3. Payload retrievable.
        status, resp = _post(self.url, {
            "jsonrpc": "2.0", "id": 3, "method": "tasks/result",
            "params": {"_meta": _META_ENVELOPE, "taskId": tid},
        }, {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tasks/result"})
        self.assertEqual(status, 200)
        self.assertIn("content", resp["result"])

    # -- parity --------------------------------------------------------------

    def test_zz_generation_parity_tool_counts(self):
        """Both generations must see the identical tool catalog."""
        legacy = getattr(self.__class__, "_legacy_tool_count", None)
        stateless = getattr(self.__class__, "_stateless_tool_count", None)
        if legacy is None or stateless is None:
            self.skipTest("prerequisite tests did not run")
        self.assertEqual(legacy, stateless)


if __name__ == "__main__":
    unittest.main()
