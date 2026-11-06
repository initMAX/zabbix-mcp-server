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

"""Stopping the server while a client is connected.

A client of the 2026-07-28 protocol (Claude Code, for one) keeps a
``subscriptions/listen`` request open for as long as it is connected. The MCP
library ends that stream when the client goes away and at no other time, and
uvicorn does not exit while a response is open: ``systemctl restart`` took
the 90 seconds systemd allows and ended in SIGKILL, every time, as long as
one such client was connected. Seen on a production box on 2026-11-06.

The first half tests the layer that ends those streams, against an app that
behaves as the library does. The second half starts the real server, holds a
stream open the way Claude Code does, and stops the server.
"""

import asyncio
import contextlib
import http.client
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zabbix_mcp.server import _STOP_GRACE_SECONDS, _StopNotificationStreams  # noqa: E402

LISTEN = [(b"content-type", b"application/json"), (b"mcp-method", b"subscriptions/listen")]
TOOL_CALL = [(b"content-type", b"application/json"), (b"mcp-method", b"tools/call")]
BODY = {"type": "http.request", "body": b"{}", "more_body": False}


class Server:
    """What the layer reads of a uvicorn server."""
    should_exit = False


class Client:
    """The two ASGI callables, with a record of what was sent."""

    def __init__(self, *messages):
        self.inbox: asyncio.Queue = asyncio.Queue()
        for message in messages:
            self.inbox.put_nowait(message)
        self.sent: list[dict] = []

    async def receive(self):
        return await self.inbox.get()

    async def send(self, event):
        self.sent.append(event)


def like_the_library(commit: bool, seen: list):
    """An app that does what the library's handler does with a notification stream: read the
    body, (after its first interval) start an event stream, and stay until the client is gone;
    then leave without ending the response."""
    async def app(scope, receive, send):
        seen.append(await receive())
        if commit:
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/event-stream")]})
            await send({"type": "http.response.body", "body": b": ping\r\n\r\n", "more_body": True})
        while True:
            message = await receive()
            seen.append(message)
            if message["type"] == "http.disconnect":
                return
    return app


def run(coroutine):
    return asyncio.run(asyncio.wait_for(coroutine, 5))


class TestTheLayer(unittest.TestCase):
    def _stream(self, *, commit=True, headers=LISTEN, stop_after=0.05, client=None):
        seen: list = []
        server = Server()
        layer = _StopNotificationStreams(like_the_library(commit, seen))
        layer.server = server
        client = client or Client(BODY)

        async def scenario():
            before = asyncio.all_tasks()
            call = asyncio.ensure_future(layer({"type": "http", "headers": headers}, client.receive, client.send))
            await asyncio.sleep(stop_after)
            still_open = not call.done()
            server.should_exit = True
            try:
                await asyncio.wait_for(asyncio.shield(call), 1)
                ended = True
            except asyncio.TimeoutError:
                ended = False
                call.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await call
            # the watcher is the only task the layer keeps; it ends once the server is stopping
            await asyncio.sleep(0.15)
            return still_open, ended, [t for t in asyncio.all_tasks() if t not in before]

        return (*run(scenario()), seen, client)

    def test_a_notification_stream_ends_when_the_server_is_told_to_stop(self):
        still_open, ended, leftover, seen, client = self._stream()
        self.assertTrue(still_open)                                   # it was waiting, as it does for hours
        self.assertTrue(ended)
        self.assertEqual(seen, [BODY, {"type": "http.disconnect"}])   # told what the library listens to
        self.assertEqual(leftover, [])

    def test_the_response_it_left_open_is_ended(self):
        client = self._stream()[4]
        self.assertEqual(client.sent[-1], {"type": "http.response.body", "body": b"", "more_body": False})
        self.assertEqual([e["type"] for e in client.sent], ["http.response.start", "http.response.body", "http.response.body"])

    def test_a_stream_that_had_not_started_answering_gets_an_answer(self):
        # the library waits one interval before it starts the event stream
        still_open, ended, _, _, client = self._stream(commit=False)
        self.assertTrue(still_open and ended)
        self.assertEqual(client.sent[0]["status"], 503)
        self.assertIn((b"retry-after", b"5"), client.sent[0]["headers"])
        self.assertEqual(client.sent[1]["more_body"], False)
        self.assertEqual(json.loads(client.sent[1]["body"]), {"error": "the server is stopping"})

    def test_a_request_that_is_being_worked_on_is_left_alone(self):
        # a tool call waits for the client's disconnect in the same way; it is not told anything
        still_open, ended, _, seen, client = self._stream(headers=TOOL_CALL)
        self.assertTrue(still_open)
        self.assertFalse(ended)
        self.assertEqual(seen, [BODY])
        self.assertEqual([e["type"] for e in client.sent], ["http.response.start", "http.response.body"])

    def test_such_a_request_gets_the_very_callables_of_the_server(self):
        got = []

        async def app(scope, receive, send):
            got.append((receive, send))

        client = Client()
        for scope in ({"type": "http", "headers": TOOL_CALL}, {"type": "http", "headers": []}, {"type": "lifespan"},
                      {"type": "http", "headers": [(b"mcp-method", b"subscriptions/listening")]}):
            run(_StopNotificationStreams(app)(scope, client.receive, client.send))
        self.assertEqual(got, [(client.receive, client.send)] * 4)

    def test_a_stream_uvicorn_itself_told_of_the_shutdown_is_ended_too(self):
        # uvicorn 0.44 hands every open request an http.disconnect when it shuts down, and then
        # cuts what the application left unfinished
        seen: list = []
        client = Client(BODY)
        layer = _StopNotificationStreams(like_the_library(True, seen))
        layer.server = Server()

        async def scenario():
            call = asyncio.ensure_future(layer({"type": "http", "headers": LISTEN}, client.receive, client.send))
            await asyncio.sleep(0.05)
            layer.server.should_exit = True
            client.inbox.put_nowait({"type": "http.disconnect"})        # uvicorn was first
            await asyncio.wait_for(call, 1)
            await asyncio.sleep(0.15)

        run(scenario())
        self.assertEqual(client.sent[-1], {"type": "http.response.body", "body": b"", "more_body": False})

    def test_a_client_that_goes_away_itself(self):
        seen: list = []
        client = Client(BODY)
        layer = _StopNotificationStreams(like_the_library(True, seen))
        layer.server = Server()

        async def scenario():
            call = asyncio.ensure_future(layer({"type": "http", "headers": LISTEN}, client.receive, client.send))
            await asyncio.sleep(0.05)
            client.inbox.put_nowait({"type": "http.disconnect"})
            await asyncio.wait_for(call, 1)
            layer.server.should_exit = True
            await asyncio.sleep(0.15)

        run(scenario())
        self.assertEqual(seen, [BODY, {"type": "http.disconnect"}])
        # nothing is added to a response whose client is gone
        self.assertEqual([e["type"] for e in client.sent], ["http.response.start", "http.response.body"])

    def test_a_stream_that_ends_by_itself_gets_nothing_added(self):
        async def app(scope, receive, send):
            await receive()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"data: {}\r\n\r\n", "more_body": False})

        client = Client(BODY)
        layer = _StopNotificationStreams(app)
        layer.server = Server()
        layer.server.should_exit = True
        run(layer({"type": "http", "headers": LISTEN}, client.receive, client.send))
        self.assertEqual(len(client.sent), 2)

    def test_a_handler_that_is_cancelled_leaves_nothing_behind(self):
        seen: list = []
        client = Client(BODY)
        layer = _StopNotificationStreams(like_the_library(True, seen))
        layer.server = Server()

        async def scenario():
            before = asyncio.all_tasks()
            call = asyncio.ensure_future(layer({"type": "http", "headers": LISTEN}, client.receive, client.send))
            await asyncio.sleep(0.05)
            call.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await call
            await asyncio.sleep(0)
            # only the watcher, which waits for the server to stop
            return [t for t in asyncio.all_tasks() if t not in before and t is not layer._watcher]

        self.assertEqual(run(scenario()), [])

    def test_before_there_is_a_server_nothing_is_stopping(self):
        self.assertFalse(_StopNotificationStreams(None).stopping())

    def test_work_in_progress_gets_time_but_less_than_systemd_allows(self):
        import inspect
        from zabbix_mcp import server
        self.assertGreaterEqual(_STOP_GRACE_SECONDS, 10)
        self.assertLess(_STOP_GRACE_SECONDS, 90)       # systemd's default TimeoutStopSec
        # and uvicorn is started with it
        self.assertIn('"timeout_graceful_shutdown": _STOP_GRACE_SECONDS', inspect.getsource(server.run_server))

    def test_the_request_itself_is_read_as_it_comes_also_while_stopping(self):
        # a body that arrives in two pieces, the server already stopping: both pieces reach the
        # application before it is told anything
        first = {"type": "http.request", "body": b'{"a', "more_body": True}
        last = {"type": "http.request", "body": b'": 1}', "more_body": False}
        seen: list = []

        async def app(scope, receive, send):
            while True:
                message = await receive()
                seen.append(message)
                if message["type"] == "http.disconnect":
                    return

        client = Client(first, last)
        layer = _StopNotificationStreams(app)
        layer.server = Server()
        layer.server.should_exit = True
        run(layer({"type": "http", "headers": LISTEN}, client.receive, client.send))
        self.assertEqual(seen, [first, last, {"type": "http.disconnect"}])
        self.assertEqual(client.sent[0]["status"], 503)


# --------------------------------------------------------------------------- the real server

MODERN = importlib.util.find_spec("mcp.server._streamable_http_modern") is not None
LISTEN_BODY = json.dumps({
    "jsonrpc": "2.0", "id": "listen:0", "method": "subscriptions/listen",
    "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                         "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"},
                         "io.modelcontextprotocol/clientCapabilities": {}},
               "notifications": {"toolsListChanged": True, "promptsListChanged": True, "resourcesListChanged": True}},
})
LISTEN_HEADERS = {"Authorization": "Bearer stop-test", "Content-Type": "application/json",
                  "Accept": "application/json, text/event-stream", "Mcp-Method": "subscriptions/listen",
                  "Mcp-Protocol-Version": "2026-07-28"}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(MODERN and os.name == "posix", "needs the 2026-07-28 transport of the MCP library and SIGTERM")
class TestTheRealServerStops(unittest.TestCase):
    """The server as the service runs it, a client holding its notification stream, SIGTERM."""

    def _start(self, ping_interval: float | None = None):
        self.port = _free_port()
        self.dir = tempfile.TemporaryDirectory(prefix="zmcp-stop-")
        self.addCleanup(self.dir.cleanup)
        cfg = Path(self.dir.name) / "config.toml"
        cfg.write_text(
            f'[server]\nhost = "127.0.0.1"\nport = {self.port}\ntransport = "http"\nauth_token = "stop-test"\n'
            f'log_level = "info"\nlog_file = "{self.dir.name}/server.log"\n\n'
            '[admin]\nenabled = false\n\n'
            '[zabbix.placeholder]\nurl = "https://127.0.0.1:65535"\napi_token = "none"\nread_only = true\nverify_ssl = false\n')
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONPATH=str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", ""))
        code = "from zabbix_mcp.cli import main; main()"
        if ping_interval is not None:
            # the library keeps a stream alive every 15 s; a shorter interval to see it happen
            code = f"import mcp.server._streamable_http_modern as modern; modern._SSE_PING_INTERVAL = {ping_interval}; " + code
        self._said: str | None = None
        self.proc = subprocess.Popen([sys.executable, "-c", code, "--config", str(cfg)], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, cwd=str(ROOT), env=env)
        self.addCleanup(self._kill)
        deadline = time.time() + 30
        while True:
            try:
                probe = http.client.HTTPConnection("127.0.0.1", self.port, timeout=1)
                probe.request("GET", "/health")
                probe.getresponse().read()
                probe.close()
                return
            except OSError:
                if time.time() > deadline or self.proc.poll() is not None:
                    raise RuntimeError("the server did not start:\n" + self._output()[-2000:])
                time.sleep(0.2)

    def _kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(10)
        if self.proc.stdout:
            self.proc.stdout.close()

    def _output(self) -> str:
        """What the server wrote: its own output (uvicorn) and its log file (the application)."""
        if self.proc.poll() is None:
            self.proc.kill()
        if self._said is None:
            self._said = (self.proc.stdout.read() or b"").decode(errors="replace") if self.proc.stdout else ""
        log = Path(self.dir.name) / "server.log"
        return self._said + (log.read_text(encoding="utf-8", errors="replace") if log.exists() else "")

    def _listen(self) -> http.client.HTTPConnection:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        connection.request("POST", "/mcp", body=LISTEN_BODY, headers=LISTEN_HEADERS)
        self.addCleanup(connection.close)
        return connection

    def _stop(self) -> float:
        started = time.time()
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(15)
        except subprocess.TimeoutExpired:
            self.fail("the server was still running 15 s after SIGTERM:\n" + self._output()[-1500:])
        return time.time() - started

    def _first_event(self, connection) -> http.client.HTTPResponse:
        response = connection.getresponse()
        self.assertEqual((response.status, response.getheader("content-type")), (200, "text/event-stream"))
        self.assertTrue(response.readline().strip())                   # the stream has begun
        return response

    def _ended_not_cut(self, response) -> bytes:
        # a stream that was cut reads as http.client.IncompleteRead
        try:
            return response.read()
        except (http.client.HTTPException, OSError) as cut:
            self.fail(f"the stream was cut, not ended ({cut!r}); the server said:\n" + self._output()[-3000:])

    def test_with_a_notification_stream_open(self):
        # as the library ships: the stream is quiet between two keep-alives 15 s apart
        self._start()
        response = self._first_event(self._listen())
        time.sleep(1.0)
        self.assertLess(self._stop(), 5)
        self._ended_not_cut(response)
        self.assertIn(self.proc.returncode, (0, -signal.SIGTERM))
        self.assertNotIn("Traceback", self._output())

    def test_with_several_streams_that_are_being_kept_alive(self):
        self._start(ping_interval=0.2)
        responses = [self._first_event(self._listen()) for _ in range(3)]
        for response in responses:
            while not response.readline().startswith(b": ping"):       # each one has had a keep-alive
                pass
        self.assertLess(self._stop(), 5)
        for response in responses:
            self._ended_not_cut(response)
        self.assertNotIn("Traceback", self._output())

    def test_with_nobody_connected(self):
        self._start()
        self.assertLess(self._stop(), 5)


if __name__ == "__main__":
    unittest.main()
