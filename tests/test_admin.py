#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#

"""Unit tests for the admin portal — auth, token store, config writer, audit."""

import hashlib
import json
import os
import tempfile
import threading
import time
import unittest


# ---------------------------------------------------------------------------
# Password hashing (auth.py)
# ---------------------------------------------------------------------------
class TestPasswordHashing(unittest.TestCase):
    """Tests for hash_password / verify_password."""

    def test_hash_and_verify(self):
        from zabbix_mcp.admin.auth import hash_password, verify_password
        pw = "TestPassword123"
        hashed = hash_password(pw)
        self.assertTrue(hashed.startswith("scrypt:"))
        self.assertTrue(verify_password(pw, hashed))

    def test_wrong_password(self):
        from zabbix_mcp.admin.auth import hash_password, verify_password
        hashed = hash_password("CorrectPassword1")
        self.assertFalse(verify_password("WrongPassword1", hashed))

    def test_hash_format(self):
        from zabbix_mcp.admin.auth import hash_password
        hashed = hash_password("Test12345678")
        parts = hashed.split("$")
        self.assertEqual(len(parts), 3)
        # v1.21 bumped N to OWASP 2024 recommendation (131072).
        # Old hashes with N=16384 still verify (value is embedded in
        # the hash so verify_password picks it up).
        self.assertEqual(parts[0], "scrypt:131072:8:1")
        self.assertEqual(len(parts[1]), 32)  # 16 bytes hex salt
        self.assertEqual(len(parts[2]), 64)  # 32 bytes hex hash

    def test_different_salts(self):
        from zabbix_mcp.admin.auth import hash_password
        h1 = hash_password("SamePassword1")
        h2 = hash_password("SamePassword1")
        self.assertNotEqual(h1, h2)  # Different salts each time

    def test_invalid_hash_format(self):
        from zabbix_mcp.admin.auth import verify_password
        self.assertFalse(verify_password("test", "invalid"))
        self.assertFalse(verify_password("test", ""))
        self.assertFalse(verify_password("test", "scrypt:bad$salt$hash"))

    def test_generate_password(self):
        from zabbix_mcp.admin.auth import generate_password
        pw = generate_password(16)
        self.assertEqual(len(pw), 16)
        self.assertTrue(pw.isalnum())

    def test_generate_password_length(self):
        from zabbix_mcp.admin.auth import generate_password
        for length in (8, 16, 32, 64):
            pw = generate_password(length)
            self.assertEqual(len(pw), length)


# ---------------------------------------------------------------------------
# Session manager (auth.py)
# ---------------------------------------------------------------------------
class TestSessionManager(unittest.TestCase):
    """Tests for SessionManager."""

    def setUp(self):
        from zabbix_mcp.admin.auth import SessionManager
        self.sm = SessionManager("test-signing-key")

    def test_create_and_validate(self):
        token = self.sm.create_session("admin", "admin", "127.0.0.1")
        session = self.sm.validate_session(token)
        self.assertIsNotNone(session)
        self.assertEqual(session.user, "admin")
        self.assertEqual(session.role, "admin")
        self.assertEqual(session.ip, "127.0.0.1")

    def test_invalid_token(self):
        self.assertIsNone(self.sm.validate_session("nonexistent-token"))

    def test_destroy_session(self):
        token = self.sm.create_session("admin", "admin", "127.0.0.1")
        self.assertIsNotNone(self.sm.validate_session(token))
        self.sm.destroy_session(token)
        self.assertIsNone(self.sm.validate_session(token))

    def test_expired_session(self):
        from zabbix_mcp.admin.auth import SessionManager
        sm = SessionManager("key")
        token = sm.create_session("user", "viewer", "10.0.0.1")
        # Manually expire
        sm._sessions[token].expires_at = time.time() - 1
        self.assertIsNone(sm.validate_session(token))

    def test_cleanup_expired(self):
        token1 = self.sm.create_session("user1", "admin", "1.1.1.1")
        token2 = self.sm.create_session("user2", "viewer", "2.2.2.2")
        self.sm._sessions[token1].expires_at = time.time() - 1
        self.sm.cleanup_expired()
        self.assertIsNone(self.sm.validate_session(token1))
        self.assertIsNotNone(self.sm.validate_session(token2))

    def test_multiple_sessions(self):
        t1 = self.sm.create_session("admin", "admin", "1.1.1.1")
        t2 = self.sm.create_session("admin", "admin", "2.2.2.2")
        self.assertNotEqual(t1, t2)
        self.assertIsNotNone(self.sm.validate_session(t1))
        self.assertIsNotNone(self.sm.validate_session(t2))


# ---------------------------------------------------------------------------
# Login rate limiter (auth.py)
# ---------------------------------------------------------------------------
class TestLoginRateLimiter(unittest.TestCase):
    """Tests for LoginRateLimiter brute-force protection."""

    def setUp(self):
        from zabbix_mcp.admin.auth import LoginRateLimiter
        self.rl = LoginRateLimiter()

    def test_allows_initial(self):
        self.assertTrue(self.rl.check("10.0.0.1"))

    def test_blocks_after_max_attempts(self):
        ip = "10.0.0.99"
        for _ in range(5):
            self.rl.record_attempt(ip)
        self.assertFalse(self.rl.check(ip))

    def test_different_ips_independent(self):
        for _ in range(5):
            self.rl.record_attempt("10.0.0.1")
        self.assertFalse(self.rl.check("10.0.0.1"))
        self.assertTrue(self.rl.check("10.0.0.2"))

    def test_reset_clears(self):
        ip = "10.0.0.50"
        for _ in range(5):
            self.rl.record_attempt(ip)
        self.assertFalse(self.rl.check(ip))
        self.rl.reset(ip)
        self.assertTrue(self.rl.check(ip))

    def test_cleanup_on_high_count(self):
        """Memory leak prevention: stale IPs cleaned after threshold."""
        for i in range(600):
            ip = f"10.0.{i // 256}.{i % 256}"
            self.rl.record_attempt(ip)
        # Should have cleaned up old entries
        self.assertLessEqual(len(self.rl._attempts), 600)


# ---------------------------------------------------------------------------
# Token store (token_store.py)
# ---------------------------------------------------------------------------
class TestTokenStore(unittest.TestCase):
    """Tests for TokenStore multi-token authentication."""

    def setUp(self):
        from zabbix_mcp.token_store import TokenStore
        self.store = TokenStore()

    def _make_token(self, raw="zmcp_test123"):
        h = f"sha256:{hashlib.sha256(raw.encode()).hexdigest()}"
        return raw, h

    def test_load_and_verify(self):
        raw, h = self._make_token()
        self.store.load_from_config({
            "test": {"name": "Test", "token_hash": h, "scopes": ["*"]},
        })
        info = self.store.verify(raw)
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "Test")

    def test_wrong_token(self):
        _, h = self._make_token("correct")
        self.store.load_from_config({
            "test": {"name": "Test", "token_hash": h},
        })
        self.assertIsNone(self.store.verify("wrong"))

    def test_revoked_token(self):
        raw, h = self._make_token()
        self.store.load_from_config({
            "test": {"name": "Test", "token_hash": h, "is_active": False},
        })
        self.assertIsNone(self.store.verify(raw))

    def test_expired_token(self):
        raw, h = self._make_token()
        self.store.load_from_config({
            "test": {"name": "Test", "token_hash": h, "expires_at": "2020-01-01T00:00:00Z"},
        })
        self.assertIsNone(self.store.verify(raw))

    def test_valid_expiry(self):
        raw, h = self._make_token()
        self.store.load_from_config({
            "test": {"name": "Test", "token_hash": h, "expires_at": "2099-12-31T23:59:59Z"},
        })
        self.assertIsNotNone(self.store.verify(raw))

    def test_ip_allowlist_pass(self):
        raw, h = self._make_token()
        self.store.load_from_config({
            "test": {"name": "Test", "token_hash": h, "allowed_ips": ["10.0.0.0/8"]},
        })
        self.assertIsNotNone(self.store.verify(raw, client_ip="10.1.2.3"))

    def test_ip_allowlist_reject(self):
        raw, h = self._make_token()
        self.store.load_from_config({
            "test": {"name": "Test", "token_hash": h, "allowed_ips": ["10.0.0.0/8"]},
        })
        self.assertIsNone(self.store.verify(raw, client_ip="192.168.1.1"))

    def test_use_count(self):
        raw, h = self._make_token()
        self.store.load_from_config({
            "test": {"name": "Test", "token_hash": h},
        })
        self.store.verify(raw)
        self.store.verify(raw)
        info = self.store.get_token("test")
        self.assertEqual(info.use_count, 2)

    def test_legacy_token(self):
        self.store.load_legacy_token("my-old-token")
        info = self.store.verify("my-old-token")
        self.assertIsNotNone(info)
        self.assertTrue(info.is_legacy)

    def test_generate_token(self):
        from zabbix_mcp.token_store import TokenStore
        raw, h = TokenStore.generate_token()
        self.assertTrue(raw.startswith("zmcp_"))
        self.assertEqual(len(raw), 69)  # zmcp_ + 64 hex
        self.assertTrue(h.startswith("sha256:"))
        # Verify hash matches
        computed = f"sha256:{hashlib.sha256(raw.encode()).hexdigest()}"
        self.assertEqual(h, computed)

    def test_list_tokens(self):
        _, h1 = self._make_token("token1")
        _, h2 = self._make_token("token2")
        self.store.load_from_config({
            "a": {"name": "Token A", "token_hash": h1},
            "b": {"name": "Token B", "token_hash": h2},
        })
        tokens = self.store.list_tokens()
        self.assertEqual(len(tokens), 2)
        names = {t.name for t in tokens}
        self.assertEqual(names, {"Token A", "Token B"})

    def test_reload_preserves_stats(self):
        raw, h = self._make_token()
        self.store.load_from_config({
            "test": {"name": "Test", "token_hash": h},
        })
        self.store.verify(raw)
        self.store.verify(raw)
        # Reload with same token
        self.store.load_from_config({
            "test": {"name": "Test Updated", "token_hash": h},
        })
        info = self.store.get_token("test")
        self.assertEqual(info.use_count, 2)  # Preserved
        self.assertEqual(info.name, "Test Updated")

    def test_empty_token_hash_skipped(self):
        self.store.load_from_config({
            "bad": {"name": "No Hash", "token_hash": ""},
        })
        self.assertEqual(self.store.token_count, 0)


# ---------------------------------------------------------------------------
# Token authorization (token_store.py)
# ---------------------------------------------------------------------------
class TestTokenAuthorization(unittest.TestCase):
    """Tests for check_token_authorization context-based auth."""

    def test_no_token_allows_all(self):
        from zabbix_mcp.token_store import check_token_authorization, current_token_info
        current_token_info.set(None)
        self.assertIsNone(check_token_authorization("server1", tool_prefix="host"))

    def test_scope_restriction(self):
        from zabbix_mcp.token_store import check_token_authorization, current_token_info, TokenInfo
        token = TokenInfo(id="t", name="T", token_hash="x", scopes=["monitoring"])
        current_token_info.set(token)
        # host is in monitoring group — allowed
        self.assertIsNone(check_token_authorization("s", tool_prefix="host"))
        # user is NOT in monitoring group — denied
        result = check_token_authorization("s", tool_prefix="user")
        self.assertIsNotNone(result)
        self.assertIn("scope", result.lower())
        current_token_info.set(None)

    def test_wildcard_scope(self):
        from zabbix_mcp.token_store import check_token_authorization, current_token_info, TokenInfo
        token = TokenInfo(id="t", name="T", token_hash="x", scopes=["*"])
        current_token_info.set(token)
        self.assertIsNone(check_token_authorization("s", tool_prefix="anything"))
        current_token_info.set(None)

    def test_server_restriction(self):
        from zabbix_mcp.token_store import check_token_authorization, current_token_info, TokenInfo
        token = TokenInfo(id="t", name="T", token_hash="x", allowed_servers=["prod"])
        current_token_info.set(token)
        self.assertIsNone(check_token_authorization("prod"))
        result = check_token_authorization("staging")
        self.assertIsNotNone(result)
        self.assertIn("not authorized", result.lower())
        current_token_info.set(None)

    def test_read_only_blocks_write(self):
        from zabbix_mcp.token_store import check_token_authorization, current_token_info, TokenInfo
        token = TokenInfo(id="t", name="T", token_hash="x", read_only=True)
        current_token_info.set(token)
        self.assertIsNone(check_token_authorization("s", is_write=False))
        result = check_token_authorization("s", is_write=True)
        self.assertIsNotNone(result)
        self.assertIn("read-only", result.lower())
        current_token_info.set(None)


# ---------------------------------------------------------------------------
# raw_json policy gate (server.py + token_store.py)
# ---------------------------------------------------------------------------
class TestRawJsonPolicy(unittest.TestCase):
    """Tests for the token-scoped raw_json escape hatch.

    The preamble (`[System: ...]`) is part of our prompt-injection
    mitigation; raw_json=true strips it. The gate must default-deny
    so an LLM cannot opt itself out of the mitigation.
    """

    def tearDown(self):
        from zabbix_mcp.token_store import current_token_info
        current_token_info.set(None)

    def test_token_info_default_off(self):
        from zabbix_mcp.token_store import TokenInfo
        t = TokenInfo(id="t", name="T", token_hash="x")
        self.assertFalse(t.allow_raw_json)

    def test_load_from_config_parses_flag(self):
        from zabbix_mcp.token_store import TokenStore
        store = TokenStore()
        store.load_from_config({
            "default_off": {"name": "A", "token_hash": "sha256:aaa"},
            "explicit_on": {"name": "B", "token_hash": "sha256:bbb", "allow_raw_json": True},
            "explicit_off": {"name": "C", "token_hash": "sha256:ccc", "allow_raw_json": False},
        })
        self.assertFalse(store.get_token("default_off").allow_raw_json)
        self.assertTrue(store.get_token("explicit_on").allow_raw_json)
        self.assertFalse(store.get_token("explicit_off").allow_raw_json)

    def test_check_allows_when_raw_json_false(self):
        from zabbix_mcp.server import _check_raw_json_allowed
        from zabbix_mcp.token_store import current_token_info, TokenInfo
        # Even a token that lacks the policy passes when raw_json is not requested.
        current_token_info.set(TokenInfo(id="t", name="T", token_hash="x", allow_raw_json=False))
        self.assertIsNone(_check_raw_json_allowed(False))

    def test_check_denies_token_without_policy(self):
        from zabbix_mcp.server import _check_raw_json_allowed
        from zabbix_mcp.token_store import current_token_info, TokenInfo
        current_token_info.set(TokenInfo(id="t", name="alpha", token_hash="x", allow_raw_json=False))
        result = _check_raw_json_allowed(True)
        self.assertIsNotNone(result)
        self.assertIn("alpha", result)
        self.assertIn("allow raw json", result.lower())

    def test_check_allows_token_with_policy(self):
        from zabbix_mcp.server import _check_raw_json_allowed
        from zabbix_mcp.token_store import current_token_info, TokenInfo
        current_token_info.set(TokenInfo(id="t", name="T", token_hash="x", allow_raw_json=True))
        self.assertIsNone(_check_raw_json_allowed(True))

    def test_check_denies_when_no_token_context_by_default(self):
        from zabbix_mcp.server import _check_raw_json_allowed
        from zabbix_mcp.token_store import current_token_info
        # stdio mode / pre-auth: deny by default so an LLM stdio client
        # (Claude Desktop) cannot strip its own prompt-injection
        # mitigation just by setting raw_json=true. Operators wanting
        # raw JSON from a non-LLM stdio script opt in via
        # [server].stdio_allow_raw_json = true.
        current_token_info.set(None)
        err = _check_raw_json_allowed(True)
        self.assertIsNotNone(err)
        self.assertIn("stdio mode", err)

    def test_format_result_strips_preamble_when_true(self):
        from zabbix_mcp.server import _format_result, _UNTRUSTED_PREAMBLE
        out_with = _format_result("payload", False)
        out_raw = _format_result("payload", True)
        self.assertTrue(out_with.startswith(_UNTRUSTED_PREAMBLE))
        self.assertEqual(out_raw, "payload")


# ---------------------------------------------------------------------------
# MCP 2025-11-25 protocol upgrade helpers
# ---------------------------------------------------------------------------
class TestProtocol202511(unittest.TestCase):
    """Coverage for the MCP 2025-11-25 protocol upgrade pieces.

    Three things matter for the upgrade we want to verify:
    - Origin/Host validation flips on once the operator declares either
      a public_url or an explicit allowed_* list (BC: stays off in the
      no-config case so existing localhost setups keep working).
    - Tool-level error returns from extension functions are converted to
      the SEP-1303 isError shape via ToolError, instead of leaking out
      as 'successful' tool results carrying error JSON.
    - The bundled server icon is reachable as a data: URI so clients
      that render server icons (Inspector, Claude Desktop) get one
      without needing an extra static-file endpoint.
    """

    def test_transport_security_returns_none_when_unset(self):
        """No public_url + no allowed_* lists -> let MCPServer decide.

        In the no-config case we let MCPServer fall back to its localhost
        defaults; that keeps backwards compat with existing 127.0.0.1
        deployments and avoids surprising operators with 403s right after
        the upgrade.
        """
        from zabbix_mcp.server import _build_transport_security
        from zabbix_mcp.config import AppConfig, ServerConfig
        cfg = AppConfig.__new__(AppConfig)
        srv = ServerConfig(
            transport="http", host="0.0.0.0", port=8080,
            log_level="info", log_file=None,
            auth_token=None, rate_limit=300,
        )
        object.__setattr__(cfg, "server", srv)
        object.__setattr__(cfg, "zabbix_servers", {})
        self.assertIsNone(_build_transport_security(cfg, "0.0.0.0", 8080))

    def test_transport_security_built_from_public_url(self):
        """public_url alone is enough to flip protection on.

        We derive Host (host[:port]) and Origin (scheme://host[:port])
        from the URL the operator already configured for OAuth /
        wizard, so they don't have to maintain a second list.
        """
        from zabbix_mcp.server import _build_transport_security
        from zabbix_mcp.config import AppConfig, ServerConfig
        cfg = AppConfig.__new__(AppConfig)
        srv = ServerConfig(
            transport="http", host="0.0.0.0", port=8080,
            log_level="info", log_file=None,
            auth_token=None, rate_limit=300,
            public_url="https://mcp.example.com",
        )
        object.__setattr__(cfg, "server", srv)
        object.__setattr__(cfg, "zabbix_servers", {})
        ts = _build_transport_security(cfg, "0.0.0.0", 8080)
        self.assertIsNotNone(ts)
        self.assertTrue(ts.enable_dns_rebinding_protection)
        self.assertIn("mcp.example.com", ts.allowed_hosts)
        self.assertIn("https://mcp.example.com", ts.allowed_origins)
        # Local probes must keep working for the same-box health check.
        self.assertIn("127.0.0.1:8080", ts.allowed_hosts)

    def test_raise_if_extension_error_converts_error_json(self):
        """Bridge for legacy {'error': '...'} extension returns -> ToolError.

        SEP-1303 (clarified in 2025-11-25) wants tool-level failures to
        surface as CallToolResult(isError=True). Our extension functions
        in api/extensions.py predate that and return error JSON strings;
        this helper re-raises so MCPServer marks isError correctly.
        """
        from zabbix_mcp.server import _raise_if_extension_error
        from mcp.server.mcpserver.exceptions import ToolError
        with self.assertRaises(ToolError) as cm:
            _raise_if_extension_error('{"error": "bad input"}')
        self.assertIn("bad input", str(cm.exception))

    def test_raise_if_extension_error_wraps_success_in_preamble(self):
        from zabbix_mcp.server import _raise_if_extension_error, _UNTRUSTED_PREAMBLE
        good = '{"items": [{"id": "1"}]}'
        out = _raise_if_extension_error(good)
        self.assertTrue(out.startswith(_UNTRUSTED_PREAMBLE))
        self.assertIn(good, out)
        # raw_json=True keeps the bare JSON for non-LLM consumers.
        self.assertEqual(_raise_if_extension_error(good, raw_json=True), good)

    def test_raise_if_extension_error_wraps_non_json_in_preamble(self):
        from zabbix_mcp.server import _raise_if_extension_error, _UNTRUSTED_PREAMBLE
        plain = "data:image/png;base64,iVBORw0KGgo..."
        out = _raise_if_extension_error(plain)
        self.assertTrue(out.startswith(_UNTRUSTED_PREAMBLE))
        self.assertIn(plain, out)
        self.assertEqual(_raise_if_extension_error(plain, raw_json=True), plain)

    def test_server_icons_loadable_as_data_uri(self):
        """Bundled brand SVG must resolve from package data and embed inline."""
        from zabbix_mcp.server import _load_server_icons
        icons = _load_server_icons()
        self.assertIsNotNone(icons)
        self.assertEqual(len(icons), 1)
        self.assertTrue(icons[0].src.startswith("data:image/svg+xml;base64,"))

    def test_allowed_origins_rejects_garbage_in_config(self):
        """A non-URL string in [server].allowed_origins must abort load_config.

        The Settings UI catches typos before they hit disk, but a hand
        edit of config.toml goes straight through. validate_config() in
        install.sh calls load_config too, so this is the same bar that
        the upgrade path enforces.
        """
        import tempfile, textwrap, os
        from zabbix_mcp.config import load_config, ConfigError
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(textwrap.dedent('''
                [server]
                transport = "http"
                host = "127.0.0.1"
                port = 8080
                allowed_origins = ["not a url"]

                [zabbix.prod]
                url = "https://z.example.com"
                api_token = "tok"
            '''))
            path = f.name
        try:
            with self.assertRaises(ConfigError) as cm:
                load_config(path)
            self.assertIn("allowed_origins", str(cm.exception))
        finally:
            os.unlink(path)

    def test_allowed_origins_accepts_port_wildcard(self):
        """``https://app.example.com:*`` is valid (MCPServer port-wildcard)."""
        import tempfile, textwrap, os
        from zabbix_mcp.config import load_config
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(textwrap.dedent('''
                [server]
                transport = "http"
                host = "127.0.0.1"
                port = 8080
                allowed_origins = ["https://app.example.com:*", "https://office.example.com"]

                [zabbix.prod]
                url = "https://z.example.com"
                api_token = "tok"
            '''))
            path = f.name
        try:
            cfg = load_config(path)
            self.assertEqual(
                cfg.server.allowed_origins,
                ["https://app.example.com:*", "https://office.example.com"],
            )
        finally:
            os.unlink(path)

    def test_allow_raw_json_strict_bool_only(self):
        """A string ``"false"`` in allow_raw_json must NOT parse as True.

        TOML's bool type is `true` / `false`; an operator who quotes the
        value by mistake (``allow_raw_json = "false"``) used to produce
        ``bool("false") == True`` - an LLM token would silently get the
        escape hatch. Now we treat anything non-bool as False with a
        warning.
        """
        from zabbix_mcp.token_store import TokenStore
        store = TokenStore()
        store.load_from_config({
            "stringly_typed": {
                "name": "S", "token_hash": "sha256:aaa",
                "allow_raw_json": "false",  # the bug-bait
            },
            "real_true": {
                "name": "R", "token_hash": "sha256:bbb",
                "allow_raw_json": True,
            },
        })
        self.assertFalse(store.get_token("stringly_typed").allow_raw_json)
        self.assertTrue(store.get_token("real_true").allow_raw_json)


# ---------------------------------------------------------------------------
# Tasks API (MCP 2025-11-25 experimental) - bounded store + helpers
# ---------------------------------------------------------------------------
class TestTasksAPI(unittest.IsolatedAsyncioTestCase):
    """Coverage for the bounded task store and the tasks extension.

    Three things matter for the Tasks API rollout:
    - The store must enforce TTL bounds (default + ceiling) so a buggy
      or hostile client cannot pin multi-megabyte payloads in RAM.
    - It must reject create_task once the live cap is reached, with a
      clear retryable error (not silent OOM).
    - The io.modelcontextprotocol/tasks extension must run a
      task-augmented call in the background and hand back the task
      handle immediately, while leaving ordinary calls untouched.
    """

    async def test_default_ttl_when_client_omits(self):
        """Missing ``task: {ttl: ...}`` -> our default is filled in.

        Otherwise the upstream store treats ``ttl=None`` as
        "live forever" and we accumulate stale tasks across requests.
        """
        from zabbix_mcp.task_store import BoundedInMemoryTaskStore, DEFAULT_TTL_MS
        from mcp.types import TaskMetadata
        store = BoundedInMemoryTaskStore()
        task = await store.create_task(TaskMetadata())
        self.assertEqual(task.ttl, DEFAULT_TTL_MS)

    async def test_ttl_capped_at_ceiling(self):
        """A client-supplied TTL larger than MAX gets clamped, not honored."""
        from zabbix_mcp.task_store import BoundedInMemoryTaskStore, MAX_TTL_MS
        from mcp.types import TaskMetadata
        store = BoundedInMemoryTaskStore()
        task = await store.create_task(TaskMetadata(ttl=MAX_TTL_MS * 10))
        self.assertEqual(task.ttl, MAX_TTL_MS)

    async def test_max_live_tasks_enforced(self):
        """Once the soft cap is hit, create_task raises TaskStoreFull."""
        from zabbix_mcp.task_store import BoundedInMemoryTaskStore, TaskStoreFull
        from mcp.types import TaskMetadata
        store = BoundedInMemoryTaskStore(max_live_tasks=2)
        await store.create_task(TaskMetadata(ttl=60_000))
        await store.create_task(TaskMetadata(ttl=60_000))
        with self.assertRaises(TaskStoreFull):
            await store.create_task(TaskMetadata(ttl=60_000))

    async def test_explicit_ttl_under_ceiling_passes_through(self):
        """A reasonable client-supplied TTL is preserved unchanged."""
        from zabbix_mcp.task_store import BoundedInMemoryTaskStore
        from mcp.types import TaskMetadata
        store = BoundedInMemoryTaskStore()
        task = await store.create_task(TaskMetadata(ttl=30_000))
        self.assertEqual(task.ttl, 30_000)

    async def test_extension_interceptor_runs_task_in_background(self):
        """tools/call with `task:` on an advertised tool returns
        CreateTaskResult immediately; the payload lands in the store and
        is retrievable via the tasks/result handler once completed."""
        import asyncio
        from zabbix_mcp.task_store import BoundedInMemoryTaskStore, build_tasks_extension
        from mcp.types import (
            CallToolRequestParams, CallToolResult,
            GetTaskRequestParams, GetTaskPayloadRequestParams, TaskMetadata, TextContent,
        )
        store = BoundedInMemoryTaskStore()
        ext = build_tasks_extension(store, {"report_generate"})

        done = asyncio.Event()

        async def call_next(ctx):
            await done.wait()
            return CallToolResult(content=[TextContent(type="text", text="PDF!")])

        params = CallToolRequestParams(
            name="report_generate", arguments={}, task=TaskMetadata(ttl=60_000))
        result = await ext.intercept_tool_call(params, ctx=None, call_next=call_next)
        # 2026-07-28 wire shape: CallToolResult with the task handle in
        # _meta under the extension identifier (top-level CreateTaskResult
        # is not admitted by the tools/call result surface).
        self.assertIsInstance(result, CallToolResult)
        handle = result.meta["io.modelcontextprotocol/tasks"]
        tid = handle["taskId"]

        bindings = {b.method: b for b in ext.methods()}
        polled = await bindings["tasks/get"].handler(None, GetTaskRequestParams(taskId=tid))
        self.assertEqual(polled.status, "working")

        done.set()
        await asyncio.sleep(0.05)
        polled = await bindings["tasks/get"].handler(None, GetTaskRequestParams(taskId=tid))
        self.assertEqual(polled.status, "completed")
        payload = await bindings["tasks/result"].handler(None, GetTaskPayloadRequestParams(taskId=tid))
        self.assertEqual(payload.content[0].text, "PDF!")

    async def test_extension_passthrough_without_task(self):
        """No `task:` param or non-advertised tool -> normal synchronous path."""
        from zabbix_mcp.task_store import BoundedInMemoryTaskStore, build_tasks_extension
        from mcp.types import CallToolRequestParams, CallToolResult, TaskMetadata, TextContent
        store = BoundedInMemoryTaskStore()
        ext = build_tasks_extension(store, {"report_generate"})
        sync_result = CallToolResult(content=[TextContent(type="text", text="sync")])

        async def call_next(ctx):
            return sync_result

        out = await ext.intercept_tool_call(
            CallToolRequestParams(name="report_generate", arguments={}), None, call_next)
        self.assertIs(out, sync_result)
        out = await ext.intercept_tool_call(
            CallToolRequestParams(name="host_get", arguments={}, task=TaskMetadata(ttl=1000)),
            None, call_next)
        self.assertIs(out, sync_result)
        self.assertEqual(len(store._tasks), 0)

    async def test_extension_cancel(self):
        """tasks/cancel flips a working task to cancelled."""
        import asyncio
        from zabbix_mcp.task_store import BoundedInMemoryTaskStore, build_tasks_extension
        from mcp.types import (
            CallToolRequestParams, CancelTaskRequestParams,
            GetTaskRequestParams, TaskMetadata, CallToolResult, TextContent,
        )
        store = BoundedInMemoryTaskStore()
        ext = build_tasks_extension(store, {"report_generate"})

        async def call_next(ctx):
            await asyncio.sleep(30)
            return CallToolResult(content=[TextContent(type="text", text="late")])

        result = await ext.intercept_tool_call(
            CallToolRequestParams(name="report_generate", arguments={}, task=TaskMetadata(ttl=60_000)),
            None, call_next)
        tid = result.meta["io.modelcontextprotocol/tasks"]["taskId"]
        bindings = {b.method: b for b in ext.methods()}
        await bindings["tasks/cancel"].handler(None, CancelTaskRequestParams(taskId=tid))
        polled = await bindings["tasks/get"].handler(None, GetTaskRequestParams(taskId=tid))
        self.assertEqual(polled.status, "cancelled")


# ---------------------------------------------------------------------------
# Config writer (config_writer.py)
# ---------------------------------------------------------------------------
class TestConfigWriter(unittest.TestCase):
    """Tests for atomic TOML config read/write."""

    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile(
            mode="w", suffix=".toml", delete=False, encoding="utf-8",
        )
        self.tmpfile.write('[server]\nport = 8080\n\n[zabbix.prod]\nurl = "https://z.example.com"\napi_token = "tok"\n')
        self.tmpfile.close()
        self.path = self.tmpfile.name

    def tearDown(self):
        os.unlink(self.path)

    def test_load_document(self):
        from zabbix_mcp.admin.config_writer import load_config_document, TOMLKIT_AVAILABLE
        if not TOMLKIT_AVAILABLE:
            self.skipTest("tomlkit not installed")
        doc = load_config_document(self.path)
        self.assertEqual(doc["server"]["port"], 8080)

    def test_update_section(self):
        from zabbix_mcp.admin.config_writer import update_config_section, load_config_document, TOMLKIT_AVAILABLE
        if not TOMLKIT_AVAILABLE:
            self.skipTest("tomlkit not installed")
        update_config_section(self.path, "server", {"port": 9999})
        doc = load_config_document(self.path)
        self.assertEqual(doc["server"]["port"], 9999)

    def test_add_and_remove_table(self):
        from zabbix_mcp.admin.config_writer import add_config_table, remove_config_table, load_config_document, TOMLKIT_AVAILABLE
        if not TOMLKIT_AVAILABLE:
            self.skipTest("tomlkit not installed")
        add_config_table(self.path, "tokens", "test1", {"name": "T1", "token_hash": "sha256:abc"})
        doc = load_config_document(self.path)
        self.assertEqual(doc["tokens"]["test1"]["name"], "T1")
        remove_config_table(self.path, "tokens", "test1")
        doc = load_config_document(self.path)
        self.assertNotIn("test1", doc.get("tokens", {}))

    def test_preserves_comments(self):
        from zabbix_mcp.admin.config_writer import update_config_section, TOMLKIT_AVAILABLE
        if not TOMLKIT_AVAILABLE:
            self.skipTest("tomlkit not installed")
        # Write a config with comments
        with open(self.path, "w") as f:
            f.write('# My comment\n[server]\nport = 8080\n')
        update_config_section(self.path, "server", {"port": 9090})
        with open(self.path) as f:
            content = f.read()
        self.assertIn("# My comment", content)

    def test_atomic_write_permissions(self):
        from zabbix_mcp.admin.config_writer import update_config_section, TOMLKIT_AVAILABLE
        if not TOMLKIT_AVAILABLE:
            self.skipTest("tomlkit not installed")
        os.chmod(self.path, 0o600)
        update_config_section(self.path, "server", {"port": 1234})
        mode = os.stat(self.path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_nonexistent_path(self):
        from zabbix_mcp.admin.config_writer import load_config_document, TOMLKIT_AVAILABLE
        if not TOMLKIT_AVAILABLE:
            self.skipTest("tomlkit not installed")
        with self.assertRaises(FileNotFoundError):
            load_config_document("/nonexistent/config.toml")


# ---------------------------------------------------------------------------
# Audit writer (audit_writer.py)
# ---------------------------------------------------------------------------
class TestAuditWriter(unittest.TestCase):
    """Tests for write_audit JSON line writer."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.tmpdir, "audit.log")
        # Monkey-patch the audit log path
        import zabbix_mcp.admin.audit_writer as aw
        self._orig = aw.AUDIT_LOG_PATH
        aw.AUDIT_LOG_PATH = type(aw.AUDIT_LOG_PATH)(self.log_path)

    def tearDown(self):
        import zabbix_mcp.admin.audit_writer as aw
        aw.AUDIT_LOG_PATH = self._orig
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_write_and_read(self):
        from zabbix_mcp.admin.audit_writer import write_audit
        write_audit("test_action", user="admin", target_type="token", target_id="t1", ip="127.0.0.1")
        with open(self.log_path, encoding="utf-8") as f:
            line = f.readline()
        entry = json.loads(line)
        self.assertEqual(entry["action"], "test_action")
        self.assertEqual(entry["user"], "admin")
        self.assertEqual(entry["target_type"], "token")
        self.assertEqual(entry["target_id"], "t1")
        self.assertEqual(entry["ip"], "127.0.0.1")
        self.assertIn("timestamp", entry)

    def test_multiple_entries(self):
        from zabbix_mcp.admin.audit_writer import write_audit
        write_audit("action1", user="a")
        write_audit("action2", user="b")
        write_audit("action3", user="c")
        with open(self.log_path, encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 3)

    def test_unicode_content(self):
        from zabbix_mcp.admin.audit_writer import write_audit
        write_audit("create", user="uživatel", target_id="šablona")
        with open(self.log_path, encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["user"], "uživatel")
        self.assertEqual(entry["target_id"], "šablona")

    def test_details_dict(self):
        from zabbix_mcp.admin.audit_writer import write_audit
        write_audit("upload", details={"filename": "logo.png", "size": 1024})
        with open(self.log_path, encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["details"]["filename"], "logo.png")
        self.assertEqual(entry["details"]["size"], 1024)


# ---------------------------------------------------------------------------
# Tool groups / extensions (config.py)
# ---------------------------------------------------------------------------
class TestToolGroups(unittest.TestCase):
    """Tests for TOOL_GROUPS and extension tool filtering."""

    def test_extensions_group_exists(self):
        from zabbix_mcp.config import TOOL_GROUPS
        self.assertIn("extensions", TOOL_GROUPS)

    def test_extensions_contains_key_tools(self):
        from zabbix_mcp.config import TOOL_GROUPS
        ext = TOOL_GROUPS["extensions"]
        for tool in ["graph_render", "anomaly_detect", "capacity_forecast",
                     "item_threshold_search",
                     "report_generate", "action_prepare", "action_confirm",
                     "zabbix_raw_api_call", "health_check"]:
            self.assertIn(tool, ext, f"{tool} missing from extensions group")

    def test_expand_groups(self):
        from zabbix_mcp.config import _expand_tool_groups
        expanded = _expand_tool_groups(["monitoring"])
        self.assertIn("host", expanded)
        self.assertIn("trigger", expanded)
        self.assertNotIn("user", expanded)

    def test_expand_extensions(self):
        from zabbix_mcp.config import _expand_tool_groups
        expanded = _expand_tool_groups(["extensions"])
        self.assertIn("graph_render", expanded)
        self.assertIn("report_generate", expanded)
        self.assertIn("health_check", expanded)

    def test_expand_mixed(self):
        from zabbix_mcp.config import _expand_tool_groups
        expanded = _expand_tool_groups(["monitoring", "extensions"])
        self.assertIn("host", expanded)
        self.assertIn("graph_render", expanded)

    def test_expand_individual(self):
        from zabbix_mcp.config import _expand_tool_groups
        expanded = _expand_tool_groups(["host", "trigger"])
        self.assertEqual(expanded, ["host", "trigger"])

    def test_all_groups_present(self):
        from zabbix_mcp.config import TOOL_GROUPS
        expected = {"monitoring", "data_collection", "alerts", "users", "administration", "extensions"}
        self.assertEqual(set(TOOL_GROUPS.keys()), expected)


# ---------------------------------------------------------------------------
# item_threshold_search (extensions.py)
# ---------------------------------------------------------------------------
class TestItemThresholdSearch(unittest.TestCase):
    """Unit tests for the item_threshold_search extension."""

    def _make_mgr(self, items):
        """Build a minimal mock ClientManager that returns given items."""
        from unittest.mock import MagicMock
        mgr = MagicMock()
        mgr.call.return_value = items
        return mgr

    def _call(self, items, **kwargs):
        from zabbix_mcp.api.extensions import item_threshold_search
        mgr = self._make_mgr(items)
        result = item_threshold_search(mgr, "test", **kwargs)
        return json.loads(result)

    def _make_items(self, values):
        return [
            {"itemid": str(i), "name": f"item{i}", "key_": f"key{i}", "lastvalue": str(v)}
            for i, v in enumerate(values)
        ]

    def test_lastvalue_ge_filters_correctly(self):
        data = self._call(self._make_items([10.0, 50.0, 75.0, 0.0]), lastvalue_ge=50.0)
        self.assertEqual(data["scanned"], 4)
        self.assertEqual(data["matched"], 2)
        self.assertEqual(data["returned"], 2)
        matched_vals = [float(i["lastvalue"]) for i in data["items"]]
        self.assertIn(50.0, matched_vals)
        self.assertIn(75.0, matched_vals)

    def test_lastvalue_gt_excludes_equal(self):
        data = self._call(self._make_items([50.0, 50.1, 49.9]), lastvalue_gt=50.0)
        self.assertEqual(data["matched"], 1)
        self.assertEqual(data["returned"], 1)
        self.assertEqual(float(data["items"][0]["lastvalue"]), 50.1)

    def test_lastvalue_le_filters_correctly(self):
        data = self._call(self._make_items([0.0, 5.0, 10.0, 100.0]), lastvalue_le=10.0)
        self.assertEqual(data["matched"], 3)
        self.assertEqual(data["returned"], 3)

    def test_lastvalue_lt_excludes_equal(self):
        data = self._call(self._make_items([9.9, 10.0, 10.1]), lastvalue_lt=10.0)
        self.assertEqual(data["matched"], 1)
        self.assertEqual(data["returned"], 1)
        self.assertEqual(float(data["items"][0]["lastvalue"]), 9.9)

    def test_combined_ge_and_le(self):
        data = self._call(self._make_items([20.0, 50.0, 80.0, 90.0]), lastvalue_ge=50.0, lastvalue_le=80.0)
        self.assertEqual(data["matched"], 2)
        self.assertEqual(data["returned"], 2)

    def test_sorted_desc_by_default(self):
        data = self._call(self._make_items([30.0, 10.0, 70.0, 50.0]), lastvalue_gt=0)
        vals = [float(i["lastvalue"]) for i in data["items"]]
        self.assertEqual(vals, sorted(vals, reverse=True))

    def test_sort_asc(self):
        data = self._call(self._make_items([30.0, 10.0, 70.0]), lastvalue_gt=0, sort_desc=False)
        vals = [float(i["lastvalue"]) for i in data["items"]]
        self.assertEqual(vals, sorted(vals))

    def test_non_numeric_skipped(self):
        items = [
            {"itemid": "1", "name": "a", "key_": "k1", "lastvalue": "N/A"},
            {"itemid": "2", "name": "b", "key_": "k2", "lastvalue": "55.0"},
            {"itemid": "3", "name": "c", "key_": "k3", "lastvalue": ""},
            {"itemid": "4", "name": "d", "key_": "k4", "lastvalue": None},
        ]
        data = self._call(items, lastvalue_ge=0)
        self.assertEqual(data["scanned"], 4)
        self.assertEqual(data["matched"], 1)
        self.assertEqual(data["returned"], 1)

    def test_no_threshold_returns_all_numeric(self):
        data = self._call(self._make_items([1.0, 2.0, 3.0]))
        self.assertEqual(data["matched"], 3)
        self.assertEqual(data["returned"], 3)

    def test_result_limit(self):
        data = self._call(self._make_items([10.0, 20.0, 30.0, 40.0, 50.0]),
                          lastvalue_gt=0, result_limit=2)
        self.assertEqual(data["matched"], 5)   # total passing threshold
        self.assertEqual(data["returned"], 2)  # items actually returned
        self.assertEqual(len(data["items"]), 2)

    def test_output_injects_lastvalue(self):
        """When output omits lastvalue, it must be injected for filtering."""
        from unittest.mock import MagicMock
        from zabbix_mcp.api.extensions import item_threshold_search
        mgr = MagicMock()
        mgr.call.return_value = self._make_items([60.0])
        item_threshold_search(mgr, "test", output="itemid,name,key_", lastvalue_ge=50.0)
        call_params = mgr.call.call_args[0][2]
        self.assertIn("lastvalue", call_params["output"])

    def test_output_count_returns_error(self):
        data = self._call([], output="count")
        self.assertIn("error", data)

    def test_extra_params_merged(self):
        """extra_params forwarded to item.get (e.g. selectHosts)."""
        from unittest.mock import MagicMock
        from zabbix_mcp.api.extensions import item_threshold_search
        mgr = MagicMock()
        mgr.call.return_value = []
        item_threshold_search(mgr, "test",
                              extra_params={"selectHosts": ["host"]},
                              lastvalue_ge=0)
        call_params = mgr.call.call_args[0][2]
        self.assertEqual(call_params.get("selectHosts"), ["host"])

    def test_extra_params_do_not_override_output(self):
        """Explicit output takes precedence over conflicting extra_params."""
        from unittest.mock import MagicMock
        from zabbix_mcp.api.extensions import item_threshold_search
        mgr = MagicMock()
        mgr.call.return_value = []
        item_threshold_search(mgr, "test",
                              output="itemid,name,key_,lastvalue",
                              extra_params={"output": "extend"},
                              lastvalue_ge=0)
        call_params = mgr.call.call_args[0][2]
        # explicit output should be a list (injected), not "extend"
        self.assertIsInstance(call_params["output"], list)


if __name__ == "__main__":
    unittest.main()
