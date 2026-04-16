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


if __name__ == "__main__":
    unittest.main()
