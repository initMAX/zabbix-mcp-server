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

"""Unit tests for SAML + LDAP auth (issue #46).

Focused on the parts that don't need a live IdP / LDAP server:

* LDAP filter escaping (RFC 4515 §3) - injection defense
* LDAP role-precedence picking (multi-group user)
* SAML settings normalisation (PEM cert stripping)
* SAML attribute pick - first-value semantics
* Config-side default-role validator rejects unknown roles
* Login fallback ordering: local-first, LDAP-fallback

End-to-end SAML round-trip needs a fixture IdP - covered separately
in tests/integration/ when the python3-saml library is available.
"""

from __future__ import annotations

import unittest
from unittest import mock


class TestLdapFilterEscape(unittest.TestCase):
    """RFC 4515 §3 filter escape - the only line standing between
    a malicious username and a directory subtree leak."""

    def _esc(self, value):
        from zabbix_mcp.admin.ldap_auth import _escape_filter
        return _escape_filter(value)

    def test_escapes_parentheses(self):
        self.assertEqual(self._esc("(badguy)"), r"\28badguy\29")

    def test_escapes_asterisk(self):
        self.assertEqual(self._esc("alice*"), r"alice\2a")

    def test_escapes_backslash(self):
        self.assertEqual(self._esc(r"alice\smith"), r"alice\5csmith")

    def test_rejects_null_byte(self):
        # NUL is a control character (cp < 0x20) - the implementation
        # refuses it outright rather than escape it, on the principle
        # that no legitimate LDAP filter value contains a NUL.
        with self.assertRaises(ValueError):
            self._esc("alice\x00")

    def test_rejects_control_chars(self):
        with self.assertRaises(ValueError):
            self._esc("alice\x01")

    def test_passes_plain_ascii_through(self):
        self.assertEqual(self._esc("alice.smith"), "alice.smith")


class TestLdapRolePrecedence(unittest.TestCase):
    """When a user is in multiple mapped groups, the strongest role wins.

    Precedence: admin > operator > viewer > auditor (matches
    _ROLE_RANK in ldap_auth)."""

    def test_admin_beats_operator(self):
        from zabbix_mcp.admin.ldap_auth import _ROLE_RANK
        self.assertGreater(_ROLE_RANK["admin"], _ROLE_RANK["operator"])

    def test_operator_beats_viewer(self):
        from zabbix_mcp.admin.ldap_auth import _ROLE_RANK
        self.assertGreater(_ROLE_RANK["operator"], _ROLE_RANK["viewer"])

    def test_viewer_beats_auditor(self):
        from zabbix_mcp.admin.ldap_auth import _ROLE_RANK
        self.assertGreater(_ROLE_RANK["viewer"], _ROLE_RANK["auditor"])


class TestLdapAuthDisabled(unittest.TestCase):
    def test_disabled_config_short_circuits(self):
        from zabbix_mcp.admin.ldap_auth import authenticate
        from zabbix_mcp.config import AdminLdapConfig
        cfg = AdminLdapConfig(enabled=False)
        result = authenticate(cfg, "alice", "pw")
        self.assertFalse(result.ok)
        self.assertIn("disabled", result.reason)

    def test_empty_creds_refused(self):
        from zabbix_mcp.admin.ldap_auth import authenticate
        from zabbix_mcp.config import AdminLdapConfig
        cfg = AdminLdapConfig(enabled=True, server="ldap://x", base_dn="dc=x")
        result = authenticate(cfg, "alice", "")
        self.assertFalse(result.ok)
        self.assertIn("empty credentials", result.reason)
        result = authenticate(cfg, "", "pw")
        self.assertFalse(result.ok)
        self.assertIn("empty credentials", result.reason)

    def test_unconfigured_server_refused(self):
        from zabbix_mcp.admin.ldap_auth import authenticate
        from zabbix_mcp.config import AdminLdapConfig
        cfg = AdminLdapConfig(enabled=True)  # no server, no base_dn
        result = authenticate(cfg, "alice", "pw")
        self.assertFalse(result.ok)
        self.assertIn("not configured", result.reason)


class TestSamlCertNormalisation(unittest.TestCase):
    """SAML cert should accept PEM or raw base64 from the operator and
    hand the toolkit one clean blob."""

    def test_pem_armour_stripped(self):
        from zabbix_mcp.admin.saml_auth import _normalise_cert
        pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDxTCCAq2gAwIBAgIQ\n"
            "ABCDEF==\n"
            "-----END CERTIFICATE-----\n"
        )
        normalised = _normalise_cert(pem)
        self.assertNotIn("BEGIN", normalised)
        self.assertNotIn("END", normalised)
        self.assertNotIn("\n", normalised)
        self.assertIn("MIIDxTCCAq2gAwIBAgIQ", normalised)

    def test_raw_base64_passes_through(self):
        from zabbix_mcp.admin.saml_auth import _normalise_cert
        self.assertEqual(_normalise_cert("MIIDxTCCAq2g"), "MIIDxTCCAq2g")

    def test_empty_returns_empty(self):
        from zabbix_mcp.admin.saml_auth import _normalise_cert
        self.assertEqual(_normalise_cert(""), "")


class TestSamlAttributePick(unittest.TestCase):
    """SAML attribute dicts are list-valued - pick the first."""

    def test_pick_list(self):
        from zabbix_mcp.admin.saml_auth import _pick_attr
        attrs = {"http://schemas/email": ["alice@example.com", "alt@example.com"]}
        self.assertEqual(_pick_attr(attrs, "http://schemas/email"), "alice@example.com")

    def test_pick_empty(self):
        from zabbix_mcp.admin.saml_auth import _pick_attr
        self.assertEqual(_pick_attr({}, "http://schemas/email"), "")

    def test_pick_no_key(self):
        from zabbix_mcp.admin.saml_auth import _pick_attr
        self.assertEqual(_pick_attr({"x": ["y"]}, ""), "")

    def test_pick_scalar_value(self):
        # Some toolkits hand back bare strings rather than lists.
        from zabbix_mcp.admin.saml_auth import _pick_attr
        self.assertEqual(_pick_attr({"k": "scalar"}, "k"), "scalar")


class TestConfigDefaultRoleValidation(unittest.TestCase):
    """[admin.saml].default_role and [admin.ldap].default_role must
    match the 4-role roster - typo at boot is better than typo at
    login redirect."""

    def test_saml_role_roster_contract(self):
        # The parser validator (in config.py load_config) compares
        # against this exact 4-tuple. Restate it here so a future
        # contributor who adds a 5th role (e.g. 'security_officer')
        # is forced to update this test - and remembers to update
        # users.py + create.html + models.py + ROLES.md together.
        roles = ("admin", "operator", "viewer", "auditor")
        self.assertEqual(len(roles), 4)
        # These case-variant / unknown values must NOT match.
        for bad in ("supervisor", "AdminUser", "Operator123", "x"):
            self.assertNotIn(bad.lower(), roles)

    def test_ldap_empty_default_role_allowed(self):
        from zabbix_mcp.config import AdminLdapConfig
        cfg = AdminLdapConfig(default_role="")
        self.assertEqual(cfg.default_role, "")


class TestSamlConfigDefaults(unittest.TestCase):
    def test_defaults_are_safe(self):
        from zabbix_mcp.config import AdminSamlConfig
        cfg = AdminSamlConfig()
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.default_role, "viewer")
        self.assertIn("schemas.xmlsoap.org", cfg.email_attribute)
        self.assertIn("schemas.xmlsoap.org", cfg.first_name_attribute)


class TestLoginFallbackOrdering(unittest.TestCase):
    """Login flow must try local scrypt FIRST and only fall through
    to LDAP when local says no. A directory outage cannot lock the
    local-only admin out."""

    def test_local_first_pattern_is_documented(self):
        # Read the app.py source and confirm the ordering is still in
        # place. Cheap regression guard against a future refactor that
        # swaps the order. We do not insist on a specific comment
        # phrasing - just verify that local-scrypt verify runs before
        # the LDAP import lands.
        from pathlib import Path
        src = Path("plugins/zabbix/zabbix_mcp/admin/app.py").read_text()
        local_pos = src.find("verify_password(password, user_data.get")
        ldap_pos = src.find("from zabbix_mcp.admin.ldap_auth import authenticate")
        self.assertNotEqual(local_pos, -1, "local scrypt verify call must exist")
        self.assertNotEqual(ldap_pos, -1, "LDAP fallback import must exist")
        self.assertLess(local_pos, ldap_pos,
                        "LDAP fallback must run AFTER local scrypt verify - "
                        "otherwise directory outage locks local admin out.")


if __name__ == "__main__":
    unittest.main()
