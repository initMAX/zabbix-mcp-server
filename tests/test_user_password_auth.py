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

"""Auth by user/password (user.login) for Zabbix < 5.4.

API tokens only exist from Zabbix 5.4 onward. A [zabbix.<name>] section
may omit ``api_token`` and authenticate with ``username``/``password``
instead. When both are present, ``api_token`` takes precedence.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

from zabbix_mcp.config import AppConfig, ConfigError, ZabbixServerConfig, load_config
from zabbix_mcp.client import ClientManager


def _load_toml(body: str) -> "AppConfig":
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(body)
        f.flush()
        path = f.name
    try:
        return load_config(path)
    finally:
        os.unlink(path)


def _write_toml(body: str) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(body)
        f.flush()
        return f.name


class TestConfigUserPasswordAuth(unittest.TestCase):
    """load_config must accept username/password in place of api_token."""

    def test_username_password_without_api_token_is_valid(self):
        cfg = _load_toml(
            '[zabbix.prod]\n'
            'url = "http://zabbix.example.com"\n'
            'username = "admin"\n'
            'password = "secret"\n'
        )
        srv = cfg.zabbix_servers["prod"]
        self.assertFalse(srv.api_token)
        self.assertEqual(srv.username, "admin")
        self.assertEqual(srv.password, "secret")

    def test_missing_api_token_and_credentials_raises(self):
        path = _write_toml(
            '[zabbix.prod]\n'
            'url = "http://zabbix.example.com"\n'
        )
        try:
            with self.assertRaises(ConfigError) as ctx:
                load_config(path)
            msg = str(ctx.exception)
            self.assertIn("api_token", msg)
            self.assertIn("username", msg)
            self.assertIn("password", msg)
        finally:
            os.unlink(path)

    def test_only_username_missing_password_raises(self):
        path = _write_toml(
            '[zabbix.prod]\n'
            'url = "http://zabbix.example.com"\n'
            'username = "admin"\n'
        )
        try:
            with self.assertRaises(ConfigError):
                load_config(path)
        finally:
            os.unlink(path)

    def test_only_password_missing_username_raises(self):
        path = _write_toml(
            '[zabbix.prod]\n'
            'url = "http://zabbix.example.com"\n'
            'password = "secret"\n'
        )
        try:
            with self.assertRaises(ConfigError):
                load_config(path)
        finally:
            os.unlink(path)

    def test_api_token_still_valid(self):
        cfg = _load_toml(
            '[zabbix.prod]\n'
            'url = "http://zabbix.example.com"\n'
            'api_token = "tok"\n'
        )
        self.assertEqual(cfg.zabbix_servers["prod"].api_token, "tok")

    def test_api_token_takes_precedence_over_credentials(self):
        cfg = _load_toml(
            '[zabbix.prod]\n'
            'url = "http://zabbix.example.com"\n'
            'api_token = "tok"\n'
            'username = "admin"\n'
            'password = "secret"\n'
        )
        srv = cfg.zabbix_servers["prod"]
        self.assertEqual(srv.api_token, "tok")
        self.assertEqual(srv.username, "admin")
        self.assertEqual(srv.password, "secret")

    def test_credentials_resolve_env_vars(self):
        os.environ["_ZABBIX_TEST_USER"] = "admin"
        os.environ["_ZABBIX_TEST_PASS"] = "s3cr3t"
        try:
            cfg = _load_toml(
                '[zabbix.prod]\n'
                'url = "http://zabbix.example.com"\n'
                'username = "${_ZABBIX_TEST_USER}"\n'
                'password = "${_ZABBIX_TEST_PASS}"\n'
            )
        finally:
            del os.environ["_ZABBIX_TEST_USER"]
            del os.environ["_ZABBIX_TEST_PASS"]
        srv = cfg.zabbix_servers["prod"]
        self.assertEqual(srv.username, "admin")
        self.assertEqual(srv.password, "s3cr3t")

    def test_missing_env_var_in_password_raises(self):
        path = _write_toml(
            '[zabbix.prod]\n'
            'url = "http://zabbix.example.com"\n'
            'username = "admin"\n'
            'password = "${_NONEXISTENT_ZABBIX_PASS}"\n'
        )
        try:
            with self.assertRaises(ConfigError):
                load_config(path)
        finally:
            os.unlink(path)


class TestClientConnectAuth(unittest.TestCase):
    """ClientManager._connect must pick the right login flavour."""

    def _manager(self, api_token: str = "", username: str = "admin", password: str = "secret") -> ClientManager:
        srv = ZabbixServerConfig(
            name="test",
            url="http://zabbix.example.com",
            api_token=api_token,
            username=username,
            password=password,
        )
        return ClientManager(AppConfig(zabbix_servers={"test": srv}))

    def test_connect_logins_with_user_password_when_no_token(self):
        mgr = self._manager(api_token="")
        with patch("zabbix_mcp.client.ZabbixAPI") as mock_cls:
            instance = mock_cls.return_value
            instance.api_version.return_value = "5.0.0"
            mgr._connect("test")
            instance.login.assert_called_once_with(user="admin", password="secret")

    def test_connect_logins_with_token_when_present(self):
        mgr = self._manager(api_token="tok")
        with patch("zabbix_mcp.client.ZabbixAPI") as mock_cls:
            instance = mock_cls.return_value
            instance.api_version.return_value = "6.0.0"
            mgr._connect("test")
            instance.login.assert_called_once_with(token="tok")

    def test_connect_token_precedence_over_credentials(self):
        mgr = self._manager(api_token="tok", username="admin", password="secret")
        with patch("zabbix_mcp.client.ZabbixAPI") as mock_cls:
            instance = mock_cls.return_value
            instance.api_version.return_value = "6.0.0"
            mgr._connect("test")
            instance.login.assert_called_once_with(token="tok")

    def test_connect_calls_api_version_after_login(self):
        mgr = self._manager(api_token="")
        with patch("zabbix_mcp.client.ZabbixAPI") as mock_cls:
            instance = mock_cls.return_value
            instance.api_version.return_value = "5.0.0"
            client = mgr._connect("test")
            self.assertIs(client, instance)
            instance.login.assert_called_once()
            instance.api_version.assert_called_once()


if __name__ == "__main__":
    unittest.main()