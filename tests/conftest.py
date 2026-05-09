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

"""pytest bootstrap - put the bundled Zabbix module on sys.path.

The bundled module moved from ``src/zabbix_mcp/`` to
``plugins/zabbix/zabbix_mcp/`` in v1.31. The editable install
(`pip install -e .`) re-creates the ``zabbix_mcp`` import name from
``[tool.hatch.build.targets.wheel] packages``, but a venv that was
installed before the move points at the old ``src/`` path and
breaks. This conftest is a belt + suspenders so the test suite works
regardless of whether the venv has been re-installed.
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_PATH = os.path.normpath(os.path.join(_HERE, "..", "plugins", "zabbix"))
if _PLUGIN_PATH not in sys.path:
    sys.path.insert(0, _PLUGIN_PATH)
