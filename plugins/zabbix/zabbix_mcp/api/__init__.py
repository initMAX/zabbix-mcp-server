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

"""Aggregates all Zabbix API method definitions into a single registry."""

from zabbix_mcp.api.monitoring import MONITORING_METHODS
from zabbix_mcp.api.data_collection import DATA_COLLECTION_METHODS
from zabbix_mcp.api.alerts import ALERTS_METHODS
from zabbix_mcp.api.users import USERS_METHODS
from zabbix_mcp.api.administration import ADMINISTRATION_METHODS
from zabbix_mcp.api.types import MethodDef

ALL_METHODS: list[MethodDef] = [
    *MONITORING_METHODS,
    *DATA_COLLECTION_METHODS,
    *ALERTS_METHODS,
    *USERS_METHODS,
    *ADMINISTRATION_METHODS,
]
