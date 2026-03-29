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
