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

"""Fetch Zabbix data and prepare report contexts."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from zabbix_mcp.client import ClientManager

logger = logging.getLogger("zabbix_mcp.reporting")


def _ts_to_str(ts: int | float) -> str:
    """Convert a Unix timestamp to a human-readable UTC string."""
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _get_hosts(
    client_manager: ClientManager,
    server_name: str,
    params: dict,
) -> list[dict[str, Any]]:
    """Resolve hosts from hostgroupid or explicit hostids."""
    if "hostids" in params:
        return client_manager.call(
            server_name,
            "host.get",
            {"hostids": params["hostids"], "output": ["hostid", "host", "name"]},
        )
    if "hostgroupid" in params:
        return client_manager.call(
            server_name,
            "host.get",
            {
                "groupids": [params["hostgroupid"]],
                "output": ["hostid", "host", "name"],
            },
        )
    raise ValueError("Either 'hostgroupid' or 'hostids' must be provided in params")


# ---------------------------------------------------------------------------
# Availability Report
# ---------------------------------------------------------------------------


def fetch_availability_data(
    client_manager: ClientManager,
    server_name: str,
    params: dict,
) -> dict:
    """Fetch availability data for the report.

    Parameters in *params*:
        hostgroupid or hostids, period_from (epoch), period_to (epoch),
        service_hours (str), operational_hours (str)

    Returns a dict suitable as Jinja2 context for ``availability.html``.
    """
    hosts = _get_hosts(client_manager, server_name, params)
    period_from = int(params["period_from"])
    period_to = int(params["period_to"])
    total_seconds = period_to - period_from

    host_results: list[dict[str, Any]] = []
    total_events = 0

    for host in hosts:
        hostid = host["hostid"]

        # Get events (problems) within the time range for this host
        events = client_manager.call(
            server_name,
            "event.get",
            {
                "hostids": [hostid],
                "time_from": period_from,
                "time_till": period_to,
                "source": 0,  # triggers
                "object": 0,  # triggers
                "value": 1,  # PROBLEM
                "output": ["eventid", "clock", "r_eventid"],
                "selectRelatedObject": ["triggerid", "priority"],
                "sortfield": ["clock"],
                "sortorder": "ASC",
            },
        )

        event_count = len(events)
        total_events += event_count

        # Calculate problem duration from events
        problem_seconds = 0
        for event in events:
            event_time = int(event["clock"])
            # Try to find the recovery event
            if event.get("r_eventid") and event["r_eventid"] != "0":
                recovery_events = client_manager.call(
                    server_name,
                    "event.get",
                    {
                        "eventids": [event["r_eventid"]],
                        "output": ["clock"],
                    },
                )
                if recovery_events:
                    recovery_time = int(recovery_events[0]["clock"])
                    # Clamp to the report period
                    start = max(event_time, period_from)
                    end = min(recovery_time, period_to)
                    if end > start:
                        problem_seconds += end - start
            else:
                # Unresolved problem — count until period_to
                start = max(event_time, period_from)
                problem_seconds += period_to - start

        if total_seconds > 0:
            availability_pct = ((total_seconds - problem_seconds) / total_seconds) * 100.0
        else:
            availability_pct = 100.0

        host_results.append(
            {
                "name": host.get("name") or host.get("host", ""),
                "event_count": event_count,
                "availability_pct": max(0.0, min(100.0, availability_pct)),
            }
        )

    # Overall availability
    if host_results:
        overall_pct = sum(h["availability_pct"] for h in host_results) / len(host_results)
    else:
        overall_pct = 100.0

    return {
        "hosts": host_results,
        "total_events": total_events,
        "availability_pct": overall_pct,
        "period_from": _ts_to_str(period_from),
        "period_to": _ts_to_str(period_to),
        "service_hours": params.get("service_hours", "24x7"),
        "operational_hours": params.get("operational_hours", "24x7"),
    }


# ---------------------------------------------------------------------------
# Capacity Report — Host
# ---------------------------------------------------------------------------

# Common item keys for capacity metrics
_CPU_KEYS = ["system.cpu.util", "system.cpu.util[,idle]"]
_MEMORY_KEYS = ["vm.memory.utilization", "vm.memory.size[pused]"]
_DISK_KEYS = ["vfs.fs.size[/,pused]", "vfs.fs.size[C:,pused]"]

_METRIC_DEFS = [
    ("CPU Usage", _CPU_KEYS),
    ("Memory Usage", _MEMORY_KEYS),
    ("Disk Usage", _DISK_KEYS),
]


def _get_trend_stats(
    client_manager: ClientManager,
    server_name: str,
    itemid: str,
    period_from: int,
    period_to: int,
) -> dict[str, float] | None:
    """Fetch trend data for an item and compute avg/min/max."""
    trends = client_manager.call(
        server_name,
        "trend.get",
        {
            "itemids": [itemid],
            "time_from": period_from,
            "time_till": period_to,
            "output": ["value_avg", "value_min", "value_max"],
        },
    )
    if not trends:
        return None

    avg_vals = [float(t["value_avg"]) for t in trends]
    min_vals = [float(t["value_min"]) for t in trends]
    max_vals = [float(t["value_max"]) for t in trends]

    return {
        "avg": sum(avg_vals) / len(avg_vals),
        "min": min(min_vals),
        "max": max(max_vals),
    }


def fetch_capacity_host_data(
    client_manager: ClientManager,
    server_name: str,
    params: dict,
) -> dict:
    """Fetch CPU/memory/disk capacity data per host.

    Parameters in *params*:
        hostgroupid or hostids, period_from (epoch), period_to (epoch)

    Returns a dict suitable as Jinja2 context for ``capacity_host.html``.
    """
    hosts = _get_hosts(client_manager, server_name, params)
    period_from = int(params["period_from"])
    period_to = int(params["period_to"])

    metrics: list[dict[str, Any]] = []

    for label, keys in _METRIC_DEFS:
        rows: list[dict[str, Any]] = []

        for host in hosts:
            hostid = host["hostid"]
            host_name = host.get("name") or host.get("host", "")

            # Find matching items for this host
            items = client_manager.call(
                server_name,
                "item.get",
                {
                    "hostids": [hostid],
                    "search": {"key_": keys[0]},
                    "searchByAny": True,
                    "output": ["itemid", "key_", "name"],
                    "limit": 1,
                },
            )
            # Try alternative keys if primary not found
            if not items and len(keys) > 1:
                for alt_key in keys[1:]:
                    items = client_manager.call(
                        server_name,
                        "item.get",
                        {
                            "hostids": [hostid],
                            "search": {"key_": alt_key},
                            "output": ["itemid", "key_", "name"],
                            "limit": 1,
                        },
                    )
                    if items:
                        break

            if not items:
                continue

            stats = _get_trend_stats(
                client_manager, server_name, items[0]["itemid"], period_from, period_to
            )
            if stats is None:
                continue

            # For cpu idle key, invert the value
            if items[0].get("key_", "").endswith(",idle]"):
                stats = {
                    "avg": 100.0 - stats["avg"],
                    "min": 100.0 - stats["max"],  # inverted
                    "max": 100.0 - stats["min"],  # inverted
                }

            rows.append(
                {
                    "endpoint": host_name,
                    "avg": stats["avg"],
                    "min": stats["min"],
                    "max": stats["max"],
                }
            )

        metrics.append({"label": label, "rows": rows})

    return {
        "hosts": hosts,
        "metrics": metrics,
        "period_from": _ts_to_str(period_from),
        "period_to": _ts_to_str(period_to),
    }


# ---------------------------------------------------------------------------
# Capacity Report — Network
# ---------------------------------------------------------------------------


def fetch_capacity_network_data(
    client_manager: ClientManager,
    server_name: str,
    params: dict,
) -> dict:
    """Fetch network bandwidth/traffic data per interface.

    Parameters in *params*:
        hostgroupid or hostids, period_from (epoch), period_to (epoch)

    Returns a dict suitable as Jinja2 context for ``capacity_network.html``.
    """
    hosts_raw = _get_hosts(client_manager, server_name, params)
    period_from = int(params["period_from"])
    period_to = int(params["period_to"])

    cpu_rows: list[dict[str, Any]] = []
    host_results: list[dict[str, Any]] = []

    for host in hosts_raw:
        hostid = host["hostid"]
        host_name = host.get("name") or host.get("host", "")

        # CPU usage for this host
        cpu_stats: dict[str, float] | None = None
        cpu_items = client_manager.call(
            server_name,
            "item.get",
            {
                "hostids": [hostid],
                "search": {"key_": "system.cpu.util"},
                "output": ["itemid", "key_"],
                "limit": 1,
            },
        )
        if cpu_items:
            cpu_stats = _get_trend_stats(
                client_manager, server_name, cpu_items[0]["itemid"], period_from, period_to
            )
            if cpu_stats:
                cpu_rows.append(
                    {
                        "endpoint": host_name,
                        "avg": cpu_stats["avg"],
                        "min": cpu_stats["min"],
                        "max": cpu_stats["max"],
                    }
                )

        # Network interfaces: look for net.if.in / net.if.out items
        net_items = client_manager.call(
            server_name,
            "item.get",
            {
                "hostids": [hostid],
                "search": {"key_": "net.if"},
                "output": ["itemid", "key_", "name"],
            },
        )

        # Group items by interface name (extract from key)
        iface_map: dict[str, dict[str, str]] = {}
        for item in net_items:
            key = item.get("key_", "")
            # Parse interface name from keys like net.if.in[eth0], net.if.out[eth0]
            if "[" in key and "]" in key:
                iface_name = key[key.index("[") + 1 : key.index("]")]
                if "," in iface_name:
                    iface_name = iface_name.split(",")[0]
                if iface_name not in iface_map:
                    iface_map[iface_name] = {}
                if "net.if.in" in key:
                    iface_map[iface_name]["in"] = item["itemid"]
                elif "net.if.out" in key:
                    iface_map[iface_name]["out"] = item["itemid"]

        interfaces: list[dict[str, Any]] = []
        for iface_name, item_ids in sorted(iface_map.items()):
            # Get bandwidth from either in or out trends
            max_bps = 0.0
            for direction in ("in", "out"):
                itemid = item_ids.get(direction)
                if not itemid:
                    continue
                stats = _get_trend_stats(
                    client_manager, server_name, itemid, period_from, period_to
                )
                if stats and stats["max"] > max_bps:
                    max_bps = stats["max"]

            # Convert bytes/sec to Mbit/s
            bandwidth_mbps = max_bps * 8.0 / 1_000_000.0

            # CPU stats for this interface context (same host-level CPU)
            cpu_stat = cpu_stats if cpu_stats else {"avg": 0.0, "min": 0.0, "max": 0.0}

            interfaces.append(
                {
                    "name": iface_name,
                    "bandwidth_mbps": bandwidth_mbps,
                    "cpu_avg": cpu_stat["avg"],
                    "cpu_min": cpu_stat["min"],
                    "cpu_max": cpu_stat["max"],
                }
            )

        host_results.append({"name": host_name, "interfaces": interfaces})

    return {
        "hosts": host_results,
        "cpu_rows": cpu_rows,
        "period_from": _ts_to_str(period_from),
        "period_to": _ts_to_str(period_to),
    }


# ---------------------------------------------------------------------------
# Backup Report
# ---------------------------------------------------------------------------


def fetch_backup_data(
    client_manager: ClientManager,
    server_name: str,
    params: dict,
) -> dict:
    """Fetch backup status per host per day.

    Parameters in *params*:
        hostgroupid or hostids, period_from (epoch), period_to (epoch),
        period_label (str, e.g. "March 2026"),
        backup_item_key (str, optional — defaults to searching for common
        backup item keys)

    Returns a dict suitable as Jinja2 context for ``backup.html``.
    """
    hosts = _get_hosts(client_manager, server_name, params)
    period_from = int(params["period_from"])
    period_to = int(params["period_to"])
    period_label = params.get("period_label", "")
    backup_key = params.get("backup_item_key", "")

    # Determine the day numbers in the report period
    from_dt = datetime.fromtimestamp(period_from, tz=timezone.utc)
    to_dt = datetime.fromtimestamp(period_to, tz=timezone.utc)

    # Build list of days (1-based day numbers)
    days: list[int] = []
    current = from_dt
    while current < to_dt:
        days.append(current.day)
        # Advance by one day
        next_day = current.replace(hour=0, minute=0, second=0) + timedelta(days=1)
        current = next_day

    # Remove duplicates and sort
    days = sorted(set(days))

    backup_matrix: list[dict[str, Any]] = []

    # Common backup-related item key patterns
    search_keys = (
        [backup_key] if backup_key else [
            "backup",
            "veeam",
            "bacula",
            "borg",
            "restic",
        ]
    )

    for host in hosts:
        hostid = host["hostid"]
        host_name = host.get("name") or host.get("host", "")

        # Find backup-related items
        backup_items: list[dict[str, Any]] = []
        for key in search_keys:
            items = client_manager.call(
                server_name,
                "item.get",
                {
                    "hostids": [hostid],
                    "search": {"key_": key},
                    "output": ["itemid", "key_", "name", "value_type"],
                },
            )
            if items:
                backup_items.extend(items)
                break  # Use the first matching key pattern

        statuses: dict[int, bool] = {}

        if backup_items:
            # Use the first matching item
            item = backup_items[0]

            # Fetch history for the period
            # value_type: 0=float, 1=str, 2=log, 3=unsigned, 4=text
            history_type = item.get("value_type", "3")
            history = client_manager.call(
                server_name,
                "history.get",
                {
                    "itemids": [item["itemid"]],
                    "time_from": period_from,
                    "time_till": period_to,
                    "output": ["clock", "value"],
                    "history": history_type,
                    "sortfield": "clock",
                    "sortorder": "ASC",
                },
            )

            # Group by day and determine success/failure
            for record in history:
                ts = int(record["clock"])
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                day_num = dt.day

                value = record.get("value", "")
                # Determine success: numeric 1/0, or string-based
                try:
                    numeric_val = float(value)
                    success = numeric_val >= 1.0
                except (ValueError, TypeError):
                    value_lower = str(value).lower()
                    success = any(
                        kw in value_lower for kw in ("success", "ok", "completed", "1")
                    )

                # Keep the latest status for each day
                statuses[day_num] = success
        else:
            # Also check triggers for backup-related problems
            triggers = client_manager.call(
                server_name,
                "trigger.get",
                {
                    "hostids": [hostid],
                    "search": {"description": "backup"},
                    "output": ["triggerid", "description"],
                    "limit": 5,
                },
            )

            if triggers:
                triggerids = [t["triggerid"] for t in triggers]
                events = client_manager.call(
                    server_name,
                    "event.get",
                    {
                        "objectids": triggerids,
                        "time_from": period_from,
                        "time_till": period_to,
                        "source": 0,
                        "object": 0,
                        "output": ["clock", "value"],
                        "sortfield": "clock",
                        "sortorder": "ASC",
                    },
                )

                # Track problem days
                problem_days: set[int] = set()
                for event in events:
                    ts = int(event["clock"])
                    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                    if event.get("value") == "1":  # PROBLEM
                        problem_days.add(dt.day)

                for day in days:
                    statuses[day] = day not in problem_days

        backup_matrix.append({"host": host_name, "statuses": statuses})

    return {
        "backup_matrix": backup_matrix,
        "days": days,
        "period_label": period_label,
    }
