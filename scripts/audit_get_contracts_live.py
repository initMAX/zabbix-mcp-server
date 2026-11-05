#!/usr/bin/env python3
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

"""Check ``api/get_contracts.json`` against a running Zabbix (read-only).

For every get method with a contract it asks the server for:

* ``output`` = every property the catalog lists for this release, then
  compares the keys that come back: a returned key the catalog lacks is a
  documentation gap, a catalogued property that never comes back (on an
  object that has rows) is a property the server does not know;
* each ``sortfield`` value on its own: an error means the catalog is wrong;
* each ``selectXxx`` with ``"count"`` / ``"extend"``: an error means the
  select does not exist on this release.

Usage: audit_get_contracts_live.py URL TOKEN   (or URL USER PASSWORD)
Nothing is written to the Zabbix server.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from zabbix_mcp.api.contracts import CONTRACTS, OBJECTS, filter_props, output_props, search_props  # noqa: E402
from zabbix_mcp.api.versions import unavailable_reason  # noqa: E402

# Methods whose get needs a mandatory parameter or is not a classic get.
SKIP = {"sla.getsli", "script.getscriptsbyhosts", "script.getscriptsbyevents", "task.get"}


class Api:
    def __init__(self, url: str, token: str | None, user: str | None, password: str | None):
        self.url = url.rstrip("/") + "/api_jsonrpc.php"
        self.token = token
        self.n = 0
        # Zabbix before 6.4 knows no Authorization header: the session id
        # travels in the ``auth`` body field. 5.0/5.2 call the login field ``user``.
        self.version = self.call("apiinfo.version", {}, auth=False)
        major_minor = tuple(int(x) for x in self.version.split(".")[:2])
        self.header_auth = major_minor >= (6, 4)
        if not token:
            field = "username" if major_minor >= (5, 4) else "user"
            self.token = self.call("user.login", {field: user, "password": password}, auth=False)

    def call(self, method: str, params, auth: bool = True):
        self.n += 1
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": self.n}
        headers = {"Content-Type": "application/json-rpc"}
        if auth and self.token:
            if self.header_auth:
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                payload["auth"] = self.token
        body = json.dumps(payload).encode()
        req = urllib.request.Request(self.url, data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        if "error" in data:
            raise RuntimeError(f"{data['error'].get('message')} {data['error'].get('data')}")
        return data["result"]


def main() -> int:
    args = sys.argv[1:]
    if len(args) == 2:
        api = Api(args[0], args[1], None, None)
    elif len(args) == 3:
        api = Api(args[0], None, args[1], args[2])
    else:
        raise SystemExit(__doc__)
    version = api.version
    print(f"Zabbix {version}")
    problems = 0
    observed: dict[str, dict] = {}     # object -> {prop: {...}} returned by the server, absent from the catalog
    not_output: dict[str, list] = {}   # object -> catalogued props a strict method refuses in output
    not_filter: dict[str, list] = {}   # object -> props the server ignores in filter
    not_search: dict[str, list] = {}   # object -> props the server ignores in search
    returned: dict[str, list] = {}     # object -> every key output=extend returned (for since/removed of observed props)
    sort_ok: dict[str, dict] = {}      # method -> {sortfield: accepted?}
    for method, c in sorted(CONTRACTS.items()):
        if method in SKIP:
            continue
        if unavailable_reason(method, version):
            print(f"  skip {method}: {unavailable_reason(method, version)}")
            continue
        base: dict = {"limit": 1} if "limit" in c.common else {}
        if method == "history.get":
            base["history"] = 0
        try:
            base.update(_required_params(api, method))
        except Exception as exc:
            print(f"  skip {method}: cannot build its required parameters ({exc})")
            continue
        props = [p.name for p in output_props(c, version)]
        # 1. output = every catalogued property. Methods that validate
        #    ``output`` strictly answer with the complete allowed list, which
        #    is the best possible cross-check of the catalog.
        try:
            rows = api.call(method, dict(base, output=props))
        except Exception as exc:
            text = str(exc)
            if "value must be one of" in text:
                allowed = re.findall(r'"([A-Za-z0-9_]+)"', text.split("value must be one of", 1)[1])
            elif re.search(r'value must be "[A-Za-z0-9_]+"', text):
                allowed = re.findall(r'value must be "([A-Za-z0-9_]+)"', text)
            else:
                allowed = None
            if allowed is not None:
                allowed = list(dict.fromkeys(allowed))
                extra = sorted(set(props) - set(allowed))
                missing = sorted(set(allowed) - set(OBJECTS[c.object].props))
                print(f"STRICT {method}: catalogued but not an output property: {extra}; "
                      f"allowed but not catalogued: {missing}")
                for name in missing:
                    observed.setdefault(c.object, {})[name] = {"type": "", "observed": version, "strict": True}
                not_output.setdefault(c.object, []).extend(extra)
                try:
                    rows = api.call(method, dict(base, output=allowed))
                except Exception as exc2:
                    print(f"FAIL {method} output(allowed): {exc2}")
                    rows = []
            elif "APM DB is not configured" in text:
                # the OpenTelemetry tools need the APM database; nothing to probe without it
                print(f"  skip {method}: no APM database on this server")
                continue
            else:
                print(f"FAIL {method} output(all): {exc}")
                rows = []
            problems += 1
        if isinstance(rows, dict):
            rows = [rows]
        if rows:
            got = set(rows[0].keys())
            try:
                full = api.call(method, dict(base, output="extend"))
                full = full[0] if isinstance(full, list) and full else full
                got_extend = set(full.keys()) if isinstance(full, dict) else set()
            except Exception:
                got_extend = set()
            if got_extend:
                returned[c.object] = sorted(got_extend)
            missing_in_catalog = sorted(got_extend - set(c and OBJECTS[c.object].props))
            not_returned = sorted(set(props) - got - {"_local"})
            # a property that 'extend' returns but output=[...] does not (and vice versa) is fine;
            # what matters is: keys the server returns that the catalog has never heard of.
            if missing_in_catalog:
                print(f"GAP  {method}: server returns {missing_in_catalog} - not in the {c.object} catalog")
                for name in missing_in_catalog:
                    observed.setdefault(c.object, {})[name] = {
                        "type": _guess_type(rows[0].get(name, full.get(name))), "observed": version}
                problems += 1
            unknown = sorted(set(props) - got_extend) if got_extend else []
            if unknown:
                print(f"NOTE {method}: catalogued but not returned by output=extend: {unknown}")
        else:
            print(f"  (no rows) {method}")
        # 1b. filter / search on every candidate property: a value that can
        #     match nothing must return no rows; rows back = silently ignored.
        if rows and "filter" in c.common:
            for spec in filter_props(c, version):
                probe = "zz-no-such-value-zz" if spec.type.lower() not in ("integer", "id", "timestamp") else "999999999"
                try:
                    got = api.call(method, dict(base, output=props[:1] or "extend", filter={spec.name: probe}))
                except Exception:
                    continue  # an error means the filter was applied (type mismatch), fine
                if got:
                    not_filter.setdefault(c.object, []).append(spec.name)
            if not_filter.get(c.object):
                print(f"IGNORED {method} filter on: {sorted(set(not_filter[c.object]))}")
        if rows and "search" in c.common:
            for spec in search_props(c, version):
                try:
                    got = api.call(method, dict(base, output=props[:1] or "extend", search={spec.name: "zz-no-such-value-zz"}))
                except Exception:
                    continue
                if got:
                    not_search.setdefault(c.object, []).append(spec.name)
            if not_search.get(c.object):
                print(f"IGNORED {method} search on: {sorted(set(not_search[c.object]))}")
        # 2. sortfield values
        if "sortfield" in c.common:
            for f in c.sortfield:
                try:
                    api.call(method, dict(base, output=props[:1] or "extend", sortfield=f))
                    sort_ok.setdefault(method, {})[f] = True
                except Exception as exc:
                    sort_ok.setdefault(method, {})[f] = False
                    if f in c.sortable(version):
                        print(f"FAIL {method} sortfield={f}: {exc}")
                        problems += 1
        # 3. selects
        for name, spec in c.selects.items():
            if not spec.available(version):
                continue
            if method == "user.get" and name == "selectRole" and tuple(int(x) for x in version.split(".")[:2]) < (5, 4):
                continue
            if spec.type != "query":
                continue  # takes its own object, not "extend" (service.get selectStatusTimeline wants periods)
            try:
                api.call(method, dict(base, output=props[:1] or "extend", **{name: "extend"}))
            except Exception as exc:
                print(f"FAIL {method} {name}: {exc}")
                problems += 1
        # 4. native parameters: an unknown one is ignored by most methods, so only the
        #    ones with a documented value list can be probed cheaply - skipped here.
    report = Path.cwd() / f"get_contracts_observed_{version}.json"
    report.write_text(json.dumps({"zabbix": version, "observed": observed, "not_output": not_output,
                                  "not_filter": {k: sorted(set(v)) for k, v in not_filter.items()},
                                  "not_search": {k: sorted(set(v)) for k, v in not_search.items()},
                                  "returned": returned, "sort_ok": sort_ok},
                                 indent=1) + "\n")
    print(f"done: {api.n} API calls, {problems} problem(s); observations in {report}")
    return 1 if problems else 0


def _required_params(api, method: str) -> dict:
    """What a get method refuses to run without."""
    if method == "hostdashboard.get":
        hosts = (api.call("host.get", {"output": ["hostid"], "filter": {"host": "Zabbix server"}})
                 or api.call("host.get", {"output": ["hostid"], "limit": 1}))
        return {"hostids": [hosts[0]["hostid"]]}
    if method == "serverinfo.get":
        return {"serverid": api.call("settings.get", {"output": ["serverid"]})["serverid"]}
    if method.startswith("apm"):
        now = int(time.time())
        return {"time_from": now - 3600, "time_till": now}
    return {}


def _guess_type(value) -> str:
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]+", value or "x"):
        return "integer"
    return "string"


if __name__ == "__main__":
    sys.exit(main())
