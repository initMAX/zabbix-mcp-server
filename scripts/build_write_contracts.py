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

"""Build ``api/write_contracts.json`` from the per-release files written by
``scripts/audit_write_roundtrip_live.py``.

    python3 scripts/build_write_contracts.py write_roundtrip_observed_6.0.48.json ... \
        [--src scripts/write_contracts_src]

For every ``X.update`` the audit measured, a path is part of the contract
when the plain objects that carried it were *always* refused with it on a
release: a read-only property (``templateid``, ``flags``, ``state``,
``error``, ``lastclock``), a row identifier inside a nested array
(``operations[].operationid``), or a sub-object that only ``selectXxx``
produces (``hosts``, ``triggers``, ``discoveryRule``). A path refused on
every measured release applies everywhere; one refused on some releases
only carries the list of those releases and applies on no other (an
unmeasured release gets the universal paths only). A path refused only
sometimes on one release depends on the object's state and is left to the
hand-written rules (``api/action_payload.py``,
``server._sanitize_create_params``), as is everything the audit saw on
templated or discovered objects only, since there the refusal means "edit
the template", which the model must hear.

A documented, writable, top-level property of the object is never stripped
on the strength of an ``unexpected parameter`` alone, because the refusal
may depend on the object's kind (an SSH script's ``username`` is refused on
a webhook script; ``ldap_host`` on an installation without LDAP) and the
model's own value would be lost: such a property is stripped only when it
is a parent reference an update cannot change (type ID: ``hostid`` on an
item), when Zabbix says it "cannot be updated", when it is a ``uuid``, or
when it is one of the few listed exceptions below.

``X.create`` gets the same paths minus the top-level keys that are documented
non-read-only properties of the object (``hostid`` on ``item.create``,
``imagetype`` on ``image.create``), which an update refuses only because the
object already has them.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from zabbix_mcp.api import ALL_METHODS  # noqa: E402
from zabbix_mcp.api.contracts import CONTRACTS, OBJECTS  # noqa: E402

KNOWN_METHODS = {m.api_method for m in ALL_METHODS}

RELEASES = ("5.0", "5.2", "5.4", "6.0", "6.2", "6.4", "7.0", "7.2", "7.4", "8.0")
OUT = Path(__file__).resolve().parent.parent / "src" / "zabbix_mcp" / "api" / "write_contracts.json"

# Refusal kinds that depend on the object's state, not on the key: handled by
# hand-written rules.
_CONDITIONAL = ("value must be empty", "should be empty", "row-dependent")

# Objects whose write payload has hand-written, state-dependent rules
# (api/action_payload.py): the generic contract leaves them alone.
_HAND_RULED = ("action.update", "correlation.update")

# Documented writable properties an update refuses whatever the value, and
# that no caller can mean: a host's auto_compress (a proxy setting the host
# table still carried up to 6.4), an image's type (fixed at creation).
_IMMUTABLE_ANYWAY = {("host.update", "auto_compress"), ("image.update", "imagetype"),
                     ("module.update", "id"), ("module.update", "relative_path"),   # a module's id / path are its file
                     ("service.update", "created_at")}   # set by the server, documented without the read-only mark

# Measured refused on every fixture row but known to depend on the row:
# a host prototype's SNMP interface needs ``details`` (the fixture rows were
# agent interfaces, where 6.2 refuses the empty ``details``).
_KNOWN_ROW_DEPENDENT = {("hostprototype.update", "interfaces[].details"),
                        # 6.x answers an "Unsupported ..." without naming the key for the
                        # read-only eval_formula / formulaid inside an LLD filter, which the
                        # bisect then blames on the whole filter; the hand rule handles it
                        ("discoveryrule.update", "filter"), ("discoveryruleprototype.update", "filter")}


def _documented_writable(obj: str, prop: str, spec, refused: list[str]) -> bool:
    """A property the reference page lists as writable on a release where it
    was refused. Not: a property only a live server returned (``observed``,
    the host columns a template shares), one the base object marks read-only
    (``error`` on a trigger prototype as on a trigger), or one documented for
    other releases only (``name`` of a 6.0 proxy, a 7.0 field)."""
    if spec.readonly or spec.observed:
        return False
    base = obj[:-len("prototype")] if obj.endswith("prototype") else None
    if base and base in OBJECTS:
        base_spec = OBJECTS[base].props.get(prop)
        if base_spec is not None and base_spec.readonly:
            return False
    return any(spec.available(r + ".0") for r in refused)


def _release(version: str) -> str:
    return ".".join(version.split(".")[:2])


def main(argv: list[str]) -> None:
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        raise SystemExit(__doc__)
    # method -> path -> release -> "refused" | "accepted"
    seen: dict[str, dict[str, dict[str, str]]] = {}
    kinds: dict[tuple[str, str], str] = {}
    # a key whose refusal depended on the row on any release depends on it
    # everywhere; a release whose sample rows happened to share the state
    # must not turn it into a rule there
    conditional: set[tuple[str, str]] = set()
    releases_measured: set[str] = set()
    # X.create measured on its own (scripts/audit_create_copy_live.py): method -> path ->
    # release -> "refused" | "accepted". An update cannot show what only a create refuses
    # (macros[].automatic, which host.update takes and host.create does not).
    create_seen: dict[str, dict[str, dict[str, str]]] = {}
    create_paths = [p for p in paths if "create_observed" in Path(p).name]
    paths = [p for p in paths if p not in create_paths]
    for path in create_paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        release = _release(str(data["zabbix"]))
        if release not in RELEASES:
            raise SystemExit(f"{path}: unknown release {release}")
        for method, refused_paths in (data.get("refused") or {}).items():
            by_path = create_seen.setdefault(method, {})
            for p in refused_paths:
                by_path.setdefault(p, {})[release] = "refused"
            by_path.setdefault("", {})[release] = "measured"
    for method, by_path in create_seen.items():
        measured = by_path.pop("", {})
        for p, by_release in by_path.items():
            for r in measured:
                by_release.setdefault(r, "accepted")
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        release = _release(str(data["zabbix"]))
        if release not in RELEASES:
            raise SystemExit(f"{path}: unknown release {release}")
        releases_measured.add(release)
        for obj, info in (data.get("objects") or {}).items():
            method = f"{obj}.update"
            if method in _HAND_RULED:
                continue
            for p, v in (info.get("paths") or {}).items():
                cats = v.get("categories") or {}
                plain = cats.get("plain") if isinstance(cats, dict) else None
                if not plain:
                    continue   # templated / discovered only
                kind = str(v.get("kind", ""))
                if any(kind.startswith(c) for c in _CONDITIONAL):
                    conditional.add((method, p))
                    continue
                refused, present = plain.get("refused", 0), plain.get("present", 0)
                if present == 0:
                    continue   # only seen in probes that got stuck
                status = "refused" if refused >= present else "accepted"
                seen.setdefault(method, {}).setdefault(p, {})[release] = status
                kinds[(method, p)] = kind

    ordered = [r for r in RELEASES if r in releases_measured]
    methods: dict[str, dict] = {}
    warnings: list[str] = []
    for method, by_path in sorted(seen.items()):
        obj = method.split(".")[0]
        props = OBJECTS.get(CONTRACTS[f"{obj}.get"].object).props if f"{obj}.get" in CONTRACTS else {}
        strip_update: dict[str, dict] = {}
        for p, by_release in sorted(by_path.items()):
            refused = [r for r in ordered if by_release.get(r) == "refused"]
            accepted = [r for r in ordered if by_release.get(r) == "accepted"]
            if not refused:
                continue
            if (method, p) in _KNOWN_ROW_DEPENDENT or (method, p) in conditional:
                continue
            kind = kinds[(method, p)]
            top = "." not in p and "[]" not in p
            spec = props.get(p) if top else None
            if spec is not None and _documented_writable(obj, p, spec, refused):
                allowed = (spec.type == "ID" or kind.startswith("cannot be updated") or kind.startswith("deprecated:")
                           or p == "uuid" or (method, p) in _IMMUTABLE_ANYWAY)
                if not allowed:
                    warnings.append(f"{method} {p}: a documented writable property, refused on {refused} ({kind[:40]}); left to Zabbix")
                    continue
            entry: dict = {}
            if accepted or len(refused) < len(ordered):
                # not refused on every measured release: applies on these only
                entry["releases"] = refused
            if kind.startswith("deprecated:"):
                # 7.0 returns the deprecated twin next to the renamed field and
                # refuses them together; alone, the old name is still accepted
                entry["only_with"] = kind.split(":", 1)[1]
                entry["kind"] = "deprecated"
            elif kind != "unexpected":
                entry["kind"] = kind[:60]
            strip_update[p] = entry
        if not strip_update:
            continue
        strip_create = {}
        for p, entry in strip_update.items():
            top = "." not in p and "[]" not in p
            spec = props.get(p) if top else None
            if top and spec is not None and _documented_writable(obj, p, spec, entry.get("releases") or ordered):
                continue   # a create field the update refuses because it is already set
                # (a property only a live server returned, such as an LLD rule's lifetime
                # on an 8.0 item, is no create field: item.create refuses it as well)
            if p == "uuid" or p.endswith(".uuid"):
                continue   # a create may carry a uuid (template objects)
            strip_create[p] = entry
        methods[method] = {"strip": strip_update}
        create = method.replace(".update", ".create")
        if strip_create and create in KNOWN_METHODS:   # settings / housekeeping / ... have no create
            methods[create] = {"strip": strip_create}

    for method, by_path in sorted(create_seen.items()):
        obj = method.split(".")[0]
        props = OBJECTS.get(CONTRACTS[f"{obj}.get"].object).props if f"{obj}.get" in CONTRACTS else {}
        strip = methods.setdefault(method, {"strip": {}})["strip"]
        for p, by_release in sorted(by_path.items()):
            refused = [r for r in RELEASES if by_release.get(r) == "refused"]
            accepted = [r for r in RELEASES if by_release.get(r) == "accepted"]
            if not refused or p == "uuid" or p.endswith(".uuid"):
                continue
            top = "." not in p and "[]" not in p
            spec = props.get(p) if top else None
            if spec is not None and _documented_writable(obj, p, spec, refused):
                warnings.append(f"{method} {p}: a documented writable property, refused by a create on {refused}; left to Zabbix")
                continue
            have = strip.get(p)
            if have is not None and not have.get("releases"):
                continue            # already stripped on every release
            releases = sorted(set(refused) | set((have or {}).get("releases") or ()), key=RELEASES.index)
            entry = dict(have or {})
            if accepted or set(releases) != set(ordered):
                entry["releases"] = releases
            else:
                entry.pop("releases", None)
            strip[p] = entry
        methods[method]["strip"] = dict(sorted(strip.items()))

    out = {
        "_comment": "Generated by scripts/build_write_contracts.py from scripts/audit_write_roundtrip_live.py "
                    "and scripts/audit_create_copy_live.py measurements. Do not edit by hand. Paths use [] for every element of an array; an entry "
                    "without 'releases' was refused on every measured release.",
        "releases": ordered,
        "methods": dict(sorted(methods.items())),
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    n_paths = sum(len(m["strip"]) for m in methods.values())
    print(f"{OUT}: {len(methods)} methods, {n_paths} paths, releases {', '.join(ordered)}")


if __name__ == "__main__":
    main(sys.argv[1:])
