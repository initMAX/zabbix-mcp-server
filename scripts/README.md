# Pre-release smoke runners

The two smoke runners target the running MCP server's HTTP transport
via the official `mcp` Python SDK; they are part of the pre-release ritual
documented in `CONTRIBUTING.md`. Wire-compatible with any Zabbix MCP
deployment, but the canonical target is the `Wiki-topics` test instance
(`https://student-postgresql-01.initmax.cz`).

## `test_all_tools.py` - synthetic CRUD coverage

Calls every tool listed by `tools/list` with hand-crafted minimal arguments
derived from sample IDs probed up front. Read-only tools (`*_get`,
`*_export`, ...) get `output=extend` queries; write tools get a
parent-before-child create / update / delete lifecycle. Reports pass /
fail / skip per tool to a markdown file.

```bash
.venv/bin/python scripts/test_all_tools.py \
  --token "<bearer>" \
  --server "Wiki-topics" \
  --report tools_test_report.md
```

What it catches: schema drift between Zabbix versions, ordering bugs in
the wrapper, broken `_make_tool_handler` glue, output normalisation
issues. What it does **not** catch: anything that depends on how an LLM
reads the tool description (see below).

## `test_with_llm.py` - real-LLM driven coverage

Drives the MCP server through OpenAI's Chat Completions API. For each of
~28 realistic operator scenarios ("List the first 5 hosts being
monitored", "Walk through this full CRUD lifecycle"), the LLM picks tools
from a curated bucket and chains them; we validate the final answer is
not a refusal and that no tool returned `isError: true`.

```bash
.venv/bin/python scripts/test_with_llm.py \
  --token "<bearer>" \
  --server "Wiki-topics" \
  --model "gpt-4o" \
  --report llm_smoke_report.md
```

OpenAI key is read from `[admin.ai].api_key` in the running server's
config (override with `--openai-key` or by editing `--config`). One full
run on `gpt-4o` is roughly $0.50 and takes 5-10 minutes.

What it catches: tool description / UX bugs that fool LLMs even when the
synthetic runner passes. v1.26 caught that the original `CREATE_PARAMS`
description lacked the explicit `{"params": {...}}` wrap example, which
made gpt-4o-mini fail every write call before the description fix landed.

## `audit_api_reference.py` / `audit_api_frontend.py` / `audit_api_sources.py` - is the catalog complete for a release?

Three checks to run when a Zabbix release comes out (they are how 8.0.0 was
signed off; each exits 1 on a difference):

```bash
# the reference pages of a release against the tools, the version table and
# the get contracts: a documented method without a tool, a tool the table
# offers that the pages do not list, a parameter / selectXxx / sort field /
# property on one side only, a different read-only mark, a method or a
# select that one side calls deprecated and the other does not. A page
# that did not arrive, or arrived without its tables, is a difference too.
python3 scripts/audit_api_reference.py 8.0 --cache /tmp/zbx-reference

# the API a frontend really exposes (CApiServiceFactory + the ACCESS_RULES of
# every API class) against the tools: finds what the pages never mention
# (hostdashboard.get, the CEP rule API before it was documented) and what a
# release took away (the host interface write methods in 8.0.0)
python3 scripts/audit_api_frontend.py /usr/share/zabbix/ui
python3 scripts/audit_api_frontend.py --docker zabbix-web:/usr/share/zabbix

# what every X.get of that frontend takes, read out of its PHP classes (the
# options of get(): $defOptions in the classic classes, $api_input_rules in
# the validated ones; and $sortColumns), against the get contracts: an option
# or sort column the source has and the contract does not, and the reverse.
# Then the tools themselves: every parameter a get tool types by hand must be
# an option of the method (under the name it is sent as), and every method
# with a signature of its own (event.acknowledge, script.execute, sla.getsli
# ...) is compared field by field with what its PHP validation takes
python3 scripts/audit_api_sources.py /usr/share/zabbix/ui
python3 scripts/audit_api_sources.py --docker zabbix-web:/usr/share/zabbix
```

The source is the last word: the pages lag behind it and are wrong in
places. Reading the sources of 6.0 to 8.0 this way found a dozen options
the classes take and no page lists (`dashboard.get` sorts by `name`,
`sla.get` filters by `service_tags`, `user.get` has `current` on 8.0,
`usermacro.get` takes `templateids` ...), one the pages list and no source
reads (`usergroup.get` `limitSelects`), and one the classes refuse
(`regexp.get` `editable`). Each was then tried on live servers before the
contract was changed; options a class declares and nothing reads are in
`KNOWN` of `audit_api_sources.py`. Pointed at the tools, the same script
found seven typed parameters that no method has (`action_get`
`eventsource`, ignored by Zabbix; `proxygroup_get` `proxygroupids`,
refused) and the fields the specially typed tools lacked (`cause_eventid`,
`suppress_until`, `manualinput`, `periods`).

Where the reference and a live server disagree the server wins; those
places are listed in `KNOWN` at the top of `audit_api_reference.py` with
what the server answered (on 8.0: the reference names a sort field
`discovered` that every server refuses in favour of `discover`, and a
`status` sort field on `template.get` that is refused too). Methods a
frontend exposes that deliberately have no tool are in `RAW_ONLY` of
`audit_api_frontend.py`.

## `mcp_roundtrip_live.py` - does an unchanged object go back through the tools?

```bash
python3 scripts/mcp_roundtrip_live.py https://zabbix.example.com Admin <password> --fixtures
```

Registers the real tool handlers in-process against that Zabbix and sends
every distinct shape of every object from `<object>_get` back through
`<object>_update` unchanged. `audit_write_roundtrip_live.py` (below) measures
what Zabbix refuses; this proves the shipped contract and the hand rules
remove exactly that. Plain objects must all pass (the few refusals that are
Zabbix's own, such as changing the guest user's language, are listed in
`EXPECTED`); templated and discovered objects are expected to be refused
with Zabbix's message. An accepted update is not yet an unchanged object
(`template.update` accepts an empty `templates` and unlinks every parent),
so each object is read on its own before and after its update, with the
same selects, and the two are compared, leaving aside what a server changes
on its own (`VOLATILE`: `lastclock`, `lastaccess`, a trigger's regenerated
`functionid` ...). The single read matters: `script.get` of 6.2.9 attaches
`actions` and `parameters` to the wrong script when several rows are read
with `selectActions`.
Exit 1 on an unexpected plain failure or on an object that came back
different.

## `restore_trigger_macros.py` - triggers that lost their user macros to v1.40 / v1.41

v1.40 and v1.41 read a trigger with Zabbix's own expansion of the expression,
which replaces every user macro by its current value; a trigger read with
`trigger_get` and sent back through `trigger_update` (or a trigger prototype
through its tools) was stored as `avg(/host/key,10m)>75` where it had been
`avg(/host/key,10m)>{$UTIL.MAX}`. Zabbix recorded each such write in its audit
log with the expression before and after. The script lists the updates in which
the only change was a user macro turning into a plain value, and with `--restore`
writes the earlier expression back where three things hold: nothing but macros
changed in that update, the trigger still has what that update left behind, and
each value written is what its macro resolves to today (looked up in the order
Zabbix uses: the macro with the context asked for, or with a regular expression
that matches it, on the host, on its templates, then among the global macros, and
only then the macro without a context). What it does not restore is listed
with the reason and left alone (`SKIPPED`: changed again since; `REVIEW`: the
value is not the macro's, or the macro is a secret or a vault macro, or the macro went in an update
that changed something else as well, which is what a model produces when it edits
the expanded text, or in an earlier update after which the expression was changed
again). A trigger a template gives to hosts is restored on the template. `--user
NAME` looks only at updates by that Zabbix user; give it the one whose API token
the MCP server uses, since the log cannot tell a number somebody typed on purpose
from the value an expansion left when the two are the same.

```bash
python3 scripts/restore_trigger_macros.py https://zabbix.example.com <api-token> --user mcp            # list only
python3 scripts/restore_trigger_macros.py https://zabbix.example.com <api-token> --user mcp --restore
python3 scripts/restore_trigger_macros.py https://zabbix.example.com Admin <password> --days 31
```

Two things it does not see: one macro put in the place of another with nothing
else changed (somebody's choice), and, since macros are counted over the whole
expression and not place by place, a loss in one place where the same macro
stands or is later written in another place: that one can go unnoticed, or be
listed under another update than the one it went in.

Zabbix 6.0 or later (the audit log of earlier releases does not carry the two
values). The log is kept for 31 days by default from 7.0 and 365 before, so run
it soon after upgrading. Exit status 1 while something is left, 2 when the script
could not do its work (an option it does not know, a `--user` Zabbix does not
have, Zabbix not reached or refusing a call).

## `audit_get_flags_live.py` - what does `false` mean?

Zabbix has yes/no get parameters of two kinds: a boolean reads its value, a
flag is on as soon as it is present (`trigger.get` with `only_true: false`
returns the triggers in problem state). The server does not send `false`
for a flag (`contracts.false_means_unset`). This script asks a running
server about every flag and boolean of every get method (rows with the
parameter left out, `true` and `false`) and exits 1 when a parameter whose
`false` is sent is switched on by it, or when one whose `false` is left out
has a meaning of its own for `false`. Read-only.

```bash
python3 scripts/audit_get_flags_live.py https://zabbix.example.com Admin <password>
python3 scripts/audit_get_flags_live.py https://zabbix.example.com <api-token> --all   # every parameter, not only failures
```

A parameter that makes no difference on the server's data (all three counts
equal) proves nothing; the summary line says how many were told apart. Run
it on a server with hosts, templates, triggers and a few problems.

## `build_get_contracts.py` / `audit_get_contracts_live.py` - get-method contracts

`src/zabbix_mcp/api/get_contracts.json` (what every `*_get` tool offers in
`output`, `filter`, `search`, `sortfield` and `extra_params`, and what the
server refuses before the call) is generated, never edited by hand:

```bash
# merge the per-page catalogs collected from the API reference (5.0 ... 8.0)
# and the live observations into the shipped file
python3 scripts/build_get_contracts.py scripts/get_contracts_src/catalog_*.json \
  --observed scripts/get_contracts_src/observed_*.json

# check the catalog against a real server (every property, sort field and
# select of every method, plus a filter / search probe per property);
# writes get_contracts_observed_<version>.json into the current directory
python3 scripts/audit_get_contracts_live.py https://zabbix.example.com <api-token>
python3 scripts/audit_get_contracts_live.py https://zabbix.example.com Admin <password>
```

The audit ends with `0 problems` on every release the catalog claims to
know; run it against each one before shipping a catalog change, then
re-run the builder with the fresh `observed_*.json` files so what a server
returns beyond the documentation (and what it refuses or ignores) is
marked in the shipped file. Releases before 6.4 are logged in with the
body `auth` field automatically.

## `roundtrip_fixtures.py` / `audit_write_roundtrip_live.py` / `build_write_contracts.py` - write contracts

`src/zabbix_mcp/api/write_contracts.json` (what `X.update` / `X.create`
refuse of what `X.get` returns, so the server can drop it before the call)
is measured the same way:

```bash
# on each release: create an object of every kind with every optional
# sub-structure filled, send every object back through its update
# unchanged, record what the server refuses, delete the fixtures again;
# writes write_roundtrip_observed_<version>.json into the current directory
python3 scripts/audit_write_roundtrip_live.py https://zabbix.example.com Admin <password> --fixtures

# the fixture set on its own (--keep leaves it on the server, --purge only
# deletes what an interrupted run left behind: every object named rt-...)
python3 scripts/roundtrip_fixtures.py https://zabbix.example.com Admin <password> [--keep | --purge]

# merge the per-release files into the shipped contract
python3 scripts/build_write_contracts.py scripts/write_contracts_src/write_roundtrip_observed_*.json
```

Measured so far on 6.0.48, 6.2.9, 6.4.21, 7.0.30, 7.2.15, 7.4.14 and 8.0.0
(`scripts/write_contracts_src/`); the business `service` and the 8.0
`ceprule` (fixtures of every condition and operation kind; documented since
8.0.0) are among the objects since v1.41. The 8.0 fixtures add what only that release has: a
maintenance scoped to triggers and event names, a telemetry query item, a
push media type, a proxy with APM settings, a user group with proxy and
APM permissions, and a SAML user directory with its certificate. Only `query`-type selects get `extend` in the
probe's get; `service.get` `selectStatusTimeline` wants periods instead.

The audit sends every object back *unchanged*, so nothing on the server
is altered by the probes; the only writes are the `rt-` fixtures, which
are deleted at the end. Run it against a test instance, never production:
it is thousands of API calls. A key is part of the contract only when every
plain object that carried it was refused with it on that release; what the
audit sees on templated or discovered objects only is left out on purpose.

## Pre-release ritual (recap)

Both runners must report green before tagging a release. Plus the OS
matrix:

```bash
cd tests/installer && ./run_all.sh   # 18 distros, ~30 min on first run
```

See `CONTRIBUTING.md` and the `feedback_release_checklist` memory for the
full checklist.
