# Plugin Development

> **Status**: this document is a placeholder. The plugin **loader** is in
> development and lands in a follow-up release - tracked under
> [issue #47](https://github.com/initMAX/zabbix-mcp-server/issues/47).
> v1.31 ships the contract (manifest schema, trust model, tool-prefix
> plumbing, example plugin) but not the runtime that loads plugins into
> the host.

## What is locked in v1.31

Plugin authors can already start writing against a stable contract:

- **Trust model** - `SECURITY.md` -> ["Plugin Architecture"](../SECURITY.md#plugin-architecture-forthcoming-design-locked-in-v131). Subprocess isolation, host as trust anchor, scope enforcement at the host, separate per-plugin config file.
- **Config schema** - `config.example.toml` "MCP Modules (plugins)" section. `[plugins.<id>]` block, `[server].tool_prefix`, `[tokens.<name>].scopes` extension grammar.
- **Manifest schema** - the bundled Zabbix module's manifest at [`plugins/zabbix/plugin.json`](../plugins/zabbix/plugin.json) + the reference example plugin (`examples/example-plugin/plugin.json`).
- **Reference implementation** - `examples/example-plugin/` ships a ~50-line stdio MCP server with a single `example__echo` tool. Plugin authors can run it standalone to validate their understanding of the stdio JSON-RPC contract before the loader exists.

## What v1.31 does NOT yet ship

- The `install.sh add-plugin / remove-plugin / update-plugin` runtime (today: stubs that print "loader is forthcoming").
- The `/modules` admin UI install / enable / disable / update / remove buttons (today: a "Coming soon" modal).
- The host-side spawn / forward / lifecycle code that runs a plugin subprocess and routes `tools/list` / `tools/call` between the AI client and the plugin.
- Plugin manifest signature verification.
- The `tests/test_plugin_protocol.py` integration test fixture.

When the loader release lands, this document expands into a full how-to: manifest field reference, packaging conventions (PyPI / git URL / local path), per-plugin venv layout, audit log integration, error handling, version compatibility rules, and a step-by-step "ship your first plugin" walkthrough.

## Where to track progress

- **Design discussion**: [issue #47](https://github.com/initMAX/zabbix-mcp-server/issues/47).
- **Migration question** (port Zabbix into `mcp-extensible` or stay standalone): tracked separately in the `mcp-extensible` repo when it becomes public.
- **First-wave plugins**: NetBox, Nagios / PRTG, Atlassian Jira / Confluence, FastSpring (see `/modules` "Coming soon" list in the admin portal).

## Reading material

- `SECURITY.md` - trust boundaries.
- `config.example.toml` - operator-side config.
- `plugin.json` (repo root) - bundled module manifest.
- `examples/example-plugin/` - minimal reference impl.
- `CHANGELOG.md` - what shipped in v1.31, what is pending.
