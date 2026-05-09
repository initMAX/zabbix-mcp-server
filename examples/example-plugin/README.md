# Example Plugin (reference implementation)

Minimal stdio MCP plugin for the initMAX MCP host. Exposes a single tool `example__echo` that returns its input verbatim. Ships in v1.31 as documentary reference; it is **not** loaded by the host in v1.31 because the plugin loader is still in development (tracked under [issue #47](https://github.com/initMAX/zabbix-mcp-server/issues/47)). Plugin authors can read the source and run it standalone today to validate their understanding of the stdio JSON-RPC contract.

## Layout

```
example-plugin/
  plugin.json                       Manifest read by the future host loader
  pyproject.toml                    PyPI packaging (initmax-mcp-example)
  README.md                         You are here
  src/
    example_plugin/
      __init__.py                   Package metadata
      __main__.py                   ~120-line stdio MCP server
```

## Run standalone

The plugin is a regular Python package. Install in a venv and feed it a JSON-RPC request to verify the contract:

```bash
cd examples/example-plugin
python -m venv venv
source venv/bin/activate
pip install -e .

# Initialize handshake
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | python -m example_plugin

# List tools
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | python -m example_plugin

# Call the echo tool
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"example__echo","arguments":{"text":"hello"}}}' | python -m example_plugin
```

Expected output for the `tools/call` line:

```json
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"hello"}]}}
```

## Contract surface

The plugin handles a small subset of MCP 2025-11-25 sufficient for the host loader:

| Method        | Purpose                                                       |
|---------------|---------------------------------------------------------------|
| `initialize`  | Handshake; returns `serverInfo`, `capabilities`, protocol ver |
| `tools/list`  | Returns the `example__echo` tool descriptor                   |
| `tools/call`  | Dispatches a tool by name and returns its result              |
| `ping`        | Liveness probe (host watchdog uses this)                      |
| `shutdown`    | Graceful stop signal from the host                            |

The host (this MCP server) is the trust anchor: it validates the caller's MCP / OAuth token before forwarding `tools/list` / `tools/call` to the plugin. Plugins do not see and do not validate the caller token. See [`SECURITY.md`](../../SECURITY.md#plugin-architecture-forthcoming-design-locked-in-v131) for the full trust model.

## Writing your own plugin

1. Copy this directory as a starting point.
2. Rename `example_plugin` -> your package name, `example` -> your plugin id, `example__echo` -> your tool naming pattern.
3. Update `plugin.json` (`id`, `name`, `version`, `tool_prefix`, `read_tools`, `write_tools`).
4. Implement the tools you want to expose under `tools/call`.
5. Test standalone with the `echo | python -m ...` pattern shown above.
6. When the loader release ships, package and publish to PyPI (or ship as a git tag); operators install via `./install.sh add-plugin <id>`.

The plugin contract is language-agnostic - any language that can speak JSON-RPC 2.0 over stdio can host a plugin. This Python implementation is the reference because the host itself is Python, but Go / Node.js / Rust plugins are equally valid once the loader supports arbitrary `exec` arrays in the manifest.

## See also

- [`../../plugin.json`](../../plugin.json) - bundled Zabbix module's manifest, real-world reference
- [`../../SECURITY.md`](../../SECURITY.md#plugin-architecture-forthcoming-design-locked-in-v131) - threat model
- [`../../config.example.toml`](../../config.example.toml) - operator-side `[plugins.<id>]` config
- [`../../docs/PLUGIN-DEVELOPMENT.md`](../../docs/PLUGIN-DEVELOPMENT.md) - how-to (placeholder, expands on loader release)
- [issue #47](https://github.com/initMAX/zabbix-mcp-server/issues/47) - loader design discussion
