# Bundled MCP Modules

Each subdirectory holds the manifest of one MCP module that ships bundled with this host. Today there is one (`zabbix/`) - the bundled Zabbix integration. Manifests in this directory are documentary in v1.31: the host implements the Zabbix integration directly and does not yet load it through the plugin runtime. They are forward-compatible with the upcoming plugin loader (issue #47) - once the loader ships and a bundled module is split into a separately-installable package, its manifest moves into that package and the host loads it the same way it loads any other plugin.

## Layout

```
plugins/
├── README.md            (this file)
└── zabbix/
    └── plugin.json      Bundled Zabbix module manifest
```

If new bundled modules ever ship with this host (rare - the design favours separately-installable plugins from the `initmax-mcp` catalog), each gets its own subdirectory: `plugins/<id>/plugin.json`, mirroring the runtime layout under `/opt/zabbix-mcp/plugins/<id>/`.

## Not the same as installed plugins

This directory holds **bundled** module manifests in the source tree. **Installed** plugins (NetBox, Jira, FastSpring, ...) live at runtime under `/opt/zabbix-mcp/plugins/<id>/` - managed by the loader, not version-controlled here.

## See also

- [`../examples/example-plugin/`](../examples/example-plugin/) - minimal hello-world plugin
- [`../SECURITY.md`](../SECURITY.md#plugin-architecture-forthcoming-design-locked-in-v131) - trust boundaries
- [`../docs/PLUGIN-DEVELOPMENT.md`](../docs/PLUGIN-DEVELOPMENT.md) - plugin author guide
- [`../config.example.toml`](../config.example.toml) `[plugins.<id>]` schema
