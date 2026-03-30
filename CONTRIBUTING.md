# Contributing to Zabbix MCP Server

Thank you for your interest in contributing!

## Getting Started

```bash
git clone https://github.com/initMAX/zabbix-mcp-server.git
cd zabbix-mcp-server
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Running Tests

```bash
python -m pytest tests/test_smoke.py -v
```

## Project Structure

```
src/zabbix_mcp/
├── cli.py              # CLI entry point
├── config.py           # TOML config loading
├── client.py           # Multi-server Zabbix client + rate limiter
├── server.py           # FastMCP server + dynamic tool registration
└── api/
    ├── types.py        # MethodDef, ParamDef dataclasses
    ├── common.py       # Shared parameter sets
    ├── monitoring.py   # dashboard, history, event, problem, ...
    ├── data_collection.py  # host, item, trigger, template, ...
    ├── alerts.py       # action, alert, mediatype, script
    ├── users.py        # user, role, token, authentication
    └── administration.py   # proxy, settings, auditlog, ...
```

## Adding a New Zabbix API Method

1. Find the right file in `src/zabbix_mcp/api/` for the API group
2. Add a `MethodDef` entry with the API method name, tool name, description, and parameters
3. The tool is auto-registered — no other changes needed
4. Run the tests to verify

## Code Style

- Type hints on all public functions
- AGPL-3.0 copyright header on all source files
- Keep descriptions LLM-friendly (the AI reads them to decide which tool to call)

## Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the tests
5. Submit a pull request

## License

By contributing, you agree that your contributions will be licensed under AGPL-3.0.
