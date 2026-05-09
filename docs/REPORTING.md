# PDF Reporting Guide

> **Status: BETA**
>
> Server-side PDF reporting was introduced in v1.16. The 4 built-in templates are stable, but the authoring API, the set of context variables, and the admin editor UI are still evolving. Feedback (what's missing, what's confusing, what should be configurable) is very welcome at [issues](https://github.com/initMAX/zabbix-mcp-server/issues).
>
> **Why server-side reports?** LLMs cannot reliably produce consistent, well-formatted reports on their own. Templates make the output deterministic: the model picks the report type and parameters, the server fetches data from Zabbix, fills a Jinja2 template, and renders it to PDF. Same input -> same output, every time.

## Contents

- [Architecture](#architecture)
- [Built-in templates](#built-in-templates)
- [The `report_generate` MCP tool](#the-report_generate-mcp-tool)
- [Branding](#branding)
- [Custom templates](#custom-templates)
  - [Authoring with the admin portal](#authoring-with-the-admin-portal)
  - [Authoring by hand](#authoring-by-hand)
  - [Available context variables](#available-context-variables)
  - [CSS classes provided by `base.html`](#css-classes-provided-by-basehtml)
  - [Worked example: simple problems summary](#worked-example-simple-problems-summary)
- [Migration: `/var/log` -> `/etc/zabbix-mcp/templates`](#migration-varlog---etczabbix-mcptemplates)
- [Limitations and roadmap](#limitations-and-roadmap)

---

## Architecture

```
LLM call -> report_generate tool
              |
              v
       data_fetcher.fetch_<type>_data()    <- queries Zabbix via JSON-RPC
              |
              v
       ReportEngine.generate_report()      <- merges with branding context
              |
              v
       Jinja2 template (HTML)              <- /plugins/zabbix/zabbix_mcp/reporting/templates/
              |                                or /etc/zabbix-mcp/templates/ (custom)
              v
       WeasyPrint -> PDF bytes
              |
              v
       base64 data URI returned to client
```

Key files in the source tree:

| File | Purpose |
|---|---|
| `plugins/zabbix/zabbix_mcp/reporting/engine.py` | `ReportEngine` class, template registry, branding logic |
| `plugins/zabbix/zabbix_mcp/reporting/data_fetcher.py` | One `fetch_<type>_data()` per report type |
| `plugins/zabbix/zabbix_mcp/reporting/templates/base.html` | Common layout, CSS, header/footer, page numbering |
| `plugins/zabbix/zabbix_mcp/reporting/templates/*.html` | One Jinja2 template per built-in report type |
| `plugins/zabbix/zabbix_mcp/admin/views/templates.py` | Admin portal CRUD + Jinja2 preview with sample data |

Required Python packages: `jinja2`, `weasyprint`. Install with the optional extra:

```bash
pip install zabbix-mcp-server[reporting]
```

If either dependency is missing, the `report_generate` tool is not registered and a log line `PDF reporting disabled (install 'weasyprint' and 'jinja2' to enable)` is emitted at startup.

---

## Built-in templates

| Type | Description | Zabbix API methods used |
|---|---|---|
| `availability` | Host availability over a period: SLA gauge, total events, per-host availability table | `host.get`, `event.get` (problem + recovery) |
| `capacity_host` | CPU / memory / disk usage (avg, min, max) per host with colored bars | `host.get`, `item.get`, `trend.get` |
| `capacity_network` | Network bandwidth per interface (Mbit/s, derived from `net.if.in/out`) plus per-host CPU stats | `host.get`, `item.get`, `trend.get` |
| `backup` | Daily backup status matrix (hosts x days) - auto-detects backup item keys (`veeam`, `bacula`, `borg`, `restic`, `backup`); falls back to backup-named triggers | `host.get`, `item.get`, `history.get`, `trigger.get`, `event.get` |

### What each template needs from `data_fetcher`

The fetcher functions return a Python dict that becomes the Jinja2 context. Each fetcher accepts a `params` dict with `hostgroupid` (or `hostids`) plus `period_from` / `period_to` epoch timestamps. The `report_generate` tool builds these from the high-level `period` argument (`"7d"`, `"30d"`, `"90d"`).

---

## The `report_generate` MCP tool

```
report_generate(
    report_type: str,           # "availability" | "capacity_host" | "capacity_network" | "backup"
    hostgroupid: str,           # Zabbix host group ID
    period: str = "30d",        # "<int><d|h|m>" - days, hours, or minutes
    company: str | None = None, # overrides report_company from config
    server: str | None = None,  # multi-server: target Zabbix instance
)
```

**Returns** a JSON document:

```json
{
  "report": "data:application/pdf;base64,JVBERi0xLj...",
  "report_type": "availability",
  "pages": 4,
  "size_kb": 38.2
}
```

The base64 payload can be saved as a `.pdf` file by the client. Most LLM frontends will offer a download link automatically when they see a PDF data URI in the tool output.

**Authorization:** the call requires the same scope as `host_get` (the underlying API calls fetch hosts, items, events, and trends; a token without monitoring read access cannot generate reports).

---

## Branding

Three optional `[server]` keys control the look of the report header:

```toml
[server]
report_logo     = "/etc/zabbix-mcp/logo.png"     # PNG, JPG, JPEG, or SVG
report_company  = "ACME Corp"                    # appears in <h1>: "ACME Corp / Availability Report"
report_subtitle = "IT Monitoring Service"        # small subtitle in the header
```

**Logo handling:** the engine reads the file at startup, base64-encodes it, and embeds it as a data URI - so the file path does not need to be readable by WeasyPrint at render time. Symlinks are rejected (TOCTOU protection) and the extension allowlist is `.png`, `.jpg`, `.jpeg`, `.svg`.

The `company` value can be overridden per-call by passing the `company` argument to `report_generate`.

---

## Custom templates

### Authoring with the admin portal

The recommended flow:

1. Open the admin portal (`http://<host>:9090`) -> **Templates**.
2. Click **Create new** (or **Duplicate** on a built-in to start from a working template).
3. Edit in the GrapesJS visual editor (drag & drop blocks: Header, Title, Info Table, Host Table, SLA Gauge, Graph) or switch to the **HTML** tab for direct Jinja2.
4. Use **Preview** for a server-side render with sample data and the initMAX logo as a fallback.
5. Save - the portal writes the HTML to `/etc/zabbix-mcp/templates/<name>.html` and adds a `[report_templates.<name>]` section to `config.toml`.
6. Click **Restart** when the badge appears to load the new template into the running server.

### Authoring by hand

If you prefer to work outside the portal:

1. Create the HTML file in `/etc/zabbix-mcp/templates/`:

   ```bash
   sudo install -m 640 -o zabbix-mcp -g zabbix-mcp my_template.html /etc/zabbix-mcp/templates/
   ```

2. Register it in `config.toml`:

   ```toml
   [report_templates.my_custom]
   display_name  = "My Custom Report"
   description   = "Brief description shown in the admin portal"
   template_file = "/etc/zabbix-mcp/templates/my_custom.html"
   ```

3. Restart the server:

   ```bash
   sudo systemctl restart zabbix-mcp-server
   ```

   The startup log should show `Loaded N custom report templates`.

> **Important:** custom templates registered via `[report_templates.*]` reuse the existing built-in **data fetchers**. The fetcher is selected by the `report_type` you pass to `report_generate`. There is currently no way to register a custom fetcher from the config - if your template needs different data, you will need to base it on the same context that one of the built-in fetchers produces. Custom data fetchers are tracked in the [roadmap](#limitations-and-roadmap).

### Available context variables

Every template (built-in and custom) receives a common context plus the per-report fetcher output.

**Common context (always present):**

| Variable | Type | Description |
|---|---|---|
| `company` | str | From `report_company` config or `company` tool argument |
| `subtitle` | str | From `report_subtitle` config |
| `logo_base64` | str or None | Data URI for the configured logo, or None if not set |
| `generated_at` | str | Render timestamp, formatted `YYYY-MM-DD HH:MM UTC` |
| `page_label` | str | Localizable "Page" label used in the footer |

**Per-report context:**

`availability`:
| Variable | Type | Description |
|---|---|---|
| `hosts` | list of `{name, event_count, availability_pct}` | Per-host availability rows |
| `total_events` | int | Total number of problem events in the period |
| `availability_pct` | float | Average availability across all hosts |
| `gauge_arc_path` | str | Pre-computed SVG arc path for the gauge |
| `period_from` / `period_to` | str | Human-readable period boundaries |
| `service_hours` | str | From `params.service_hours` (default `"24x7"`) |
| `operational_hours` | str | From `params.operational_hours` (default `"24x7"`) |

`capacity_host`:
| Variable | Type | Description |
|---|---|---|
| `hosts` | list | Resolved Zabbix host objects |
| `metrics` | list of `{label, rows}` | One entry per metric (CPU, Memory, Disk); each `rows` is a list of `{endpoint, avg, min, max}` |
| `period_from` / `period_to` | str | Human-readable period boundaries |

`capacity_network`:
| Variable | Type | Description |
|---|---|---|
| `hosts` | list of `{name, interfaces}` | Per-host interface list; each interface is `{name, bandwidth_mbps, cpu_avg, cpu_min, cpu_max}` |
| `cpu_rows` | list of `{endpoint, avg, min, max}` | Per-host CPU summary |
| `period_from` / `period_to` | str | Human-readable period boundaries |

`backup`:
| Variable | Type | Description |
|---|---|---|
| `backup_matrix` | list of `{host, statuses}` | `statuses` is a `{day_number: bool}` map (True = success) |
| `days` | list of int | Sorted day numbers covered by the period |
| `period_label` | str | From `params.period_label`, e.g. `"March 2026"` |

### CSS classes provided by `base.html`

If you `{% extends "base.html" %}`, the following classes are pre-styled:

| Class | Use |
|---|---|
| `.info-table` | Two-column key/value tables (gray header column) |
| `.metric-box` / `.metric-value` / `.metric-label` | Big-number summary tiles |
| `.gauge-container` | Wrapper for an SVG gauge (centered, margin) |
| `.bar` / `.bar-fill.green` / `.bar-fill.yellow` / `.bar-fill.red` | Inline progress bars; pick the color via a Jinja2 expression |
| `.check` / `.cross` | Green check / red cross glyphs |
| `.page-break` | Force a page break before the element |

The default font is Helvetica Neue / Arial 10pt, table headers use the initMAX red (`#d32f2f`), and pagination ("Page N/M") + `generated_at` are rendered automatically in the page footer via WeasyPrint `@page` rules.

### Worked example: simple problems summary

A minimal custom template that lists problem counts per host. It reuses the `availability` fetcher (so `report_type=availability` when calling), but only renders a subset of the data:

```html
{% extends "base.html" %}

{% block content %}
<h1>{{ company }} / Problems Summary</h1>

<table class="info-table">
    <tr><th>Period</th><td>{{ period_from }} - {{ period_to }}</td></tr>
    <tr><th>Total events</th><td>{{ total_events }}</td></tr>
    <tr><th>Hosts checked</th><td>{{ hosts | length }}</td></tr>
</table>

<h2>Top noisy hosts</h2>
<table>
    <thead>
        <tr><th>Host</th><th>Events</th><th>Availability</th></tr>
    </thead>
    <tbody>
        {% for h in hosts | sort(attribute='event_count', reverse=true) %}
        <tr>
            <td>{{ h.name }}</td>
            <td>{{ h.event_count }}</td>
            <td>
                <div class="bar" style="width: 200px;">
                    <div class="bar-fill {% if h.availability_pct > 99 %}green{% elif h.availability_pct > 95 %}yellow{% else %}red{% endif %}"
                         style="width: {{ h.availability_pct }}%;"></div>
                </div>
            </td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
```

Save as `/etc/zabbix-mcp/templates/problems_summary.html`, register it:

```toml
[report_templates.problems_summary]
display_name  = "Problems Summary"
description   = "Top noisy hosts by event count"
template_file = "/etc/zabbix-mcp/templates/problems_summary.html"
```

Restart the server. The new template appears in the admin portal next to the built-ins.

---

## Migration: `/var/log` -> `/etc/zabbix-mcp/templates`

Versions **v1.16** stored custom templates in `/var/log/zabbix-mcp/templates/` - an oversight from the beta release (config files do not belong in a log directory). From **v1.17** custom templates live in `/etc/zabbix-mcp/templates/`.

The installer migrates automatically on `sudo ./deploy/install.sh update`:

1. Creates `/etc/zabbix-mcp/templates/` with `zabbix-mcp:zabbix-mcp` ownership and `0750` permissions.
2. Moves every `*.html` from the old location to the new one (preserving timestamps, setting `0640` mode).
3. Rewrites `template_file` paths in `config.toml`'s `[report_templates.*]` sections via tomlkit (preserves comments and formatting).
4. Removes the now-empty old directory.

The migration is **idempotent** - safe to re-run, no-op if there is nothing to migrate. If a file with the same name already exists in the new location, the source is left in place and a warning is printed so you can resolve it manually.

After the update, verify your templates show up in the admin portal and that `report_generate` still works.

---

## Limitations and roadmap

**Current limitations:**

- Custom **data fetchers** cannot be registered from config - you can only swap the HTML template, not what data is loaded.
- The `period` argument is limited to a single suffix (`"30d"`, `"7d"`, `"24h"`); explicit `period_from` / `period_to` cannot be passed from the LLM.
- The `backup` fetcher uses heuristic key/trigger matching - works for common backup tools but may need a `backup_item_key` override for unusual setups (currently only settable from a Python call, not the MCP tool).
- The visual editor (GrapesJS) covers a fixed set of blocks; complex layouts still require switching to the HTML tab.
- Internationalization is limited - templates are English-only and date formats are fixed UTC.

**Planned improvements:**

- Pluggable custom data fetchers (declared in config or a Python entry point).
- Richer block library in the visual editor.
- Optional caching of fetched data so subsequent renders are cheap.
- Localized date/time formatting and translatable labels.
- Built-in template for SLA reports based on Zabbix Services / SLA API.

If your use case is not covered by the built-ins, please open an issue describing what report you need and what data should be in it - this is exactly the feedback that drives the next iteration.
