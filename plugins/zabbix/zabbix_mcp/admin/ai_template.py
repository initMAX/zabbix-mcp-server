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

"""AI-assisted Jinja2 report-template generation.

Accepts a plain-English description of the report the operator wants
("Weekly SRE review: top 10 problematic hosts by event count, an
availability gauge, and a table of currently open high-severity
problems") and produces a valid Jinja2 HTML template that plugs into
the existing PDF report engine.

Architecture
------------
The endpoint (admin/views/templates.py:template_generate) calls
`generate_template()` here, which:

1. Builds a system+user prompt describing the available context
   variables (derived from reporting/data_fetcher return shapes), the
   template base layout, a worked example, and security constraints.
2. Dispatches to an LLM provider (Anthropic or OpenAI) configured
   under `[admin.ai]` in config.toml.
3. Validates the response by rendering it through the
   `SandboxedEnvironment` with the same sample context the preview
   uses. If the sandbox raises, the error bubbles up to the UI so the
   operator can iterate on the prompt.
4. Returns the raw HTML for the UI to show in the editor. The admin
   saves via the existing /templates/create flow.

Providers
---------
Both providers implement the `LLMProvider` protocol. Adding a new one
(e.g. Gemini, Azure OpenAI) is one class. API keys come from config
(env-var expanded) so the key never touches the audit log or the UI.

No key configured? `generate_template` raises `AIDisabledError` which
the view turns into a 412 with a clear message. The "Generate with AI"
button only renders when `is_ai_enabled()` returns True.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

logger = logging.getLogger("zabbix_mcp.admin.ai")


class AIDisabledError(Exception):
    """Raised when AI template generation is not configured in config.toml."""


class AIProviderError(Exception):
    """Raised when the LLM provider call fails for any reason."""


class AITemplateValidationError(Exception):
    """Raised when the returned HTML does not render in the sandbox."""


# Single source of truth for the variables each report type exposes. The
# LLM sees this in the prompt so it does not hallucinate field names.
# Shape names intentionally match what `reporting.data_fetcher` emits at
# runtime - the admin portal preview now mirrors these exactly too
# (v1.22 fix), so "what the LLM writes" and "what the PDF renders" line up.
_AVAILABLE_VARIABLES: dict[str, str] = {
    "company": "str - company / customer name from config",
    "subtitle": "str - configured report subtitle (default 'IT Monitoring Service')",
    "generated_at": "str - human-friendly timestamp, UTC",
    "page_label": "str - 'Page' text used by base.html footer pagination",
    "logo_base64": "str | None - data URI for the company logo image; may be None",
    "period_from": "str - inclusive start date (YYYY-MM-DD)",
    "period_to": "str - inclusive end date (YYYY-MM-DD)",
    "period_label": "str - human-friendly period like '01/2026' (backup reports)",
    # Availability fields
    "availability_pct": "float - overall availability percentage 0-100 (availability reports only)",
    "gauge_arc_path": "str - pre-computed SVG path for the semicircular gauge; paste in <path d>",
    "total_events": "int - total event count across all hosts",
    "hosts": (
        "list[dict] - each dict has: name, host (same as name), availability_pct (float), "
        "event_count (int), and (for capacity_network reports) interfaces: list[dict] "
        "with name, bandwidth_mbps, cpu_avg, cpu_min, cpu_max"
    ),
    # Capacity host
    "metrics": (
        "list[dict] - each dict is {label: str, rows: list[dict]} where each row has "
        "endpoint (str), avg (float), min (float), max (float). Used by capacity_host."
    ),
    # Capacity network
    "cpu_rows": (
        "list[dict] - {endpoint, avg, min, max} top-level CPU rows used by capacity_network "
        "alongside the per-host hosts[*].interfaces breakdown"
    ),
    "landline_count": "int - number of network landlines (defaults to hosts | length)",
    # Backup
    "backup_matrix": (
        "list[dict] - {host: str, statuses: {day_int: bool | None}}. True means backup "
        "succeeded, False failed, missing key / None means no data for that day."
    ),
    "days": "list[int] - 1..31 (or the days covered by the report period)",
}


# CSS classes provided by reporting/templates/base.html. The LLM is
# instructed to reuse these rather than inline new styles.
_AVAILABLE_CSS_CLASSES: list[tuple[str, str]] = [
    ("info-table", "two-column <th><td> table with bold headers on the left"),
    ("bar", "wrapper div for a horizontal progress bar"),
    ("bar-fill", "fill element inside .bar; must be colored by .green/.yellow/.red modifier"),
    ("green", "color modifier: avg < 60% thresholds"),
    ("yellow", "color modifier: 60 <= avg < 85%"),
    ("red", "color modifier: >= 85%"),
    ("check", "green check mark used in backup matrix"),
    ("cross", "red X mark used in backup matrix"),
    ("metric-box", "big-number callout card (wraps .metric-value + .metric-label)"),
    ("metric-value", "the number inside .metric-box"),
    ("metric-label", "the caption under .metric-value"),
    ("gauge-container", "centered wrapper for the availability gauge SVG"),
    ("page-break", "CSS page-break-before:always for PDF pagination"),
]


_SYSTEM_PROMPT = """You are generating a Jinja2 HTML template for a PDF
monitoring report in the initMAX Zabbix MCP Server. The template will
be rendered by weasyprint under a SandboxedEnvironment. Follow these
rules strictly:

1. Extend the existing base layout: the first non-comment line MUST be
   `{% extends "base.html" %}` followed by `{% block content %}...{% endblock %}`.
   Do NOT emit a full <html>/<head>/<body> document - base.html provides it.

2. Use only the context variables listed in the user prompt. Do not
   invent new ones. Every `{{ var }}` you emit must correspond to
   something in the "Available variables" list.

3. Reuse the provided CSS classes (.info-table, .bar, .bar-fill with
   .green/.yellow/.red, .metric-box, etc.) instead of inline styles
   wherever possible. Inline style="..." is allowed for small tweaks
   (width percent, padding) but keep colors / layout consistent with
   the built-in templates.

4. For bar widths: `style="width: {{ value }}%;"`. Clamp to [0, 100]
   via `{{ [value, 100] | min }}` if the source can exceed 100.

5. Security: SandboxedEnvironment blocks `{{ ''.__class__ }}`,
   `{% import %}`, attribute access on internals, etc. Do not try to
   sidestep - it will fail validation. No <script> or external <link>
   tags (CSP blocks them in weasyprint anyway). No {{ config }} or
   {{ self }} references.

6. Produce CLEAN, SHIP-READY HTML. No TODO comments, no lorem ipsum,
   no placeholder "{{ /* ... */ }}" blocks. If the user asks for a
   section you cannot derive from the available variables, skip that
   section and add an HTML comment explaining why.

7. Respond with ONLY the template body. No markdown code fences, no
   prose, no explanation. The first character of your response must be
   either `{` (for `{% extends %}`) or `<` (if you need a comment).

8. CRITICAL Jinja syntax rules - violations here will make the
   template refuse to render:
   - Ternary: `{{ 'green' if x >= 99.9 else ('yellow' if x >= 97 else 'red') }}`.
     NEVER write `{{ 'yellow' 97 'red' }}` or similar tuple-like forms.
     Always use the full `A if cond else B` spelling, nested when needed.
   - Loops: every `{% for x in seq %}...{% endfor %}` MUST surround the
     element that uses `x`. Do NOT put the `{% for %}` block above an
     empty line and then the loop body outside the block - Jinja will
     raise UndefinedError for `x` on render. A `<tr>{{ x.name }}</tr>`
     referencing `x` belongs BETWEEN the `{% for %}` and `{% endfor %}`,
     never before or after.
   - Conditionals: match `{% if %}` with `{% endif %}`, `{% else %}`
     (not `{% elif %}...{% else %}{% endif %}` left unterminated).
   - Do not emit empty `{% for %}{% endfor %}` or `{% if %}{% endif %}`
     shells - the compiler accepts them but they never help.
"""


def _format_variables() -> str:
    lines = [f"- {name}: {desc}" for name, desc in _AVAILABLE_VARIABLES.items()]
    return "\n".join(lines)


def _format_css_classes() -> str:
    lines = [f"- .{cls}: {desc}" for cls, desc in _AVAILABLE_CSS_CLASSES]
    return "\n".join(lines)


def _load_example_template() -> str:
    """Read availability.html as a worked example for the LLM."""
    here = Path(__file__).resolve().parent.parent
    example = here / "reporting" / "templates" / "availability.html"
    try:
        return example.read_text(encoding="utf-8")
    except OSError:
        # Template dir was moved or removed - LLM will still work from
        # the variable list alone, just less precisely.
        logger.warning("AI generator could not load example template from %s", example)
        return ""


def build_prompt(user_request: str) -> tuple[str, str]:
    """Return `(system_prompt, user_prompt)` ready for an LLM call."""
    example = _load_example_template()
    example_block = (
        f"\n\n## Example template (availability.html):\n```jinja\n{example}\n```"
        if example
        else ""
    )
    user = f"""## What the operator wants:

{user_request.strip()}

## Available variables:

{_format_variables()}

## Available CSS classes (from base.html):

{_format_css_classes()}
{example_block}

Produce the Jinja2 template now. Respond with only the template body.
"""
    return _SYSTEM_PROMPT, user


# ---------------------------------------------------------------------------
# LLM provider protocol + implementations
# ---------------------------------------------------------------------------


class LLMProvider(Protocol):
    """Anything with a `.generate(system, user) -> str` method will do."""

    def generate(self, system: str, user: str) -> str:
        ...


@dataclass(frozen=True)
class AnthropicProvider:
    """Claude (Sonnet/Opus/Haiku) via the Messages API.

    No SDK dependency - we use stdlib urllib so the reporting extra
    does not need to grow an extra pinned package. The whole call is
    about 40 lines of HTTP.
    """

    api_key: str
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 8000
    timeout: int = 180

    def generate(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        req = urllib_request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            raise AIProviderError(f"Anthropic API returned {exc.code}: {body}") from exc
        except URLError as exc:
            raise AIProviderError(f"Anthropic API unreachable: {exc.reason}") from exc

        # Messages API returns {"content": [{"type": "text", "text": ...}], ...}
        parts = data.get("content") or []
        text_pieces = [p.get("text", "") for p in parts if p.get("type") == "text"]
        if not text_pieces:
            raise AIProviderError(
                f"Anthropic API returned no text content: {json.dumps(data)[:300]}"
            )
        return "".join(text_pieces)


@dataclass(frozen=True)
class OpenAIProvider:
    """GPT (4o/5) via the Chat Completions API.

    Also reused for OpenAI-compatible endpoints (Ollama, Mistral,
    Groq) by passing a different ``base_url``. The wire format is
    identical; the only thing that varies is the host.
    """

    api_key: str
    model: str = "gpt-5"
    max_tokens: int = 8000
    timeout: int = 180
    base_url: str = "https://api.openai.com/v1"
    # Human-readable label for error messages (e.g. "OpenAI", "Ollama").
    label: str = "OpenAI"

    def generate(self, system: str, user: str) -> str:
        # Some OpenAI-compatible backends (Ollama, older forks)
        # reject `max_completion_tokens` and only accept the legacy
        # `max_tokens` key. Use the legacy key except for canonical
        # OpenAI where the new one is required for gpt-5.
        token_key = (
            "max_completion_tokens"
            if "api.openai.com" in self.base_url
            else "max_tokens"
        )
        payload = {
            "model": self.model,
            token_key: self.max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        req = urllib_request.Request(
            self.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            raise AIProviderError(f"{self.label} API returned {exc.code}: {body}") from exc
        except URLError as exc:
            raise AIProviderError(f"{self.label} API unreachable: {exc.reason}") from exc

        choices = data.get("choices") or []
        if not choices:
            raise AIProviderError(
                f"{self.label} API returned no choices: {json.dumps(data)[:300]}"
            )
        msg = (choices[0].get("message") or {}).get("content", "")
        if not msg:
            raise AIProviderError(f"{self.label} API returned empty content")
        return msg


@dataclass(frozen=True)
class GeminiProvider:
    """Google Gemini via the Generative Language v1beta REST API.

    Request shape differs from the OpenAI/Anthropic APIs: Google
    embeds the system prompt as ``systemInstruction`` and the user
    message as ``contents[].parts[].text``. Auth is via the ``key``
    query parameter.
    """

    api_key: str
    model: str = "gemini-2.0-flash"
    max_tokens: int = 8000
    timeout: int = 180

    def generate(self, system: str, user: str) -> str:
        payload = {
            "systemInstruction": {
                "parts": [{"text": system}],
            },
            "contents": [
                {"role": "user", "parts": [{"text": user}]},
            ],
            "generationConfig": {
                "maxOutputTokens": self.max_tokens,
            },
        }
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        req = urllib_request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            raise AIProviderError(f"Gemini API returned {exc.code}: {body}") from exc
        except URLError as exc:
            raise AIProviderError(f"Gemini API unreachable: {exc.reason}") from exc

        candidates = data.get("candidates") or []
        if not candidates:
            raise AIProviderError(
                f"Gemini API returned no candidates: {json.dumps(data)[:300]}"
            )
        parts = ((candidates[0].get("content") or {}).get("parts") or [])
        text_pieces = [p.get("text", "") for p in parts if p.get("text")]
        if not text_pieces:
            raise AIProviderError(
                f"Gemini API returned no text parts: {json.dumps(data)[:300]}"
            )
        return "".join(text_pieces)


@dataclass(frozen=True)
class AzureOpenAIProvider:
    """Azure OpenAI Service via its deployment-scoped chat endpoint.

    The operator must set ``api_base`` to the deployment URL, e.g.
    ``https://my-resource.openai.azure.com/openai/deployments/gpt-5``.
    Unlike vanilla OpenAI this uses the ``api-key`` header and
    requires the ``api-version`` query parameter.
    """

    api_key: str
    model: str = ""  # informational; Azure routes by deployment in URL
    max_tokens: int = 8000
    timeout: int = 180
    base_url: str = ""
    api_version: str = "2024-10-21"

    def generate(self, system: str, user: str) -> str:
        if not self.base_url:
            raise AIProviderError(
                "Azure OpenAI requires api_base set to the deployment URL "
                "(https://{resource}.openai.azure.com/openai/deployments/{deployment})"
            )
        payload = {
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        url = self.base_url.rstrip("/") + f"/chat/completions?api-version={self.api_version}"
        req = urllib_request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "api-key": self.api_key,
                "content-type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            raise AIProviderError(f"Azure OpenAI API returned {exc.code}: {body}") from exc
        except URLError as exc:
            raise AIProviderError(f"Azure OpenAI API unreachable: {exc.reason}") from exc

        choices = data.get("choices") or []
        if not choices:
            raise AIProviderError(
                f"Azure OpenAI returned no choices: {json.dumps(data)[:300]}"
            )
        msg = (choices[0].get("message") or {}).get("content", "")
        if not msg:
            raise AIProviderError("Azure OpenAI returned empty content")
        return msg


# Provider registry: supported names + default model + default base_url.
# Empty base_url means "use the provider's canonical hardcoded URL or
# require the operator to supply api_base" (Azure). Empty model means
# "fall back to provider's default" which get_provider resolves.
PROVIDER_DEFAULTS: dict[str, tuple[str, str]] = {
    # name: (default base_url, default model)
    "anthropic": ("", "claude-sonnet-4-6"),
    "openai": ("https://api.openai.com/v1", "gpt-5"),
    "gemini": ("", "gemini-2.0-flash"),
    "azure-openai": ("", ""),  # api_base + deployment name required
    "ollama": ("http://localhost:11434/v1", "llama3.2"),
    "mistral": ("https://api.mistral.ai/v1", "mistral-small-latest"),
    "groq": ("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
}
SUPPORTED_PROVIDERS = frozenset(PROVIDER_DEFAULTS.keys())
# Providers where api_key may be empty (self-hosted with no auth).
PROVIDERS_KEY_OPTIONAL = frozenset({"ollama"})


def _resolve_env(value: str | None) -> str:
    """Expand `${VAR}` env var references in config values."""
    if not value:
        return ""
    match = re.fullmatch(r"\$\{([A-Z_][A-Z0-9_]*)\}", value)
    if match:
        return os.environ.get(match.group(1), "") or ""
    return value


def is_ai_enabled(config: Any) -> bool:
    """True when `[admin.ai]` is configured with a supported provider.

    The explicit ``enabled`` flag (added in v1.24 so the admin portal
    can expose a toggle) short-circuits to False when set to False.
    Legacy configs without the flag default to enabled so upgrades
    continue to work without touching config.toml. Providers that
    allow unauthenticated access (Ollama) skip the API-key check.
    """
    ai = getattr(config, "admin_ai", None)
    if ai is None:
        return False
    if getattr(ai, "enabled", True) is False:
        return False
    provider = (getattr(ai, "provider", "") or "").lower()
    if provider not in SUPPORTED_PROVIDERS:
        return False
    if provider in PROVIDERS_KEY_OPTIONAL:
        return True
    return bool(_resolve_env(getattr(ai, "api_key", "")))


def get_provider(
    config: Any,
    *,
    override_provider: str | None = None,
    override_api_key: str | None = None,
    override_model: str | None = None,
    override_api_base: str | None = None,
) -> LLMProvider:
    """Instantiate the configured provider.

    When `override_provider` and `override_api_key` are both set, they
    replace the server-side `[admin.ai]` config for this call. Used by
    the "bring your own key" path in the admin portal AI wizard so an
    operator can pick a different provider without restarting the
    server or editing config.toml. Override keys are never persisted.

    Raises AIDisabledError when neither the override nor the server
    config is usable so the caller can return a clean 412 to the UI.
    """
    override_provider = (override_provider or "").strip().lower()
    override_api_key = (override_api_key or "").strip()
    override_model = (override_model or "").strip()
    override_api_base = (override_api_base or "").strip()

    ai_cfg = getattr(config, "admin_ai", None)
    # Prefer the per-call override for api_base (Azure deployment URL
    # or self-hosted Ollama endpoint) over the server-side default.
    api_base_cfg = override_api_base or (getattr(ai_cfg, "api_base", "") or "").strip()

    if override_provider or override_api_key:
        # BYO path. Provider must be supported; key must be present
        # unless the provider allows unauthenticated use (Ollama).
        if override_provider not in SUPPORTED_PROVIDERS:
            raise AIDisabledError(
                f"Override provider must be one of {sorted(SUPPORTED_PROVIDERS)}, "
                f"got '{override_provider}'"
            )
        if not override_api_key and override_provider not in PROVIDERS_KEY_OPTIONAL:
            raise AIDisabledError("Override provider requires a non-empty API key")
        provider_name = override_provider
        api_key = override_api_key
        model_cfg = override_model
    else:
        # Fall back to server-side [admin.ai] config.
        if ai_cfg is None:
            raise AIDisabledError("[admin.ai] section is missing from config.toml")
        provider_name = (getattr(ai_cfg, "provider", "") or "").lower()
        if provider_name not in SUPPORTED_PROVIDERS:
            raise AIDisabledError(
                f"Unsupported [admin.ai].provider: '{provider_name}'. "
                f"Use one of {sorted(SUPPORTED_PROVIDERS)}."
            )
        api_key = _resolve_env(getattr(ai_cfg, "api_key", ""))
        if not api_key and provider_name not in PROVIDERS_KEY_OPTIONAL:
            raise AIDisabledError(
                "[admin.ai].api_key is not set (or env var is empty)"
            )
        model_cfg = getattr(ai_cfg, "model", "") or ""

    default_base, default_model = PROVIDER_DEFAULTS.get(provider_name, ("", ""))
    model = model_cfg or default_model
    base_url = api_base_cfg or default_base
    max_tokens = int(getattr(ai_cfg, "max_tokens", 0) or 8000)
    timeout = int(getattr(ai_cfg, "timeout", 0) or 180)

    if provider_name == "anthropic":
        return AnthropicProvider(api_key=api_key, model=model, max_tokens=max_tokens, timeout=timeout)
    if provider_name == "gemini":
        return GeminiProvider(api_key=api_key, model=model, max_tokens=max_tokens, timeout=timeout)
    if provider_name == "azure-openai":
        return AzureOpenAIProvider(
            api_key=api_key, model=model, max_tokens=max_tokens, timeout=timeout,
            base_url=base_url,
        )
    # openai + ollama + mistral + groq share the OpenAI wire format;
    # only the base URL and default model differ.
    labels = {
        "openai": "OpenAI",
        "ollama": "Ollama",
        "mistral": "Mistral",
        "groq": "Groq",
    }
    return OpenAIProvider(
        api_key=api_key, model=model, max_tokens=max_tokens, timeout=timeout,
        base_url=base_url, label=labels.get(provider_name, provider_name),
    )


# ---------------------------------------------------------------------------
# Validation + top-level generate()
# ---------------------------------------------------------------------------


def _strip_markdown_fences(raw: str) -> str:
    """Remove leading/trailing ```jinja / ``` fences if the LLM added them."""
    s = raw.strip()
    if s.startswith("```"):
        # Drop first line (``` or ```jinja) and last ``` line.
        lines = s.splitlines()
        # Drop opening fence.
        lines = lines[1:]
        # Drop trailing fence if present.
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    return s


def _sample_context() -> dict:
    """Mirror what admin/views/templates.template_preview passes.

    This is the validation context - if the generated template renders
    against it without raising, it will also render against the real
    data_fetcher output at runtime.
    """
    sample_days = list(range(1, 32))
    statuses = {d: True for d in sample_days}
    for d in (7, 14, 22):
        statuses[d] = False
    return {
        "company": "Preview Company",
        "subtitle": "IT Monitoring Service",
        "generated_at": "2026-01-01 00:00 UTC",
        "page_label": "Page",
        "logo_base64": None,
        "availability_pct": 99.5,
        "gauge_arc_path": "M 20 100 A 80 80 0 0 1 180.0 98.7",
        "total_events": 3,
        "period_from": "2026-01-01",
        "period_to": "2026-01-31",
        "period_label": "01/2026",
        "hosts": [
            {
                "name": "host-01", "host": "host-01",
                "availability_pct": 100.0, "event_count": 0,
                "interfaces": [
                    {"name": "eth0", "bandwidth_mbps": 1000.0, "cpu_avg": 12.5, "cpu_min": 2.0, "cpu_max": 34.1},
                ],
            },
            {
                "name": "host-02", "host": "host-02",
                "availability_pct": 98.5, "event_count": 3,
                "interfaces": [],
            },
        ],
        "metrics": [
            {"label": "CPU Usage (%)", "rows": [
                {"endpoint": "host-01", "avg": 15.2, "min": 2.1, "max": 78.5},
            ]},
        ],
        "cpu_rows": [{"endpoint": "host-01", "avg": 15.2, "min": 2.1, "max": 78.5}],
        "landline_count": 2,
        "days": sample_days,
        "backup_matrix": [{"host": "host-01", "statuses": statuses}],
    }


def validate_template(html: str) -> None:
    """Render `html` in a SandboxedEnvironment with sample context.

    Raises AITemplateValidationError if the template is malformed or
    tries to access disallowed attributes. A successful render here
    guarantees the runtime report generator can at least start.
    """
    import jinja2  # lazy - reporting extra may not be installed on bare minimum installs
    import jinja2.sandbox

    # FileSystemLoader lets the generated template `{% extends "base.html" %}`
    # (which is what we instruct the LLM to do).
    here = Path(__file__).resolve().parent.parent
    templates_dir = here / "reporting" / "templates"
    env = jinja2.sandbox.SandboxedEnvironment(
        loader=jinja2.FileSystemLoader(str(templates_dir)),
        autoescape=True,
    )
    try:
        tmpl = env.from_string(html)
        tmpl.render(**_sample_context())
    except jinja2.TemplateSyntaxError as exc:
        raise AITemplateValidationError(
            f"Generated template has a syntax error at line {exc.lineno}: {exc.message}"
        ) from exc
    except jinja2.UndefinedError as exc:
        raise AITemplateValidationError(
            f"Generated template references an unknown variable: {exc}. "
            "Only the documented variables are available."
        ) from exc
    except jinja2.exceptions.SecurityError as exc:
        raise AITemplateValidationError(
            f"Generated template tried a sandboxed operation: {exc}"
        ) from exc
    except Exception as exc:
        # Catch weasyprint / runtime quirks so the UI sees a clear msg.
        raise AITemplateValidationError(
            f"Generated template failed to render: {exc.__class__.__name__}: {exc}"
        ) from exc


@dataclass(frozen=True)
class GeneratedTemplate:
    """Result of a successful generation."""

    html: str
    provider: str
    model: str
    elapsed_ms: int


def generate_template(
    config: Any,
    user_request: str,
    *,
    override_provider: str | None = None,
    override_api_key: str | None = None,
    override_model: str | None = None,
    override_api_base: str | None = None,
) -> GeneratedTemplate:
    """End-to-end: pick provider, call LLM, clean up output, validate.

    Operators can override the server-configured provider for a single
    call by passing `override_provider` + `override_api_key` (the
    "bring your own key" path from the admin portal AI wizard). The
    override key is not logged or persisted.

    The caller (admin view) is expected to wrap this in try/except and
    surface each concrete exception type as the appropriate HTTP
    status: 412 for AIDisabledError, 502 for AIProviderError, 400 for
    AITemplateValidationError.
    """
    user_request = (user_request or "").strip()
    if not user_request:
        raise AITemplateValidationError("Request is empty - describe the report you want.")
    if len(user_request) > 4000:
        raise AITemplateValidationError(
            "Request is too long (>4000 chars). Trim it to the essentials."
        )

    provider = get_provider(
        config,
        override_provider=override_provider,
        override_api_key=override_api_key,
        override_model=override_model,
        override_api_base=override_api_base,
    )
    system, user = build_prompt(user_request)

    t0 = time.monotonic()
    raw = provider.generate(system, user)
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    html = _strip_markdown_fences(raw)
    if not html:
        raise AIProviderError("LLM returned an empty response")

    # Run through the sandbox before handing back to the UI so an
    # invalid template never gets saved to /etc/zabbix-mcp/templates/.
    validate_template(html)

    return GeneratedTemplate(
        html=html,
        provider=provider.__class__.__name__.replace("Provider", "").lower(),
        model=getattr(provider, "model", "unknown"),
        elapsed_ms=elapsed_ms,
    )
