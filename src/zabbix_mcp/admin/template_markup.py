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

"""Markup a report template may not contain.

A report template is HTML its author writes, and the portal shows it: in the
visual editor (GrapesJS draws it on the portal's own origin) and in the
preview. A report never needs script (WeasyPrint runs none), so markup that can
run script is refused when a template is saved, and a stored template that has
it is kept out of the visual editor.

The check is deliberately coarse. It looks at the raw text, not at a parse
tree, because a browser and Python's HTML parser do not always split a
malformed tag the same way, and a template is not made of untrusted text that
would hit it by accident.
"""

from __future__ import annotations

import html
import re

# Elements that run script or load another document.
_ELEMENTS = ("script", "iframe", "frame", "frameset", "object", "embed", "applet", "base", "portal")
_ELEMENT = re.compile(r"<\s*/?\s*(" + "|".join(_ELEMENTS) + r")(?=[\s/>]|$)", re.IGNORECASE)
# Event handlers, attributes that carry a document or an action of their own, and
# GrapesJS's data-gjs-* attributes: the editor turns them into component properties,
# and data-gjs-script becomes a script it runs in its canvas.
_ATTRIBUTE = re.compile(r"[\s\"'/](on[a-z]+|srcdoc|formaction|data-gjs-[\w-]*)\s*=", re.IGNORECASE)
# URL schemes that run script or open an HTML document, once entities are decoded and
# the characters a browser ignores inside a scheme are gone.
_SCHEMES = ("javascript:", "vbscript:", "data:text/html", "data:application/xhtml")
_IGNORED_IN_A_SCHEME = re.compile(r"[\x00-\x20\x7f]+")


def unsafe_markup(content: str) -> list[str]:
    """What in *content* is refused (empty when nothing is), for the message."""
    found: list[str] = []
    text = str(content or "")
    for match in _ELEMENT.finditer(text):
        name = f"<{match.group(1).lower()}>"
        if name not in found:
            found.append(name)
    for match in _ATTRIBUTE.finditer(text):
        name = f"{match.group(1).lower()}="
        if name not in found:
            found.append(name)
    decoded = _IGNORED_IN_A_SCHEME.sub("", html.unescape(html.unescape(text))).lower()
    for scheme in _SCHEMES:
        if scheme in decoded and scheme not in found:
            found.append(scheme)
    return found


def refusal(content: str) -> str | None:
    """The error to show when *content* may not be saved, else None."""
    found = unsafe_markup(content)
    if not found:
        return None
    return ("A report template may not contain markup that runs script or loads another "
            "document (reports never run script): " + ", ".join(found) + ". Remove it and save again.")
