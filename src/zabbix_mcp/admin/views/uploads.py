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

"""File upload handlers for logo and TLS certificate/key files."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from zabbix_mcp.admin.audit_writer import write_audit
from zabbix_mcp.admin.config_writer import (
    load_config_document,
    save_config_document,
    TOMLKIT_AVAILABLE,
)

logger = logging.getLogger("zabbix_mcp.admin")

ASSETS_DIR = Path("/etc/zabbix-mcp/assets")
TLS_DIR = Path("/etc/zabbix-mcp/tls")

# Extension allow-lists
LOGO_EXTENSIONS = {".png", ".jpg", ".jpeg", ".svg"}  # SVG: sanitized on upload (script tags stripped)
TLS_CERT_EXTENSIONS = {".pem", ".crt", ".cert"}
TLS_KEY_EXTENSIONS = {".pem", ".key"}

# Size limits (bytes)
MAX_LOGO_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_TLS_SIZE = 100 * 1024  # 100 KB


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename: strip path components, allow only safe characters."""
    # Take only the basename (no directory traversal)
    name = Path(filename).name
    # Replace anything that is not alphanumeric, dash, underscore, or dot
    name = re.sub(r"[^\w.\-]", "_", name)
    # Collapse multiple dots/underscores
    name = re.sub(r"\.{2,}", ".", name)
    name = re.sub(r"_{2,}", "_", name)
    return name


def _validate_extension(filename: str, allowed: set[str]) -> str | None:
    """Return the lowered extension if allowed, else None."""
    ext = Path(filename).suffix.lower()
    if ext in allowed:
        return ext
    return None


async def _read_upload(request: Request, field: str = "file") -> tuple[str, bytes] | tuple[None, None]:
    """Read the uploaded file from multipart form. Returns (filename, content)."""
    form = await request.form()
    upload = form.get(field)
    if upload is None or not hasattr(upload, "read"):
        return None, None
    filename = getattr(upload, "filename", "") or ""
    content = await upload.read()
    return filename, content


async def upload_logo(request: Request) -> Response:
    """Handle logo file upload — save to assets dir, update config.toml."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role not in ("admin", "operator"):
        return RedirectResponse("/settings", status_code=303)

    client_ip = request.client.host if request.client else "unknown"

    filename, content = await _read_upload(request)
    if filename is None or content is None or not filename:
        logger.warning("Logo upload: no file provided by %s", session.user)
        return RedirectResponse("/settings", status_code=303)

    # Validate extension
    if _validate_extension(filename, LOGO_EXTENSIONS) is None:
        logger.warning("Logo upload: invalid extension '%s' by %s", filename, session.user)
        write_audit("upload_rejected", user=session.user, target_type="logo",
                     details={"filename": filename, "reason": "invalid_extension"}, ip=client_ip)
        return RedirectResponse("/settings", status_code=303)

    # Validate size
    if len(content) > MAX_LOGO_SIZE:
        logger.warning("Logo upload: file too large (%d bytes) by %s", len(content), session.user)
        write_audit("upload_rejected", user=session.user, target_type="logo",
                     details={"filename": filename, "reason": "file_too_large", "size": len(content)}, ip=client_ip)
        return RedirectResponse("/settings", status_code=303)

    if len(content) == 0:
        logger.warning("Logo upload: empty file by %s", session.user)
        return RedirectResponse("/settings", status_code=303)

    # SVG security: strip script tags and event handlers
    ext = Path(filename).suffix.lower()
    if ext == ".svg":
        import re as _re
        svg_text = content.decode("utf-8", errors="replace")
        svg_text = _re.sub(r"<script[^>]*>.*?</script>", "", svg_text, flags=_re.DOTALL | _re.IGNORECASE)
        svg_text = _re.sub(r"\bon\w+\s*=\s*[\"'][^\"']*[\"']", "", svg_text, flags=_re.IGNORECASE)
        content = svg_text.encode("utf-8")
        logger.info("SVG sanitized: stripped script tags and event handlers")

    safe_name = _sanitize_filename(filename)
    dest = ASSETS_DIR / safe_name

    try:
        ASSETS_DIR.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
        logger.info("Logo saved: %s (%d bytes) by %s", dest, len(content), session.user)
    except OSError as e:
        logger.error("Failed to save logo %s: %s", dest, e)
        return RedirectResponse("/settings", status_code=303)

    # Update config.toml
    if TOMLKIT_AVAILABLE:
        try:
            doc = load_config_document(admin_app.config_path)
            if "server" not in doc:
                import tomlkit
                doc.add("server", tomlkit.table())
            doc["server"]["report_logo"] = str(dest)
            save_config_document(admin_app.config_path, doc)
        except Exception as e:
            logger.error("Failed to update config with logo path: %s", e)

    write_audit("upload_logo", user=session.user, target_type="logo",
                 details={"filename": safe_name, "path": str(dest), "size": len(content)}, ip=client_ip)

    return RedirectResponse("/settings", status_code=303)


async def upload_tls_cert(request: Request) -> Response:
    """Handle TLS certificate upload — save to tls dir, update config.toml."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/settings", status_code=303)

    client_ip = request.client.host if request.client else "unknown"

    filename, content = await _read_upload(request)
    if filename is None or content is None or not filename:
        logger.warning("TLS cert upload: no file provided by %s", session.user)
        return RedirectResponse("/settings", status_code=303)

    # Validate extension
    if _validate_extension(filename, TLS_CERT_EXTENSIONS) is None:
        logger.warning("TLS cert upload: invalid extension '%s' by %s", filename, session.user)
        write_audit("upload_rejected", user=session.user, target_type="tls_cert",
                     details={"filename": filename, "reason": "invalid_extension"}, ip=client_ip)
        return RedirectResponse("/settings", status_code=303)

    # Validate size
    if len(content) > MAX_TLS_SIZE:
        logger.warning("TLS cert upload: file too large (%d bytes) by %s", len(content), session.user)
        write_audit("upload_rejected", user=session.user, target_type="tls_cert",
                     details={"filename": filename, "reason": "file_too_large", "size": len(content)}, ip=client_ip)
        return RedirectResponse("/settings", status_code=303)

    if len(content) == 0:
        logger.warning("TLS cert upload: empty file by %s", session.user)
        return RedirectResponse("/settings", status_code=303)

    dest = TLS_DIR / "cert.pem"

    try:
        TLS_DIR.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
        logger.info("TLS cert saved: %s (%d bytes) by %s", dest, len(content), session.user)
    except OSError as e:
        logger.error("Failed to save TLS cert %s: %s", dest, e)
        return RedirectResponse("/settings", status_code=303)

    # Update config.toml
    if TOMLKIT_AVAILABLE:
        try:
            doc = load_config_document(admin_app.config_path)
            if "server" not in doc:
                import tomlkit
                doc.add("server", tomlkit.table())
            doc["server"]["tls_cert_file"] = str(dest)
            save_config_document(admin_app.config_path, doc)
        except Exception as e:
            logger.error("Failed to update config with TLS cert path: %s", e)

    write_audit("upload_tls_cert", user=session.user, target_type="tls_cert",
                 details={"path": str(dest), "size": len(content), "original_name": filename}, ip=client_ip)

    return RedirectResponse("/settings", status_code=303)


async def upload_tls_key(request: Request) -> Response:
    """Handle TLS private key upload — save to tls dir with 0600, update config.toml."""
    admin_app = request.app.state.admin_app
    session = admin_app.require_auth(request)
    if not session or session.role != "admin":
        return RedirectResponse("/settings", status_code=303)

    client_ip = request.client.host if request.client else "unknown"

    filename, content = await _read_upload(request)
    if filename is None or content is None or not filename:
        logger.warning("TLS key upload: no file provided by %s", session.user)
        return RedirectResponse("/settings", status_code=303)

    # Validate extension
    if _validate_extension(filename, TLS_KEY_EXTENSIONS) is None:
        logger.warning("TLS key upload: invalid extension '%s' by %s", filename, session.user)
        write_audit("upload_rejected", user=session.user, target_type="tls_key",
                     details={"filename": filename, "reason": "invalid_extension"}, ip=client_ip)
        return RedirectResponse("/settings", status_code=303)

    # Validate size
    if len(content) > MAX_TLS_SIZE:
        logger.warning("TLS key upload: file too large (%d bytes) by %s", len(content), session.user)
        write_audit("upload_rejected", user=session.user, target_type="tls_key",
                     details={"filename": filename, "reason": "file_too_large", "size": len(content)}, ip=client_ip)
        return RedirectResponse("/settings", status_code=303)

    if len(content) == 0:
        logger.warning("TLS key upload: empty file by %s", session.user)
        return RedirectResponse("/settings", status_code=303)

    dest = TLS_DIR / "key.pem"

    try:
        TLS_DIR.mkdir(parents=True, exist_ok=True)
        # Write with restricted permissions — open with 0600 from the start
        fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
        logger.info("TLS key saved: %s (%d bytes, mode 0600) by %s", dest, len(content), session.user)
    except OSError as e:
        logger.error("Failed to save TLS key %s: %s", dest, e)
        return RedirectResponse("/settings", status_code=303)

    # Update config.toml
    if TOMLKIT_AVAILABLE:
        try:
            doc = load_config_document(admin_app.config_path)
            if "server" not in doc:
                import tomlkit
                doc.add("server", tomlkit.table())
            doc["server"]["tls_key_file"] = str(dest)
            save_config_document(admin_app.config_path, doc)
        except Exception as e:
            logger.error("Failed to update config with TLS key path: %s", e)

    write_audit("upload_tls_key", user=session.user, target_type="tls_key",
                 details={"path": str(dest), "size": len(content), "original_name": filename}, ip=client_ip)

    return RedirectResponse("/settings", status_code=303)
