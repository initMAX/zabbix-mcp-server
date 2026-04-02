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

FROM python:3.13.5-slim AS builder

WORKDIR /build
COPY . .
RUN python -m venv /opt/zabbix-mcp/venv \
    && /opt/zabbix-mcp/venv/bin/pip install --no-cache-dir --quiet .

FROM python:3.13.5-slim

LABEL maintainer="initMAX s.r.o. <info@initmax.com>"
LABEL org.opencontainers.image.title="Zabbix MCP Server"
LABEL org.opencontainers.image.description="MCP server for the complete Zabbix API"
LABEL org.opencontainers.image.source="https://github.com/initMAX/zabbix-mcp-server"
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"

RUN useradd --system --shell /usr/sbin/nologin --home-dir /opt/zabbix-mcp zabbix-mcp \
    && mkdir -p /var/log/zabbix-mcp \
    && chown zabbix-mcp:zabbix-mcp /var/log/zabbix-mcp

COPY --from=builder /opt/zabbix-mcp/venv /opt/zabbix-mcp/venv

USER zabbix-mcp
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

ENTRYPOINT ["/opt/zabbix-mcp/venv/bin/zabbix-mcp-server"]
CMD ["--config", "/etc/zabbix-mcp/config.toml"]
