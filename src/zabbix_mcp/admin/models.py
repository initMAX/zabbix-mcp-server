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

"""Pydantic models for admin portal form validation."""

from pydantic import BaseModel, Field, field_validator
from typing import Optional


class TokenCreate(BaseModel):
    """Create a new API token."""

    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = ["*"]
    read_only: bool = True
    allowed_ips: Optional[str] = None  # newline-separated, validated to CIDR
    expires_at: Optional[str] = None  # ISO 8601 or empty

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: list[str]) -> list[str]:
        valid = {"*", "monitoring", "data_collection", "alerts", "users", "administration"}
        for s in v:
            if s not in valid:
                raise ValueError(f"Invalid scope: {s}")
        return v


class TokenUpdate(BaseModel):
    """Update an existing API token."""

    name: Optional[str] = None
    scopes: Optional[list[str]] = None
    read_only: Optional[bool] = None
    allowed_ips: Optional[str] = None
    expires_at: Optional[str] = None

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return v
        valid = {"*", "monitoring", "data_collection", "alerts", "users", "administration"}
        for s in v:
            if s not in valid:
                raise ValueError(f"Invalid scope: {s}")
        return v


class UserCreate(BaseModel):
    """Create a new admin portal user."""

    username: str = Field(min_length=1, max_length=50, pattern=r"^[a-zA-Z][a-zA-Z0-9_-]*$")
    password: str = Field(min_length=8, max_length=128)
    role: str = "viewer"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ("admin", "operator", "viewer"):
            raise ValueError("Role must be admin, operator, or viewer")
        return v


class UserUpdate(BaseModel):
    """Update an existing admin portal user."""

    password: Optional[str] = Field(None, min_length=8, max_length=128)
    role: Optional[str] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ("admin", "operator", "viewer"):
            raise ValueError("Role must be admin, operator, or viewer")
        return v


class ServerSettingsUpdate(BaseModel):
    """For editing server settings via admin UI."""

    rate_limit: Optional[int] = Field(None, ge=0, le=10000)
    log_level: Optional[str] = None
    compact_output: Optional[bool] = None
    report_company: Optional[str] = None
    report_subtitle: Optional[str] = None
    # Note: host, port, transport, TLS require restart - UI warns about this

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError("Invalid log level")
        return v
