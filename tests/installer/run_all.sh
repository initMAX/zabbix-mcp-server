#!/usr/bin/env bash

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

#
# Run installer integration tests across multiple OS images.
# Requires Docker.
#
# Usage:
#   cd tests/installer
#   ./run_all.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
GREEN='\e[1;32m'
RED='\e[1;31m'
YELLOW='\e[1;33m'
RESET='\e[0m'

IMAGES=(
    "Dockerfile.rhel8:RHEL 8 / Rocky 8 (python3.9 only — expect rejection)"
    "Dockerfile.alma8:AlmaLinux 8 (python3.9 only — expect rejection)"
    "Dockerfile.oracle8:Oracle Linux 8 (python3.9 only — expect rejection)"
    "Dockerfile.rhel9:RHEL 9 / Rocky 9 (python3.11)"
    "Dockerfile.alma9:AlmaLinux 9 (python3.11)"
    "Dockerfile.oracle9:Oracle Linux 9 (python3.11)"
    "Dockerfile.rhel8-autoinstall:RHEL 8 --install-python (auto-install python3.12)"
    "Dockerfile.rhel10:RHEL 10 / Rocky 10 (python3.12)"
    "Dockerfile.alma10:AlmaLinux 10 (python3.12)"
    "Dockerfile.oracle10:Oracle Linux 10 (python3.12)"
    "Dockerfile.fedora:Fedora latest (python3.13+)"
    "Dockerfile.amazon2023:Amazon Linux 2023 (python3.11)"
    "Dockerfile.suse15:openSUSE Leap 15 (python3.11)"
    "Dockerfile.ubuntu22:Ubuntu 22.04 (python3.10)"
    "Dockerfile.ubuntu24:Ubuntu 24.04 (python3.12)"
    "Dockerfile.debian12:Debian 12 (python3.11)"
    "Dockerfile.debian13:Debian 13 Trixie (python3.12)"
    "Dockerfile.minimal:Minimal (python3.10-slim)"
)

PASS=0
FAIL=0
RESULTS=()

echo "=============================================="
echo "  Zabbix MCP Server — Installer Tests"
echo "=============================================="
echo
echo "Repo root: $REPO_ROOT"
echo

for entry in "${IMAGES[@]}"; do
    dockerfile="${entry%%:*}"
    description="${entry#*:}"
    tag="zabbix-mcp-test-${dockerfile,,}"
    tag="${tag//./-}"

    echo -e "${YELLOW}--- $description ---${RESET}"
    echo "  Building: $dockerfile"

    if docker build \
        -f "$SCRIPT_DIR/$dockerfile" \
        -t "$tag" \
        "$REPO_ROOT" 2>&1 | tail -5; then
        echo -e "  ${GREEN}PASS${RESET}: $description"
        RESULTS+=("PASS: $description")
        # Use PASS=$((PASS+1)) rather than ((PASS++)): the post-increment
        # form returns the pre-increment value as the command's exit code,
        # which is 0 (arithmetic false) on the very first increment and
        # trips `set -e`, aborting the loop after the first distro.
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${RESET}: $description"
        RESULTS+=("FAIL: $description")
        FAIL=$((FAIL + 1))
    fi
    echo
done

echo "=============================================="
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "=============================================="
for r in "${RESULTS[@]}"; do
    if [[ "$r" == PASS* ]]; then
        echo -e "  ${GREEN}$r${RESET}"
    else
        echo -e "  ${RED}$r${RESET}"
    fi
done
echo

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
