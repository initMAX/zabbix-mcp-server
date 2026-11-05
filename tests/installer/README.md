# Installer Integration Tests

Docker-based tests that verify the `deploy/install.sh` installer works correctly on different Linux distributions and Python versions.

## Prerequisites

- Docker installed and running

## Usage

```bash
cd tests/installer
./run_all.sh
```

## Test matrix

| Dockerfile | OS | System Python | Expected result |
|---|---|---|---|
| `Dockerfile.rhel8` | Rocky Linux 8 | python3.9 | Installer rejects — prints install hint |
| `Dockerfile.alma8` | AlmaLinux 8 | python3.9 | Installer rejects — prints install hint |
| `Dockerfile.oracle8` | Oracle Linux 8 | python3.9 | Installer rejects — prints install hint |
| `Dockerfile.rhel9` | Rocky Linux 9 | python3.11 | Full install succeeds |
| `Dockerfile.alma9` | AlmaLinux 9 | python3.11 | Full install succeeds |
| `Dockerfile.oracle9` | Oracle Linux 9 | python3.11 | Full install succeeds |
| `Dockerfile.rhel8-autoinstall` | Rocky Linux 8 | python3.9 → auto 3.12 | `--install-python` installs Python and succeeds |
| `Dockerfile.rhel10` | Rocky Linux 10 | python3.12 | Full install succeeds |
| `Dockerfile.alma10` | AlmaLinux 10 | python3.12 | Full install succeeds |
| `Dockerfile.oracle10` | Oracle Linux 10 | python3.12 | Full install succeeds |
| `Dockerfile.fedora` | Fedora (latest) | python3.13+ | Full install succeeds |
| `Dockerfile.amazon2023` | Amazon Linux 2023 | python3.11 | Full install succeeds |
| `Dockerfile.suse15` | openSUSE Leap 15 | python3.11 | Full install succeeds |
| `Dockerfile.ubuntu22` | Ubuntu 22.04 | python3.10 | Full install succeeds |
| `Dockerfile.ubuntu24` | Ubuntu 24.04 | python3.12 | Full install succeeds |
| `Dockerfile.debian12` | Debian 12 | python3.11 | Full install succeeds |
| `Dockerfile.debian13` | Debian 13 (Trixie) | python3.12 | Full install succeeds |
| `Dockerfile.minimal` | python:3.10-slim | python3.10 | Full install succeeds |
| `Dockerfile.zabbix80-coexist` | Debian 12 + the unit and logrotate file of the Zabbix 8.0 `zabbix-mcp-server` package (as in 8.0.0-1, line for line) | python3.11 | Install and update next to it leave the package's files byte for byte and warn about the shared unit name; uninstall (with a `systemctl` stub that reports the name active and enabled) removes only ours and says that the name is the package's again; a pre-1.42 logrotate config moves to its own name on install and on update; the units are as designed (the server part of `zabbix-mcp-initmax.service` and pulling in the watcher, that unit requiring the server and declaring the alias `zabbix-mcp`, one watched path on a merged `/usr`, no hand-made alias symlink); an alias name that belongs to another unit is left out, and a foreign `zabbix-mcp-initmax.service` is neither overwritten nor removed (the server is then installed without it and without any reference to it). The installer's own exit status counts (`pipefail`). What systemd then does with the shared name cannot be seen in a container without systemd; that was played through separately on Ubuntu and AlmaLinux (see the v1.42 entry of the changelog) |

## What it tests

1. **Python auto-detection** — finds the best available Python >=3.10
2. **Graceful rejection** — prints OS-specific install instructions when no suitable Python is found
3. **Full install** — creates venv, installs package, verifies `zabbix-mcp-server --version` works
4. **Dry-run mode** — `--dry-run` checks prerequisites without making changes

## Adding a new OS

1. Create `Dockerfile.<name>` based on an existing one
2. Add an entry to the `IMAGES` array in `run_all.sh`
3. Run `./run_all.sh` to verify
