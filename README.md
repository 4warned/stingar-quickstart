# STINGAR quickstart

Interactive helper (`configure_stingar.py`) generates `stingar.env`, `nginx.conf`, and `docker-compose.yml` from `templates/`.

Detects the host OS and selects **Docker** (Debian/Ubuntu) or **Podman** (RedHat-family), matching the v2.4 honeypot deployment engine.

## Release v2.4

Pins all `4warned/*` images to **`v2.4`**. Override with `STINGAR_VERSION=v2.4.x python3 configure_stingar.py`.

## Usage

### 1. Install container runtime (first time, as root)

```bash
sudo ./scripts/install_prerequisites.sh
```

On RHEL 8/9 this installs Podman plus the Compose V2 plugin for **`podman compose`** (validated on Rocky Linux 8.9 and 9.3). On Ubuntu/Debian it installs Docker and the **`docker compose`** plugin.

Log out and back in after install on Docker hosts (group membership).

### 2. Generate configuration

```bash
python3 configure_stingar.py
```

### 3. Launch STINGAR

```bash
./scripts/compose.sh up -d
```

Ensure `certs/` contains TLS material referenced by `nginx.conf`, and review `stingar.env` after generation.

## Podman / RHEL notes

- Rootful Podman uses ports 80/443 (no manual nginx port remapping).
- Admin server uses **`podman compose`**, not the Python `podman-compose` package. The latter fails on RHEL 8 when installed with system Python 3.6; native `podman compose` works on RHEL 8 and 9.
- In-app auto-update is **disabled** on Podman installs. Upgrade manually:

  ```bash
  ./scripts/compose.sh pull
  ./scripts/compose.sh up -d
  ```

- Override runtime detection: `CONTAINER_RUNTIME=docker|podman`

## Files written

| File | Purpose |
|------|---------|
| `.stingar-runtime` | Selected runtime and compose command |
| `stingar.env` | Application settings |
| `docker-compose.yml` | Platform stack |
| `nginx.conf` | TLS reverse proxy |
