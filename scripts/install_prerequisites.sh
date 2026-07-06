#!/usr/bin/env bash
#
# Install container runtime prerequisites for STINGAR quickstart.
# RedHat-family -> Podman + native "podman compose" (Compose V2 plugin)
# Debian/Ubuntu -> Docker CE + "docker compose" plugin
#
# RHEL 8/9 testing (Rocky Linux 8.9 / 9.3, 2026-07): pip podman-compose on
# default Python 3.6 (RHEL 8) fails; native "podman compose" works on both.
#
# Usage: sudo ./scripts/install_prerequisites.sh

set -euo pipefail

COMPOSE_PLUGIN_VERSION="${COMPOSE_PLUGIN_VERSION:-v2.40.3}"
COMPOSE_PLUGIN_DIR="/usr/local/lib/docker/cli-plugins"
RUNTIME_FILE=".stingar-runtime"
STINGAR_USER="${SUDO_USER:-${USER:-root}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QUICKSTART_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root: sudo $0"
  fi
}

read_os_release() {
  if [[ ! -f /etc/os-release ]]; then
    echo "unknown"
    return
  fi
  # shellcheck disable=SC1091
  source /etc/os-release
  echo "${ID:-unknown}|${ID_LIKE:-}|${VERSION_ID:-}|${VERSION_CODENAME:-}"
}

detect_runtime() {
  if [[ -n "${CONTAINER_RUNTIME:-}" ]]; then
    echo "${CONTAINER_RUNTIME}"
    return
  fi
  local id id_like
  IFS='|' read -r id id_like _ _ <<< "$(read_os_release)"
  id="${id,,}"
  id_like="${id_like,,}"
  case "$id" in
    rhel|rocky|almalinux|fedora|centos|ol|oraclelinux)
      echo "podman"
      return
      ;;
  esac
  if [[ "$id_like" == *rhel* || "$id_like" == *fedora* ]]; then
    echo "podman"
    return
  fi
  echo "docker"
}

map_compose_arch() {
  case "$(uname -m)" in
    x86_64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
  esac
}

redhat_pkg_manager() {
  if command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  else
    die "Neither dnf nor yum found"
  fi
}

# UBI 9 and minimal RHEL images ship curl-minimal, which conflicts with the
# full curl package. Never install both; use whichever provides /usr/bin/curl.
ensure_curl() {
  local pkg="$1"
  if command -v curl >/dev/null 2>&1; then
    log "Download tool: $(command -v curl)"
    return 0
  fi
  log "Installing curl-minimal for downloads..."
  if $pkg install -y curl-minimal; then
    return 0
  fi
  log "curl-minimal unavailable; installing curl package..."
  $pkg install -y curl
}

enable_podman_socket() {
  if [[ ! -d /run/systemd/system ]] || ! command -v systemctl >/dev/null 2>&1; then
    log "Note: systemd not running; skipping podman.socket enable (expected in containers)."
    return 0
  fi
  systemctl enable podman.socket
  if systemctl start podman.socket; then
    log "Podman socket enabled (Docker API compatibility via podman-docker)."
  else
    log "Warning: podman.socket could not be started; verify on a systemd host."
  fi
}

install_compose_plugin() {
  local arch url dest
  arch="$(map_compose_arch)"
  url="https://github.com/docker/compose/releases/download/${COMPOSE_PLUGIN_VERSION}/docker-compose-linux-${arch}"
  dest="${COMPOSE_PLUGIN_DIR}/docker-compose"
  log "Installing Compose plugin ${COMPOSE_PLUGIN_VERSION} for ${arch}..."
  mkdir -p "${COMPOSE_PLUGIN_DIR}"
  curl -fsSL "${url}" -o "${dest}"
  chmod +x "${dest}"
}

install_docker_debian() {
  log "Installing Docker (Debian/Ubuntu family)..."
  apt-get update
  apt-get install -y ca-certificates curl gnupg python3 python3-venv

  install -m 0755 -d /etc/apt/keyrings
  local codename distro_uri gpg_url
  # shellcheck disable=SC1091
  source /etc/os-release
  # Ubuntu also reports ID_LIKE=debian; match on ID, not ID_LIKE, so Ubuntu
  # hosts use download.docker.com/linux/ubuntu (not .../debian).
  if [[ "${ID}" == "ubuntu" ]]; then
    codename="${UBUNTU_CODENAME:-${VERSION_CODENAME:-$(lsb_release -cs 2>/dev/null || echo noble)}}"
    gpg_url="https://download.docker.com/linux/ubuntu/gpg"
    distro_uri="https://download.docker.com/linux/ubuntu"
  elif [[ "${ID}" == "debian" ]]; then
    codename="${VERSION_CODENAME:-bookworm}"
    gpg_url="https://download.docker.com/linux/debian/gpg"
    distro_uri="https://download.docker.com/linux/debian"
  else
    die "Automatic Docker install supports Debian and Ubuntu only (detected ID=${ID})."
  fi

  log "Using Docker CE apt suite: ${codename} (${distro_uri})"
  curl -fsSL "${gpg_url}" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  rm -f /etc/apt/sources.list.d/docker.list
  tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: ${distro_uri}
Suites: ${codename}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  apt-get update
  apt-get install -y \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  groupadd -f docker
  usermod -aG docker "$STINGAR_USER"
  systemctl enable --now docker.service containerd.service
}

install_podman_redhat() {
  log "Installing Podman (RedHat family)..."
  local pkg
  pkg="$(redhat_pkg_manager)"
  # Do not install the full curl package here: UBI 9 ships curl-minimal and dnf
  # will fail if both are requested. ensure_curl() runs before downloading assets.
  $pkg install -y podman podman-docker

  ensure_curl "$pkg"
  install_compose_plugin
  enable_podman_socket

  if ! podman compose version >/dev/null 2>&1; then
    die "'podman compose' failed after installing Compose plugin. Check network/arch."
  fi
  log "Verified: $(podman compose version 2>&1 | head -1)"
}

write_runtime_file() {
  local runtime="$1"
  local compose_cmd launch_hint compose_mode
  if [[ "$runtime" == "podman" ]]; then
    compose_cmd="podman compose"
    compose_mode="native"
    launch_hint="podman compose up -d"
  else
    compose_cmd="docker compose"
    compose_mode="native"
    launch_hint="docker compose up -d"
  fi
  cat > "${QUICKSTART_DIR}/${RUNTIME_FILE}" <<EOF
{
  "runtime": "${runtime}",
  "compose_cmd": "${compose_cmd}",
  "compose_mode": "${compose_mode}",
  "launch_hint": "${launch_hint}",
  "socket_host_path": "/var/run/docker.sock"
}
EOF
  chown "${STINGAR_USER}:${STINGAR_USER}" "${QUICKSTART_DIR}/${RUNTIME_FILE}" 2>/dev/null || true
  log "Wrote ${QUICKSTART_DIR}/${RUNTIME_FILE} (runtime=${runtime})."
}

main() {
  require_root
  local runtime
  runtime="$(detect_runtime)"
  log "Selected container runtime: ${runtime}"

  case "$runtime" in
    docker)
      if command -v apt-get >/dev/null 2>&1; then
        install_docker_debian
      else
        die "Automatic Docker install supports Debian/Ubuntu only."
      fi
      ;;
    podman)
      install_podman_redhat
      ;;
    *)
      die "Unknown runtime: ${runtime}"
      ;;
  esac

  write_runtime_file "$runtime"

  log ""
  log "Installation complete."
  if [[ "$runtime" == "docker" ]]; then
    log "Log out and back in (or: newgrp docker) so group membership takes effect."
  fi
  log "Next steps:"
  log "  cd stingar"
  log "  python3 configure_stingar.py"
  log "  ./scripts/compose.sh up -d"
}

main "$@"
