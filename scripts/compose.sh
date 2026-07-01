#!/usr/bin/env bash
# Run "docker compose" or "podman compose" based on .stingar-runtime or CONTAINER_RUNTIME.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

RUNTIME="${CONTAINER_RUNTIME:-}"

if [[ -z "${RUNTIME}" && -f .stingar-runtime ]]; then
  RUNTIME="$(python3 -c "import json; print(json.load(open('.stingar-runtime'))['runtime'])" 2>/dev/null || true)"
fi
RUNTIME="${RUNTIME:-docker}"

if [[ "${RUNTIME}" == "podman" ]]; then
  if ! command -v podman >/dev/null 2>&1; then
    echo "ERROR: podman not found. Run: sudo ./scripts/install_prerequisites.sh" >&2
    exit 1
  fi
  if ! podman compose version >/dev/null 2>&1; then
    echo "ERROR: 'podman compose' not available. Re-run: sudo ./scripts/install_prerequisites.sh" >&2
    exit 1
  fi
  exec podman compose "$@"
fi

exec docker compose "$@"
