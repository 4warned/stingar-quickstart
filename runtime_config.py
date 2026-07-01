"""
Container runtime detection for STINGAR quickstart.

RedHat-family admin hosts use native ``podman compose`` (Compose V2 plugin).
Debian/Ubuntu use ``docker compose``. Honeypot hosts deployed by Langstroth
still use podman-compose in a venv; see container_runtime docs for RHEL 8 notes.
"""

import json
import os
import shutil
import subprocess

RUNTIME_FILE = ".stingar-runtime"
DEFAULT_STINGAR_VERSION = "v2.4"

REDHAT_OS_IDS = frozenset(
    {"rhel", "rocky", "almalinux", "fedora", "centos", "ol", "oraclelinux"}
)


def _read_os_release():
    data = {}
    path = "/etc/os-release"
    if not os.path.isfile(path):
        return data
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            data[key] = value.strip().strip('"').lower()
    return data


def detect_os_runtime():
    """Return 'podman' or 'docker' from env, runtime file, or OS family."""
    override = os.environ.get("CONTAINER_RUNTIME", "").strip().lower()
    if override in ("docker", "podman"):
        return override

    if os.path.isfile(RUNTIME_FILE):
        try:
            with open(RUNTIME_FILE, encoding="utf-8") as handle:
                saved = json.load(handle)
            runtime = saved.get("runtime", "").lower()
            if runtime in ("docker", "podman"):
                return runtime
        except (json.JSONDecodeError, OSError):
            pass

    os_release = _read_os_release()
    os_id = os_release.get("id", "")
    id_like = os_release.get("id_like", "")
    if os_id in REDHAT_OS_IDS or "rhel" in id_like or "fedora" in id_like:
        return "podman"
    return "docker"


def get_runtime_config(runtime=None):
    """Build template and preflight settings for the selected runtime."""
    runtime = (runtime or detect_os_runtime()).lower()
    selinux = "Z" if runtime == "podman" else "z"

    if runtime == "podman":
        return {
            "runtime": "podman",
            "compose_cmd": "podman compose",
            "compose_mode": "native",
            "launch_hint": "podman compose up -d",
            "volume_selinux": selinux,
            "nginx_volume_opts": "ro,Z",
            "update_service_enabled": "false",
            "container_runtime": "podman",
            "socket_host_path": "/var/run/docker.sock",
        }

    return {
        "runtime": "docker",
        "compose_cmd": "docker compose",
        "compose_mode": "native",
        "launch_hint": "docker compose up -d",
        "volume_selinux": selinux,
        "nginx_volume_opts": "ro",
        "update_service_enabled": "true",
        "container_runtime": "docker",
        "socket_host_path": "/var/run/docker.sock",
    }


def write_runtime_file(config, directory="."):
    """Persist runtime metadata for compose.sh and documentation."""
    path = os.path.join(directory, RUNTIME_FILE)
    payload = {
        "runtime": config["runtime"],
        "compose_cmd": config["compose_cmd"],
        "compose_mode": config.get("compose_mode", "native"),
        "launch_hint": config["launch_hint"],
        "socket_host_path": config["socket_host_path"],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return path


def _run_version(cmd):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip().splitlines()[0]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def validate_runtime_tools(config):
    """
    Verify container runtime CLI is available.

    Returns (ok: bool, message: str).
    """
    runtime = config["runtime"]
    if runtime == "docker":
        if not shutil.which("docker"):
            return False, (
                "'docker' not found. Run scripts/install_prerequisites.sh "
                "or install Docker manually."
            )
        version = _run_version(["docker", "compose", "version"])
        if not version:
            return False, (
                "'docker compose' (Compose V2 plugin) not found. "
                "Run scripts/install_prerequisites.sh."
            )
        return True, "docker compose: %s" % version

    if not shutil.which("podman"):
        return False, (
            "'podman' not found. Run scripts/install_prerequisites.sh "
            "or install Podman manually."
        )
    version = _run_version(["podman", "compose", "version"])
    if not version:
        return False, (
            "'podman compose' not available. Re-run scripts/install_prerequisites.sh "
            "to install the Compose V2 plugin."
        )
    return True, "podman compose: %s" % version
