"""
Docker security check for ufw-audit.

Verifies that Docker is configured to not bypass UFW rules via iptables,
and lists any running containers with exposed ports.

The main risk: by default Docker manipulates iptables directly, bypassing
UFW rules entirely. The fix is to set {"iptables": false} in daemon.json.

Split into two parts:
  1. DockerSnapshot.from_system() — collects data via subprocess.
  2. check_docker(snapshot, t)    — pure logic, returns a CheckResult.

Usage:
    from ufw_audit.checks.docker import DockerSnapshot, check_docker

    snapshot = DockerSnapshot.from_system()
    result = check_docker(snapshot, t=t)
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ufw_audit.scoring import CheckResult

logger = logging.getLogger(__name__)

DAEMON_JSON_PATH = Path("/etc/docker/daemon.json")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ExposedPort:
    """A port exposed by a running Docker container."""
    container_name: str
    host_port:      int
    container_port: int
    proto:          str
    host_ip:        str   # "0.0.0.0" | "127.0.0.1" | specific IP

    @property
    def port_proto(self) -> str:
        return f"{self.host_port}/{self.proto}"

    @property
    def is_public(self) -> bool:
        """True if the port is bound to all interfaces."""
        return self.host_ip in ("0.0.0.0", "::")


@dataclass
class DockerSnapshot:
    """
    Docker security state as collected from the live system.

    Args:
        installed:          True if docker is available.
        iptables_disabled:  True if {"iptables": false} is set in daemon.json.
        daemon_json_exists: True if /etc/docker/daemon.json exists.
        exposed_ports:      List of ports exposed by running containers.
    """
    installed:          bool
    iptables_disabled:  bool
    daemon_json_exists: bool
    exposed_ports:      list[ExposedPort] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "DockerSnapshot":
        """
        Collect Docker state from the live system.

        Returns:
            Populated DockerSnapshot. Never raises.
        """
        installed = _command_exists("docker")
        if not installed:
            return cls(
                installed=False,
                iptables_disabled=False,
                daemon_json_exists=False,
                exposed_ports=[],
            )

        daemon_json_exists, iptables_disabled = _check_daemon_json()
        exposed_ports = _get_exposed_ports()

        return cls(
            installed=True,
            iptables_disabled=iptables_disabled,
            daemon_json_exists=daemon_json_exists,
            exposed_ports=exposed_ports,
        )

    @classmethod
    def not_installed(cls) -> "DockerSnapshot":
        """Factory for a snapshot representing Docker not installed."""
        return cls(
            installed=False,
            iptables_disabled=False,
            daemon_json_exists=False,
            exposed_ports=[],
        )

    @classmethod
    def safe(cls, exposed_ports: list[ExposedPort] | None = None) -> "DockerSnapshot":
        """Factory for a safe Docker configuration (iptables disabled)."""
        return cls(
            installed=True,
            iptables_disabled=True,
            daemon_json_exists=True,
            exposed_ports=exposed_ports or [],
        )

    @classmethod
    def unsafe(cls, exposed_ports: list[ExposedPort] | None = None) -> "DockerSnapshot":
        """Factory for an unsafe Docker configuration (iptables NOT disabled)."""
        return cls(
            installed=True,
            iptables_disabled=False,
            daemon_json_exists=False,
            exposed_ports=exposed_ports or [],
        )


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_docker(
    snapshot: DockerSnapshot,
    network_context: str = "local",
    t=None,
) -> CheckResult:
    """
    Evaluate Docker security snapshot and return findings.

    Args:
        snapshot:        DockerSnapshot from the system.
        network_context: "local" or "public".
        t:               Translation function.

    Returns:
        CheckResult with Docker findings and score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.installed:
        result.info(message=_t("docker.not_installed"))
        return result

    # iptables bypass check
    if snapshot.iptables_disabled:
        result.ok(message=_t("docker.iptables_disabled"))
    else:
        result.alert(
            message=_t("docker.iptables_bypass"),
            nature="action",
            cmd=(
                'sudo mkdir -p /etc/docker && '
                'echo \'{"iptables": false}\' | sudo tee /etc/docker/daemon.json'
            ),
        )
        points = 2 if network_context == "public" else 1
        result.add_deduction(
            reason=_t("docker.iptables_bypass"),
            points=points,
            context=network_context,
        )

    # Exposed container ports
    public_ports = [p for p in snapshot.exposed_ports if p.is_public]

    if not snapshot.exposed_ports:
        result.ok(message=_t("docker.no_containers"))
    elif not public_ports:
        result.ok(message=_t("docker.no_containers"))
    else:
        for port in public_ports:
            result.warn(
                message=(
                    f"{port.container_name}: {port.port_proto} "
                    f"→ {port.container_port}/{port.proto}"
                ),
                nature="improvement",
            )
            # Additional deduction if iptables is NOT disabled
            # (port is truly bypassing UFW)
            if not snapshot.iptables_disabled:
                result.add_deduction(
                    reason=f"Docker bypass: {port.container_name} {port.port_proto}",
                    points=2 if network_context == "public" else 1,
                    context=network_context,
                )

    return result


# ---------------------------------------------------------------------------
# System helpers
# ---------------------------------------------------------------------------

def _check_daemon_json() -> tuple[bool, bool]:
    """
    Read /etc/docker/daemon.json and check if iptables is disabled.

    Returns:
        Tuple of (file_exists: bool, iptables_disabled: bool).
    """
    if not DAEMON_JSON_PATH.exists():
        return False, False

    try:
        content = DAEMON_JSON_PATH.read_text(encoding="utf-8")
        config = json.loads(content)
        iptables_disabled = config.get("iptables") is False
        return True, iptables_disabled
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot parse %s: %s", DAEMON_JSON_PATH, exc)
        return True, False


def _get_exposed_ports() -> list[ExposedPort]:
    """
    List ports exposed by running Docker containers.

    Returns:
        List of ExposedPort objects.
    """
    output = _run(
        "docker", "ps", "--format",
        "{{.Names}}\t{{.Ports}}"
    )
    if not output.strip():
        return []

    ports: list[ExposedPort] = []

    for line in output.strip().splitlines():
        parts = line.split("\t", 1)
        if len(parts) < 2:
            continue
        container_name = parts[0].strip()
        ports_str = parts[1].strip()

        if not ports_str:
            continue

        for port_entry in ports_str.split(", "):
            parsed = _parse_port_entry(container_name, port_entry)
            if parsed:
                ports.append(parsed)

    return ports


def _parse_port_entry(container_name: str, entry: str) -> Optional[ExposedPort]:
    """
    Parse a Docker port mapping entry.

    Expected formats:
      - "0.0.0.0:8080->80/tcp"
      - ":::8080->80/tcp"
      - "0.0.0.0:8080->80/tcp, :::8080->80/tcp"

    Returns:
        ExposedPort or None if parsing fails.
    """
    # Match: host_ip:host_port->container_port/proto
    match = re.match(
        r"^([\d.:]+):(\d+)->(\d+)/(tcp|udp)$",
        entry.strip(),
    )
    if not match:
        return None

    return ExposedPort(
        container_name=container_name,
        host_ip=match.group(1),
        host_port=int(match.group(2)),
        container_port=int(match.group(3)),
        proto=match.group(4),
    )


def _command_exists(name: str) -> bool:
    """Return True if the command is available in PATH."""
    try:
        subprocess.run(["which", name], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, OSError):
        return False


def _run(*args: str) -> str:
    """Run a command and return stdout. Returns empty string on error."""
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, timeout=10,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Command %r failed: %s", args, exc)
        return ""


def _identity_t(key: str, **kwargs) -> str:
    return key
