"""
Network services check for ufw-audit.

Detects installed network services, their systemd state, and their
UFW exposure level for each listening port.

Split into two parts:
  1. ServiceSnapshot.from_system()  — collects data via subprocess.
  2. check_services(snapshots, t)   — pure logic, returns a CheckResult.

Usage:
    from ufw_audit.checks.services import ServiceSnapshot, check_services
    from ufw_audit.registry import ServiceRegistry

    registry = ServiceRegistry.load()
    snapshots = ServiceSnapshot.collect(registry)
    result = check_services(snapshots, t=t)
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from ufw_audit.registry import Service, ServiceRegistry
from ufw_audit.scoring import CheckResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ServiceState(Enum):
    """Systemd service state."""
    ACTIVE_ENABLED    = "active_enabled"
    ACTIVE_DISABLED   = "active_disabled"
    INACTIVE_ENABLED  = "inactive_enabled"
    INACTIVE_DISABLED = "inactive_disabled"
    UNKNOWN           = "unknown"

    @property
    def is_active(self) -> bool:
        return self in (ServiceState.ACTIVE_ENABLED, ServiceState.ACTIVE_DISABLED)

    @property
    def is_inactive(self) -> bool:
        return self in (ServiceState.INACTIVE_ENABLED, ServiceState.INACTIVE_DISABLED)


class Exposure(Enum):
    """UFW exposure level for a single port."""
    OPEN_WORLD = "open_world"   # ALLOW without source restriction
    OPEN_LOCAL = "open_local"   # ALLOW restricted to private IP/range
    DENY       = "deny"         # explicit DENY rule
    NO_RULE    = "no_rule"      # no UFW rule covers this port


# ---------------------------------------------------------------------------
# Service snapshot
# ---------------------------------------------------------------------------

@dataclass
class ServiceSnapshot:
    """
    State of a single service as detected on the live system.

    Args:
        service:     Service definition from the registry.
        installed:   True if the service was detected on this system.
        install_via: How the service was detected: "dpkg", "snap", "binary", or "".
        state:       Systemd service state.
        ports:       Resolved port list (may differ from registry defaults if auto-detected).
        exposures:   Mapping of port string to Exposure enum value.
                     e.g. {"22/tcp": Exposure.OPEN_WORLD, "22/udp": Exposure.NO_RULE}
    """
    service:     Service
    installed:   bool
    install_via: str
    state:       ServiceState
    ports:       list[str]
    exposures:   dict[str, Exposure] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.service.label

    @property
    def risk(self) -> str:
        return self.service.risk

    @property
    def is_active(self) -> bool:
        return self.state.is_active

    @classmethod
    def collect(
        cls,
        registry: ServiceRegistry,
        ufw_rules: Optional[str] = None,
    ) -> list["ServiceSnapshot"]:
        """
        Collect snapshots for all services in the registry.

        Args:
            registry:  Loaded ServiceRegistry.
            ufw_rules: Output of `ufw status numbered` (injected for testing).
                       If None, fetched from the system.

        Returns:
            List of ServiceSnapshot for every installed service.
            Non-installed services are excluded.
        """
        if ufw_rules is None:
            ufw_rules = _run("ufw", "status", "numbered")

        snapshots = []
        for service in registry:
            installed, via = _detect_installation(service)
            if not installed:
                continue

            state = _detect_state(service)
            ports = _resolve_ports(service)
            exposures = {
                port: _classify_exposure(port, ufw_rules)
                for port in ports
            }

            snapshots.append(cls(
                service=service,
                installed=True,
                install_via=via,
                state=state,
                ports=ports,
                exposures=exposures,
            ))

        return snapshots


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_services(
    snapshots: list[ServiceSnapshot],
    network_context: str = "local",
    t=None,
) -> CheckResult:
    """
    Evaluate service snapshots and return findings and deductions.

    Args:
        snapshots:       List of installed ServiceSnapshots.
        network_context: "local" or "public" — affects deduction weight.
        t:               Translation function. If None, key names are used.

    Returns:
        CheckResult with all service findings and score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    for snap in snapshots:
        _check_single_service(snap, result, network_context, _t)

    return result


def _check_single_service(
    snap: ServiceSnapshot,
    result: CheckResult,
    network_context: str,
    _t,
) -> None:
    """Evaluate a single service snapshot and add findings to result."""

    # Inactive and disabled — low risk, informational only
    if snap.state == ServiceState.INACTIVE_DISABLED:
        result.info(
            message=_t("services.state.inactive_disabled", label=snap.label),
        )
        return

    # Active but not enabled at boot
    if snap.state == ServiceState.ACTIVE_DISABLED:
        result.warn(
            message=_t("services.state.active_disabled"),
            nature="improvement",
        )

    # Active and enabled — OK
    if snap.state == ServiceState.ACTIVE_ENABLED:
        result.ok(message=_t("services.state.active_enabled"))

    # Unknown state — informational
    if snap.state == ServiceState.UNKNOWN:
        result.info(message=_t("services.state.unknown"))

    # Analyse each port exposure
    for port, exposure in snap.exposures.items():
        _check_port_exposure(snap, port, exposure, result, network_context, _t)


def _check_port_exposure(
    snap: ServiceSnapshot,
    port: str,
    exposure: Exposure,
    result: CheckResult,
    network_context: str,
    _t,
) -> None:
    """Add findings for a single port exposure."""

    port_msg = _t("services.port_exposure", port=port,
                  exposure=_t(f"services.exposure.{exposure.value}"))

    if exposure == Exposure.OPEN_WORLD:
        # High/critical services exposed to internet get extra penalty in public context
        base_points = 1
        if snap.service.is_high_or_critical and network_context == "public":
            base_points = 3
        elif snap.service.is_high_or_critical:
            base_points = 2

        result.warn(
            message=port_msg,
            nature="improvement",
        )
        result.add_deduction(
            reason=f"{snap.label} {port} open_world",
            points=base_points,
            context=network_context,
        )

    elif exposure == Exposure.OPEN_LOCAL:
        result.warn(
            message=port_msg,
            nature="structural",
        )

    elif exposure == Exposure.DENY:
        result.ok(message=port_msg)

    elif exposure == Exposure.NO_RULE:
        result.info(message=port_msg)


# ---------------------------------------------------------------------------
# System detection helpers
# ---------------------------------------------------------------------------

def _detect_installation(service: Service) -> tuple[bool, str]:
    """
    Check if a service is installed via dpkg, snap, or binary.

    Returns:
        Tuple of (installed: bool, method: str).
        Method is one of: "dpkg", "snap", "binary", or "".
    """
    # dpkg check
    for pkg in service.packages:
        output = _run("dpkg", "-l", pkg)
        if re.search(r"^ii\s+" + re.escape(pkg), output, re.MULTILINE):
            return True, "dpkg"

    # snap check
    for snap_pkg in service.detection.snap:
        output = _run("snap", "list", snap_pkg)
        if snap_pkg in output and "error" not in output.lower():
            return True, "snap"

    # binary check
    for binary_path in service.detection.binary:
        if Path(binary_path).is_file():
            return True, "binary"

    return False, ""


def _detect_state(service: Service) -> ServiceState:
    """
    Determine the systemd state of a service.

    Returns:
        ServiceState enum value.
    """
    for svc_name in service.services:
        # Handle template services like wg-quick@
        if svc_name.endswith("@"):
            pattern = svc_name
            list_output = _run("systemctl", "list-units", "--all", pattern + "*")
            if not list_output.strip():
                # No instance found — service is installed but not configured
                return ServiceState.INACTIVE_DISABLED
            # Find the first active instance
            match = re.search(r"(\S+\.service)", list_output)
            if match:
                svc_name = match.group(1)
            else:
                return ServiceState.INACTIVE_DISABLED

        active  = _run("systemctl", "is-active",  svc_name).strip()
        enabled = _run("systemctl", "is-enabled", svc_name).strip()

        is_active  = active  == "active"
        is_enabled = enabled == "enabled"

        if is_active and is_enabled:
            return ServiceState.ACTIVE_ENABLED
        if is_active:
            return ServiceState.ACTIVE_DISABLED
        if is_enabled:
            return ServiceState.INACTIVE_ENABLED

        # Service exists in systemd but is inactive/disabled
        if active in ("inactive", "failed", "activating"):
            return ServiceState.INACTIVE_DISABLED

    return ServiceState.UNKNOWN


def _resolve_ports(service: Service) -> list[str]:
    """
    Resolve the actual ports for a service.

    For services with config_key="auto", attempts to read the port
    from the service's configuration file. Falls back to registry defaults.

    Returns:
        List of port strings in "number/proto" format.
    """
    if service.config_key == "auto":
        detected = _auto_detect_port(service)
        if detected:
            return [detected]

    return list(service.ports)


def _is_safe_config_path(path: Path) -> bool:
    """Return True only for safe, non-symlink absolute paths."""
    return path.is_absolute() and not path.is_symlink()


def _auto_detect_port(service: Service) -> Optional[str]:
    """
    Attempt to detect the actual port from the service configuration file.

    Returns:
        Port string like "8080/tcp", or None if detection fails.
    """
    for config_file in service.detection.config_files:
        path = Path(config_file)
        if not path.exists() or not _is_safe_config_path(path):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # Generic patterns — specific services may need custom parsing
        # Port = 8080 / port=8080 / listen 8080 / HTTP_PORT = 3000
        match = re.search(
            r"(?:^|\s)(?:port|listen|HTTP_PORT|http_port)\s*[=:]\s*(\d+)",
            content,
            re.IGNORECASE | re.MULTILINE,
        )
        if match:
            port_num = match.group(1)
            # Determine proto from registry default
            proto = "tcp"
            if service.ports:
                proto = service.ports[0].split("/")[-1]
            return f"{port_num}/{proto}"

    return None


def _classify_exposure(port: str, ufw_rules: str) -> Exposure:
    """
    Classify how a port is handled by UFW rules.

    Args:
        port:      Port string like "22/tcp" or "5353/udp".
        ufw_rules: Output of `ufw status numbered`.

    Returns:
        Exposure enum value.
    """
    port_num  = port.split("/")[0]
    proto     = port.split("/")[1] if "/" in port else "tcp"

    if not port_num.isdigit() or not (1 <= int(port_num) <= 65535):
        logger.warning("Invalid port number in registry: %r", port_num)
        return Exposure.NO_RULE
    if proto not in ("tcp", "udp"):
        logger.warning("Invalid protocol in registry: %r", proto)
        return Exposure.NO_RULE

    # Private IP ranges for open_local detection
    _PRIVATE = re.compile(
        r"(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.)"
    )

    port_pattern = re.compile(
        r"\b" + re.escape(port_num) + r"(?:/" + re.escape(proto) + r")?\b",
        re.IGNORECASE,
    )

    # UFW uses first-match semantics — process rules in order and return immediately
    for line in ufw_rules.splitlines():
        # Skip non-rule lines
        if not re.match(r"\s*\[\s*\d+\]", line):
            continue

        if not port_pattern.search(line):
            continue

        line_upper = line.upper()

        if "DENY" in line_upper:
            return Exposure.DENY
        elif "ALLOW" in line_upper:
            # Check if rule has a source restriction to a private range
            if _PRIVATE.search(line):
                return Exposure.OPEN_LOCAL
            else:
                return Exposure.OPEN_WORLD

    return Exposure.NO_RULE


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def _run(*args: str) -> str:
    """Run a command and return stdout. Returns empty string on error."""
    try:
        proc = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Command %r failed: %s", args, exc)
        return ""


def _identity_t(key: str, **kwargs) -> str:
    return key