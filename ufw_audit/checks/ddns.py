"""
DDNS / external exposure check for ufw-audit.

Detects active DDNS clients (ddclient, inadyn, No-IP DUC, DuckDNS),
extracts the configured domain, and crosses with unrestricted UFW ALLOW
rules to identify ports potentially exposed to the internet.

Score: -1 global if DDNS active + open ports (not per port).

Split into two parts:
  1. DdnsSnapshot.from_system() — detects DDNS clients on the live system.
  2. check_ddns(snapshot, t)    — pure logic, returns a CheckResult.

Usage:
    from ufw_audit.checks.ddns import DdnsSnapshot, check_ddns

    snapshot = DdnsSnapshot.from_system()
    result = check_ddns(snapshot, ufw_rules=rules, t=t)
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ufw_audit.scoring import CheckResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DDNS client registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DdnsClientDef:
    """
    Definition of a known DDNS client.

    Args:
        name:         Human-readable client name.
        packages:     dpkg package names.
        services:     systemd service names.
        config_files: Config file paths to search for the domain.
        client_type:  Internal identifier for domain extraction logic.
    """
    name:         str
    packages:     tuple[str, ...]
    services:     tuple[str, ...]
    config_files: tuple[str, ...]
    client_type:  str


_DDNS_CLIENTS: list[DdnsClientDef] = [
    DdnsClientDef(
        name="ddclient",
        packages=("ddclient",),
        services=("ddclient",),
        config_files=("/etc/ddclient.conf",),
        client_type="ddclient",
    ),
    DdnsClientDef(
        name="inadyn",
        packages=("inadyn",),
        services=("inadyn",),
        config_files=("/etc/inadyn.conf", "/etc/inadyn/inadyn.conf"),
        client_type="inadyn",
    ),
    DdnsClientDef(
        name="No-IP DUC",
        packages=("noip2",),
        services=("noip2",),
        config_files=("/etc/no-ip2.conf",),
        client_type="noip",
    ),
    DdnsClientDef(
        name="DuckDNS (script)",
        packages=(),
        services=(),
        config_files=("/etc/cron.d/duckdns", "/root/duckdns/duck.sh"),
        client_type="duckdns",
    ),
]

# Private IP ranges — these source restrictions make a rule "local only"
_PRIVATE_SOURCE = re.compile(
    r"(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.)"
)


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class DdnsSnapshot:
    """
    DDNS detection result for the live system.

    Args:
        client_name:  Name of the detected DDNS client, or None.
        domain:       Configured domain extracted from config, or None.
        active:       True if the DDNS service is currently running.
        installed:    True if the DDNS client was found on the system.
    """
    client_name: Optional[str]
    domain:      Optional[str]
    active:      bool
    installed:   bool

    @classmethod
    def from_system(cls) -> "DdnsSnapshot":
        """
        Detect DDNS clients on the live system.

        Returns:
            DdnsSnapshot. Never raises.
        """
        for client_def in _DDNS_CLIENTS:
            installed = _is_installed(client_def)
            if not installed:
                continue

            active = _is_active(client_def)
            domain = _extract_domain(client_def)

            return cls(
                client_name=client_def.name,
                domain=domain,
                active=active,
                installed=True,
            )

        return cls(client_name=None, domain=None, active=False, installed=False)

    @classmethod
    def none(cls) -> "DdnsSnapshot":
        """Return a snapshot representing no DDNS client detected."""
        return cls(client_name=None, domain=None, active=False, installed=False)

    @classmethod
    def detected(
        cls,
        client_name: str,
        domain: Optional[str] = None,
        active: bool = True,
    ) -> "DdnsSnapshot":
        """Factory for building test snapshots."""
        return cls(
            client_name=client_name,
            domain=domain,
            active=active,
            installed=True,
        )


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_ddns(
    snapshot: DdnsSnapshot,
    ufw_rules: str = "",
    t=None,
) -> CheckResult:
    """
    Evaluate DDNS snapshot and return findings.

    Args:
        snapshot:  DdnsSnapshot from the system.
        ufw_rules: Output of `ufw status numbered` for open port detection.
        t:         Translation function.

    Returns:
        CheckResult with DDNS findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # No DDNS client found
    if not snapshot.installed:
        result.ok(message=_t("ddns.none"))
        return result

    # Installed but inactive
    if not snapshot.active:
        result.info(message=_t("ddns.inactive") + f": {snapshot.client_name}")
        return result

    # Active DDNS client
    result.warn(
        message=_t("ddns.found") + f": {snapshot.client_name}",
        nature="improvement",
    )

    if snapshot.domain:
        result.info(message=_t("ddns.domain") + f": {snapshot.domain}")
    else:
        result.info(message=_t("ddns.no_domain"))

    # Find open ports (ALLOW without source restriction)
    open_ports = _find_open_ports(ufw_rules)

    if not open_ports:
        result.ok(message=_t("ddns.no_open_ports"))
        return result

    # Open ports detected — warn and deduct
    result.warn(
        message=_t("ddns.warn"),
        nature="improvement",
    )
    result.add_deduction(
        reason=_t("ddns.warn"),
        points=1,
        context="local",
    )

    # Store open ports for display by orchestrator
    result._ddns_open_ports = open_ports  # type: ignore[attr-defined]

    # Note Fail2ban advice
    result.info(message=_t("ddns.advice"))

    return result


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _is_installed(client_def: DdnsClientDef) -> bool:
    """Return True if the DDNS client is installed via dpkg or config file."""
    # dpkg check
    for pkg in client_def.packages:
        output = _run("dpkg", "-l", pkg)
        if re.search(r"^ii\s+" + re.escape(pkg), output, re.MULTILINE):
            return True

    # Config file check (for script-based clients like DuckDNS)
    for cfg_path in client_def.config_files:
        if Path(cfg_path).exists():
            return True

    return False


def _is_active(client_def: DdnsClientDef) -> bool:
    """Return True if the DDNS service is currently active."""
    for svc in client_def.services:
        output = _run("systemctl", "is-active", svc).strip()
        if output == "active":
            return True

    # DuckDNS: check cron entry
    if client_def.client_type == "duckdns":
        for cfg_path in client_def.config_files:
            if Path(cfg_path).exists():
                return True

    return False


def _extract_domain(client_def: DdnsClientDef) -> Optional[str]:
    """
    Attempt to extract the configured domain from the client's config file.

    Returns:
        Domain string, or None if not found.
    """
    for cfg_path in client_def.config_files:
        path = Path(cfg_path)
        if not path.exists():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        domain = None

        if client_def.client_type == "ddclient":
            domain = _extract_ddclient_domain(content)
        elif client_def.client_type == "inadyn":
            domain = _extract_inadyn_domain(content)
        elif client_def.client_type == "noip":
            domain = _extract_noip_domain(content)
        elif client_def.client_type == "duckdns":
            domain = _extract_duckdns_domain(content)

        if domain:
            return domain

    return None


def _extract_ddclient_domain(content: str) -> Optional[str]:
    """Extract domain from ddclient.conf."""
    # Standard key: hostname = domain.tld
    match = re.search(r"^(?:host|hostname)\s*=\s*(.+)", content, re.MULTILINE)
    if match:
        return match.group(1).strip().strip('"')

    # DuckDNS format: last non-comment line may be the domain
    # e.g. "http://masbateno.duckdns.org" or just "masbateno"
    for line in reversed(content.splitlines()):
        line = line.strip().rstrip("\\").strip()
        if not line or line.startswith("#"):
            continue
        if any(kw in line for kw in ("protocol=", "use=", "login=", "password=")):
            continue
        # Strip http:// or https://
        domain = re.sub(r"^https?://", "", line)
        if domain and re.match(r"[\w.-]+\.[a-z]{2,}", domain):
            return domain

    return None


def _extract_inadyn_domain(content: str) -> Optional[str]:
    """Extract domain from inadyn.conf."""
    match = re.search(r"hostname\s*=\s*(.+)", content, re.MULTILINE)
    if match:
        return match.group(1).strip().strip('"')
    return None


def _extract_noip_domain(content: str) -> Optional[str]:
    """Extract domain from no-ip2.conf."""
    match = re.search(r"^hostname\s+(\S+)", content, re.MULTILINE)
    if match:
        return match.group(1)
    return None


def _extract_duckdns_domain(content: str) -> Optional[str]:
    """Extract domain from DuckDNS script or cron entry."""
    match = re.search(r"([a-z0-9-]+\.duckdns\.org)", content)
    if match:
        return match.group(1)
    return None


# ---------------------------------------------------------------------------
# UFW helpers
# ---------------------------------------------------------------------------

def _find_open_ports(ufw_rules: str) -> list[str]:
    """
    Find ports with unrestricted ALLOW rules (no source IP restriction).

    Returns:
        List of port/proto strings e.g. ["80/tcp", "443/tcp"].
    """
    open_ports: list[str] = []

    for line in ufw_rules.splitlines():
        if not re.match(r"\s*\[\s*\d+\]", line):
            continue
        if "ALLOW" not in line.upper():
            continue
        # Skip rules with source restriction to private IP
        if _PRIVATE_SOURCE.search(line):
            continue
        # Skip rules that are "Anywhere ALLOW IN Anywhere" (default rules)
        if re.search(r"Anywhere\s+ALLOW\s+IN\s+Anywhere", line, re.IGNORECASE):
            continue

        # Extract port/proto from the rule
        port_match = re.search(r"\b(\d+)/(tcp|udp)\b", line, re.IGNORECASE)
        if port_match:
            port_proto = f"{port_match.group(1)}/{port_match.group(2).lower()}"
            if port_proto not in open_ports:
                open_ports.append(port_proto)

    return open_ports


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def _run(*args: str) -> str:
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
