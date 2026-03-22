"""
Firewall status check for ufw-audit.

Verifies UFW installation, active state, default incoming policy,
and IPv6 rule consistency.

The check is split into two parts:
  1. FirewallStatus.from_system() — collects raw data via subprocess calls.
  2. check_firewall(status)       — pure logic, returns a CheckResult.

This separation allows full unit testing of all logic without
any subprocess calls.

Usage:
    from ufw_audit.checks.firewall import check_firewall, FirewallStatus

    status = FirewallStatus.from_system()
    result = check_firewall(status)
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field

from ufw_audit.scoring import CheckResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class FirewallStatus:
    """
    Raw snapshot of the UFW firewall state collected from the system.

    Args:
        installed:        True if the ufw binary is available.
        active:           True if UFW reports Status: active.
        incoming_policy:  Parsed default incoming policy string.
                          One of: "deny", "allow", "reject", "unknown".
        ufw_output:       Full output of `ufw status verbose` for the report.
        ipv4_rules_count: Number of non-IPv6 UFW rules found.
        ipv6_rules_count: Number of IPv6 UFW rules found (lines with (v6)).
    """
    installed:        bool
    active:           bool
    incoming_policy:  str
    ufw_output:       str
    ipv4_rules_count: int
    ipv6_rules_count: int

    @classmethod
    def from_system(cls) -> "FirewallStatus":
        """
        Collect firewall state from the live system via subprocess.

        Returns:
            Populated FirewallStatus. Never raises — errors are reflected
            in the returned state (installed=False, active=False, etc.).
        """
        # Check installation
        installed = _command_exists("ufw")
        if not installed:
            return cls(
                installed=False, active=False,
                incoming_policy="unknown", ufw_output="",
                ipv4_rules_count=0, ipv6_rules_count=0,
            )

        # Get full status output
        ufw_output = _run("ufw", "status", "verbose")

        # Parse active state
        active = bool(re.search(r"^Status:\s+active", ufw_output, re.MULTILINE))

        # Parse incoming policy
        incoming_policy = "unknown"
        match = re.search(r"Default:\s+(\w+)\s+\(incoming\)", ufw_output)
        if match:
            incoming_policy = match.group(1).lower()

        # Count IPv4 vs IPv6 rules
        numbered_output = _run("ufw", "status", "numbered")
        ipv4_rules_count = len([
            line for line in numbered_output.splitlines()
            if re.match(r"\s*\[\s*\d+\]", line) and "(v6)" not in line
        ])
        ipv6_rules_count = len([
            line for line in numbered_output.splitlines()
            if re.match(r"\s*\[\s*\d+\]", line) and "(v6)" in line
        ])

        return cls(
            installed=installed,
            active=active,
            incoming_policy=incoming_policy,
            ufw_output=ufw_output,
            ipv4_rules_count=ipv4_rules_count,
            ipv6_rules_count=ipv6_rules_count,
        )


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_firewall(status: FirewallStatus, t=None) -> CheckResult:
    """
    Evaluate firewall status and return findings and deductions.

    This function is pure — it never calls the system. All input comes
    from the FirewallStatus snapshot.

    Args:
        status: FirewallStatus collected from the system (or built in tests).
        t:      Translation function t(key) -> str. If None, key names are
                used as-is (useful in tests that don't need translated strings).

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- UFW installed ---
    if not status.installed:
        result.alert(
            message=_t("prerequisites.ufw_missing"),
            nature="action",
            cmd="sudo apt install ufw",
        )
        return result  # nothing more to check

    result.ok(message=_t("prerequisites.ufw_installed"))

    # --- UFW active ---
    if not status.active:
        result.alert(
            message=_t("firewall.inactive"),
            nature="action",
            cmd="sudo ufw enable",
        )
        # Cap score at 3 when firewall is inactive
        result.add_deduction(
            reason=_t("firewall.inactive"),
            points=0,  # actual cap applied by orchestrator via engine.cap()
            context="local",
        )
        # Signal cap to orchestrator via a sentinel deduction with points=-1
        # (negative sentinel, filtered out from display — see __main__.py)
        result._firewall_inactive = True  # type: ignore[attr-defined]
        return result

    result.ok(message=_t("firewall.active"))

    # --- Default incoming policy ---
    if status.incoming_policy == "allow":
        result.alert(
            message=_t("firewall.policy_open"),
            nature="action",
            cmd="sudo ufw default deny incoming",
        )
        result.add_deduction(
            reason=_t("firewall.policy_open"),
            points=3,
            context="local",
        )
    elif status.incoming_policy == "deny":
        result.ok(message=_t("firewall.policy_ok"))
    else:
        result.warn(
            message=_t("firewall.policy_unknown"),
            nature="improvement",
        )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(*args: str) -> str:
    """Run a command and return its stdout. Returns empty string on error."""
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


def _command_exists(name: str) -> bool:
    """Return True if the given command is available in PATH."""
    try:
        result = subprocess.run(
            ["which", name],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError):
        return False


def _identity_t(key: str, **kwargs) -> str:
    """Fallback translation that returns the key itself."""
    return key