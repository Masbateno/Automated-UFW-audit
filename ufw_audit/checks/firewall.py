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

import re
from dataclasses import dataclass
from pathlib import Path

from ufw_audit.checks._run import _command_exists, _identity_t, _run
from ufw_audit.scoring import CheckResult


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
        numbered_output:  Full output of `ufw status numbered` (rules list).
        ipv4_rules_count: Number of non-IPv6 UFW rules found.
        ipv6_rules_count: Number of IPv6 UFW rules found (lines with (v6)).
        ipv6_ufw_enabled: True if IPV6=yes (or absent) in /etc/default/ufw.
                          Used to suppress false-positive IPv6 coverage warnings.
    """
    installed:        bool
    active:           bool
    incoming_policy:  str
    ufw_output:       str
    numbered_output:  str
    ipv4_rules_count: int
    ipv6_rules_count: int
    ipv6_ufw_enabled: bool = True

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
                numbered_output="",
                ipv4_rules_count=0, ipv6_rules_count=0,
            )

        # Get full status output (verbose for policy, numbered for rules)
        ufw_output     = _run("ufw", "status", "verbose")
        numbered_output = _run("ufw", "status", "numbered")

        # Parse active state
        active = bool(re.search(r"^Status:\s+active", ufw_output, re.MULTILINE))

        # Parse incoming policy
        incoming_policy = "unknown"
        match = re.search(r"Default:\s+(\w+)\s+\(incoming\)", ufw_output)
        if match:
            incoming_policy = match.group(1).lower()

        # Count IPv4 vs IPv6 rules
        rule_lines = [
            line for line in numbered_output.splitlines()
            if re.match(r"\s*\[\s*\d+\]", line)
        ]
        ipv4_rules_count = sum(1 for l in rule_lines if "(v6)" not in l)
        ipv6_rules_count = sum(1 for l in rule_lines if "(v6)" in l)

        # Read IPv6 config from /etc/default/ufw (default: enabled)
        ipv6_ufw_enabled = _read_ipv6_config()

        return cls(
            installed=installed,
            active=active,
            incoming_policy=incoming_policy,
            ufw_output=ufw_output,
            numbered_output=numbered_output,
            ipv4_rules_count=ipv4_rules_count,
            ipv6_rules_count=ipv6_rules_count,
            ipv6_ufw_enabled=ipv6_ufw_enabled,
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
        # Request a score cap — processed automatically by ScoreEngine.apply()
        result.set_cap(maximum=3, reason=_t("firewall.inactive"))
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
# UFW rules check
# ---------------------------------------------------------------------------

def check_rules(
    ufw_verbose: str,
    ufw_numbered: str,
    t,
    ipv6_enabled: bool = True,
) -> "CheckResult":
    """
    Check UFW rules for duplicates, open-any wildcards, and IPv6 consistency.

    Args:
        ufw_verbose:  Output of `ufw status verbose`.
        ufw_numbered: Output of `ufw status numbered`.
        t:            Translation function.
        ipv6_enabled: True if IPv6 is enabled in /etc/default/ufw.
                      When False, the IPv6 coverage warning is suppressed.

    Returns:
        CheckResult with rule-level findings and deductions.
    """
    result = CheckResult()
    lines = [
        l for l in ufw_numbered.splitlines()
        if re.match(r"\s*\[\s*\d+\]", l)
    ]
    _check_duplicates(lines, t, result)
    _check_open_any(lines, t, result)
    _check_ipv6_coverage(lines, t, result, ipv6_enabled)
    return result


def _check_duplicates(lines: list, t, result: CheckResult) -> None:
    """Detect duplicate and proto-redundant UFW rules."""

    def _strip_comment(text: str) -> str:
        return re.sub(r"\s*#.*$", "", text).strip()

    def _rule_without_index(line: str) -> str:
        return re.sub(r"\[\s*\d+\]\s*", "", line).strip()

    proto_less_rules: set[str] = set()
    for line in lines:
        tokens = _strip_comment(_rule_without_index(line)).split()
        if tokens and re.match(r"^\d+$", tokens[0]):
            proto_less_rules.add(" ".join(tokens))

    seen_clean: dict[str, int] = {}
    for line in lines:
        idx_match  = re.match(r"\[\s*(\d+)\]", line)
        real_index = int(idx_match.group(1)) if idx_match else None
        clean      = " ".join(_strip_comment(_rule_without_index(line)).split())

        is_dup = False
        if clean in seen_clean:
            del_index = real_index if real_index else seen_clean[clean]
            result.alert(
                message=t("rules.duplicate_found", rule=clean),
                nature="action",
                cmd=f"sudo ufw --force delete {del_index}",
            )
            result.add_deduction(reason=t("rules.duplicate_found", rule=clean), points=1)
            is_dup = True
        else:
            tokens = clean.split()
            if tokens:
                m = re.match(r"^(\d+)/(tcp|udp)$", tokens[0])
                if m:
                    proto_less_clean = " ".join([m.group(1)] + tokens[1:])
                    if proto_less_clean in proto_less_rules:
                        result.alert(
                            message=t("rules.duplicate_found", rule=clean),
                            nature="action",
                            cmd=f"sudo ufw --force delete {real_index}",
                        )
                        result.add_deduction(
                            reason=t("rules.duplicate_found", rule=clean), points=1)
                        is_dup = True

        if not is_dup and real_index is not None:
            seen_clean[clean] = real_index

    if not any(f.message.startswith(t("rules.duplicate_found")[:20])
               for f in result.findings):
        result.ok(message=t("rules.no_duplicates"))


def _check_open_any(lines: list, t, result: CheckResult) -> None:
    """Detect 'Anywhere ALLOW IN Anywhere' wildcard rules."""
    open_any_pattern = re.compile(
        r"Anywhere(?:/\w+)?(?:\s+\(v6\))?\s+ALLOW\s+IN\s+Anywhere(?:/\w+)?(?:\s+\(v6\))?\s*$",
        re.IGNORECASE,
    )
    found_open_any = False
    for line in lines:
        if open_any_pattern.search(line):
            idx_match  = re.match(r"\[\s*(\d+)\]", line)
            real_index = int(idx_match.group(1)) if idx_match else None
            result.alert(
                message=t("rules.open_any_found", rule=line.strip()),
                nature="action",
                cmd=f"sudo ufw --force delete {real_index}" if real_index is not None else "",
            )
            result.add_deduction(reason=t("rules.open_any_found", rule=""), points=2)
            found_open_any = True

    if not found_open_any:
        result.ok(message=t("rules.no_open_any"))


def _check_ipv6_coverage(
    lines: list,
    t,
    result: CheckResult,
    ipv6_enabled: bool,
) -> None:
    """
    Warn if IPv4 rules exist but no IPv6 rules are present.

    Suppressed when IPv6 is disabled in /etc/default/ufw to avoid
    false positives on systems that intentionally run IPv4-only.
    """
    ipv4_count = sum(1 for l in lines if "(v6)" not in l)
    ipv6_count = sum(1 for l in lines if "(v6)" in l)

    if ipv4_count > 0 and ipv6_count == 0:
        if ipv6_enabled:
            result.warn(message=t("rules.ipv6_missing"), nature="improvement")
            result.add_deduction(reason=t("rules.ipv6_missing"), points=1)
        # else: IPv6 is disabled in /etc/default/ufw — no warning
    elif ipv4_count > 0:
        result.ok(message=t("rules.ipv6_ok"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_ipv6_config() -> bool:
    """
    Read /etc/default/ufw to determine if IPv6 is enabled.

    Returns False only when IPV6=no is explicitly set.
    Defaults to True (enabled) if the file is absent or unreadable.
    """
    try:
        content = Path("/etc/default/ufw").read_text(encoding="utf-8", errors="ignore")
        if re.search(r"^IPV6\s*=\s*no\b", content, re.MULTILINE | re.IGNORECASE):
            return False
    except OSError:
        pass
    return True
