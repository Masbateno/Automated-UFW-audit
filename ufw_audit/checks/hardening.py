"""
System hardening check for ufw-audit.

Detects common hardening gaps: automatic updates, fail2ban, AppArmor,
and kernel network parameters (rp_filter, ICMP redirects, log_martians).

The check is split into two parts:
  1. HardeningSnapshot.from_system() — collects raw data via subprocess.
  2. check_hardening(snapshot)        — pure logic, returns a CheckResult.

Usage:
    from ufw_audit.checks.hardening import HardeningSnapshot, check_hardening

    snapshot = HardeningSnapshot.from_system()
    result   = check_hardening(snapshot)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ufw_audit.checks._run import _command_exists, _identity_t, _run
from ufw_audit.scoring import CheckResult

# Compiled once at import time — used by _parse_aa_count
_AA_COUNT_RE = re.compile(
    r"(\d+)\s+profiles?\s+(?:are|is)\s+in\s+(?P<mode>\S+)\s+mode",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class HardeningSnapshot:
    """
    Raw snapshot of system hardening state collected from the system.

    Args:
        fail2ban_active:              True if fail2ban service is running.
        auto_updates_enabled:         True if unattended-upgrades is enabled.
        apparmor_loaded:              True if AppArmor module is loaded.
        apparmor_mode:                "enforce"|"permissive"|"inactive"|"not_installed".
        apparmor_enforced:            Number of profiles in enforce mode.
        apparmor_complain:            Number of profiles in complain mode.
        rp_filter:                    Value of net.ipv4.conf.all.rp_filter (0, 1 or 2).
        accept_redirects:             True if net.ipv4.conf.all.accept_redirects == 1.
        log_martians:                 True if net.ipv4.conf.all.log_martians == 1.
        icmp_echo_ignore_broadcasts:  True if net.ipv4.icmp_echo_ignore_broadcasts == 1.
    """
    fail2ban_active:             bool = False
    auto_updates_enabled:        bool = False
    apparmor_loaded:             bool = False
    apparmor_mode:               str  = "not_installed"
    apparmor_enforced:           int  = 0
    apparmor_complain:           int  = 0
    rp_filter:                   int  = 1
    accept_redirects:            bool = False
    log_martians:                bool = True
    icmp_echo_ignore_broadcasts: bool = True

    @classmethod
    def from_system(cls) -> "HardeningSnapshot":
        """
        Collect hardening state from the live system via subprocess.

        Returns:
            Populated HardeningSnapshot. Never raises — errors are
            reflected as safe/default values.
        """
        # --- fail2ban ---
        # Primary: systemctl is-active is locale-independent and reliable.
        # Fallback: fail2ban-client status for non-systemd systems.
        fail2ban_active = False
        if _command_exists("systemctl"):
            out = _run("systemctl", "is-active", "fail2ban")
            fail2ban_active = out.strip() == "active"
        if not fail2ban_active and _command_exists("fail2ban-client"):
            out = _run("fail2ban-client", "status")
            fail2ban_active = bool(out and "Number of jail" in out)

        # --- unattended-upgrades ---
        auto_updates_enabled = _check_auto_updates()

        # --- AppArmor ---
        apparmor_loaded  = False
        apparmor_mode    = "not_installed"
        apparmor_enforced = 0
        apparmor_complain = 0

        if _command_exists("aa-status"):
            aa_out = _run("aa-status")
            if aa_out is not None:
                apparmor_loaded   = True
                apparmor_mode     = _parse_apparmor_mode(aa_out)
                apparmor_enforced = _parse_aa_count(aa_out, "enforce")
                apparmor_complain = _parse_aa_count(aa_out, "complain")
        elif Path("/sys/module/apparmor").is_dir():
            apparmor_loaded = True
            apparmor_mode   = "inactive"

        # --- kernel sysctl parameters ---
        rp_filter                   = _read_sysctl_int("net.ipv4.conf.all.rp_filter",    default=1)
        accept_redirects            = _read_sysctl_bool("net.ipv4.conf.all.accept_redirects", default=False)
        log_martians                = _read_sysctl_bool("net.ipv4.conf.all.log_martians",     default=True)
        icmp_echo_ignore_broadcasts = _read_sysctl_bool("net.ipv4.icmp_echo_ignore_broadcasts", default=True)

        return cls(
            fail2ban_active=fail2ban_active,
            auto_updates_enabled=auto_updates_enabled,
            apparmor_loaded=apparmor_loaded,
            apparmor_mode=apparmor_mode,
            apparmor_enforced=apparmor_enforced,
            apparmor_complain=apparmor_complain,
            rp_filter=rp_filter,
            accept_redirects=accept_redirects,
            log_martians=log_martians,
            icmp_echo_ignore_broadcasts=icmp_echo_ignore_broadcasts,
        )


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_hardening(snapshot: HardeningSnapshot, t=None) -> CheckResult:
    """
    Check system hardening configuration.

    Args:
        snapshot: HardeningSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()
    found_issue = False  # tracks deduction-worthy (warn-level) issues only

    # --- Automatic security updates ---
    if snapshot.auto_updates_enabled:
        result.ok(message=_t("hardening.auto_updates_ok"),
                  key="hardening.auto_updates_ok")
    else:
        result.warn(
            message=_t("hardening.auto_updates_missing"),
            nature="improvement",
            cmd="sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
            key="hardening.auto_updates_missing",
        )
        result.add_deduction(
            reason=_t("hardening.auto_updates_missing"),
            points=1,
            context="local",
            key="hardening.auto_updates_missing",
        )
        found_issue = True

    # --- fail2ban ---
    if snapshot.fail2ban_active:
        result.ok(message=_t("hardening.fail2ban_ok"),
                  key="hardening.fail2ban_ok")
    else:
        result.info(message=_t("hardening.fail2ban_missing"),
                    key="hardening.fail2ban_missing")

    # --- AppArmor ---
    mode = snapshot.apparmor_mode
    if mode == "not_installed":
        result.info(message=_t("hardening.apparmor_not_installed"),
                    key="hardening.apparmor_not_installed")
    elif mode == "enforce":
        result.ok(
            message=_t(
                "hardening.apparmor_enforce",
                enforced=snapshot.apparmor_enforced,
                complain=snapshot.apparmor_complain,
            ),
            key="hardening.apparmor_enforce",
        )
    else:
        result.info(
            message=_t("hardening.apparmor_not_enforce", mode=mode),
            key="hardening.apparmor_not_enforce",
        )

    # --- rp_filter (reverse path filtering) ---
    # 0 = disabled (insecure), 1 = strict mode (best), 2 = loose mode (weaker)
    if snapshot.rp_filter == 1:
        result.ok(message=_t("hardening.rp_filter_ok"),
                  key="hardening.rp_filter_ok")
    elif snapshot.rp_filter == 2:
        result.info(message=_t("hardening.rp_filter_loose"),
                    key="hardening.rp_filter_loose")
    else:
        result.warn(
            message=_t("hardening.rp_filter_disabled"),
            nature="improvement",
            cmd="sudo sysctl -w net.ipv4.conf.all.rp_filter=1",
            key="hardening.rp_filter_disabled",
        )
        result.add_deduction(
            reason=_t("hardening.rp_filter_disabled"),
            points=1,
            context="local",
            key="hardening.rp_filter_disabled",
        )
        found_issue = True

    # --- ICMP redirects ---
    if not snapshot.accept_redirects:
        result.ok(message=_t("hardening.redirects_ok"),
                  key="hardening.redirects_ok")
    else:
        result.warn(
            message=_t("hardening.redirects_enabled"),
            nature="improvement",
            cmd="sudo sysctl -w net.ipv4.conf.all.accept_redirects=0",
            key="hardening.redirects_enabled",
        )
        result.add_deduction(
            reason=_t("hardening.redirects_enabled"),
            points=1,
            context="local",
            key="hardening.redirects_enabled",
        )
        found_issue = True

    # --- log_martians ---
    if snapshot.log_martians:
        result.ok(message=_t("hardening.log_martians_ok"),
                  key="hardening.log_martians_ok")
    else:
        result.info(
            message=_t("hardening.log_martians_disabled"),
            key="hardening.log_martians_disabled",
        )

    # --- ICMP broadcast echo ---
    if snapshot.icmp_echo_ignore_broadcasts:
        result.ok(message=_t("hardening.icmp_broadcast_ok"),
                  key="hardening.icmp_broadcast_ok")
    else:
        result.info(
            message=_t("hardening.icmp_broadcast_enabled"),
            key="hardening.icmp_broadcast_enabled",
        )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_auto_updates() -> bool:
    """Return True if unattended-upgrades is installed and configured to run.

    Uses dpkg-query as the authoritative source for package presence,
    then checks the APT periodic config, falling back to the systemd timer.
    """
    # Step 1 — package installed? (dpkg-query is locale-independent and precise)
    dpkg_out = _run("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
    if not dpkg_out or "install ok installed" not in dpkg_out:
        return False

    # Step 2 — is it configured to actually run upgrades?
    apt_conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if apt_conf.exists():
        try:
            content = apt_conf.read_text(encoding="utf-8", errors="ignore")
            if re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', content):
                return True
        except OSError:
            pass

    # Step 3 — fallback: systemd timer active
    timer_out = _run("systemctl", "is-active", "apt-daily-upgrade.timer")
    return timer_out.strip() == "active"


def _parse_apparmor_mode(aa_status_output: str) -> str:
    """Parse the operating mode from `aa-status` output."""
    out = aa_status_output.lower()
    if "apparmor module is not loaded" in out:
        return "not_installed"
    if "apparmor module is loaded" in out or "profiles are in enforce mode" in out:
        # Determine dominant mode
        enforced = _parse_aa_count(aa_status_output, "enforce")
        if enforced > 0:
            return "enforce"
        complain = _parse_aa_count(aa_status_output, "complain")
        if complain > 0:
            return "permissive"
        return "inactive"
    return "inactive"


def _parse_aa_count(aa_status_output: str, mode: str) -> int:
    """
    Extract the count of profiles in a given mode from `aa-status` output.
    Looks for lines like:  "   3 profiles are in enforce mode."
    Uses the module-level compiled regex _AA_COUNT_RE.
    """
    for m in _AA_COUNT_RE.finditer(aa_status_output):
        if m.group("mode").lower() == mode.lower():
            return int(m.group(1))
    return 0


def _read_sysctl_int(key: str, default: int) -> int:
    """Read a sysctl value as int via /proc/sys."""
    path = Path("/proc/sys") / key.replace(".", "/")
    try:
        return int(path.read_text(encoding="ascii", errors="ignore").strip())
    except (OSError, ValueError):
        return default


def _read_sysctl_bool(key: str, default: bool) -> bool:
    """Read a sysctl value and return True if it equals "1"."""
    path = Path("/proc/sys") / key.replace(".", "/")
    try:
        val = path.read_text(encoding="ascii", errors="ignore").strip()
        return val == "1"
    except OSError:
        return default
