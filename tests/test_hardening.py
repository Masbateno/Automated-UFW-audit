"""
Unit tests for ufw_audit.checks.hardening module.

All tests use HardeningSnapshot instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_hardening.py -v
"""

from __future__ import annotations

import pytest
from ufw_audit.checks.hardening import (
    HardeningSnapshot,
    _parse_aa_count,
    _parse_apparmor_mode,
    check_hardening,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _t(key, **kwargs):
    return key


def make_snapshot(**overrides) -> HardeningSnapshot:
    """Return a fully-hardened HardeningSnapshot with optional overrides."""
    defaults = dict(
        fail2ban_active=True,
        apparmor_loaded=True,
        apparmor_mode="enforce",
        apparmor_enforced=5,
        apparmor_complain=0,
        rp_filter=1,
        accept_redirects=False,
        log_martians=True,
        icmp_echo_ignore_broadcasts=True,
    )
    defaults.update(overrides)
    return HardeningSnapshot(**defaults)


def levels(result) -> list[str]:
    return [f.level.value for f in result.findings]


def has_level(result, level: str) -> bool:
    return level in levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# Clean (fully hardened) system
# ---------------------------------------------------------------------------

class TestCleanSystem:
    def test_ok_when_fully_hardened(self):
        result = check_hardening(make_snapshot(), t=_t)
        assert has_level(result, "ok")

    def test_no_deductions_when_fully_hardened(self):
        result = check_hardening(make_snapshot(), t=_t)
        assert total_deductions(result) == 0

    def test_no_warn_when_fully_hardened(self):
        result = check_hardening(make_snapshot(), t=_t)
        assert not has_level(result, "warn")

    def test_no_alert_when_fully_hardened(self):
        result = check_hardening(make_snapshot(), t=_t)
        assert not has_level(result, "alert")


# ---------------------------------------------------------------------------
# fail2ban
# ---------------------------------------------------------------------------

class TestFail2ban:
    def test_ok_when_fail2ban_active(self):
        result = check_hardening(make_snapshot(fail2ban_active=True), t=_t)
        assert has_level(result, "ok")

    def test_info_when_fail2ban_missing(self):
        result = check_hardening(make_snapshot(fail2ban_active=False), t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_fail2ban_missing(self):
        """fail2ban absence is INFO only — no score impact."""
        result = check_hardening(
            make_snapshot(fail2ban_active=False),
            t=_t,
        )
        fail2ban_deductions = [d for d in result.deductions if "fail2ban" in d.reason]
        assert len(fail2ban_deductions) == 0


# ---------------------------------------------------------------------------
# AppArmor
# ---------------------------------------------------------------------------

class TestAppArmor:
    def test_ok_when_enforce(self):
        result = check_hardening(
            make_snapshot(apparmor_mode="enforce", apparmor_enforced=5),
            t=_t,
        )
        assert has_level(result, "ok")

    def test_info_when_not_installed(self):
        result = check_hardening(
            make_snapshot(apparmor_mode="not_installed", apparmor_loaded=False),
            t=_t,
        )
        assert has_level(result, "info")

    def test_info_when_permissive(self):
        result = check_hardening(
            make_snapshot(apparmor_mode="permissive"),
            t=_t,
        )
        assert has_level(result, "info")

    def test_info_when_inactive(self):
        result = check_hardening(
            make_snapshot(apparmor_mode="inactive"),
            t=_t,
        )
        assert has_level(result, "info")

    def test_no_deduction_for_apparmor_modes(self):
        """AppArmor is INFO-only — no score deduction."""
        for mode in ("not_installed", "permissive", "inactive"):
            result = check_hardening(make_snapshot(apparmor_mode=mode), t=_t)
            aa_deductions = [d for d in result.deductions if "apparmor" in d.reason.lower()]
            assert aa_deductions == [], f"Unexpected deduction for mode={mode}"

    def test_enforce_count_passed_to_t(self):
        """apparmor_enforce key must receive enforced= and complain= kwargs."""
        received = {}

        def _capture(key, **kwargs):
            if key == "hardening.apparmor_enforce":
                received.update(kwargs)
            return key

        check_hardening(
            make_snapshot(apparmor_mode="enforce", apparmor_enforced=3, apparmor_complain=1),
            t=_capture,
        )
        assert received.get("enforced") == 3
        assert received.get("complain") == 1


# ---------------------------------------------------------------------------
# rp_filter
# ---------------------------------------------------------------------------

class TestRpFilter:
    def test_ok_when_rp_filter_1(self):
        result = check_hardening(make_snapshot(rp_filter=1), t=_t)
        assert has_level(result, "ok")

    def test_info_when_rp_filter_2(self):
        """Loose mode (2) is sub-optimal — INFO, no deduction."""
        result = check_hardening(make_snapshot(rp_filter=2), t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_rp_filter_2(self):
        result = check_hardening(make_snapshot(rp_filter=2), t=_t)
        rp_deductions = [d for d in result.deductions if "rp_filter" in d.reason]
        assert rp_deductions == []

    def test_warn_when_rp_filter_0(self):
        result = check_hardening(make_snapshot(rp_filter=0), t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_rp_filter_0(self):
        result = check_hardening(make_snapshot(rp_filter=0), t=_t)
        assert total_deductions(result) >= 1

    def test_deduction_key_rp_filter(self):
        result = check_hardening(make_snapshot(rp_filter=0), t=_t)
        reasons = [d.reason for d in result.deductions]
        assert "hardening.rp_filter_disabled" in reasons


# ---------------------------------------------------------------------------
# ICMP redirects
# ---------------------------------------------------------------------------

class TestAcceptRedirects:
    def test_ok_when_redirects_disabled(self):
        result = check_hardening(make_snapshot(accept_redirects=False), t=_t)
        assert has_level(result, "ok")

    def test_warn_when_redirects_enabled(self):
        result = check_hardening(make_snapshot(accept_redirects=True), t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_redirects_enabled(self):
        result = check_hardening(make_snapshot(accept_redirects=True), t=_t)
        assert total_deductions(result) >= 1

    def test_deduction_key_redirects(self):
        result = check_hardening(make_snapshot(accept_redirects=True), t=_t)
        reasons = [d.reason for d in result.deductions]
        assert "hardening.redirects_enabled" in reasons


# ---------------------------------------------------------------------------
# log_martians
# ---------------------------------------------------------------------------

class TestLogMartians:
    def test_ok_when_enabled(self):
        result = check_hardening(make_snapshot(log_martians=True), t=_t)
        assert has_level(result, "ok")

    def test_info_when_disabled(self):
        result = check_hardening(make_snapshot(log_martians=False), t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_disabled(self):
        """log_martians is INFO-only."""
        result = check_hardening(make_snapshot(log_martians=False), t=_t)
        martian_deductions = [d for d in result.deductions if "martian" in d.reason]
        assert martian_deductions == []


# ---------------------------------------------------------------------------
# ICMP broadcast echo
# ---------------------------------------------------------------------------

class TestIcmpBroadcast:
    def test_ok_when_ignored(self):
        result = check_hardening(make_snapshot(icmp_echo_ignore_broadcasts=True), t=_t)
        assert has_level(result, "ok")

    def test_info_when_not_ignored(self):
        result = check_hardening(make_snapshot(icmp_echo_ignore_broadcasts=False), t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_not_ignored(self):
        """ICMP broadcast is INFO-only."""
        result = check_hardening(make_snapshot(icmp_echo_ignore_broadcasts=False), t=_t)
        broadcast_deductions = [d for d in result.deductions if "broadcast" in d.reason or "icmp" in d.reason.lower()]
        assert broadcast_deductions == []


# ---------------------------------------------------------------------------
# Cumulative deductions
# ---------------------------------------------------------------------------

class TestCumulativeDeductions:
    def test_two_issues_two_deductions(self):
        """rp_filter=0 + accept_redirects = 2 points."""
        snap = make_snapshot(
            rp_filter=0,
            accept_redirects=True,
        )
        result = check_hardening(snap, t=_t)
        assert total_deductions(result) == 2

    def test_no_deductions_for_info_only_fields(self):
        """fail2ban + apparmor_mode + log_martians + icmp_broadcast = 0 deductions."""
        snap = make_snapshot(
            fail2ban_active=False,
            apparmor_mode="not_installed",
            log_martians=False,
            icmp_echo_ignore_broadcasts=False,
        )
        result = check_hardening(snap, t=_t)
        assert total_deductions(result) == 0

    def test_mixed_warn_and_info_coexist(self):
        """rp_filter=0 (WARN) + fail2ban=False (INFO) must both appear."""
        snap = make_snapshot(
            rp_filter=0,
            fail2ban_active=False,
        )
        result = check_hardening(snap, t=_t)
        assert has_level(result, "warn")
        assert has_level(result, "info")
        assert total_deductions(result) == 1

    def test_mixed_ok_info_warn_all_present(self):
        """Verify all three levels can coexist in one result."""
        snap = make_snapshot(
            rp_filter=0,           # WARN
            fail2ban_active=False, # INFO
        )
        result = check_hardening(snap, t=_t)
        assert has_level(result, "ok")
        assert has_level(result, "info")
        assert has_level(result, "warn")


# ---------------------------------------------------------------------------
# _parse_aa_count
# ---------------------------------------------------------------------------

class TestParseAaCount:
    AA_STATUS = (
        "apparmor module is loaded.\n"
        "23 profiles are loaded.\n"
        "18 profiles are in enforce mode.\n"
        "   /snap/snapd/18357 (enforce)\n"
        "5 profiles are in complain mode.\n"
        "   /usr/bin/man\n"
    )

    def test_parses_enforce_count(self):
        assert _parse_aa_count(self.AA_STATUS, "enforce") == 18

    def test_parses_complain_count(self):
        assert _parse_aa_count(self.AA_STATUS, "complain") == 5

    def test_returns_zero_when_not_found(self):
        assert _parse_aa_count("no profiles here", "enforce") == 0

    def test_singular_profile(self):
        out = "1 profile is in enforce mode."
        assert _parse_aa_count(out, "enforce") == 1

    def test_leading_whitespace_in_line(self):
        """Real aa-status output often has leading spaces."""
        out = "   18 profiles are in enforce mode.\n"
        assert _parse_aa_count(out, "enforce") == 18

    def test_case_insensitive(self):
        out = "5 profiles are in Enforce mode."
        assert _parse_aa_count(out, "enforce") == 5


# ---------------------------------------------------------------------------
# _parse_apparmor_mode
# ---------------------------------------------------------------------------

class TestParseAppArmorMode:
    def test_returns_enforce_when_profiles_enforced(self):
        aa_out = (
            "apparmor module is loaded.\n"
            "5 profiles are in enforce mode.\n"
            "0 profiles are in complain mode.\n"
        )
        assert _parse_apparmor_mode(aa_out) == "enforce"

    def test_returns_permissive_when_only_complain(self):
        aa_out = (
            "apparmor module is loaded.\n"
            "0 profiles are in enforce mode.\n"
            "3 profiles are in complain mode.\n"
        )
        assert _parse_apparmor_mode(aa_out) == "permissive"

    def test_returns_not_installed_when_not_loaded(self):
        aa_out = "apparmor module is not loaded.\n"
        assert _parse_apparmor_mode(aa_out) == "not_installed"

    def test_returns_inactive_when_loaded_but_no_profiles(self):
        aa_out = (
            "apparmor module is loaded.\n"
            "0 profiles are in enforce mode.\n"
            "0 profiles are in complain mode.\n"
        )
        assert _parse_apparmor_mode(aa_out) == "inactive"


# ---------------------------------------------------------------------------
# AppArmor edge cases
# ---------------------------------------------------------------------------

class TestAppArmorEdgeCases:
    def test_enforce_mode_with_zero_enforced_profiles(self):
        """mode='enforce' but enforced=0 is an artificial inconsistency.
        check_hardening uses apparmor_mode, not the count, for OK/INFO routing.
        Document: OK is emitted (the mode string drives the branch)."""
        result = check_hardening(
            make_snapshot(apparmor_mode="enforce", apparmor_enforced=0),
            t=_t,
        )
        # mode string is "enforce" → OK branch is taken regardless of count
        assert has_level(result, "ok")

    def test_apparmor_enforce_count_zero_still_no_deduction(self):
        """Even the artificial enforce+0 case must not cause a deduction."""
        result = check_hardening(
            make_snapshot(apparmor_mode="enforce", apparmor_enforced=0),
            t=_t,
        )
        aa_deductions = [d for d in result.deductions if "apparmor" in d.reason.lower()]
        assert aa_deductions == []
