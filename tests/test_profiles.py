"""
Unit tests for ufw_audit.profiles module.

Tests cover: built-in profile loading, extends chain, overrides (downgrade
and skip), skip_sections, apply_profile() mutations, and edge cases.

Run with: python3 -m pytest tests/test_profiles.py -v
"""

from __future__ import annotations

import configparser
from pathlib import Path

import pytest

from ufw_audit.checks.hardening import HardeningSnapshot, check_hardening
from ufw_audit.checks.ipv6 import IPv6Snapshot, check_ipv6
from ufw_audit.profiles import (
    AuditProfile,
    _DEFAULT_PROFILE,
    _find_profile_file,
    _load_from_path,
    apply_profile,
    load_profile,
)
from ufw_audit.scoring import CheckResult, FindingLevel


# ---------------------------------------------------------------------------
# Autouse fixture — clear lru_cache between tests so monkeypatching works
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_profile_cache():
    _find_profile_file.cache_clear()
    yield
    _find_profile_file.cache_clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _t(key, **kwargs):
    return key


def write_profile(directory: Path, name: str, content: str) -> Path:
    path = directory / f"{name}.conf"
    path.write_text(content, encoding="utf-8")
    return path


def make_result(**overrides) -> CheckResult:
    """Return a CheckResult with a single warn finding + keyed deduction."""
    key = overrides.get("key", "hardening.auto_updates_missing")
    result = CheckResult()
    result.warn(message="something is wrong", key=key)
    result.add_deduction(
        reason="something is wrong",
        points=overrides.get("points", 1),
        key=key,
    )
    return result


# ---------------------------------------------------------------------------
# load_profile — built-in profiles
# ---------------------------------------------------------------------------

class TestLoadBuiltinProfiles:
    def test_server_profile_loads(self):
        p = load_profile("server")
        assert p.name == "server"

    def test_default_alias_returns_server(self):
        p = load_profile("default")
        assert p is _DEFAULT_PROFILE

    def test_empty_string_returns_server(self):
        p = load_profile("")
        assert p is _DEFAULT_PROFILE

    def test_workstation_profile_loads(self):
        p = load_profile("workstation")
        assert p.name == "workstation"

    def test_container_profile_loads(self):
        p = load_profile("container")
        assert p.name == "container"

    def test_unknown_profile_returns_default(self):
        p = load_profile("nonexistent_xyz")
        assert p is _DEFAULT_PROFILE

    def test_server_has_no_overrides(self):
        p = load_profile("server")
        assert p.overrides == {}

    def test_server_has_no_skip_sections(self):
        p = load_profile("server")
        assert p.skip_sections == set()

    def test_workstation_overrides_auto_updates(self):
        p = load_profile("workstation")
        assert p.override_for("hardening.auto_updates_missing") == "info"

    def test_workstation_overrides_rp_filter(self):
        p = load_profile("workstation")
        assert p.override_for("hardening.rp_filter_disabled") == "info"

    def test_container_skips_hardening_section(self):
        p = load_profile("container")
        assert p.should_skip_section("hardening")

    def test_container_inherits_workstation_overrides(self):
        p = load_profile("container")
        assert p.override_for("hardening.auto_updates_missing") == "info"


# ---------------------------------------------------------------------------
# load_profile — user-defined profiles (tmp_path)
# ---------------------------------------------------------------------------

class TestLoadUserProfiles:
    def test_loads_from_path(self, tmp_path, monkeypatch):
        monkeypatch.setattr("ufw_audit.profiles._USER_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "myprofile", """
[profile]
name = myprofile
description = test profile

[overrides]
hardening.fail2ban_missing = skip
""")
        p = load_profile("myprofile")
        assert p.name == "myprofile"
        assert p.override_for("hardening.fail2ban_missing") == "skip"

    def test_user_profile_takes_priority_over_builtin(self, tmp_path, monkeypatch):
        monkeypatch.setattr("ufw_audit.profiles._USER_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "workstation", """
[profile]
name = workstation
description = custom override

[overrides]
hardening.auto_updates_missing = warn
""")
        p = load_profile("workstation")
        assert p.override_for("hardening.auto_updates_missing") == "warn"

    def test_extends_chain_resolved(self, tmp_path, monkeypatch):
        monkeypatch.setattr("ufw_audit.profiles._USER_PROFILES_DIR", tmp_path)
        monkeypatch.setattr("ufw_audit.profiles._BUILTIN_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "base", """
[profile]
name = base

[overrides]
hardening.fail2ban_missing = info
""")
        write_profile(tmp_path, "child", """
[profile]
name = child
extends = base

[overrides]
hardening.rp_filter_disabled = skip
""")
        p = load_profile("child")
        # Child adds its own override
        assert p.override_for("hardening.rp_filter_disabled") == "skip"
        # Child inherits from base
        assert p.override_for("hardening.fail2ban_missing") == "info"

    def test_child_override_wins_over_parent(self, tmp_path, monkeypatch):
        monkeypatch.setattr("ufw_audit.profiles._USER_PROFILES_DIR", tmp_path)
        monkeypatch.setattr("ufw_audit.profiles._BUILTIN_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "base", """
[profile]
name = base

[overrides]
hardening.fail2ban_missing = info
""")
        write_profile(tmp_path, "child", """
[profile]
name = child
extends = base

[overrides]
hardening.fail2ban_missing = skip
""")
        p = load_profile("child")
        assert p.override_for("hardening.fail2ban_missing") == "skip"

    def test_unknown_override_level_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setattr("ufw_audit.profiles._USER_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "bad", """
[profile]
name = bad

[overrides]
hardening.fail2ban_missing = invalid_level
""")
        p = load_profile("bad")
        assert p.override_for("hardening.fail2ban_missing") is None

    def test_skip_sections_loaded(self, tmp_path, monkeypatch):
        monkeypatch.setattr("ufw_audit.profiles._USER_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "nohardening", """
[profile]
name = nohardening

[skip_sections]
hardening
ipv6
""")
        p = load_profile("nohardening")
        assert p.should_skip_section("hardening")
        assert p.should_skip_section("ipv6")
        assert not p.should_skip_section("docker")

    def test_missing_extends_parent_logged_and_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setattr("ufw_audit.profiles._USER_PROFILES_DIR", tmp_path)
        monkeypatch.setattr("ufw_audit.profiles._BUILTIN_PROFILES_DIR", tmp_path)
        write_profile(tmp_path, "orphan", """
[profile]
name = orphan
extends = nonexistent_parent

[overrides]
hardening.fail2ban_missing = skip
""")
        p = load_profile("orphan")
        # Own override still applied even if parent missing
        assert p.override_for("hardening.fail2ban_missing") == "skip"


# ---------------------------------------------------------------------------
# AuditProfile — methods
# ---------------------------------------------------------------------------

class TestAuditProfile:
    def test_override_for_returns_none_for_unknown_key(self):
        p = AuditProfile(name="test")
        assert p.override_for("unknown.key") is None

    def test_should_skip_section_true(self):
        p = AuditProfile(name="test", skip_sections={"hardening"})
        assert p.should_skip_section("hardening")

    def test_should_skip_section_false(self):
        p = AuditProfile(name="test", skip_sections={"hardening"})
        assert not p.should_skip_section("ipv6")

    def test_empty_profile_no_effect_marker(self):
        p = AuditProfile(name="empty")
        assert p.overrides == {}
        assert p.skip_sections == set()


# ---------------------------------------------------------------------------
# apply_profile — finding mutations
# ---------------------------------------------------------------------------

class TestApplyProfileNoOverrides:
    def test_no_overrides_leaves_result_unchanged(self):
        result = make_result()
        profile = AuditProfile(name="server")
        original_levels = [f.level for f in result.findings]
        apply_profile(result, profile)
        assert [f.level for f in result.findings] == original_levels

    def test_no_key_finding_never_modified(self):
        result = CheckResult()
        result.warn(message="no key finding")  # key="" by default
        profile = AuditProfile(
            name="test",
            overrides={"hardening.auto_updates_missing": "info"},
        )
        apply_profile(result, profile)
        assert result.findings[0].level == FindingLevel.WARN


class TestApplyProfileDowngrade:
    def test_warn_downgraded_to_info(self):
        result = make_result(key="hardening.auto_updates_missing")
        profile = AuditProfile(
            name="workstation",
            overrides={"hardening.auto_updates_missing": "info"},
        )
        apply_profile(result, profile)
        assert result.findings[0].level == FindingLevel.INFO

    def test_deduction_removed_when_downgraded_to_info(self):
        result = make_result(key="hardening.auto_updates_missing", points=1)
        profile = AuditProfile(
            name="workstation",
            overrides={"hardening.auto_updates_missing": "info"},
        )
        apply_profile(result, profile)
        assert sum(d.points for d in result.deductions) == 0

    def test_level_unchanged_when_override_matches_current(self):
        result = CheckResult()
        result.warn(message="already warn", key="hardening.rp_filter_disabled")
        profile = AuditProfile(
            name="test",
            overrides={"hardening.rp_filter_disabled": "warn"},
        )
        apply_profile(result, profile)
        assert result.findings[0].level == FindingLevel.WARN

    def test_multiple_findings_only_matching_key_modified(self):
        result = CheckResult()
        result.warn(message="msg1", key="hardening.auto_updates_missing")
        result.warn(message="msg2", key="hardening.rp_filter_disabled")
        profile = AuditProfile(
            name="test",
            overrides={"hardening.auto_updates_missing": "info"},
        )
        apply_profile(result, profile)
        assert result.findings[0].level == FindingLevel.INFO
        assert result.findings[1].level == FindingLevel.WARN


class TestApplyProfileSkip:
    def test_skip_removes_finding(self):
        result = make_result(key="hardening.fail2ban_missing")
        profile = AuditProfile(
            name="test",
            overrides={"hardening.fail2ban_missing": "skip"},
        )
        apply_profile(result, profile)
        assert not any(f.key == "hardening.fail2ban_missing" for f in result.findings)

    def test_skip_removes_deduction(self):
        result = make_result(key="hardening.fail2ban_missing", points=2)
        profile = AuditProfile(
            name="test",
            overrides={"hardening.fail2ban_missing": "skip"},
        )
        apply_profile(result, profile)
        assert result.deductions == []

    def test_skip_leaves_other_findings_intact(self):
        result = CheckResult()
        result.warn(message="skip me", key="hardening.fail2ban_missing")
        result.warn(message="keep me", key="hardening.rp_filter_disabled")
        profile = AuditProfile(
            name="test",
            overrides={"hardening.fail2ban_missing": "skip"},
        )
        apply_profile(result, profile)
        assert len(result.findings) == 1
        assert result.findings[0].key == "hardening.rp_filter_disabled"


# ---------------------------------------------------------------------------
# Integration — workstation profile on real hardening check
# ---------------------------------------------------------------------------

class TestWorkstationIntegration:
    def test_auto_updates_warn_becomes_info(self):
        snap = HardeningSnapshot(auto_updates_enabled=False)
        result = check_hardening(snap, t=_t)
        profile = load_profile("workstation")
        apply_profile(result, profile)
        auto_update_findings = [
            f for f in result.findings
            if f.key == "hardening.auto_updates_missing"
        ]
        assert auto_update_findings
        assert auto_update_findings[0].level == FindingLevel.INFO

    def test_auto_updates_deduction_removed(self):
        snap = HardeningSnapshot(auto_updates_enabled=False, rp_filter=1,
                                  accept_redirects=False)
        result = check_hardening(snap, t=_t)
        before_deductions = sum(d.points for d in result.deductions)
        profile = load_profile("workstation")
        apply_profile(result, profile)
        after_deductions = sum(d.points for d in result.deductions)
        assert after_deductions < before_deductions

    def test_score_lower_with_workstation_profile(self):
        from ufw_audit.scoring import ScoreEngine
        snap = HardeningSnapshot(auto_updates_enabled=False, rp_filter=0,
                                  accept_redirects=False)
        # Server profile
        result_server = check_hardening(snap, t=_t)
        engine_server = ScoreEngine()
        engine_server.apply(result_server)
        engine_server.finalize()

        # Workstation profile
        result_ws = check_hardening(snap, t=_t)
        profile = load_profile("workstation")
        apply_profile(result_ws, profile)
        engine_ws = ScoreEngine()
        engine_ws.apply(result_ws)
        engine_ws.finalize()

        assert engine_ws.score >= engine_server.score

    def test_ipv6_uncovered_port_becomes_info(self):
        snap = IPv6Snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=True,
            ipv6_listeners=["80/tcp"],
            ufw_v6_covered=[],
        )
        result = check_ipv6(snap, t=_t)
        profile = load_profile("workstation")
        apply_profile(result, profile)
        port_findings = [f for f in result.findings if f.key == "ipv6.port_no_v6_rule"]
        assert port_findings
        assert port_findings[0].level == FindingLevel.INFO
