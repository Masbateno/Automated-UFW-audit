"""
Unit tests for ufw_audit.checks.firewall module.

All tests use FirewallStatus instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_firewall.py -v
"""

import pytest
from ufw_audit.checks.firewall import FirewallStatus, check_firewall
from ufw_audit.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_status(**overrides) -> FirewallStatus:
    """Return a default healthy FirewallStatus with optional overrides."""
    defaults = dict(
        installed=True,
        active=True,
        incoming_policy="deny",
        ufw_output="Status: active\nDefault: deny (incoming)",
        ipv4_rules_count=2,
        ipv6_rules_count=2,
    )
    defaults.update(overrides)
    return FirewallStatus(**defaults)


def levels(result) -> list[str]:
    """Return list of finding level values from a CheckResult."""
    return [f.level.value for f in result.findings]


def has_level(result, level: str) -> bool:
    return level in levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# UFW not installed
# ---------------------------------------------------------------------------

class TestUFWNotInstalled:
    def test_alert_when_not_installed(self):
        status = make_status(installed=False)
        result = check_firewall(status)
        assert has_level(result, "alert")

    def test_no_further_checks_when_not_installed(self):
        """If UFW is not installed, no other findings should be added."""
        status = make_status(installed=False)
        result = check_firewall(status)
        assert len(result.findings) == 1

    def test_fix_cmd_present(self):
        status = make_status(installed=False)
        result = check_firewall(status)
        assert result.findings[0].cmd != ""


# ---------------------------------------------------------------------------
# UFW inactive
# ---------------------------------------------------------------------------

class TestUFWInactive:
    def test_alert_when_inactive(self):
        status = make_status(active=False)
        result = check_firewall(status)
        assert has_level(result, "alert")

    def test_firewall_inactive_flag_set(self):
        status = make_status(active=False)
        result = check_firewall(status)
        assert getattr(result, "_firewall_inactive", False) is True

    def test_fix_cmd_is_ufw_enable(self):
        status = make_status(active=False)
        result = check_firewall(status)
        alert = next(f for f in result.findings if f.level == FindingLevel.ALERT)
        assert "ufw enable" in alert.cmd

    def test_no_further_checks_when_inactive(self):
        """Policy and IPv6 checks must not run when UFW is inactive."""
        status = make_status(active=False)
        result = check_firewall(status)
        # Only one finding: the inactive alert (after the installed OK)
        alerts = [f for f in result.findings if f.level == FindingLevel.ALERT]
        assert len(alerts) == 1


# ---------------------------------------------------------------------------
# Default incoming policy
# ---------------------------------------------------------------------------

class TestIncomingPolicy:
    def test_ok_when_deny(self):
        result = check_firewall(make_status(incoming_policy="deny"))
        assert has_level(result, "ok")

    def test_alert_when_allow(self):
        result = check_firewall(make_status(incoming_policy="allow"))
        assert has_level(result, "alert")

    def test_deduction_3_when_allow(self):
        result = check_firewall(make_status(incoming_policy="allow"))
        assert total_deductions(result) >= 3

    def test_fix_cmd_deny_incoming(self):
        result = check_firewall(make_status(incoming_policy="allow"))
        alert = next(f for f in result.findings if f.level == FindingLevel.ALERT)
        assert "deny incoming" in alert.cmd

    def test_warn_when_unknown_policy(self):
        result = check_firewall(make_status(incoming_policy="unknown"))
        assert has_level(result, "warn")

    def test_no_deduction_when_deny(self):
        result = check_firewall(make_status(
            incoming_policy="deny",
            ipv4_rules_count=2,
            ipv6_rules_count=2,
        ))
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# IPv6 consistency
# ---------------------------------------------------------------------------

class TestIPv6Consistency:
    def test_warn_when_ipv4_rules_but_no_ipv6(self):
        result = check_firewall(make_status(
            ipv4_rules_count=2,
            ipv6_rules_count=0,
        ))
        assert has_level(result, "warn")

    def test_deduction_1_for_ipv6_missing(self):
        result = check_firewall(make_status(
            ipv4_rules_count=2,
            ipv6_rules_count=0,
        ))
        assert total_deductions(result) == 1

    def test_ok_when_ipv6_consistent(self):
        result = check_firewall(make_status(
            ipv4_rules_count=2,
            ipv6_rules_count=2,
        ))
        ok_messages = [f.message for f in result.findings if f.level == FindingLevel.OK]
        assert any("ipv6" in m.lower() or "rules.ipv6_ok" in m for m in ok_messages)

    def test_no_ipv6_check_when_no_rules(self):
        """No IPv6 finding if there are no IPv4 rules either."""
        result = check_firewall(make_status(
            ipv4_rules_count=0,
            ipv6_rules_count=0,
        ))
        all_messages = [f.message for f in result.findings]
        assert not any("ipv6" in m.lower() or "ipv6" in m for m in all_messages)


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombinedScenarios:
    def test_clean_configuration_no_deductions(self):
        """Perfect setup — no deductions, all OK."""
        result = check_firewall(make_status(
            installed=True, active=True,
            incoming_policy="deny",
            ipv4_rules_count=3,
            ipv6_rules_count=3,
        ))
        assert total_deductions(result) == 0
        assert not has_level(result, "alert")
        assert not has_level(result, "warn")

    def test_allow_policy_plus_no_ipv6(self):
        """Two problems: open policy and missing IPv6 rules."""
        result = check_firewall(make_status(
            incoming_policy="allow",
            ipv4_rules_count=2,
            ipv6_rules_count=0,
        ))
        assert total_deductions(result) >= 4  # 3 for policy + 1 for IPv6
        assert has_level(result, "alert")
        assert has_level(result, "warn")

    def test_translation_function_used(self):
        """When a translation function is provided, its output appears in findings."""
        def my_t(key, **kwargs):
            return f"TRANSLATED:{key}"

        result = check_firewall(make_status(), t=my_t)
        assert any("TRANSLATED:" in f.message for f in result.findings)
