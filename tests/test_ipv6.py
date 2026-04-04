"""
Unit tests for ufw_audit.checks.ipv6 module.

All tests use IPv6Snapshot instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_ipv6.py -v
"""

from __future__ import annotations

import pytest
from ufw_audit.checks.ipv6 import (
    IPv6Snapshot,
    _extract_ipv6_listeners,
    _extract_ufw_v6_covered,
    check_ipv6,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _t(key, **kwargs):
    return key


def make_snapshot(**overrides) -> IPv6Snapshot:
    """Return a clean (fully consistent) IPv6Snapshot with optional overrides."""
    defaults = dict(
        kernel_ipv6_enabled=True,
        ufw_ipv6_enabled=True,
        ipv6_listeners=["22/tcp", "80/tcp"],
        ufw_v6_covered=["22/tcp", "80/tcp"],
    )
    defaults.update(overrides)
    return IPv6Snapshot(**defaults)


def levels(result) -> list[str]:
    return [f.level.value for f in result.findings]


def has_level(result, level: str) -> bool:
    return level in levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# Clean system — all covered
# ---------------------------------------------------------------------------

class TestCleanSystem:
    def test_ok_when_all_covered(self):
        result = check_ipv6(make_snapshot(), t=_t)
        assert has_level(result, "ok")

    def test_no_deductions_when_all_covered(self):
        result = check_ipv6(make_snapshot(), t=_t)
        assert total_deductions(result) == 0

    def test_no_warn_when_all_covered(self):
        result = check_ipv6(make_snapshot(), t=_t)
        assert not has_level(result, "warn")

    def test_no_listeners_no_warn(self):
        """No IPv6 listeners at all — clean."""
        snap = make_snapshot(ipv6_listeners=[], ufw_v6_covered=[])
        result = check_ipv6(snap, t=_t)
        assert not has_level(result, "warn")
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# Kernel / UFW mismatch
# ---------------------------------------------------------------------------

class TestKernelUfwMismatch:
    def test_info_when_ufw_enabled_kernel_disabled(self):
        """UFW thinks IPv6 is active but kernel has it off — INFO, no deduction."""
        snap = make_snapshot(kernel_ipv6_enabled=False, ufw_ipv6_enabled=True)
        result = check_ipv6(snap, t=_t)
        assert has_level(result, "info")

    def test_no_deduction_ufw_enabled_kernel_disabled(self):
        snap = make_snapshot(kernel_ipv6_enabled=False, ufw_ipv6_enabled=True)
        result = check_ipv6(snap, t=_t)
        assert total_deductions(result) == 0

    def test_no_warn_ufw_enabled_kernel_disabled(self):
        snap = make_snapshot(kernel_ipv6_enabled=False, ufw_ipv6_enabled=True)
        result = check_ipv6(snap, t=_t)
        assert not has_level(result, "warn")

    def test_ok_both_disabled(self):
        snap = make_snapshot(
            kernel_ipv6_enabled=False,
            ufw_ipv6_enabled=False,
            ipv6_listeners=[],
            ufw_v6_covered=[],
        )
        result = check_ipv6(snap, t=_t)
        assert has_level(result, "ok")
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# UFW IPv6 disabled + listeners present
# ---------------------------------------------------------------------------

class TestUfwDisabledWithListeners:
    def test_warn_when_ufw_disabled_listeners_present(self):
        snap = make_snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=False,
            ipv6_listeners=["22/tcp", "80/tcp"],
        )
        result = check_ipv6(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_ufw_disabled_listeners_present(self):
        snap = make_snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=False,
            ipv6_listeners=["22/tcp"],
        )
        result = check_ipv6(snap, t=_t)
        assert total_deductions(result) == 2

    def test_count_passed_to_t(self):
        received = {}

        def _capture(key, **kwargs):
            if "count" in kwargs:
                received.update(kwargs)
            return key

        snap = make_snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=False,
            ipv6_listeners=["22/tcp", "443/tcp"],
        )
        check_ipv6(snap, t=_capture)
        assert received.get("count") == 2

    def test_info_when_ufw_disabled_no_listeners(self):
        snap = make_snapshot(
            kernel_ipv6_enabled=True,
            ufw_ipv6_enabled=False,
            ipv6_listeners=[],
        )
        result = check_ipv6(snap, t=_t)
        assert has_level(result, "info")
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# Per-port gap detection
# ---------------------------------------------------------------------------

class TestPerPortGap:
    def test_warn_on_uncovered_ipv6_port(self):
        snap = make_snapshot(
            ipv6_listeners=["22/tcp", "8080/tcp"],
            ufw_v6_covered=["22/tcp"],  # 8080 not covered
        )
        result = check_ipv6(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_on_uncovered_ipv6_port(self):
        snap = make_snapshot(
            ipv6_listeners=["8080/tcp"],
            ufw_v6_covered=[],
        )
        result = check_ipv6(snap, t=_t)
        assert total_deductions(result) == 1

    def test_port_passed_to_t(self):
        received = {}

        def _capture(key, **kwargs):
            if key == "ipv6.port_no_v6_rule":
                received.update(kwargs)
            return key

        snap = make_snapshot(
            ipv6_listeners=["8080/tcp"],
            ufw_v6_covered=[],
        )
        check_ipv6(snap, t=_capture)
        assert received.get("port") == "8080/tcp"

    def test_no_warn_when_port_covered(self):
        snap = make_snapshot(
            ipv6_listeners=["22/tcp"],
            ufw_v6_covered=["22/tcp"],
        )
        result = check_ipv6(snap, t=_t)
        assert not has_level(result, "warn")

    def test_deductions_capped_at_three(self):
        """More than 3 uncovered ports must not exceed 3 points of deduction."""
        snap = make_snapshot(
            ipv6_listeners=["80/tcp", "443/tcp", "8080/tcp", "8443/tcp", "3000/tcp"],
            ufw_v6_covered=[],
        )
        result = check_ipv6(snap, t=_t)
        assert total_deductions(result) == 3

    def test_warn_count_matches_uncovered_ports(self):
        snap = make_snapshot(
            ipv6_listeners=["80/tcp", "443/tcp", "8080/tcp"],
            ufw_v6_covered=["80/tcp"],
        )
        result = check_ipv6(snap, t=_t)
        warn_count = sum(1 for f in result.findings if f.level.value == "warn")
        assert warn_count == 2

    def test_no_deductions_when_no_uncovered(self):
        snap = make_snapshot(
            ipv6_listeners=["22/tcp", "443/tcp"],
            ufw_v6_covered=["22/tcp", "443/tcp"],
        )
        result = check_ipv6(snap, t=_t)
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# _extract_ipv6_listeners
# ---------------------------------------------------------------------------

class TestExtractIPv6Listeners:
    SS_OUTPUT = (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
        "tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*\n"
        "tcp   LISTEN 0      128    [::]:22             [::]:*\n"
        "tcp   LISTEN 0      128    [::]:80             [::]:*\n"
        "udp   UNCONN 0      0      [::]:5353           [::]:*\n"
        "tcp   LISTEN 0      128    127.0.0.1:5432      0.0.0.0:*\n"
    )

    def test_detects_ipv6_wildcard_tcp(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT)
        assert "22/tcp" in result

    def test_detects_ipv6_wildcard_udp(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT)
        assert "5353/udp" in result

    def test_does_not_include_ipv4(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT)
        # 0.0.0.0:22 is IPv4 — should not appear
        assert "22/tcp" in result  # from [::]:22 — but only once
        assert len([p for p in result if p == "22/tcp"]) == 1

    def test_does_not_include_loopback(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT)
        assert "5432/tcp" not in result

    def test_empty_string_returns_empty(self):
        assert _extract_ipv6_listeners("") == set()

    def test_multiple_ipv6_ports(self):
        result = _extract_ipv6_listeners(self.SS_OUTPUT)
        assert "80/tcp" in result
        assert "22/tcp" in result


# ---------------------------------------------------------------------------
# _extract_ufw_v6_covered
# ---------------------------------------------------------------------------

class TestExtractUfwV6Covered:
    UFW_OUTPUT = (
        "Status: active\n"
        "\n"
        "     To                         Action      From\n"
        "     --                         ------      ----\n"
        "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
        "[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n"
        "[ 3] 80/tcp                     ALLOW IN    Anywhere\n"
        "[ 4] 80/tcp (v6)                ALLOW IN    Anywhere (v6)\n"
        "[ 5] 8080/tcp                   ALLOW IN    Anywhere\n"
    )

    def test_detects_v6_rule_for_22(self):
        result = _extract_ufw_v6_covered(self.UFW_OUTPUT)
        assert "22/tcp" in result

    def test_detects_v6_rule_for_80(self):
        result = _extract_ufw_v6_covered(self.UFW_OUTPUT)
        assert "80/tcp" in result

    def test_does_not_include_ipv4_only_rule(self):
        result = _extract_ufw_v6_covered(self.UFW_OUTPUT)
        assert "8080/tcp" not in result

    def test_empty_string_returns_empty(self):
        assert _extract_ufw_v6_covered("") == set()

    def test_ufw_disabled_output(self):
        assert _extract_ufw_v6_covered("Status: inactive\n") == set()

    def test_proto_defaults_to_tcp(self):
        """Rules with no explicit proto default to tcp."""
        output = "[ 1] 443 (v6)                   ALLOW IN    Anywhere (v6)\n"
        result = _extract_ufw_v6_covered(output)
        assert "443/tcp" in result

    def test_malformed_ss_output_returns_empty(self):
        assert _extract_ipv6_listeners("???") == set()

    def test_malformed_ufw_lines_returns_empty(self):
        assert _extract_ufw_v6_covered("[ x] invalid line") == set()
