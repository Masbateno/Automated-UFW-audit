"""
Unit tests for ufw_audit.checks.ports module.

All tests build PortsSnapshot instances directly — no subprocess calls.

Run with: python -m pytest tests/test_ports.py -v
"""

import pytest
from ufw_audit.checks.ports import (
    EPHEMERAL_THRESHOLD,
    ListeningPort,
    PortCategory,
    PortsSnapshot,
    _categorize_port,
    _is_covered_by_ufw,
    _parse_ss_output,
    _split_addr_port,
    check_ports,
)
from ufw_audit.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_port(port=22, proto="tcp", address="0.0.0.0") -> ListeningPort:
    return ListeningPort(port=port, proto=proto, address=address, raw_line="")


def make_snapshot(ports=None, ufw_rules="", ss_output="") -> PortsSnapshot:
    return PortsSnapshot(
        ports=ports or [],
        ufw_rules=ufw_rules,
        ss_output=ss_output,
    )


def levels(result) -> list[str]:
    return [f.level.value for f in result.findings]


def has_level(result, level: str) -> bool:
    return level in levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# ListeningPort properties
# ---------------------------------------------------------------------------

class TestListeningPort:
    def test_port_proto(self):
        p = make_port(port=22, proto="tcp")
        assert p.port_proto == "22/tcp"

    def test_is_all_interfaces_true(self):
        assert make_port(address="0.0.0.0").is_all_interfaces is True
        assert make_port(address="::").is_all_interfaces is True

    def test_is_all_interfaces_false(self):
        assert make_port(address="127.0.0.1").is_all_interfaces is False
        assert make_port(address="192.168.1.1").is_all_interfaces is False

    def test_is_loopback_true(self):
        assert make_port(address="127.0.0.1").is_loopback is True
        assert make_port(address="::1").is_loopback is True

    def test_is_loopback_false(self):
        assert make_port(address="0.0.0.0").is_loopback is False


# ---------------------------------------------------------------------------
# _split_addr_port
# ---------------------------------------------------------------------------

class TestSplitAddrPort:
    def test_ipv4_simple(self):
        assert _split_addr_port("0.0.0.0:22") == ("0.0.0.0", "22")

    def test_ipv4_with_iface(self):
        addr, port = _split_addr_port("127.0.0.53%lo:53")
        assert addr == "127.0.0.53"
        assert port == "53"

    def test_ipv6_bracket(self):
        assert _split_addr_port("[::]:22") == ("::", "22")

    def test_ipv6_loopback(self):
        assert _split_addr_port("[::1]:631") == ("::1", "631")

    def test_invalid_returns_none(self):
        assert _split_addr_port("invalid") == (None, None)

    def test_private_ipv4(self):
        assert _split_addr_port("192.168.1.10:445") == ("192.168.1.10", "445")


# ---------------------------------------------------------------------------
# _parse_ss_output
# ---------------------------------------------------------------------------

class TestParseSsOutput:
    SS_OUTPUT = """\
Netid  State   Recv-Q Send-Q Local Address:Port   Peer Address:Port
udp    UNCONN  0      0      0.0.0.0:5353         0.0.0.0:*
tcp    LISTEN  0      128    0.0.0.0:22           0.0.0.0:*
tcp    LISTEN  0      128    127.0.0.1:6379       0.0.0.0:*
tcp    LISTEN  0      128    [::1]:631            [::]:*
"""

    def test_parses_udp(self):
        ports = _parse_ss_output(self.SS_OUTPUT)
        udp = [p for p in ports if p.proto == "udp"]
        assert len(udp) == 1
        assert udp[0].port == 5353

    def test_parses_tcp(self):
        ports = _parse_ss_output(self.SS_OUTPUT)
        tcp = [p for p in ports if p.proto == "tcp"]
        assert len(tcp) == 3

    def test_parses_address(self):
        ports = _parse_ss_output(self.SS_OUTPUT)
        ssh = next(p for p in ports if p.port == 22)
        assert ssh.address == "0.0.0.0"

    def test_parses_loopback(self):
        ports = _parse_ss_output(self.SS_OUTPUT)
        redis = next(p for p in ports if p.port == 6379)
        assert redis.address == "127.0.0.1"

    def test_parses_ipv6_loopback(self):
        ports = _parse_ss_output(self.SS_OUTPUT)
        cups = next(p for p in ports if p.port == 631)
        assert cups.address == "::1"

    def test_deduplicates(self):
        output = "tcp LISTEN 0 0 0.0.0.0:22 0.0.0.0:*\n" * 3
        ports = _parse_ss_output(output)
        assert len(ports) == 1

    def test_empty_output(self):
        assert _parse_ss_output("") == []

    def test_skips_header_line(self):
        output = "Netid State Recv-Q Send-Q Local\ntcp LISTEN 0 0 0.0.0.0:22 0.0.0.0:*\n"
        ports = _parse_ss_output(output)
        assert len(ports) == 1


# ---------------------------------------------------------------------------
# _is_covered_by_ufw
# ---------------------------------------------------------------------------

class TestIsCoveredByUfw:
    RULES_WITH_22 = "[ 1] 22/tcp  ALLOW IN  Anywhere\n"
    RULES_WITHOUT_22 = "[ 1] 80/tcp  ALLOW IN  Anywhere\n"

    def test_covered(self):
        assert _is_covered_by_ufw(22, "tcp", self.RULES_WITH_22) is True

    def test_not_covered(self):
        assert _is_covered_by_ufw(22, "tcp", self.RULES_WITHOUT_22) is False

    def test_empty_rules(self):
        assert _is_covered_by_ufw(22, "tcp", "") is False


# ---------------------------------------------------------------------------
# _categorize_port
# ---------------------------------------------------------------------------

class TestCategorizePort:
    def test_ephemeral(self):
        p = make_port(port=EPHEMERAL_THRESHOLD + 1)
        assert _categorize_port(p, "") == PortCategory.EPHEMERAL

    def test_system_dns_tcp(self):
        p = make_port(port=53, proto="tcp", address="127.0.0.1")
        assert _categorize_port(p, "") == PortCategory.SYSTEM_INTERNAL

    def test_system_dns_udp(self):
        p = make_port(port=53, proto="udp", address="127.0.0.1")
        assert _categorize_port(p, "") == PortCategory.SYSTEM_INTERNAL

    def test_system_dhcp(self):
        p = make_port(port=67, proto="udp")
        assert _categorize_port(p, "") == PortCategory.SYSTEM_INTERNAL

    def test_netbios_137(self):
        p = make_port(port=137, proto="udp", address="0.0.0.0")
        assert _categorize_port(p, "") == PortCategory.NETBIOS

    def test_netbios_138(self):
        p = make_port(port=138, proto="udp", address="0.0.0.0")
        assert _categorize_port(p, "") == PortCategory.NETBIOS

    def test_covered(self):
        rules = "[ 1] 22/tcp  ALLOW IN  Anywhere\n"
        p = make_port(port=22, proto="tcp", address="0.0.0.0")
        assert _categorize_port(p, rules) == PortCategory.COVERED

    def test_uncovered_public(self):
        p = make_port(port=9999, proto="tcp", address="0.0.0.0")
        assert _categorize_port(p, "") == PortCategory.UNCOVERED_PUBLIC

    def test_uncovered_local_loopback(self):
        p = make_port(port=9999, proto="tcp", address="127.0.0.1")
        assert _categorize_port(p, "") == PortCategory.UNCOVERED_LOCAL

    def test_uncovered_local_private_ip(self):
        p = make_port(port=9999, proto="tcp", address="192.168.1.10")
        assert _categorize_port(p, "") == PortCategory.UNCOVERED_LOCAL


# ---------------------------------------------------------------------------
# check_ports
# ---------------------------------------------------------------------------

class TestCheckPorts:
    def test_all_covered_ok(self):
        rules = "[ 1] 22/tcp  ALLOW IN  Anywhere\n"
        snapshot = make_snapshot(
            ports=[make_port(port=22, proto="tcp", address="0.0.0.0")],
            ufw_rules=rules,
        )
        result = check_ports(snapshot)
        assert has_level(result, "ok")

    def test_uncovered_public_alert(self):
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot)
        assert has_level(result, "alert")

    def test_uncovered_public_deduction(self):
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot)
        assert total_deductions(result) > 0

    def test_uncovered_local_info(self):
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="127.0.0.1")],
            ufw_rules="",
        )
        result = check_ports(snapshot)
        assert has_level(result, "info")

    def test_ephemeral_info(self):
        snapshot = make_snapshot(
            ports=[make_port(port=EPHEMERAL_THRESHOLD + 1)],
            ufw_rules="",
        )
        result = check_ports(snapshot)
        assert has_level(result, "info")

    def test_audited_ports_skipped(self):
        snapshot = make_snapshot(
            ports=[make_port(port=22, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot, audited_ports={"22/tcp"})
        # With audited port skipped and nothing uncovered → all_covered OK
        assert has_level(result, "ok")

    def test_no_ports_ok(self):
        snapshot = make_snapshot(ports=[], ufw_rules="")
        result = check_ports(snapshot)
        assert has_level(result, "ok")

    def test_system_port_info(self):
        snapshot = make_snapshot(
            ports=[make_port(port=53, proto="tcp", address="127.0.0.1")],
            ufw_rules="",
        )
        result = check_ports(snapshot)
        assert has_level(result, "info")

    def test_public_context_higher_deduction(self):
        snapshot = make_snapshot(
            ports=[make_port(port=9999, proto="tcp", address="0.0.0.0")],
            ufw_rules="",
        )
        r_local  = check_ports(snapshot, network_context="local")
        r_public = check_ports(snapshot, network_context="public")
        assert total_deductions(r_public) >= total_deductions(r_local)

    def test_translation_function_used(self):
        def my_t(key, **kwargs): return f"T:{key}"
        snapshot = make_snapshot(ports=[], ufw_rules="")
        result = check_ports(snapshot, t=my_t)
        assert any("T:" in f.message for f in result.findings)

    def test_netbios_warn(self):
        snapshot = make_snapshot(
            ports=[make_port(port=137, proto="udp", address="0.0.0.0")],
            ufw_rules="",
        )
        result = check_ports(snapshot)
        assert has_level(result, "warn")
