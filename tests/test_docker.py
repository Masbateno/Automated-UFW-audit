"""
Unit tests for ufw_audit.checks.docker module.

All tests use DockerSnapshot instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_docker.py -v
"""

import pytest
from ufw_audit.checks.docker import (
    DockerSnapshot,
    ExposedPort,
    _parse_port_entry,
    check_docker,
)
from ufw_audit.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_port(
    container_name="nginx",
    host_port=8080,
    container_port=80,
    proto="tcp",
    host_ip="0.0.0.0",
) -> ExposedPort:
    return ExposedPort(
        container_name=container_name,
        host_port=host_port,
        container_port=container_port,
        proto=proto,
        host_ip=host_ip,
    )


def levels(result):
    return [f.level.value for f in result.findings]


def has_level(result, level):
    return level in levels(result)


def total_deductions(result):
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# ExposedPort
# ---------------------------------------------------------------------------

class TestExposedPort:
    def test_port_proto(self):
        p = make_port(host_port=8080, proto="tcp")
        assert p.port_proto == "8080/tcp"

    def test_is_public_0000(self):
        assert make_port(host_ip="0.0.0.0").is_public is True

    def test_is_public_ipv6(self):
        assert make_port(host_ip="::").is_public is True

    def test_not_public_loopback(self):
        assert make_port(host_ip="127.0.0.1").is_public is False

    def test_not_public_private(self):
        assert make_port(host_ip="192.168.1.10").is_public is False


# ---------------------------------------------------------------------------
# _parse_port_entry
# ---------------------------------------------------------------------------

class TestParsePortEntry:
    def test_ipv4_tcp(self):
        p = _parse_port_entry("nginx", "0.0.0.0:8080->80/tcp")
        assert p is not None
        assert p.host_ip == "0.0.0.0"
        assert p.host_port == 8080
        assert p.container_port == 80
        assert p.proto == "tcp"

    def test_ipv6(self):
        p = _parse_port_entry("nginx", ":::8080->80/tcp")
        assert p is not None
        assert p.host_ip == "::"
        assert p.host_port == 8080

    def test_udp(self):
        p = _parse_port_entry("vpn", "0.0.0.0:51820->51820/udp")
        assert p is not None
        assert p.proto == "udp"

    def test_invalid_format(self):
        assert _parse_port_entry("nginx", "invalid") is None

    def test_no_mapping(self):
        assert _parse_port_entry("nginx", "80/tcp") is None

    def test_container_name_preserved(self):
        p = _parse_port_entry("myapp", "0.0.0.0:3000->3000/tcp")
        assert p.container_name == "myapp"

    def test_loopback(self):
        p = _parse_port_entry("redis", "127.0.0.1:6379->6379/tcp")
        assert p is not None
        assert p.host_ip == "127.0.0.1"
        assert p.is_public is False


# ---------------------------------------------------------------------------
# DockerSnapshot factories
# ---------------------------------------------------------------------------

class TestDockerSnapshotFactories:
    def test_not_installed(self):
        s = DockerSnapshot.not_installed()
        assert s.installed is False
        assert s.iptables_disabled is False

    def test_safe(self):
        s = DockerSnapshot.safe()
        assert s.installed is True
        assert s.iptables_disabled is True

    def test_unsafe(self):
        s = DockerSnapshot.unsafe()
        assert s.installed is True
        assert s.iptables_disabled is False

    def test_safe_with_ports(self):
        port = make_port()
        s = DockerSnapshot.safe(exposed_ports=[port])
        assert len(s.exposed_ports) == 1


# ---------------------------------------------------------------------------
# check_docker — not installed
# ---------------------------------------------------------------------------

class TestCheckDockerNotInstalled:
    def test_info_when_not_installed(self):
        result = check_docker(DockerSnapshot.not_installed())
        assert has_level(result, "info")

    def test_no_deduction_when_not_installed(self):
        result = check_docker(DockerSnapshot.not_installed())
        assert total_deductions(result) == 0

    def test_only_one_finding(self):
        result = check_docker(DockerSnapshot.not_installed())
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# check_docker — iptables bypass
# ---------------------------------------------------------------------------

class TestCheckDockerIptables:
    def test_ok_when_iptables_disabled(self):
        result = check_docker(DockerSnapshot.safe())
        assert has_level(result, "ok")

    def test_alert_when_iptables_enabled(self):
        result = check_docker(DockerSnapshot.unsafe())
        assert has_level(result, "alert")

    def test_deduction_when_iptables_enabled(self):
        result = check_docker(DockerSnapshot.unsafe())
        assert total_deductions(result) > 0

    def test_fix_cmd_present(self):
        result = check_docker(DockerSnapshot.unsafe())
        alert = next(f for f in result.findings if f.level == FindingLevel.ALERT)
        assert "daemon.json" in alert.cmd

    def test_higher_deduction_on_public(self):
        r_local  = check_docker(DockerSnapshot.unsafe(), network_context="local")
        r_public = check_docker(DockerSnapshot.unsafe(), network_context="public")
        assert total_deductions(r_public) > total_deductions(r_local)


# ---------------------------------------------------------------------------
# check_docker — exposed ports
# ---------------------------------------------------------------------------

class TestCheckDockerExposedPorts:
    def test_ok_when_no_containers(self):
        result = check_docker(DockerSnapshot.safe(exposed_ports=[]))
        assert has_level(result, "ok")

    def test_ok_when_loopback_only(self):
        loopback_port = make_port(host_ip="127.0.0.1")
        result = check_docker(DockerSnapshot.safe(exposed_ports=[loopback_port]))
        assert has_level(result, "ok")

    def test_warn_when_public_port(self):
        public_port = make_port(host_ip="0.0.0.0")
        result = check_docker(DockerSnapshot.safe(exposed_ports=[public_port]))
        assert has_level(result, "warn")

    def test_no_extra_deduction_when_iptables_disabled(self):
        """With iptables disabled, exposed ports are visible but UFW covers them."""
        public_port = make_port(host_ip="0.0.0.0")
        result = check_docker(DockerSnapshot.safe(exposed_ports=[public_port]))
        # Only warn, no deduction (iptables is disabled so UFW rules apply)
        assert total_deductions(result) == 0

    def test_extra_deduction_when_iptables_enabled(self):
        """With iptables enabled, exposed ports bypass UFW — extra deduction."""
        public_port = make_port(host_ip="0.0.0.0")
        result = check_docker(DockerSnapshot.unsafe(exposed_ports=[public_port]))
        # iptables deduction + bypass deduction per port
        assert total_deductions(result) >= 2

    def test_multiple_public_ports_multiple_warns(self):
        ports = [
            make_port("nginx", 80, 80, "tcp"),
            make_port("app",  3000, 3000, "tcp"),
        ]
        result = check_docker(DockerSnapshot.safe(exposed_ports=ports))
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warns) == 2

    def test_container_name_in_finding(self):
        port = make_port(container_name="myredis", host_port=6379)
        result = check_docker(DockerSnapshot.safe(exposed_ports=[port]))
        warn = next(f for f in result.findings if f.level == FindingLevel.WARN)
        assert "myredis" in warn.message


# ---------------------------------------------------------------------------
# Translation
# ---------------------------------------------------------------------------

class TestCheckDockerTranslation:
    def test_translation_used(self):
        def my_t(key, **kwargs): return f"T:{key}"
        result = check_docker(DockerSnapshot.not_installed(), t=my_t)
        assert any("T:" in f.message for f in result.findings)
