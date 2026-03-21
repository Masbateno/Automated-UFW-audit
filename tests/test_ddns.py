"""
Unit tests for ufw_audit.checks.ddns module.

All tests use DdnsSnapshot instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_ddns.py -v
"""

import pytest
from ufw_audit.checks.ddns import (
    DdnsSnapshot,
    _extract_ddclient_domain,
    _extract_duckdns_domain,
    _extract_inadyn_domain,
    _extract_noip_domain,
    _find_open_ports,
    check_ddns,
)
from ufw_audit.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def levels(result):
    return [f.level.value for f in result.findings]


def has_level(result, level):
    return level in levels(result)


def total_deductions(result):
    return sum(d.points for d in result.deductions)


UFW_OPEN = """\
[ 1] 8096/tcp                   ALLOW IN    Anywhere
[ 2] 80/tcp                     ALLOW IN    Anywhere
"""

UFW_LOCAL_ONLY = """\
[ 1] 22/tcp                     ALLOW IN    192.168.1.0/24
"""

UFW_EMPTY = ""


# ---------------------------------------------------------------------------
# DdnsSnapshot factories
# ---------------------------------------------------------------------------

class TestDdnsSnapshotFactories:
    def test_none_factory(self):
        s = DdnsSnapshot.none()
        assert s.installed is False
        assert s.active is False
        assert s.client_name is None

    def test_detected_factory(self):
        s = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        assert s.installed is True
        assert s.active is True
        assert s.client_name == "ddclient"
        assert s.domain == "test.duckdns.org"

    def test_detected_inactive(self):
        s = DdnsSnapshot.detected("ddclient", active=False)
        assert s.active is False
        assert s.installed is True


# ---------------------------------------------------------------------------
# _find_open_ports
# ---------------------------------------------------------------------------

class TestFindOpenPorts:
    def test_finds_unrestricted_ports(self):
        ports = _find_open_ports(UFW_OPEN)
        assert "8096/tcp" in ports
        assert "80/tcp" in ports

    def test_skips_local_restricted(self):
        ports = _find_open_ports(UFW_LOCAL_ONLY)
        assert ports == []

    def test_empty_rules(self):
        assert _find_open_ports(UFW_EMPTY) == []

    def test_no_duplicates(self):
        rules = "[ 1] 80/tcp  ALLOW IN  Anywhere\n[ 2] 80/tcp  ALLOW IN  Anywhere\n"
        ports = _find_open_ports(rules)
        assert ports.count("80/tcp") == 1

    def test_skips_deny_rules(self):
        rules = "[ 1] 22/tcp  DENY IN  Anywhere\n"
        assert _find_open_ports(rules) == []

    def test_private_10_skipped(self):
        rules = "[ 1] 22/tcp  ALLOW IN  10.0.0.0/8\n"
        assert _find_open_ports(rules) == []

    def test_private_172_skipped(self):
        rules = "[ 1] 22/tcp  ALLOW IN  172.16.0.0/12\n"
        assert _find_open_ports(rules) == []

    def test_udp_port_detected(self):
        rules = "[ 1] 51820/udp  ALLOW IN  Anywhere\n"
        ports = _find_open_ports(rules)
        assert "51820/udp" in ports


# ---------------------------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------------------------

class TestExtractDdclientDomain:
    def test_standard_hostname_key(self):
        content = "protocol=duckdns\nhostname=myhost.duckdns.org\n"
        assert _extract_ddclient_domain(content) == "myhost.duckdns.org"

    def test_host_key(self):
        content = "protocol=dyndns\nhost=myhost.example.com\n"
        assert _extract_ddclient_domain(content) == "myhost.example.com"

    def test_duckdns_format_last_line(self):
        content = (
            "protocol=duckdns \\\n"
            "use=web \\\n"
            "login=myhost \\\n"
            "password=token \\\n"
            "http://myhost.duckdns.org \n"
        )
        result = _extract_ddclient_domain(content)
        assert result == "myhost.duckdns.org"

    def test_empty_content(self):
        assert _extract_ddclient_domain("") is None


class TestExtractInadynDomain:
    def test_hostname_key(self):
        content = "provider dyndns {\n  hostname = myhost.ddns.net\n}\n"
        assert _extract_inadyn_domain(content) == "myhost.ddns.net"

    def test_empty(self):
        assert _extract_inadyn_domain("") is None


class TestExtractNoipDomain:
    def test_hostname_key(self):
        content = "hostname myhost.ddns.net\n"
        assert _extract_noip_domain(content) == "myhost.ddns.net"

    def test_empty(self):
        assert _extract_noip_domain("") is None


class TestExtractDuckdnsDomain:
    def test_finds_duckdns_org(self):
        content = "curl https://www.duckdns.org/update?domains=myhost&token=abc\n"
        assert _extract_duckdns_domain(content) == "myhost.duckdns.org"

    def test_empty(self):
        assert _extract_duckdns_domain("") is None


# ---------------------------------------------------------------------------
# check_ddns
# ---------------------------------------------------------------------------

class TestCheckDdnsNoClient:
    def test_ok_when_no_ddns(self):
        result = check_ddns(DdnsSnapshot.none())
        assert has_level(result, "ok")

    def test_no_deduction_when_no_ddns(self):
        result = check_ddns(DdnsSnapshot.none())
        assert total_deductions(result) == 0


class TestCheckDdnsInactive:
    def test_info_when_inactive(self):
        snap = DdnsSnapshot.detected("ddclient", active=False)
        result = check_ddns(snap)
        assert has_level(result, "info")

    def test_no_deduction_when_inactive(self):
        snap = DdnsSnapshot.detected("ddclient", active=False)
        result = check_ddns(snap)
        assert total_deductions(result) == 0


class TestCheckDdnsActiveNoPorts:
    def test_warn_for_active_ddns(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_EMPTY)
        assert has_level(result, "warn")

    def test_ok_when_no_open_ports(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_EMPTY)
        assert has_level(result, "ok")

    def test_no_deduction_when_no_open_ports(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_EMPTY)
        assert total_deductions(result) == 0

    def test_domain_in_findings(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_EMPTY)
        messages = [f.message for f in result.findings]
        assert any("test.duckdns.org" in m for m in messages)

    def test_no_domain_info(self):
        snap = DdnsSnapshot.detected("ddclient", domain=None)
        result = check_ddns(snap, ufw_rules=UFW_EMPTY)
        assert has_level(result, "info")


class TestCheckDdnsActiveWithPorts:
    def test_warn_with_open_ports(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_OPEN)
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warns) >= 1

    def test_deduction_1_with_open_ports(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_OPEN)
        assert total_deductions(result) == 1

    def test_open_ports_stored(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_OPEN)
        assert hasattr(result, "_ddns_open_ports")
        assert "8096/tcp" in result._ddns_open_ports

    def test_advice_info_present(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_OPEN)
        assert has_level(result, "info")

    def test_local_only_ports_no_deduction(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_LOCAL_ONLY)
        assert total_deductions(result) == 0

    def test_single_global_deduction_regardless_of_port_count(self):
        """One deduction total, not per open port."""
        rules = (
            "[ 1] 80/tcp    ALLOW IN  Anywhere\n"
            "[ 2] 443/tcp   ALLOW IN  Anywhere\n"
            "[ 3] 8096/tcp  ALLOW IN  Anywhere\n"
        )
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=rules)
        assert total_deductions(result) == 1


class TestCheckDdnsTranslation:
    def test_translation_used(self):
        def my_t(key, **kwargs): return f"T:{key}"
        result = check_ddns(DdnsSnapshot.none(), t=my_t)
        assert any("T:" in f.message for f in result.findings)
