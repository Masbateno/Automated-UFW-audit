"""
Unit tests for ufw_audit.checks.logs module.

All tests use synthetic log content and LogsSnapshot instances —
no filesystem or subprocess calls.

Run with: python -m pytest tests/test_logs.py -v
"""

import pytest
from datetime import datetime, timedelta
from ufw_audit.checks.logs import (
    BruteforceHit,
    LogEntry,
    LogsSnapshot,
    _count_available_days,
    _detect_bruteforce,
    _max_in_window,
    _parse_log,
    _parse_timestamp,
    _service_hits,
    _top_ports,
    _top_sources,
    check_logs,
)
from ufw_audit.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_entry(
    src_ip="1.2.3.4",
    dst_port=22,
    proto="TCP",
    ts=None,
) -> LogEntry:
    if ts is None:
        ts = datetime(2026, 3, 19, 10, 0, 0)
    return LogEntry(timestamp=ts, src_ip=src_ip, dst_port=dst_port, proto=proto)


def make_snapshot(
    entries=None,
    days_available=5,
    log_days=7,
    log_found=True,
) -> LogsSnapshot:
    return LogsSnapshot(
        entries=entries or [],
        days_available=days_available,
        log_days=log_days,
        log_found=log_found,
    )


def levels(result):
    return [f.level.value for f in result.findings]


def has_level(result, level):
    return level in levels(result)


# ---------------------------------------------------------------------------
# LogEntry
# ---------------------------------------------------------------------------

class TestLogEntry:
    def test_port_proto_tcp(self):
        e = make_entry(dst_port=22, proto="TCP")
        assert e.port_proto == "22/tcp"

    def test_port_proto_udp(self):
        e = make_entry(dst_port=5353, proto="UDP")
        assert e.port_proto == "5353/udp"


# ---------------------------------------------------------------------------
# _parse_timestamp
# ---------------------------------------------------------------------------

class TestParseTimestamp:
    def test_iso_format(self):
        line = "2026-03-19T18:20:08.898446+01:00 host kernel: [UFW BLOCK]"
        ts = _parse_timestamp(line, 2026)
        assert ts is not None
        assert ts.year == 2026
        assert ts.month == 3
        assert ts.day == 19

    def test_syslog_format(self):
        line = "Mar 19 10:23:14 host kernel: [UFW BLOCK]"
        ts = _parse_timestamp(line, 2026)
        assert ts is not None
        assert ts.month == 3
        assert ts.day == 19
        assert ts.year == 2026

    def test_invalid_returns_none(self):
        assert _parse_timestamp("not a timestamp", 2026) is None

    def test_no_timestamp_returns_none(self):
        assert _parse_timestamp("[UFW BLOCK] IN=eth0", 2026) is None


# ---------------------------------------------------------------------------
# _parse_log
# ---------------------------------------------------------------------------

class TestParseLog:
    ISO_LINE = (
        "2026-03-19T10:23:14.000+01:00 host kernel: [UFW BLOCK] "
        "IN=eth0 SRC=1.2.3.4 DST=192.168.1.1 PROTO=TCP DPT=22\n"
    )
    SYSLOG_LINE = (
        "Mar 19 10:23:14 host kernel: [UFW BLOCK] "
        "IN=eth0 SRC=5.6.7.8 DST=192.168.1.1 PROTO=UDP DPT=5353\n"
    )
    NOT_BLOCK = "Mar 19 10:23:14 host kernel: [UFW ALLOW] IN=eth0 SRC=1.2.3.4\n"

    def test_parses_iso_line(self):
        entries = _parse_log(self.ISO_LINE, "2026-03-01")
        assert len(entries) == 1
        assert entries[0].src_ip == "1.2.3.4"
        assert entries[0].dst_port == 22
        assert entries[0].proto == "TCP"

    def test_parses_syslog_line(self):
        entries = _parse_log(self.SYSLOG_LINE, "2026-03-01")
        assert len(entries) == 1
        assert entries[0].src_ip == "5.6.7.8"
        assert entries[0].dst_port == 5353

    def test_skips_non_block_lines(self):
        entries = _parse_log(self.NOT_BLOCK, "2026-01-01")
        assert entries == []

    def test_filters_by_cutoff(self):
        entries = _parse_log(self.ISO_LINE, "2026-03-20")
        assert entries == []

    def test_includes_on_cutoff_day(self):
        entries = _parse_log(self.ISO_LINE, "2026-03-19")
        assert len(entries) == 1

    def test_empty_content(self):
        assert _parse_log("", "2026-01-01") == []

    def test_multiple_lines(self):
        content = self.ISO_LINE + self.SYSLOG_LINE
        entries = _parse_log(content, "2026-03-01")
        assert len(entries) == 2


# ---------------------------------------------------------------------------
# _count_available_days
# ---------------------------------------------------------------------------

class TestCountAvailableDays:
    def test_iso_dates(self):
        content = (
            "2026-03-19T10:00:00 line1\n"
            "2026-03-19T11:00:00 line2\n"
            "2026-03-20T10:00:00 line3\n"
        )
        assert _count_available_days(content) == 2

    def test_syslog_dates(self):
        content = (
            "Mar 19 10:00:00 line1\n"
            "Mar 19 11:00:00 line2\n"
            "Mar 20 10:00:00 line3\n"
        )
        assert _count_available_days(content) == 2

    def test_empty(self):
        assert _count_available_days("") == 0


# ---------------------------------------------------------------------------
# _top_sources / _top_ports
# ---------------------------------------------------------------------------

class TestTopSources:
    def test_top_ips_sorted(self):
        entries = [
            make_entry(src_ip="1.1.1.1"),
            make_entry(src_ip="1.1.1.1"),
            make_entry(src_ip="2.2.2.2"),
        ]
        top = _top_sources(entries, 10)
        assert top[0] == ("1.1.1.1", 2)
        assert top[1] == ("2.2.2.2", 1)

    def test_top_n_respected(self):
        entries = [make_entry(src_ip=f"{i}.{i}.{i}.{i}") for i in range(1, 15)]
        top = _top_sources(entries, 5)
        assert len(top) == 5

    def test_empty(self):
        assert _top_sources([], 10) == []


class TestTopPorts:
    def test_top_ports_sorted(self):
        entries = [
            make_entry(dst_port=22, proto="TCP"),
            make_entry(dst_port=22, proto="TCP"),
            make_entry(dst_port=80, proto="TCP"),
        ]
        top = _top_ports(entries, 10)
        assert top[0][0] == "22/tcp"
        assert top[0][1] == 2

    def test_empty(self):
        assert _top_ports([], 10) == []


# ---------------------------------------------------------------------------
# _max_in_window / _detect_bruteforce
# ---------------------------------------------------------------------------

class TestMaxInWindow:
    def test_all_in_window(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        ts = [base + timedelta(seconds=i * 5) for i in range(5)]
        assert _max_in_window(ts, 60) == 5

    def test_spread_across_windows(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        # 0s, 30s, 60s, 90s — [0,30,60] fits in 60s window → max is 3
        ts = [base + timedelta(seconds=i * 30) for i in range(4)]
        assert _max_in_window(ts, 60) == 3

    def test_spread_strictly_outside_window(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        # 0s, 61s, 122s — each pair is >60s apart → max is 1
        ts = [base + timedelta(seconds=i * 61) for i in range(3)]
        assert _max_in_window(ts, 60) == 1

    def test_empty(self):
        assert _max_in_window([], 60) == 0

    def test_single(self):
        assert _max_in_window([datetime.now()], 60) == 1


class TestDetectBruteforce:
    def test_detects_bruteforce(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry(src_ip="1.2.3.4", dst_port=22, proto="TCP",
                       ts=base + timedelta(seconds=i * 3))
            for i in range(15)
        ]
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert len(hits) == 1
        assert hits[0].src_ip == "1.2.3.4"
        assert hits[0].dst_port == 22

    def test_no_bruteforce_below_threshold(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry(src_ip="1.2.3.4", dst_port=22, proto="TCP",
                       ts=base + timedelta(seconds=i * 3))
            for i in range(5)
        ]
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert hits == []

    def test_spread_out_attempts_not_detected(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry(src_ip="1.2.3.4", dst_port=22, proto="TCP",
                       ts=base + timedelta(seconds=i * 120))
            for i in range(20)
        ]
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert hits == []

    def test_different_ports_not_grouped(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = []
        for port in (22, 80, 443):
            for i in range(5):
                entries.append(make_entry(src_ip="1.2.3.4", dst_port=port,
                                          proto="TCP",
                                          ts=base + timedelta(seconds=i)))
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert hits == []

    def test_sorted_by_count_descending(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = []
        for i in range(20):
            entries.append(make_entry("1.1.1.1", 22, "TCP",
                                      base + timedelta(seconds=i)))
        for i in range(15):
            entries.append(make_entry("2.2.2.2", 22, "TCP",
                                      base + timedelta(seconds=i)))
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert hits[0].count >= hits[-1].count


# ---------------------------------------------------------------------------
# _service_hits
# ---------------------------------------------------------------------------

class TestServiceHits:
    def test_counts_hits_on_audited_ports(self):
        entries = [
            make_entry(dst_port=22, proto="TCP"),
            make_entry(dst_port=22, proto="TCP"),
            make_entry(dst_port=80, proto="TCP"),
        ]
        hits = _service_hits(entries, {"22/tcp"})
        assert hits.get("22/tcp") == 2
        assert "80/tcp" not in hits

    def test_empty_audited_ports(self):
        entries = [make_entry(dst_port=22, proto="TCP")]
        assert _service_hits(entries, set()) == {}

    def test_no_matching_ports(self):
        entries = [make_entry(dst_port=9999, proto="TCP")]
        assert _service_hits(entries, {"22/tcp"}) == {}


# ---------------------------------------------------------------------------
# check_logs
# ---------------------------------------------------------------------------

class TestCheckLogs:
    def test_no_logfile_info(self):
        snap = make_snapshot(log_found=False)
        result = check_logs(snap)
        assert has_level(result, "info")

    def test_empty_log_ok(self):
        snap = make_snapshot(entries=[], log_found=True)
        result = check_logs(snap)
        assert has_level(result, "ok")

    def test_bruteforce_warn(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry("1.2.3.4", 22, "TCP", base + timedelta(seconds=i * 3))
            for i in range(15)
        ]
        snap = make_snapshot(entries=entries)
        result = check_logs(snap)
        assert has_level(result, "warn")

    def test_bruteforce_deduction(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry("1.2.3.4", 22, "TCP", base + timedelta(seconds=i * 3))
            for i in range(15)
        ]
        snap = make_snapshot(entries=entries)
        result = check_logs(snap)
        assert sum(d.points for d in result.deductions) > 0

    def test_log_data_attached(self):
        entries = [make_entry("1.2.3.4", 22, "TCP")]
        snap = make_snapshot(entries=entries)
        result = check_logs(snap)
        assert hasattr(result, "_log_data")
        assert result._log_data["total"] == 1

    def test_top_ips_in_log_data(self):
        entries = [make_entry("1.2.3.4", 22, "TCP")] * 5
        snap = make_snapshot(entries=entries)
        result = check_logs(snap)
        top_ips = result._log_data["top_ips"]
        assert top_ips[0] == ("1.2.3.4", 5)

    def test_service_hits_in_log_data(self):
        entries = [make_entry("1.2.3.4", 22, "TCP")] * 3
        snap = make_snapshot(entries=entries)
        result = check_logs(snap, audited_ports={"22/tcp"})
        assert result._log_data["svc_hits"].get("22/tcp") == 3

    def test_translation_used(self):
        def my_t(key, **kwargs): return f"T:{key}"
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry("1.2.3.4", 22, "TCP", base + timedelta(seconds=i * 3))
            for i in range(15)
        ]
        snap = make_snapshot(entries=entries)
        result = check_logs(snap, t=my_t)
        assert any("T:" in f.message for f in result.findings)
