"""
Unit tests for _check_rules() — open-any detection, duplicate detection,
IPv6 consistency.

Focus: trailing-space regression (ufw status numbered pads lines with spaces,
which caused the open-any pattern to silently miss the wildcard rule).

Run with: python -m pytest tests/test_check_rules.py -v
"""

import pytest
from ufw_audit.checks.firewall import check_rules as _check_rules
from ufw_audit.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Minimal translation stub
# ---------------------------------------------------------------------------

def t(key, **kwargs):
    """Return the key itself so assertions stay readable."""
    return key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def levels(result):
    return [f.level.value for f in result.findings]


def has_alert(result):
    return FindingLevel.ALERT.value in levels(result)


def has_warn(result):
    return FindingLevel.WARN.value in levels(result)


def total_deductions(result):
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# open-any detection — trailing spaces (regression for the v0.11.3 bug)
# ---------------------------------------------------------------------------

# ufw status numbered pads lines with trailing spaces — this was the root cause
OPEN_ANY_TRAILING_SPACES = (
    "[ 1] Anywhere                   ALLOW IN    Anywhere                  \n"
    "[ 2] 22/tcp                     ALLOW IN    Anywhere                  \n"
)

OPEN_ANY_NO_TRAILING = (
    "[ 1] Anywhere                   ALLOW IN    Anywhere\n"
    "[ 2] 22/tcp                     ALLOW IN    Anywhere\n"
)

OPEN_ANY_V6 = (
    "[ 1] Anywhere                   ALLOW IN    Anywhere                  \n"
    "[ 2] Anywhere (v6)              ALLOW IN    Anywhere (v6)             \n"
)

OPEN_ANY_TCP = (
    "[ 1] Anywhere/tcp               ALLOW IN    Anywhere/tcp              \n"
    "[ 2] 22/tcp                     ALLOW IN    Anywhere                  \n"
)

OPEN_ANY_UDP = (
    "[ 1] Anywhere/udp               ALLOW IN    Anywhere/udp              \n"
)

CLEAN_RULES = (
    "[ 1] 22/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 80/tcp                     ALLOW IN    Anywhere                  \n"
)


def test_open_any_with_trailing_spaces_is_detected():
    """Regression: trailing spaces must not prevent open-any detection."""
    result = _check_rules("", OPEN_ANY_TRAILING_SPACES, t)
    assert has_alert(result), "Wildcard ALLOW IN Anywhere with trailing spaces not detected"


def test_open_any_without_trailing_spaces_is_detected():
    """Baseline: detection works when there are no trailing spaces."""
    result = _check_rules("", OPEN_ANY_NO_TRAILING, t)
    assert has_alert(result)


def test_open_any_v6_both_detected():
    """Both IPv4 and IPv6 wildcard rules trigger alerts."""
    result = _check_rules("", OPEN_ANY_V6, t)
    alert_count = sum(
        1 for f in result.findings if f.level == FindingLevel.ALERT
        and "rules.open_any_found" in f.message
    )
    assert alert_count == 2, f"Expected 2 open-any alerts (IPv4 + IPv6), got {alert_count}"


def test_open_any_deduction_applied():
    """Wildcard rule carries a score deduction."""
    result = _check_rules("", OPEN_ANY_TRAILING_SPACES, t)
    assert total_deductions(result) >= 2


def test_open_any_tcp_detected():
    """Anywhere/tcp ALLOW IN Anywhere/tcp — all TCP ports open — must be detected."""
    result = _check_rules("", OPEN_ANY_TCP, t)
    assert has_alert(result)


def test_open_any_udp_detected():
    """Anywhere/udp ALLOW IN Anywhere/udp — all UDP ports open — must be detected."""
    result = _check_rules("", OPEN_ANY_UDP, t)
    assert has_alert(result)


def test_clean_rules_no_open_any_alert():
    """No false positive when rules are port-restricted."""
    result = _check_rules("", CLEAN_RULES, t)
    assert not has_alert(result)


# ---------------------------------------------------------------------------
# Duplicate detection
# ---------------------------------------------------------------------------

DUPLICATE_EXACT = (
    "[ 1] 80/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 80/tcp                     ALLOW IN    Anywhere                  \n"
)

DUPLICATE_COMMENT_IGNORED = (
    "[ 1] 80/tcp                     ALLOW IN    Anywhere                   # test2\n"
    "[ 2] 80/tcp                     ALLOW IN    Anywhere                  \n"
)

# PORT/proto is redundant when PORT (no proto) exists for same action+source
DUPLICATE_SEMANTIC_TCP = (
    "[ 1] 80/tcp                     ALLOW IN    Anywhere                   # test2\n"
    "[ 2] 80                         ALLOW IN    Anywhere                  \n"
)

DUPLICATE_SEMANTIC_UDP = (
    "[ 1] 5353/udp                   ALLOW IN    Anywhere                  \n"
    "[ 2] 5353                       ALLOW IN    Anywhere                  \n"
)

# PORT/tcp + PORT/udp only (no PORT) — NOT a duplicate, they are complementary
NO_DUPLICATE_TCP_UDP_ONLY = (
    "[ 1] 80/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 80/udp                     ALLOW IN    Anywhere                  \n"
)

NO_DUPLICATE_RULES = (
    "[ 1] 80/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 443/tcp                    ALLOW IN    Anywhere                  \n"
)


def test_exact_duplicate_detected():
    result = _check_rules("", DUPLICATE_EXACT, t)
    assert has_alert(result)


def test_comment_stripped_for_duplicate_check():
    """80/tcp # test2 and 80/tcp without comment are the same rule."""
    result = _check_rules("", DUPLICATE_COMMENT_IGNORED, t)
    assert has_alert(result)


def test_semantic_duplicate_tcp_detected():
    """80/tcp is redundant when 80 (no proto) exists — must be flagged."""
    result = _check_rules("", DUPLICATE_SEMANTIC_TCP, t)
    assert has_alert(result)


def test_semantic_duplicate_udp_detected():
    """5353/udp is redundant when 5353 (no proto) exists — must be flagged."""
    result = _check_rules("", DUPLICATE_SEMANTIC_UDP, t)
    assert has_alert(result)


def test_tcp_and_udp_only_no_false_positive():
    """PORT/tcp + PORT/udp without PORT — complementary rules, not duplicates."""
    result = _check_rules("", NO_DUPLICATE_TCP_UDP_ONLY, t)
    assert not any("rules.duplicate_found" in f.message for f in result.findings)


def test_no_false_positive_duplicates():
    result = _check_rules("", NO_DUPLICATE_RULES, t)
    assert not any("rules.duplicate_found" in f.message for f in result.findings)


# ---------------------------------------------------------------------------
# IPv6 consistency
# ---------------------------------------------------------------------------

IPV4_ONLY_RULES = (
    "[ 1] 22/tcp                     ALLOW IN    Anywhere                  \n"
)

IPV4_AND_IPV6_RULES = (
    "[ 1] 22/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)             \n"
)


def test_ipv6_missing_triggers_warning():
    result = _check_rules("", IPV4_ONLY_RULES, t)
    assert has_warn(result)


def test_ipv4_and_ipv6_no_warning():
    result = _check_rules("", IPV4_AND_IPV6_RULES, t)
    assert not has_warn(result)
