"""
Tests for ufw_audit/explain.py
"""

from __future__ import annotations

import io
import sys
import pytest

from ufw_audit.explain import normalize_key, run_explain, EXPLAIN_KEYS


# ---------------------------------------------------------------------------
# normalize_key
# ---------------------------------------------------------------------------

class TestNormalizeKey:
    def test_ssh_key_unchanged(self):
        assert normalize_key("ssh.password_auth") == "ssh.password_auth"

    def test_updates_key_unchanged(self):
        assert normalize_key("updates.security_pending") == "updates.security_pending"

    def test_hardening_key_unchanged(self):
        assert normalize_key("hardening.rp_filter_disabled") == "hardening.rp_filter_disabled"

    def test_file_perms_no_middle_unchanged(self):
        assert normalize_key("file_perms.world_writable") == "file_perms.world_writable"

    def test_file_perms_world_writable_strips_middle(self):
        assert normalize_key("file_perms.shadow.world_writable") == "file_perms.world_writable"

    def test_file_perms_too_permissive_strips_middle(self):
        assert normalize_key("file_perms.authorized_keys.too_permissive") == "file_perms.too_permissive"

    def test_file_perms_sudoers_strips_middle(self):
        assert normalize_key("file_perms.sudoers.sudoers_nopasswd_all") == "file_perms.sudoers_nopasswd_all"

    def test_file_perms_ssh_host_key_perms_strips_middle(self):
        assert normalize_key("file_perms.etc_ssh.ssh_host_key_perms") == "file_perms.ssh_host_key_perms"

    def test_other_prefix_unchanged(self):
        assert normalize_key("firewall.status") == "firewall.status"

    def test_empty_string_unchanged(self):
        assert normalize_key("") == ""

    def test_single_segment_unchanged(self):
        assert normalize_key("ssh") == "ssh"

    def test_file_perms_multiple_middle_segments(self):
        """Deep nesting (3+ middle segments) must still resolve to the canonical key."""
        assert normalize_key("file_perms.a.b.c.world_writable") == "file_perms.world_writable"

    def test_file_perms_two_segments_not_modified(self):
        """A canonical file_perms key (no middle segment) must not be over-stripped."""
        assert normalize_key("file_perms.world_writable") == "file_perms.world_writable"

    def test_all_explain_keys_are_already_normalized(self):
        """Every key in EXPLAIN_KEYS must already be in canonical form."""
        for key in EXPLAIN_KEYS:
            assert normalize_key(key) == key, (
                f"EXPLAIN_KEYS contains a non-canonical key: {key!r}"
            )


# ---------------------------------------------------------------------------
# EXPLAIN_KEYS list
# ---------------------------------------------------------------------------

class TestExplainKeysList:
    def test_has_seventy_three_keys(self):
        assert len(EXPLAIN_KEYS) == 73

    def test_all_keys_are_strings(self):
        for k in EXPLAIN_KEYS:
            assert isinstance(k, str)

    def test_known_keys_present(self):
        # original 20
        assert "ssh.password_auth" in EXPLAIN_KEYS
        assert "ssh.permit_root_login" in EXPLAIN_KEYS
        assert "file_perms.world_writable" in EXPLAIN_KEYS
        assert "updates.security_pending" in EXPLAIN_KEYS
        assert "hardening.rp_filter_disabled" in EXPLAIN_KEYS
        assert "hardening.redirects_enabled" in EXPLAIN_KEYS
        # Phase A2 additions — SSH
        assert "ssh.max_auth_tries" in EXPLAIN_KEYS
        assert "ssh.permit_user_env" in EXPLAIN_KEYS
        assert "ssh.weak_ciphers" in EXPLAIN_KEYS
        assert "ssh.weak_macs" in EXPLAIN_KEYS
        assert "ssh.weak_kex" in EXPLAIN_KEYS
        # Phase A2 additions — hardening
        assert "hardening.fail2ban_missing" in EXPLAIN_KEYS
        assert "hardening.log_martians_disabled" in EXPLAIN_KEYS
        assert "hardening.rp_filter_loose" in EXPLAIN_KEYS
        # Phase A2 additions — new checks
        assert "kernel_modules.risky_fs" in EXPLAIN_KEYS
        assert "kernel_modules.risky_net" in EXPLAIN_KEYS
        assert "cron_audit.pipe_to_shell" in EXPLAIN_KEYS
        assert "cron_audit.world_writable" in EXPLAIN_KEYS
        assert "services_state.enabled_inactive" in EXPLAIN_KEYS
        # ClamAV keys (v1.14.0)
        assert "clamav.db_very_outdated" in EXPLAIN_KEYS
        assert "clamav.db_outdated" in EXPLAIN_KEYS
        assert "clamav.scan_very_old" in EXPLAIN_KEYS
        assert "clamav.scan_old" in EXPLAIN_KEYS
        # Samba keys (v1.14.0)
        assert "samba.smb1_enabled" in EXPLAIN_KEYS
        assert "samba.null_passwords" in EXPLAIN_KEYS
        assert "samba.guest_writable" in EXPLAIN_KEYS
        assert "samba.guest_readonly" in EXPLAIN_KEYS
        assert "samba.server_signing_disabled" in EXPLAIN_KEYS
        assert "samba.map_to_guest" in EXPLAIN_KEYS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _identity_t(key, **_kwargs):
    """Minimal t() that returns the key itself (unknown-key behaviour)."""
    return key


def _make_t():
    """Return a t() function backed by the real en.json locale."""
    from ufw_audit import i18n
    i18n.init(lang="en")
    return i18n.t


def _capture_run_explain(key, t):
    """Call run_explain and return captured stdout."""
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        run_explain(key, t)
    finally:
        sys.stdout = old
    return buf.getvalue()


# ---------------------------------------------------------------------------
# run_explain — unknown key
# ---------------------------------------------------------------------------

class TestRunExplainUnknownKey:
    def test_unknown_key_prints_not_available(self):
        out = _capture_run_explain("firewall.unknown_key", _identity_t)
        assert "No explanation available for" in out

    def test_unknown_key_mentions_list(self):
        out = _capture_run_explain("firewall.unknown_key", _identity_t)
        # Test behaviour (shows real keys) not exact wording
        assert any(k in out for k in EXPLAIN_KEYS) or "list" in out.lower()


# ---------------------------------------------------------------------------
# run_explain — list mode
# ---------------------------------------------------------------------------

class TestRunExplainListMode:
    def test_list_prints_all_keys(self):
        t = _make_t()
        out = _capture_run_explain("list", t)
        for k in EXPLAIN_KEYS:
            assert k in out

    def test_list_shows_titles(self):
        t = _make_t()
        out = _capture_run_explain("list", t)
        # Titles should not look like key paths (i.e. not "explain.ssh.password_auth.title")
        assert "explain.ssh.password_auth.title" not in out

    def test_list_has_one_line_per_key(self):
        """Output must have at least one non-empty line per key (no silent truncation)."""
        t = _make_t()
        out = _capture_run_explain("list", t)
        non_empty_lines = [l for l in out.splitlines() if l.strip()]
        assert len(non_empty_lines) >= len(EXPLAIN_KEYS)


# ---------------------------------------------------------------------------
# run_explain — known keys with real locale
# ---------------------------------------------------------------------------

class TestRunExplainKnownKeys:
    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_known_key_shows_title(self, key):
        t = _make_t()
        out = _capture_run_explain(key, t)
        assert "No explanation available" not in out
        # No leaked i18n key paths in output
        assert "explain." not in out

    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_known_key_shows_why_and_how_headers(self, key):
        t = _make_t()
        out = _capture_run_explain(key, t)
        assert "WHY IT IS A RISK" in out
        assert "HOW TO FIX" in out

    @pytest.mark.parametrize("key", EXPLAIN_KEYS)
    def test_known_key_includes_cis_reference(self, key):
        """Every explainable key must show its CIS reference in the output."""
        t = _make_t()
        out = _capture_run_explain(key, t)
        assert "CIS" in out, f"No CIS reference in explain output for {key!r}"

    def test_ssh_password_auth_content(self):
        t = _make_t()
        out = _capture_run_explain("ssh.password_auth", t)
        assert any(w in out.lower() for w in ("brute", "attack", "password"))
        assert "PasswordAuthentication no" in out

    def test_file_perms_normalisation_works(self):
        """file_perms.shadow.world_writable normalises and resolves correctly."""
        t = _make_t()
        out = _capture_run_explain("file_perms.shadow.world_writable", t)
        assert "No explanation available" not in out
        assert "WHY IT IS A RISK" in out

    def test_file_perms_deep_normalisation_works(self):
        """file_perms with multiple middle segments still resolves."""
        t = _make_t()
        out = _capture_run_explain("file_perms.a.b.too_permissive", t)
        assert "No explanation available" not in out
        assert "WHY IT IS A RISK" in out

    def test_updates_security_pending_content(self):
        t = _make_t()
        out = _capture_run_explain("updates.security_pending", t)
        assert any(w in out.lower() for w in ("cve", "vulnerabilit", "patch"))

    def test_hardening_rp_filter_content(self):
        t = _make_t()
        out = _capture_run_explain("hardening.rp_filter_disabled", t)
        assert any(w in out.lower() for w in ("rp_filter", "sysctl", "spoof"))

    def test_ssh_password_auth_snapshot(self):
        """Snapshot-style: password_auth output must contain all key sections."""
        t = _make_t()
        out = _capture_run_explain("ssh.password_auth", t)
        assert "ssh.password_auth" in out          # key in header
        assert "WHY IT IS A RISK" in out
        assert "HOW TO FIX" in out
        assert "CIS" in out
        assert "PasswordAuthentication no" in out
        assert "explain." not in out               # no leaked i18n paths


# ---------------------------------------------------------------------------
# CLI integration — parse_args
# ---------------------------------------------------------------------------

class TestCLIExplainParsing:
    def test_explain_equals_syntax(self):
        from ufw_audit.cli import parse_args
        cfg = parse_args(["--explain=ssh.password_auth"])
        assert cfg.explain_key == "ssh.password_auth"

    def test_explain_space_syntax(self):
        from ufw_audit.cli import parse_args
        cfg = parse_args(["--explain", "ssh.password_auth"])
        assert cfg.explain_key == "ssh.password_auth"

    def test_explain_list(self):
        from ufw_audit.cli import parse_args
        cfg = parse_args(["--explain=list"])
        assert cfg.explain_key == "list"

    def test_explain_with_lang(self):
        from ufw_audit.cli import parse_args
        cfg = parse_args(["--french", "--explain=ssh.password_auth"])
        assert cfg.explain_key == "ssh.password_auth"
        assert cfg.lang == "fr"

    def test_explain_default_is_empty(self):
        from ufw_audit.cli import parse_args
        cfg = parse_args([])
        assert cfg.explain_key == ""

    def test_explain_flag_without_value_raises(self):
        """--explain with no following argument must raise CLIError, not crash."""
        from ufw_audit.cli import parse_args, CLIError
        with pytest.raises(CLIError):
            parse_args(["--explain"])
