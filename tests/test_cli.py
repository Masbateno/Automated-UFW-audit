"""
Unit tests for ufw_audit.cli module.

Run with: python -m pytest tests/test_cli.py -v
"""

import pytest
from ufw_audit.cli import AuditConfig, CLIError, parse_args


class TestDefaults:
    def test_empty_argv_returns_defaults(self):
        config = parse_args([])
        assert config.lang == "en"
        assert config.verbose is False
        assert config.detailed is False
        assert config.fix is False
        assert config.yes is False
        assert config.reconfigure is False
        assert config.no_color is False
        assert config.quiet is False
        assert config.json_mode is False
        assert config.json_full is False
        assert config.log_days == 7
        assert config.manage_logs is False
        assert config.install_cron is False
        assert config.manage_cron is False
        assert config.show_version is False
        assert config.show_help is False
        assert config.install_completion is False
        assert config.offline is False
        assert config.profile == ""
        assert config.reset_baseline is False
        assert config.explain_key == ""
        assert config.diff_mode is False
        assert config.webhook_url == ""
        assert config.webhook_format == "auto"


class TestFlags:
    @pytest.mark.parametrize("argv", [["-v"], ["--verbose"]])
    def test_verbose(self, argv):
        assert parse_args(argv).verbose is True

    @pytest.mark.parametrize("argv", [["-d"], ["--detailed"]])
    def test_detailed(self, argv):
        assert parse_args(argv).detailed is True

    def test_fix(self):
        assert parse_args(["--fix"]).fix is True

    @pytest.mark.parametrize("argv", [["-y", "--fix"], ["--yes", "--fix"]])
    def test_yes(self, argv):
        assert parse_args(argv).yes is True

    def test_reconfigure(self):
        assert parse_args(["--reconfigure"]).reconfigure is True

    def test_no_color(self):
        assert parse_args(["--no-color"]).no_color is True

    def test_json(self):
        config = parse_args(["--json"])
        assert config.json_mode is True
        assert config.json_full is False

    def test_json_full_implies_json_mode(self):
        config = parse_args(["--json-full"])
        assert config.json_mode is True
        assert config.json_full is True

    def test_french(self):
        assert parse_args(["--french"]).lang == "fr"

    def test_version(self):
        assert parse_args(["--version"]).show_version is True

    @pytest.mark.parametrize("argv", [["-h"], ["--help"]])
    def test_help(self, argv):
        assert parse_args(argv).show_help is True

    @pytest.mark.parametrize("argv", [["-o"], ["--offline"]])
    def test_offline(self, argv):
        assert parse_args(argv).offline is True

    @pytest.mark.parametrize("argv", [["-q"], ["--quiet"]])
    def test_quiet(self, argv):
        assert parse_args(argv).quiet is True

    def test_diff(self):
        assert parse_args(["--diff"]).diff_mode is True

    def test_explain_with_equals(self):
        assert parse_args(["--explain=ssh.password_auth"]).explain_key == "ssh.password_auth"

    def test_explain_with_space(self):
        assert parse_args(["--explain", "ssh.password_auth"]).explain_key == "ssh.password_auth"

    def test_profile(self):
        assert parse_args(["--profile=server"]).profile == "server"

    def test_reset_baseline(self):
        assert parse_args(["--reset-baseline"]).reset_baseline is True

    def test_json_full_order_independent(self):
        """--json --json-full and --json-full --json must produce identical config."""
        c1 = parse_args(["--json", "--json-full"])
        c2 = parse_args(["--json-full", "--json"])
        assert c1.json_full is True and c1.json_mode is True
        assert c2.json_full is True and c2.json_mode is True


class TestLogDays:
    def test_log_days_valid(self):
        assert parse_args(["--log-days=30"]).log_days == 30

    def test_log_days_default(self):
        assert parse_args([]).log_days == 7

    def test_log_days_one(self):
        assert parse_args(["--log-days=1"]).log_days == 1

    def test_log_days_zero_raises(self):
        with pytest.raises(CLIError, match="positive integer"):
            parse_args(["--log-days=0"])

    def test_log_days_negative_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--log-days=-5"])

    def test_log_days_non_numeric_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--log-days=abc"])

    def test_log_days_large_valid(self):
        """A large but valid number must be accepted."""
        assert parse_args(["--log-days=365"]).log_days == 365

    def test_log_days_float_raises(self):
        """A float string is not a valid integer."""
        with pytest.raises(CLIError):
            parse_args(["--log-days=7.5"])


class TestCombinations:
    def test_multiple_flags(self):
        config = parse_args(["-v", "-d", "--french", "--fix", "--log-days=14"])
        assert config.verbose is True
        assert config.detailed is True
        assert config.lang == "fr"
        assert config.fix is True
        assert config.log_days == 14

    def test_unknown_option_raises(self):
        with pytest.raises(CLIError, match="Unknown option"):
            parse_args(["--unknown-flag"])

    def test_unknown_short_option_raises(self):
        with pytest.raises(CLIError):
            parse_args(["-z"])

    def test_duplicate_flags_idempotent(self):
        """Repeating a boolean flag must not crash or change the result."""
        config = parse_args(["--verbose", "--verbose"])
        assert config.verbose is True

    def test_config_isolation_between_calls(self):
        """Two separate parse_args calls must not share state."""
        c1 = parse_args(["--verbose"])
        c2 = parse_args([])
        assert c2.verbose is False


class TestAuditConfigDirectInstantiation:
    def test_can_instantiate_directly(self):
        """AuditConfig can be built without parse_args — useful in tests."""
        config = AuditConfig(lang="fr", verbose=True, log_days=30)
        assert config.lang == "fr"
        assert config.verbose is True
        assert config.log_days == 30
        assert config.fix is False  # default preserved


class TestMutuallyExclusiveModes:
    def test_manage_logs_and_fix_raises(self):
        """--manage-logs and --fix cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--manage-logs", "--fix"])

    def test_install_cron_and_fix_raises(self):
        """--install-cron and --fix cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--install-cron", "--fix"])

    def test_manage_cron_and_fix_raises(self):
        """--manage-cron and --fix cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--manage-cron", "--fix"])

    def test_manage_logs_and_install_cron_raises(self):
        """--manage-logs and --install-cron cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--manage-logs", "--install-cron"])

    def test_manage_logs_and_manage_cron_raises(self):
        """--manage-logs and --manage-cron cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--manage-logs", "--manage-cron"])

    def test_install_cron_and_manage_cron_raises(self):
        """--install-cron and --manage-cron cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--install-cron", "--manage-cron"])

    def test_fix_alone_ok(self):
        """--fix alone is valid."""
        assert parse_args(["--fix"]).fix is True

    def test_manage_logs_alone_ok(self):
        """--manage-logs alone is valid."""
        assert parse_args(["--manage-logs"]).manage_logs is True

    def test_install_cron_alone_ok(self):
        """--install-cron alone is valid."""
        assert parse_args(["--install-cron"]).install_cron is True

    def test_manage_cron_alone_ok(self):
        """--manage-cron alone is valid."""
        assert parse_args(["--manage-cron"]).manage_cron is True

    def test_yes_without_fix_raises(self):
        """--yes without --fix must raise CLIError."""
        with pytest.raises(CLIError, match="--yes requires --fix"):
            parse_args(["--yes"])

    def test_json_and_fix_raises(self):
        """--json and --fix are incompatible (fix mode is interactive)."""
        with pytest.raises(CLIError):
            parse_args(["--json", "--fix"])

    def test_quiet_and_json_raises(self):
        """--quiet and --json are incompatible (JSON requires stdout)."""
        with pytest.raises(CLIError):
            parse_args(["--quiet", "--json"])

    def test_quiet_and_fix_raises(self):
        """--quiet and --fix are incompatible (fix mode requires prompts)."""
        with pytest.raises(CLIError):
            parse_args(["--quiet", "--fix"])


class TestWebhook:
    def test_webhook_url_with_equals(self):
        config = parse_args(["--webhook=https://hooks.example.com/abc"])
        assert config.webhook_url == "https://hooks.example.com/abc"

    def test_webhook_url_with_space(self):
        config = parse_args(["--webhook", "https://hooks.example.com/abc"])
        assert config.webhook_url == "https://hooks.example.com/abc"

    def test_webhook_format_generic(self):
        assert parse_args(["--webhook-format=generic"]).webhook_format == "generic"

    def test_webhook_format_slack(self):
        assert parse_args(["--webhook-format=slack"]).webhook_format == "slack"

    def test_webhook_format_auto(self):
        assert parse_args(["--webhook-format=auto"]).webhook_format == "auto"

    def test_webhook_format_invalid_raises(self):
        """An unrecognised format value must raise CLIError."""
        with pytest.raises(CLIError, match="webhook-format"):
            parse_args(["--webhook-format=discord"])


class TestExplain:
    def test_explain_key_default_empty(self):
        assert parse_args([]).explain_key == ""

    def test_explain_key_set(self):
        assert parse_args(["--explain=updates.security_pending"]).explain_key == "updates.security_pending"

    def test_explain_key_with_space_arg(self):
        assert parse_args(["--explain", "hardening.rp_filter_disabled"]).explain_key == "hardening.rp_filter_disabled"
