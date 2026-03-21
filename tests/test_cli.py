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
        assert config.json_mode is False
        assert config.json_full is False
        assert config.log_days == 7
        assert config.show_version is False
        assert config.show_help is False


class TestFlags:
    def test_verbose_short(self):
        assert parse_args(["-v"]).verbose is True

    def test_verbose_long(self):
        assert parse_args(["--verbose"]).verbose is True

    def test_detailed_short(self):
        assert parse_args(["-d"]).detailed is True

    def test_detailed_long(self):
        assert parse_args(["--detailed"]).detailed is True

    def test_fix(self):
        assert parse_args(["--fix"]).fix is True

    def test_yes_short(self):
        assert parse_args(["-y"]).yes is True

    def test_yes_long(self):
        assert parse_args(["--yes"]).yes is True

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

    def test_help_short(self):
        assert parse_args(["-h"]).show_help is True

    def test_help_long(self):
        assert parse_args(["--help"]).show_help is True


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


class TestAuditConfigDirectInstantiation:
    def test_can_instantiate_directly(self):
        """AuditConfig can be built without parse_args — useful in tests."""
        config = AuditConfig(lang="fr", verbose=True, log_days=30)
        assert config.lang == "fr"
        assert config.verbose is True
        assert config.log_days == 30
        assert config.fix is False  # default preserved
