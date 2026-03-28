"""
Command-line interface for ufw-audit.

Parses sys.argv and returns a typed AuditConfig dataclass consumed
by the rest of the application. No business logic lives here.

Usage:
    from ufw_audit.cli import parse_args
    config = parse_args()
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------

@dataclass
class AuditConfig:
    """
    Typed representation of all command-line options.

    Instantiated by parse_args() and passed to the audit orchestrator.
    Can also be constructed directly in tests without touching sys.argv.
    """

    lang: str = "en"
    """Interface language: 'en' or 'fr'."""

    verbose: bool = False
    """-v / --verbose: show detailed port exposure per service."""

    detailed: bool = False
    """-d / --detailed: write full report to a log file."""

    fix: bool = False
    """--fix: offer automatic corrections after the audit."""

    yes: bool = False
    """-y / --yes: auto-confirm all fixes without prompting."""

    reconfigure: bool = False
    """--reconfigure: reset saved port configuration and re-ask."""

    no_color: bool = False

    quiet: bool = False
    """-q / --quiet: suppress all terminal output; use exit code to detect issues."""
    """--no-color: disable ANSI colour output."""

    json_mode: bool = False
    """--json: export audit summary as JSON."""

    json_full: bool = False
    """--json-full: export complete audit details as JSON."""

    log_days: int = 7
    """--log-days=N: number of days of UFW logs to analyse."""

    manage_logs: bool = False
    """--manage-logs: standalone log management UI (list/delete reports)."""

    install_cron: bool = False
    """--install-cron: install a cron job for automated audits (scheduler wizard)."""

    manage_cron: bool = False
    """--manage-cron: manage installed cron jobs (list/edit/delete)."""

    show_version: bool = False
    """--version: print version string and exit."""

    show_help: bool = False
    """-h / --help: print help message and exit."""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class CLIError(ValueError):
    """Raised when an unrecognised or malformed argument is encountered."""


def parse_args(argv: list[str] | None = None) -> AuditConfig:
    """
    Parse command-line arguments and return a populated AuditConfig.

    Args:
        argv: Argument list to parse. Defaults to sys.argv[1:].
              Pass an explicit list in tests to avoid touching sys.argv.

    Returns:
        AuditConfig with all fields populated from argv.

    Raises:
        CLIError: On unknown options or invalid argument values.
    """
    if argv is None:
        argv = sys.argv[1:]

    config = AuditConfig()

    i = 0
    while i < len(argv):
        arg = argv[i]

        if arg in ("-v", "--verbose"):
            config.verbose = True

        elif arg in ("-d", "--detailed"):
            config.detailed = True

        elif arg in ("-f", "--fix"):
            config.fix = True

        elif arg in ("-y", "--yes"):
            config.yes = True

        elif arg in ("-r", "--reconfigure"):
            config.reconfigure = True

        elif arg in ("-n", "--no-color", "--no-colour"):
            config.no_color = True
        elif arg in ("-q", "--quiet"):
            config.quiet = True

        elif arg in ("-j", "--json"):
            config.json_mode = True

        elif arg == "--json-full":
            config.json_mode = True
            config.json_full = True

        elif arg == "--french":
            config.lang = "fr"

        elif arg in ("-l", "--log-days") and i + 1 < len(argv):
            i += 1
            value = argv[i]
            if not value.isdigit() or int(value) < 1:
                raise CLIError(
                    f"--log-days requires a positive integer, got: {value!r}"
                )
            config.log_days = int(value)

        elif arg.startswith("--log-days="):
            value = arg.split("=", 1)[1]
            if not value.isdigit() or int(value) < 1:
                raise CLIError(
                    f"--log-days requires a positive integer, got: {value!r}"
                )
            config.log_days = int(value)

        elif arg in ("-m", "--manage-logs"):
            config.manage_logs = True

        elif arg in ("-c", "--install-cron"):
            config.install_cron = True

        elif arg == "--manage-cron":
            config.manage_cron = True

        elif arg in ("-V", "--version"):
            config.show_version = True

        elif arg in ("-h", "--help"):
            config.show_help = True

        else:
            raise CLIError(f"Unknown option: {arg!r}")

        i += 1

    # Validate
    if config.yes and not config.fix:
        raise CLIError("--yes requires --fix")
    if config.quiet and config.fix:
        raise CLIError("--quiet is incompatible with --fix (fix mode requires interactive prompts)")

    # Mutually exclusive operating modes
    exclusive_modes = [
        (config.manage_logs,  "--manage-logs"),
        (config.install_cron, "--install-cron"),
        (config.manage_cron,  "--manage-cron"),
        (config.fix,          "--fix"),
    ]
    active_modes = [name for flag, name in exclusive_modes if flag]
    if len(active_modes) > 1:
        raise CLIError(
            f"Incompatible options: {' and '.join(active_modes)} cannot be used together"
        )

    return config

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def print_help(t, version: str) -> None:  # noqa: ARG001 — t reserved for future i18n
    """Print the CLI help message."""
    opts = [
        ("-v, --verbose",      "Show detailed port exposure for each service"),
        ("-d, --detailed",     "Save full audit report to a log file"),
        ("-q, --quiet",        "Suppress all output — use exit code to detect issues"),
        ("-f, --fix",          "Offer to apply automatic corrections after the audit"),
        ("-y, --yes",          "Auto-confirm all fixes with audit trail (use with -f)"),
        ("-r, --reconfigure",  "Reset saved port configuration and re-ask"),
        ("-n, --no-color",     "Disable colour output"),
        ("-j, --json",         "Export summary as JSON"),
        ("--json-full",        "Export full audit details as JSON"),
        ("-l N, --log-days=N", "Analyse the last N days of UFW logs (default: 7)"),
        ("-m, --manage-logs",  "List and delete saved audit reports"),
        ("-c, --install-cron", "Install an automated audit cron job (schedule wizard)"),
        ("--manage-cron",      "List, edit or delete installed cron jobs"),
        ("--french",           "Switch interface to French"),
        ("-V, --version",      "Show version and exit (no sudo required)"),
        ("-h, --help",         "Show this help message (no sudo required)"),
    ]
    col = 22
    print(f"ufw-audit v{version} — UFW firewall audit tool")
    print()
    print("Usage: sudo ufw-audit [OPTIONS]")
    print()
    print("Options:")
    for flag, desc in opts:
        print(f"  {flag:<{col}}  {desc}")
    print()
    print("Examples:")
    print("  sudo ufw-audit                  Standard audit")
    print("  sudo ufw-audit -v -d            Verbose + save report")
    print("  sudo ufw-audit --french -d      French + save report")
    print("  sudo ufw-audit -f               Audit + fix mode")
    print("  sudo ufw-audit --log-days=14    Analyse 14 days of logs")
    print()
    print("Exit codes (--quiet mode):")
    print("  0   Clean audit — no alerts, no warnings")
    print("  1   Warnings detected")
    print("  2   Alerts detected (action required)")
    print("  3   Technical error")
    print()
    print("Documentation: https://github.com/Masbateno/ufw-audit")
