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
from dataclasses import dataclass


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
    """--no-color: disable ANSI colour output."""

    quiet: bool = False
    """-q / --quiet: suppress all terminal output; use exit code to detect issues."""

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

    install_completion: bool = False
    """--install-completion: install bash completion script to /etc/bash_completion.d/."""

    offline: bool = False
    """--offline: skip all external HTTP calls (no public IP lookup)."""

    profile: str = ""
    """--profile=NAME: audit profile to apply (server|workstation|container or custom)."""

    reset_baseline: bool = False
    """--reset-baseline: delete the stored audit baseline and exit."""

    explain_key: str = ""
    """--explain=KEY: print a detailed explanation for a finding key and exit."""

    diff_mode: bool = False
    """--diff: run audit silently and show only changes since the last baseline."""

    webhook_url: str = ""
    """--webhook=URL: POST audit result as JSON to this URL after the audit."""

    webhook_format: str = "auto"
    """--webhook-format=FMT: payload format — 'auto' (default), 'generic', or 'slack'."""


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

        elif arg.startswith("--lang="):
            config.lang = arg.split("=", 1)[1]

        elif arg in ("-l", "--log-days") and i + 1 < len(argv):
            i += 1
            value = argv[i]
            if not value.isdigit() or not (1 <= int(value) <= 3650):
                raise CLIError(
                    f"--log-days requires a positive integer (1–3650), got: {value!r}"
                )
            config.log_days = int(value)

        elif arg.startswith("--log-days="):
            value = arg.split("=", 1)[1]
            if not value.isdigit() or not (1 <= int(value) <= 3650):
                raise CLIError(
                    f"--log-days requires a positive integer (1–3650), got: {value!r}"
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

        elif arg == "--install-completion":
            config.install_completion = True

        elif arg in ("-o", "--offline"):
            config.offline = True

        elif arg.startswith("--profile="):
            config.profile = arg.split("=", 1)[1].strip()

        elif arg == "--reset-baseline":
            config.reset_baseline = True

        elif arg.startswith("--explain="):
            config.explain_key = arg.split("=", 1)[1].strip()

        elif arg == "--explain" and i + 1 < len(argv):
            i += 1
            config.explain_key = argv[i].strip()

        elif arg == "--diff":
            config.diff_mode = True

        elif arg.startswith("--webhook="):
            config.webhook_url = arg.split("=", 1)[1].strip()

        elif arg == "--webhook" and i + 1 < len(argv):
            i += 1
            config.webhook_url = argv[i].strip()

        elif arg.startswith("--webhook-format="):
            config.webhook_format = arg.split("=", 1)[1].strip()

        else:
            raise CLIError(f"Unknown option: {arg!r}")

        i += 1

    # Validate
    if config.webhook_format not in ("auto", "generic", "slack"):
        raise CLIError(
            f"--webhook-format must be 'auto', 'generic', or 'slack', got: {config.webhook_format!r}"
        )

    if config.yes and not config.fix:
        raise CLIError("--yes requires --fix")
    if config.quiet and config.json_mode:
        raise CLIError("--quiet is incompatible with --json (JSON output requires stdout)")
    if config.quiet and config.fix:
        raise CLIError("--quiet is incompatible with --fix (fix mode requires interactive prompts)")
    if config.json_mode and config.fix:
        raise CLIError("--json is incompatible with --fix (fix mode is interactive)")

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
        ("--french",           "Switch interface to French (alias for --lang=fr)"),
        ("--lang=CODE",        "Set interface language (e.g. --lang=fr, --lang=en)"),
        ("--install-completion", "Install bash completion to /etc/bash_completion.d/"),
        ("-o, --offline",      "Skip external IP lookup (no HTTP calls)"),
        ("--profile=NAME",     "Audit profile: server (default), workstation, container, or custom"),
        ("--reset-baseline",   "Delete the stored audit baseline and exit"),
        ("--explain=KEY",      "Print explanation for a finding key and exit (no sudo required)"),
        ("--diff",             "Show only changes since last baseline (silent audit)"),
        ("--webhook=URL",      "POST audit result as JSON to URL after audit"),
        ("--webhook-format=F", "Webhook format: auto (default), generic, or slack"),
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
    print("  ufw-audit --explain list        List all explainable keys")
    print("  ufw-audit --explain ssh.password_auth  Explain a specific finding")
    print("  sudo ufw-audit --webhook=https://hooks.slack.com/...  Send to Slack")
    print()
    print("Exit codes (--quiet mode):")
    print("  0   Clean audit — no alerts, no warnings")
    print("  1   Warnings detected")
    print("  2   Alerts detected (action required)")
    print("  3   Technical error")
    print()
    print("Documentation: https://github.com/Masbateno/ufw-audit")
