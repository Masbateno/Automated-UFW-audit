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
    """--no-color: disable ANSI colour output."""

    json_mode: bool = False
    """--json: export audit summary as JSON."""

    json_full: bool = False
    """--json-full: export complete audit details as JSON."""

    log_days: int = 7
    """--log-days=N: number of days of UFW logs to analyse."""

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

        elif arg == "--fix":
            config.fix = True

        elif arg in ("-y", "--yes"):
            config.yes = True

        elif arg == "--reconfigure":
            config.reconfigure = True

        elif arg == "--no-color":
            config.no_color = True

        elif arg == "--json":
            config.json_mode = True

        elif arg == "--json-full":
            config.json_mode = True
            config.json_full = True

        elif arg == "--french":
            config.lang = "fr"

        elif arg.startswith("--log-days="):
            value = arg.split("=", 1)[1]
            if not value.isdigit() or int(value) < 1:
                raise CLIError(
                    f"--log-days requires a positive integer, got: {value!r}"
                )
            config.log_days = int(value)

        elif arg == "--version":
            config.show_version = True

        elif arg in ("-h", "--help"):
            config.show_help = True

        else:
            raise CLIError(f"Unknown option: {arg!r}")

        i += 1

    return config
