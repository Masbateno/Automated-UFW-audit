"""
Terminal output module for ufw-audit.

Handles all ANSI colour formatting and structured display functions.
No translation logic lives here — all strings are pre-translated
by the caller before being passed to print_* functions.

Usage:
    from ufw_audit import output
    output.init(no_color=False)

    from ufw_audit.output import print_ok, print_warn, print_section
    print_ok(t("firewall.active"))
    print_section(t("sections.firewall"))
"""

from __future__ import annotations

import re
import shutil
import sys
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Input sanitization — strip ANSI codes from external data before display
# ---------------------------------------------------------------------------

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[mGKHFABCDJr]")

def sanitize(value: str, max_len: int = 256) -> str:
    """
    Strip ANSI escape sequences and non-printable characters from a string,
    then truncate to max_len. Apply to all data coming from the system
    (container names, hostnames, domains, etc.) before terminal display.
    """
    value = _ANSI_ESCAPE_RE.sub("", value)
    value = "".join(c for c in value if c.isprintable())
    if len(value) > max_len:
        value = value[:max_len] + "…"
    return value


# ---------------------------------------------------------------------------
# ANSI colour codes
# ---------------------------------------------------------------------------

class _Colours(NamedTuple):
    reset:  str
    bold:   str
    dim:    str
    red:    str
    yellow: str
    green:  str
    cyan:   str
    blue:   str
    red_bold:    str
    yellow_bold: str
    green_bold:  str
    cyan_bold:   str
    blue_bold:   str


_COLOURS_ON = _Colours(
    reset        = "\033[0m",
    bold         = "\033[1m",
    dim          = "\033[2m",
    red          = "\033[31m",
    yellow       = "\033[33m",
    green        = "\033[32m",
    cyan         = "\033[36m",
    blue         = "\033[34m",
    red_bold     = "\033[1;31m",
    yellow_bold  = "\033[1;33m",
    green_bold   = "\033[1;32m",
    cyan_bold    = "\033[1;36m",
    blue_bold    = "\033[1;34m",
)

_COLOURS_OFF = _Colours(
    **{field: "" for field in _Colours._fields}
)


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_c: _Colours = _COLOURS_ON
_no_color: bool = False
_quiet:    bool = False

# Terminal width — used for section boxes and banner
_TERM_WIDTH: int = 64


def init(no_color: bool = False, quiet: bool = False) -> None:
    """
    Initialise the output module.

    Must be called once before any print_* function.
    Safe to call multiple times (e.g. in tests).

    Args:
        no_color: If True, all ANSI codes are suppressed.
        quiet:    If True, all print_* functions are silenced.
    """
    global _c, _no_color, _quiet
    _no_color = no_color
    _quiet    = quiet
    _c = _COLOURS_OFF if (no_color or quiet) else _COLOURS_ON


def _p(*args, **kwargs) -> None:
    """Internal print wrapper — respects quiet mode."""
    if not _quiet:
        print(*args, **kwargs)


# ---------------------------------------------------------------------------
# Status line printers
# ---------------------------------------------------------------------------

def print_ok(message: str, detail: str = "") -> None:
    """Print a green OK status line.

    Args:
        message: Main message text.
        detail:  Optional secondary detail printed on the next line.
    """
    _print_status(f"{_c.green_bold}✔{_c.reset}", "OK", _c.green, message, detail)


def print_warn(message: str, detail: str = "") -> None:
    """Print a yellow WARNING status line."""
    _print_status(f"{_c.yellow_bold}⚠{_c.reset}", "ATTENTION", _c.yellow, message, detail)


def print_alert(message: str, detail: str = "") -> None:
    """Print a red ALERT status line."""
    _print_status(f"{_c.red_bold}✖{_c.reset}", "ALERTE", _c.red, message, detail)


def print_info(message: str, detail: str = "") -> None:
    """Print a neutral INFO status line."""
    _print_status(f"{_c.cyan}ℹ{_c.reset}", "INFO", _c.dim, message, detail)


def _print_status(
    icon: str,
    label: str,
    colour: str,
    message: str,
    detail: str,
) -> None:
    print(f"{icon} {colour}[{label}]{_c.reset} {message}")
    if detail:
        print(f"    {_c.dim}{detail}{_c.reset}")


# ---------------------------------------------------------------------------
# Structural display
# ---------------------------------------------------------------------------

def print_section(title: str) -> None:
    """Print a section header box.

    Example:
        ┌─────────────────────────────────────────────────────────────┐
        │  ÉTAT DU PARE-FEU                                           │
        └─────────────────────────────────────────────────────────────┘
    """
    inner = _TERM_WIDTH - 2  # space inside │ borders
    bar = "─" * inner
    padding = inner - 2 - len(_strip_ansi(title))
    padding = max(0, padding)

    _p()  # blank line before each section
    _p(f"{_c.blue}┌{bar}┐{_c.reset}")
    _p(f"{_c.blue}│{_c.reset}  {_c.bold}{title}{_c.reset}{' ' * padding}  {_c.blue}│{_c.reset}")
    _p(f"{_c.blue}└{bar}┘{_c.reset}")
    _p()


def print_service_header(label: str) -> None:
    """Print a service name as a sub-section marker.

    Example:
        ▶ SSH Server
    """
    _p(f"\n  {_c.bold}▶ {label}{_c.reset}")


def print_port_detail(message: str) -> None:
    """Print an indented port detail line (↳ prefix)."""
    _p(f"    {_c.dim}↳ {message}{_c.reset}")


def print_recommendation(lines: str | list[str]) -> None:
    """Print a recommendation block with arrow prefix.

    Args:
        lines: Single string or list of strings. Each line is printed
               with a → prefix on a new indented line.
    """
    if isinstance(lines, str):
        lines = lines.splitlines()
    _p(f"\n    {_c.dim}Que faire ?{_c.reset}")
    for line in lines:
        _p(f"    {_c.cyan}→ {line}{_c.reset}")
    _p()


def print_dim(message: str) -> None:
    """Print a dimmed informational line."""
    _p(f"  {_c.dim}{message}{_c.reset}")


def print_risk_context(
    title: str,
    level: str,
    exposure_label: str,
    exposure: str,
    threat_label: str,
    threat: str,
    is_critical: bool = False,
) -> None:
    """Print the two-axis risk context block for a service.

    Args:
        title:          Label for the context block (e.g. "Contexte de risque").
        level:          Risk level string (e.g. "CRITIQUE", "ÉLEVÉ").
        exposure_label: Translated label for exposure axis.
        exposure:       Exposure description text.
        threat_label:   Translated label for threat axis.
        threat:         Threat description text.
        is_critical:    If True, level is displayed in red; otherwise yellow.
    """
    level_colour = _c.red_bold if is_critical else _c.yellow_bold
    print(f"    {_c.dim}┄ {title} — {level_colour}{level}{_c.reset}")
    print(f"    {_c.dim}{exposure_label} : {_c.reset}{_c.dim}{exposure}{_c.reset}")
    print(f"    {_c.dim}{threat_label}   : {_c.reset}{_c.dim}{threat}{_c.reset}")
    print()


# ---------------------------------------------------------------------------
# Summary box
# ---------------------------------------------------------------------------

def print_summary_box(lines: list[tuple[str, str]]) -> None:
    """Print the audit summary box.

    Args:
        lines: List of (label, value) pairs to display inside the box.
               Pass an empty string as value for section separators.

    Example:
        print_summary_box([
            ("Score de sécurité", "10/10"),
            ("Niveau de risque",  "✔ FAIBLE"),
            ("Contexte réseau",   "🏠 Réseau local uniquement"),
        ])
    """
    inner = _TERM_WIDTH - 2
    bar = "─" * inner

    print(f"{_c.blue_bold}╔{'═' * inner}╗{_c.reset}")
    for label, value in lines:
        if label == "---":
            print(f"{_c.blue_bold}╠{'═' * inner}╣{_c.reset}")
            continue
        content = f"  {label} : {value}" if value else f"  {label}"
        padding = inner - len(_strip_ansi(content))
        padding = max(0, padding)
        print(f"{_c.blue_bold}║{_c.reset}{content}{' ' * padding}{_c.blue_bold}║{_c.reset}")
    print(f"{_c.blue_bold}╚{'═' * inner}╝{_c.reset}")


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def _build_logo(version: str, subtitle: str) -> str:
    """
    Build the ASCII art logo with a dynamically sized badge.

    The badge width adapts to the longest of version and subtitle strings
    so the box always closes properly.
    """
    # Badge inner width = max(len("UFW-AUDIT  " + version), len(subtitle)) + 2 padding
    line1_content = f"UFW-AUDIT  {version}"
    badge_inner = max(len(line1_content), len(subtitle)) + 2
    badge_inner = max(badge_inner, 24)  # minimum width

    bar     = "─" * badge_inner
    line1   = f"│  {line1_content:<{badge_inner - 2}}│"
    line2   = f"│  {subtitle:<{badge_inner - 2}}│"
    corners = f"┌{bar}┐"
    bottom  = f"└{bar}┘"

    # Right-align the badge to sit after the ASCII art (offset = 34 chars)
    offset = "  "
    return (
        f"   ██╗   ██╗███████╗██╗    ██╗  {corners}\n"
        f"   ██║   ██║██╔════╝██║    ██║  {line1}\n"
        f"   ██║   ██║█████╗  ██║ █╗ ██║  {line2}\n"
        f"   ██║   ██║██╔══╝  ██║███╗██║  {bottom}\n"
        f"   ╚██████╔╝██║     ╚███╔███╔╝              _ _\n"
        f"    ╚═════╝ ╚═╝      ╚══╝╚══╝             _(-_-)_\n"
        f"                                            audit"
    )


def print_banner(
    version: str,
    subtitle: str,
    system: str,
    host: str,
    ufw_version: str,
    user: str,
    date: str,
    labels: dict[str, str],
) -> None:
    """Print the ASCII art banner with system information.

    Args:
        version:     Application version string (e.g. "v0.9.0").
        subtitle:    Translated subtitle (e.g. "Audit pare-feu UFW").
        system:      OS/distro string.
        host:        Hostname.
        ufw_version: UFW version string.
        user:        Current user.
        date:        Formatted date string.
        labels:      Dict of translated field labels:
                     {"system", "host", "ufw", "user", "date"}.
    """
    inner = _TERM_WIDTH - 2
    bar_double = "═" * inner

    logo = _build_logo(version, subtitle)

    print(f"{_c.blue_bold}╔{bar_double}╗{_c.reset}")
    for line in logo.splitlines():
        padding = inner - len(_strip_ansi(line))
        padding = max(0, padding)
        print(f"{_c.blue_bold}║{_c.reset}{line}{' ' * padding}{_c.blue_bold}║{_c.reset}")
    print(f"{_c.blue_bold}╠{bar_double}╣{_c.reset}")

    info_rows = [
        (labels.get("system", "System"), system),
        (labels.get("host",   "Host"),   host),
        (labels.get("ufw",    "UFW"),    f"v{ufw_version}"),
        (labels.get("user",   "User"),   user),
        (labels.get("date",   "Date"),   date),
    ]
    for label, value in info_rows:
        content = f"  {label:<14}: {value}"
        padding = inner - len(_strip_ansi(content))
        padding = max(0, padding)
        print(f"{_c.blue_bold}║{_c.reset}{content}{' ' * padding}{_c.blue_bold}║{_c.reset}")

    print(f"{_c.blue_bold}╚{bar_double}╝{_c.reset}")
    print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from a string for length calculation."""
    import re
    return re.sub(r"\033\[[0-9;]*m", "", text)


def supports_color() -> bool:
    """Return True if the current terminal supports ANSI colours."""
    return (
        hasattr(sys.stdout, "isatty")
        and sys.stdout.isatty()
        and sys.platform != "win32"
    )