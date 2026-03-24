"""
Cron management utilities for ufw-audit.

Handles:
- CronEntry dataclass representing an installed cron job
- Listing installed cron jobs (/etc/cron.d/ufw-audit-*)
- Parsing generated cron files to extract metadata
- Converting cron expressions to human-readable descriptions (EN/FR)
- Building cron expressions from wizard answers
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

CRON_DIR = Path("/etc/cron.d")
SCRIPT_DIR = Path("/usr/local/bin")

# Legacy paths created by v0.12 --install-cron
LEGACY_CRON_PATH = CRON_DIR / "ufw-audit"
LEGACY_SCRIPT_PATH = SCRIPT_DIR / "ufw-audit-nightly"

_DAYS_EN = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
_DAYS_FR = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]


@dataclass
class CronEntry:
    """Represents an installed ufw-audit cron job."""

    name: str
    schedule_expr: str  # e.g. "0 3 * * *"
    hour: int
    minute: int
    script_path: Path
    cron_path: Path
    email: str = ""
    legacy: bool = False  # True if this is a pre-v0.13 cron


def list_installed_crons() -> list[CronEntry]:
    """Return all installed ufw-audit cron entries."""
    entries: list[CronEntry] = []
    seen: set[Path] = set()

    # v0.13+ named crons: /etc/cron.d/ufw-audit-*
    for cron_path in sorted(CRON_DIR.glob("ufw-audit-*")):
        entry = parse_cron_file(cron_path)
        if entry:
            entries.append(entry)
            seen.add(cron_path)

    # Legacy v0.12 cron: /etc/cron.d/ufw-audit (no suffix)
    if LEGACY_CRON_PATH.exists() and LEGACY_CRON_PATH not in seen:
        entry = parse_cron_file(LEGACY_CRON_PATH, legacy=True)
        if entry:
            entries.append(entry)

    return entries


def parse_cron_file(path: Path, legacy: bool = False) -> Optional[CronEntry]:
    """Parse a ufw-audit cron file and return a CronEntry, or None if unrecognised."""
    try:
        text = path.read_text()
    except OSError:
        return None

    # Extract name from metadata comment (v0.13+) or derive from filename
    name_match = re.search(r"^# name: (.+)$", text, re.MULTILINE)
    if name_match:
        name = name_match.group(1).strip()
    elif legacy:
        name = "nightly"
    else:
        stem = path.name
        if stem.startswith("ufw-audit-"):
            stem = stem[len("ufw-audit-"):]
        name = stem or path.name

    # Extract email from metadata comment
    email_match = re.search(r"^# email: (.*)$", text, re.MULTILINE)
    email = email_match.group(1).strip() if email_match else ""

    # Extract cron expression line (format: "M H DOM MON DOW  root  /path/script")
    cron_match = re.search(
        r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+root\s+(\S+)",
        text,
        re.MULTILINE,
    )
    if not cron_match:
        return None

    minute_s, hour_s, dom, month, dow, script = cron_match.groups()
    schedule_expr = f"{minute_s} {hour_s} {dom} {month} {dow}"

    try:
        hour = int(hour_s)
        minute = int(minute_s)
    except ValueError:
        hour, minute = 0, 0

    return CronEntry(
        name=name,
        schedule_expr=schedule_expr,
        hour=hour,
        minute=minute,
        script_path=Path(script),
        cron_path=path,
        email=email,
        legacy=legacy,
    )


def cron_to_human(expr: str, lang: str = "en") -> str:
    """Convert a 5-field cron expression to a human-readable description."""
    parts = expr.strip().split()
    if len(parts) != 5:
        return expr

    minute, hour, dom, month, dow = parts
    days_list = _DAYS_EN if lang == "en" else _DAYS_FR

    try:
        time_str = f"{int(hour):02d}:{int(minute):02d}"
    except ValueError:
        time_str = f"{hour}:{minute}"

    if dom == "*" and month == "*" and dow == "*":
        # Every day
        if lang == "fr":
            return f"tous les jours à {time_str}"
        return f"every day at {time_str}"

    if dom == "*" and month == "*" and dow != "*":
        # Specific days of the week
        day_names = _parse_day_names(dow, days_list)
        if lang == "fr":
            return f"tous les {', '.join(day_names)} à {time_str}"
        return f"every {', '.join(day_names)} at {time_str}"

    if dom != "*" and month == "*" and dow == "*":
        # Specific days of the month
        day_nums = _parse_dom(dom)
        if lang == "fr":
            days_fmt = ", ".join(str(d) for d in day_nums)
            return f"le {days_fmt} de chaque mois à {time_str}"
        days_fmt = ", ".join(_ordinal(d) for d in day_nums)
        return f"the {days_fmt} of every month at {time_str}"

    # Fallback: raw expression
    if lang == "fr":
        return f"expression personnalisée : {expr}"
    return f"custom expression: {expr}"


def build_schedule_expr(
    choice: int,
    hour: int,
    minute: int,
    week_days: Optional[list[int]] = None,
    month_days: Optional[list[int]] = None,
    custom_expr: Optional[str] = None,
) -> str:
    """
    Build a cron schedule expression from wizard answers.

    Args:
        choice:      1=daily, 2=week days, 3=month days, 4=custom expression
        hour:        0-23
        minute:      0-59
        week_days:   list of 1-7 (1=Mon, 7=Sun) for choice 2
        month_days:  list of 1-31 for choice 3
        custom_expr: full 5-field expression for choice 4

    Returns:
        5-field cron expression string
    """
    if choice == 1:
        return f"{minute} {hour} * * *"
    if choice == 2:
        dow = ",".join(str(d) for d in sorted(week_days or []))
        return f"{minute} {hour} * * {dow}"
    if choice == 3:
        dom = ",".join(str(d) for d in sorted(month_days or []))
        return f"{minute} {hour} {dom} * *"
    if choice == 4:
        return (custom_expr or "").strip()
    raise ValueError(f"Invalid choice: {choice}")


def make_slug(name: str) -> str:
    """Convert a free-form name to a filesystem-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "custom"


def suggest_name(existing_names: list[str]) -> str:
    """Suggest a cron name that does not conflict with existing ones."""
    for candidate in ("nightly", "daily", "weekly", "monthly"):
        if candidate not in existing_names:
            return candidate
    i = 2
    while f"audit-{i}" in existing_names:
        i += 1
    return f"audit-{i}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_day_names(dow: str, days_list: list[str]) -> list[str]:
    """Parse a DOW field (1-7, Mon=1) into a list of day names."""
    result = []
    for part in dow.split(","):
        part = part.strip()
        if part.isdigit():
            idx = (int(part) - 1) % 7
            result.append(days_list[idx])
        else:
            result.append(part)
    return result


def _parse_dom(dom: str) -> list[int]:
    """Parse a DOM field into a sorted list of day-of-month integers."""
    result = []
    for part in re.split(r"[,\s]+", dom.strip()):
        if part.isdigit():
            result.append(int(part))
    return sorted(result)


def _ordinal(n: int) -> str:
    """Return the English ordinal string for an integer (1st, 2nd, 3rd, …)."""
    suffix = (
        "th"
        if 11 <= (n % 100) <= 13
        else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    )
    return f"{n}{suffix}"
