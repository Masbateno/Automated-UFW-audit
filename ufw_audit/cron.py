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
import shlex
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

    if dom == "*" and month == "*" and dow != "*" and re.fullmatch(r"[\d,]+", dow):
        # Specific days of the week (simple numeric values only — not ranges or expressions)
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


# ---------------------------------------------------------------------------
# Interactive runners (--install-cron, --manage-cron, --remove-cron)
# ---------------------------------------------------------------------------

def prompt_email(t) -> str:
    """
    Interactive email selection prompt.

    Shows saved addresses from EmailStore with numeric shortcuts.
    The user can select a saved address by number, type a new one,
    or press Enter to skip (no email).

    New valid addresses are offered for saving before being returned.

    Returns:
        Selected email string, or "" if user skipped.
    """
    from ufw_audit.config import EmailStore

    store = EmailStore.load()
    saved = store.all()

    print()
    print(f"  {t('email_prompt.title')}")
    print(f"    0. {t('email_prompt.none')}")
    for i, addr in enumerate(saved, 1):
        print(f"    {i}. {addr}")
    print(f"    {len(saved) + 1}. {t('email_prompt.new')}")
    print()

    answer = input("  > ").strip()

    if not answer or answer == "0":
        return ""

    if answer.isdigit():
        idx = int(answer)
        if 1 <= idx <= len(saved):
            return saved[idx - 1]

    if answer.isdigit() and int(answer) == len(saved) + 1:
        answer = input(f"  {t('email_prompt.enter_new')} : ").strip()

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", answer):
        print(f"  ⚠ {t('email_prompt.invalid')}")
        return ""

    if answer not in saved:
        save_ans = input(f"  {t('email_prompt.save', email=answer)} ").strip().lower()
        if save_ans == "y":
            store.add(answer)

    return answer


def run_install_cron(user_config, config, t) -> int:
    """Install a cron job for automated audits using the schedule wizard."""
    import os
    import shutil
    from datetime import datetime
    from pathlib import Path
    from ufw_audit import output
    output.init(no_color=config.no_color)

    W = 62
    title = t("install_cron.title")
    pad = W - 4 - len(title)
    print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
    print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
    print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
    print()

    log_dir_str = user_config.get("log_dir")
    if not log_dir_str:
        print(f"  ✖ {t('install_cron.no_log_dir')}")
        return 1
    log_dir = Path(log_dir_str)

    # --- Step 1: Name ---
    existing_names = [e.name for e in list_installed_crons()]
    suggestion = suggest_name(existing_names)
    raw_name = input(f"  {t('install_cron.prompt_name', suggestion=suggestion)} : ").strip()
    if not raw_name:
        raw_name = suggestion
    slug = make_slug(raw_name)
    if not slug:
        print(f"  ✖ {t('install_cron.invalid_name')}")
        return 1

    # --- Step 2: Schedule type ---
    print()
    print(f"  {t('install_cron.prompt_schedule')}")
    print(f"    1. {t('install_cron.schedule_daily')}")
    print(f"    2. {t('install_cron.schedule_weekdays')}")
    print(f"    3. {t('install_cron.schedule_monthdays')}")
    print(f"    4. {t('install_cron.schedule_custom')}")
    print()
    raw_choice = input("  > ").strip()
    if not raw_choice:
        raw_choice = "1"
    if raw_choice not in ("1", "2", "3", "4"):
        print(f"  ✖ {t('install_cron.invalid_schedule')}")
        return 1
    choice = int(raw_choice)

    week_days = None
    month_days = None
    custom_expr = None
    hour = 3
    minute = 0

    if choice == 2:
        print()
        print(f"  {t('install_cron.prompt_weekdays')}")
        raw_days = input("  > ").strip()
        parts = re.split(r"[\s,]+", raw_days)
        week_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 7]
        if not week_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return 1

    elif choice == 3:
        print()
        print(f"  {t('install_cron.prompt_monthdays')}")
        raw_days = input("  > ").strip()
        parts = re.split(r"[\s,]+", raw_days)
        month_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 31]
        if not month_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return 1

    elif choice == 4:
        print()
        print(f"  {t('install_cron.prompt_custom')}")
        custom_expr = input("  > ").strip()
        if not re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+$", custom_expr):
            print(f"  ✖ {t('install_cron.invalid_schedule')}")
            return 1

    # --- Step 3: Time ---
    if choice != 4:
        print()
        raw_time = input(f"  {t('install_cron.prompt_time')} : ").strip()
        if not raw_time:
            raw_time = "03:00"
        if not re.match(r"^\d{1,2}:\d{2}$", raw_time):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return 1
        h, m = raw_time.split(":")
        hour, minute = int(h), int(m)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return 1

    schedule_expr = build_schedule_expr(
        choice, hour, minute,
        week_days=week_days, month_days=month_days, custom_expr=custom_expr,
    )
    human = cron_to_human(schedule_expr, lang=config.lang)
    print()
    print(f"  {t('install_cron.preview', schedule=human)}")
    print()

    # --- Step 4: Notification email ---
    notify_email = prompt_email(t)
    if notify_email and not shutil.which("mail"):
        print(f"  ⚠ {t('install_cron.mail_missing')}")

    cron_path   = CRON_DIR / f"ufw-audit-{slug}"
    script_path = SCRIPT_DIR / f"ufw-audit-{slug}"

    if cron_path.exists():
        ans = input(f"\n  {t('install_cron.overwrite', path=str(cron_path))} ").strip().lower()
        if ans != "y":
            return 0

    audit_bin = shutil.which("ufw-audit") or "/usr/local/bin/ufw-audit"
    now_str   = datetime.now().strftime("%Y-%m-%d")
    try:
        ufw_audit_path = str(Path(__file__).parent.parent)
    except (TypeError, AttributeError):
        ufw_audit_path = "/usr/local/lib"

    script_content = (
        "#!/bin/bash\n"
        f"# UFW-AUDIT script — generated {now_str} by ufw-audit --install-cron\n"
        "# Re-generate: sudo ufw-audit --install-cron\n\n"
        f'NOTIFY_EMAIL={shlex.quote(notify_email)}\n'
        f'LOG_DIR={shlex.quote(str(log_dir))}\n'
        f'export PYTHONPATH={shlex.quote(ufw_audit_path)}:"$PYTHONPATH"\n\n'
        f'{shlex.quote(str(audit_bin))} --quiet --detailed\n'
        "RC=$?\n\n"
        'if [ "$RC" -gt 0 ] && [ -n "$NOTIFY_EMAIL" ]; then\n'
        '    LOG=$(ls -t "$LOG_DIR"/ufw_audit_*.log 2>/dev/null | head -1)\n'
        '    if [ -n "$LOG" ]; then\n'
        "        export AUDIT_LOG=\"$LOG\"\n"
        "        export AUDIT_EMAIL=\"$NOTIFY_EMAIL\"\n"
        "        export AUDIT_RC=\"$RC\"\n"
        "        python3 << 'PYTHON_EOF'\n"
        "import os\n"
        "from ufw_audit.report_markdown import send_audit_log_as_html_email\n\n"
        "hostname = os.uname().nodename\n"
        "log_file = os.environ.get('AUDIT_LOG')\n"
        "email = os.environ.get('AUDIT_EMAIL')\n"
        "rc = os.environ.get('AUDIT_RC')\n"
        "subject = f'UFW-AUDIT [{rc}] {hostname}'\n"
        "if log_file and email:\n"
        "    send_audit_log_as_html_email(log_file, email, subject)\n"
        "PYTHON_EOF\n"
        "    fi\n"
        "fi\n"
    )

    try:
        fd = os.open(str(script_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o755)
        with os.fdopen(fd, "w") as fh:
            fh.write(script_content)
    except OSError as exc:
        print(f"  ✖ Cannot write {script_path}: {exc}")
        return 1

    print(f"  ✔ {t('install_cron.script_written', path=str(script_path))}")

    cron_content = (
        f"# UFW-AUDIT cron — generated {now_str} by ufw-audit --install-cron\n"
        f"# name: {raw_name}\n"
        f"# email: {notify_email}\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
        f"{schedule_expr}  root  {script_path}\n"
    )

    try:
        fd = os.open(str(cron_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w") as fh:
            fh.write(cron_content)
    except OSError as exc:
        print(f"  ✖ Cannot write {cron_path}: {exc}")
        return 1

    print(f"  ✔ {t('install_cron.cron_written', path=str(cron_path))}")

    root_config_path = Path("/root/.config/ufw-audit/config.conf")
    try:
        from ufw_audit.config import UserConfig as _UC
        root_cfg = _UC.load(path=root_config_path)
        if not root_cfg.get("log_dir"):
            root_cfg.set("log_dir", str(log_dir))
    except OSError:
        pass

    print()
    print(f"  ✔ {t('install_cron.done_schedule', name=raw_name, schedule=human)}")
    return 0


def _manage_email_store(t) -> None:
    """Interactive sub-menu to manage the EmailStore (add / delete emails).

    Loops until the user explicitly quits with Enter or 'q'.
    The list is refreshed from disk before each iteration.
    """
    from ufw_audit.config import EmailStore

    W = 62
    title = t("manage_cron.email_store_title")
    pad = W - 4 - len(title)

    while True:
        store = EmailStore.load()
        emails = store.all()

        print()
        print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
        print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
        print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
        print()

        if not emails:
            print(f"  ℹ {t('manage_cron.email_store_empty')}")
        else:
            for i, addr in enumerate(emails, 1):
                print(f"  {i}. {addr}")

        print()
        print(f"  {t('manage_cron.email_store_prompt')}")
        answer = input("  > ").strip().lower()

        if not answer or answer in ("q", "quit"):
            return

        if answer == "a":
            raw = input(f"  {t('manage_cron.email_store_enter')} : ").strip()
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", raw):
                print(f"  ✖ {t('manage_cron.email_store_invalid_email')}")
            else:
                store.add(raw)
                print(f"  ✔ {t('manage_cron.email_store_added', email=raw)}")
            continue

        if answer == "all":
            if not emails:
                print(f"  ℹ {t('manage_cron.email_store_empty')}")
            else:
                count = len(emails)
                for addr in emails:
                    store.remove(addr)
                print(f"  ✔ {t('manage_cron.email_store_cleared', count=count)}")
            continue

        # Parse individual number, comma list, or range
        indices = set()  # type: set[int]
        valid = True
        try:
            if re.match(r"^\d+$", answer):
                indices.add(int(answer))
            elif re.match(r"^\d+(?:,\d+)+$", answer):
                for part in answer.split(","):
                    indices.add(int(part))
            elif re.match(r"^\d+-\d+$", answer):
                start_s, end_s = answer.split("-")
                for n in range(int(start_s), int(end_s) + 1):
                    indices.add(n)
            else:
                print(f"  ✖ {t('manage_cron.invalid')}")
                valid = False
        except ValueError:
            print(f"  ✖ {t('manage_cron.invalid')}")
            valid = False

        if not valid:
            continue

        if not indices:
            print(f"  ✖ {t('manage_cron.email_store_invalid_sel')}")
            continue

        to_delete = []
        for idx in sorted(indices):
            if not (1 <= idx <= len(emails)):
                print(f"  ✖ {t('manage_cron.email_store_invalid_sel')}")
                to_delete = []
                break
            to_delete.append(emails[idx - 1])

        for addr in to_delete:
            store.remove(addr)
            print(f"  ✔ {t('manage_cron.email_store_removed', email=addr)}")


def run_manage_cron(config, t) -> int:
    """Manage installed cron jobs — list, edit schedule/email, delete."""
    from ufw_audit import output
    output.init(no_color=config.no_color)

    W = 62
    title = t("manage_cron.title")
    pad = W - 4 - len(title)
    print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
    print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
    print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
    print()

    crons = list_installed_crons()

    if not crons:
        print(f"  ℹ {t('manage_cron.no_crons')}")
        print()
        print(f"  {t('manage_cron.prompt_email_only')}")
        answer = input("  > ").strip().lower()
        if answer == "m":
            _manage_email_store(t)
        return 0

    lang = config.lang
    for i, entry in enumerate(crons, 1):
        human = cron_to_human(entry.schedule_expr, lang)
        legacy_tag = f"  [{t('manage_cron.legacy_tag')}]" if entry.legacy else ""
        print(f"  {i}. {entry.name:<20} {human}{legacy_tag}")
        if entry.email:
            print(f"     → {t('manage_cron.email_label')}: {entry.email}")

    print()
    print(f"  {t('manage_cron.prompt')}")
    answer = input("  > ").strip().lower()

    if not answer or answer in ("q", "quit"):
        return 0

    if answer == "m":
        _manage_email_store(t)
        return 0

    delete_match = re.match(r"^d:?(\d+)$", answer)
    email_match  = re.match(r"^e:(\d+)$", answer)
    edit_match   = re.match(r"^(\d+)$", answer)

    if delete_match:
        idx = int(delete_match.group(1)) - 1
        if not (0 <= idx < len(crons)):
            print(f"  ✖ {t('manage_cron.invalid')}")
            return 0
        entry = crons[idx]
        ans = input(f"  {t('manage_cron.confirm_delete', name=entry.name)} ").strip().lower()
        if ans == "y":
            try:
                entry.cron_path.unlink()
            except OSError:
                pass
            if entry.script_path.exists():
                try:
                    entry.script_path.unlink()
                except OSError:
                    pass
            print(f"  ✔ {t('manage_cron.deleted', name=entry.name)}")

    elif email_match:
        idx = int(email_match.group(1)) - 1
        if not (0 <= idx < len(crons)):
            print(f"  ✖ {t('manage_cron.invalid')}")
            return 0
        entry = crons[idx]
        print()
        print(f"  {t('manage_cron.edit_email', name=entry.name)}")
        edit_cron_email(entry, t)

    elif edit_match:
        idx = int(edit_match.group(1)) - 1
        if not (0 <= idx < len(crons)):
            print(f"  ✖ {t('manage_cron.invalid')}")
            return 0
        entry = crons[idx]
        print()
        print(f"  {t('manage_cron.edit_what', name=entry.name)}")
        print(f"    1. {t('manage_cron.edit_schedule_option')}")
        print(f"    2. {t('manage_cron.edit_email_option')}")
        sub = input("  > ").strip()
        if sub == "1":
            edit_cron_schedule(entry, config, t)
        elif sub == "2":
            edit_cron_email(entry, t)
        else:
            print(f"  ✖ {t('manage_cron.invalid')}")

    else:
        print(f"  ✖ {t('manage_cron.invalid')}")

    return 0


def edit_cron_email(entry, t) -> None:
    """Change the notification email of an existing cron entry."""
    new_email = prompt_email(t)

    try:
        lines = entry.cron_path.read_text(encoding="utf-8").splitlines()
        updated = []
        for line in lines:
            if line.startswith("# email:"):
                updated.append(f"# email: {new_email}")
            else:
                updated.append(line)
        entry.cron_path.write_text("\n".join(updated) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"  ✖ Cannot update cron file: {exc}")
        return

    if entry.script_path.exists():
        try:
            text = entry.script_path.read_text(encoding="utf-8")
            text = re.sub(r'^NOTIFY_EMAIL=".*"', lambda _: f'NOTIFY_EMAIL="{new_email}"', text, flags=re.MULTILINE)
            entry.script_path.write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"  ✖ Cannot update script: {exc}")
            return

    label = new_email if new_email else t("manage_cron.no_email")
    print(f"  ✔ {t('manage_cron.email_updated', name=entry.name, email=label)}")


def edit_cron_schedule(entry, config, t) -> None:
    """Re-run the schedule wizard for an existing cron entry and patch its cron file."""
    import os as _os

    print()
    print(f"  {t('install_cron.prompt_schedule')}")
    print(f"    1. {t('install_cron.schedule_daily')}")
    print(f"    2. {t('install_cron.schedule_weekdays')}")
    print(f"    3. {t('install_cron.schedule_monthdays')}")
    print(f"    4. {t('install_cron.schedule_custom')}")
    print()
    raw_choice = input("  > ").strip()
    if not raw_choice:
        raw_choice = "1"
    if raw_choice not in ("1", "2", "3", "4"):
        print(f"  ✖ {t('install_cron.invalid_schedule')}")
        return
    choice = int(raw_choice)

    week_days   = None
    month_days  = None
    custom_expr = None
    hour   = entry.hour
    minute = entry.minute

    if choice == 2:
        print()
        print(f"  {t('install_cron.prompt_weekdays')}")
        raw_days = input("  > ").strip()
        parts = re.split(r"[\s,]+", raw_days)
        week_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 7]
        if not week_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return

    elif choice == 3:
        print()
        print(f"  {t('install_cron.prompt_monthdays')}")
        raw_days = input("  > ").strip()
        parts = re.split(r"[\s,]+", raw_days)
        month_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 31]
        if not month_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return

    elif choice == 4:
        print()
        print(f"  {t('install_cron.prompt_custom')}")
        custom_expr = input("  > ").strip()
        if not re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+$", custom_expr):
            print(f"  ✖ {t('install_cron.invalid_schedule')}")
            return

    if choice != 4:
        print()
        raw_time = input(f"  {t('install_cron.prompt_time')} : ").strip()
        if not raw_time:
            raw_time = f"{entry.hour:02d}:{entry.minute:02d}"
        if not re.match(r"^\d{1,2}:\d{2}$", raw_time):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return
        h, m = raw_time.split(":")
        hour, minute = int(h), int(m)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return

    schedule_expr = build_schedule_expr(
        choice, hour, minute,
        week_days=week_days, month_days=month_days, custom_expr=custom_expr,
    )
    human = cron_to_human(schedule_expr, lang=config.lang)
    print()
    print(f"  {t('install_cron.preview', schedule=human)}")
    print()

    ans = input(f"  {t('manage_cron.confirm_update')} ").strip().lower()
    if ans != "y":
        return

    try:
        text = entry.cron_path.read_text()
    except OSError as exc:
        print(f"  ✖ Cannot read {entry.cron_path}: {exc}")
        return

    new_line = f"{schedule_expr}  root  {entry.script_path}"
    new_text = re.sub(
        r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+root\s+\S+.*$",
        lambda _: new_line,
        text,
        flags=re.MULTILINE,
    )

    try:
        fd = _os.open(str(entry.cron_path), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o640)
        with _os.fdopen(fd, "w") as fh:
            fh.write(new_text)
    except OSError as exc:
        print(f"  ✖ Cannot write {entry.cron_path}: {exc}")
        return

    print(f"  ✔ {t('manage_cron.updated', name=entry.name, schedule=human)}")
