"""
Log management UI for ufw-audit.

Handles the --manage-logs command: listing, deleting and relocating
saved audit report files, plus log directory configuration helpers.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Path prompt helper
# ---------------------------------------------------------------------------

def prompt_path(prompt_label: str, default: Path) -> Path:
    """Prompt for a filesystem path with TAB autocompletion via readline."""
    import glob as _glob

    def _path_completer(text, state):
        options = _glob.glob(text + "*")
        options = [o + "/" if os.path.isdir(o) else o for o in options]
        try:
            return options[state]
        except IndexError:
            return None

    try:
        import readline
        readline.set_completer_delims(" \t\n;")
        readline.set_completer(_path_completer)
        readline.parse_and_bind("tab: complete")
    except ImportError:
        pass

    try:
        raw = input(f"  {prompt_label} [{default}] : ").strip()
    finally:
        try:
            import readline
            readline.set_completer(None)
        except ImportError:
            pass

    # resolve() normalises ".." components and follows symlinks,
    # preventing path traversal sequences in user-supplied paths.
    return Path(raw).expanduser().resolve() if raw else default


# ---------------------------------------------------------------------------
# Log directory resolution
# ---------------------------------------------------------------------------

def get_or_prompt_log_dir(user_config, config, t) -> Path:
    """Return the configured log directory, prompting at first use.

    In non-interactive contexts (cron, pipes) the default path is used
    silently so that the process never hangs waiting for input.
    """
    saved = user_config.get("log_dir")
    if saved:
        d = Path(saved)
        d.mkdir(parents=True, exist_ok=True)
        return d

    from ufw_audit.sysinfo import get_user_home
    home = get_user_home()
    default_dir = home / ".local" / "share" / "ufw-audit" / "logs"

    # Non-interactive context (cron, piped stdin) — skip the prompt
    if not sys.stdin.isatty():
        default_dir.mkdir(parents=True, exist_ok=True)
        user_config.set("log_dir", str(default_dir))
        return default_dir

    chosen = prompt_path(t("log_dir.prompt"), default_dir)

    try:
        chosen.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"  ✖ Cannot create directory {chosen}: {exc} — falling back to cwd")
        chosen = Path.cwd()

    user_config.set("log_dir", str(chosen))
    print(f"  ✔ {t('log_dir.saved', path=str(chosen))}")
    print()
    return chosen


# ---------------------------------------------------------------------------
# Selection parser
# ---------------------------------------------------------------------------

def parse_log_selection(answer: str, max_idx: int) -> list[int]:
    """Parse user input into a sorted list of 1-based indices.

    Accepted formats:
        1          → [1]
        1,3,5      → [1, 3, 5]
        2-4        → [2, 3, 4]
        1,3-5      → [1, 3, 4, 5]
    """
    indices: set[int] = set()
    for part in answer.split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit():
                lo_i, hi_i = int(lo), int(hi)
                if 1 <= lo_i <= max_idx and 1 <= hi_i <= max_idx:
                    indices.update(range(lo_i, hi_i + 1))
        elif part.isdigit():
            n = int(part)
            if 1 <= n <= max_idx:
                indices.add(n)
    return sorted(indices)


# ---------------------------------------------------------------------------
# --manage-logs
# ---------------------------------------------------------------------------

def run_manage_logs(user_config, config, t) -> int:
    """Standalone log management UI — list, multi-delete, and change storage location."""
    from ufw_audit import output
    output.init(no_color=config.no_color)

    W = 62
    title = t("manage_logs.title")
    pad = W - 6 - len(title)
    print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
    print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
    print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
    print()

    log_dir_str = user_config.get("log_dir")
    if not log_dir_str:
        print(f"  ℹ {t('manage_logs.no_dir')}")
        return 0

    log_dir = Path(log_dir_str)

    if not log_dir.exists():
        log_dir.mkdir(parents=True, exist_ok=True)

    logs = sorted(log_dir.glob("ufw_audit_*.log"), reverse=True)

    print(f"  {t('manage_logs.stored_in', path=str(log_dir))}")
    print()

    if not logs:
        print(f"  ℹ {t('manage_logs.no_logs', path=str(log_dir))}")
    else:
        size_label = t("manage_logs.size_label")
        for i, f in enumerate(logs, 1):
            size_kb = max(1, f.stat().st_size // 1024)
            from datetime import datetime as _dt
            mtime = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            print(f"  [{i:2}]  {f.name}  ({size_kb} {size_label})  {mtime}")

    print()
    print(f"  {t('manage_logs.prompt')}")
    answer = input("  > ").strip().lower()

    if answer == "":
        return 0

    elif answer in ("c", "change"):
        from ufw_audit.sysinfo import get_user_home
        home = get_user_home()
        default_dir = Path(log_dir_str)
        chosen = prompt_path(t("manage_logs.change_prompt"), default_dir)
        try:
            chosen.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print(f"  ✖ Cannot create directory {chosen}: {exc}")
            return 1
        user_config.set("log_dir", str(chosen))
        print(f"  ✔ {t('manage_logs.location_updated', path=str(chosen))}")

    elif answer == "all":
        deleted = 0
        for f in logs:
            try:
                f.unlink()
                deleted += 1
            except OSError as exc:
                print(f"  ✖ Cannot delete {f.name}: {exc}")
        print(f"  ✔ {t('manage_logs.deleted_all', count=deleted)}")

    else:
        selected = parse_log_selection(answer, len(logs))
        if not selected:
            print(f"  ✖ {t('manage_logs.invalid')}")
        elif len(selected) == 1:
            f = logs[selected[0] - 1]
            try:
                f.unlink()
                print(f"  ✔ {t('manage_logs.deleted_one', name=f.name)}")
            except OSError as exc:
                print(f"  ✖ Cannot delete {f.name}: {exc}")
        else:
            deleted = 0
            for idx in selected:
                f = logs[idx - 1]
                try:
                    f.unlink()
                    deleted += 1
                except OSError as exc:
                    print(f"  ✖ Cannot delete {f.name}: {exc}")
            print(f"  ✔ {t('manage_logs.deleted_multi', count=deleted)}")

    return 0
