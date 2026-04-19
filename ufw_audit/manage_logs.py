"""
Log management UI for ufw-audit.

Handles the --manage-logs command: listing, deleting and relocating
saved audit report files, plus log directory configuration helpers.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Score history helpers
# ---------------------------------------------------------------------------

_SCORE_RE = re.compile(r"^Score\s*:\s*(\d+)/10", re.MULTILINE)


def _extract_score_from_log(path: Path) -> "int | None":
    """Return the security score recorded in a log file, or None if not found."""
    try:
        text = path.read_text(errors="replace")
        m = _SCORE_RE.search(text)
        if m:
            return int(m.group(1))
    except OSError:
        pass
    return None


def _parse_log_date(path: Path) -> str:
    """Extract a human-readable date from filename ufw_audit_YYYYMMDD_HHMMSS.log."""
    parts = path.stem.split("_")  # ['ufw', 'audit', '20260413', '170724']
    if len(parts) >= 4:
        d, h = parts[2], parts[3]
        if len(d) == 8 and len(h) == 6:
            return f"{d[:4]}-{d[4:6]}-{d[6:]} {h[:2]}:{h[2:4]}"
    return path.stem


def _build_score_history(log_files: "list[Path]") -> "list[tuple[str, int]]":
    """Return (date_str, score) pairs sorted oldest-first from the given log files."""
    history = []
    for f in sorted(log_files):  # lexicographic sort = chronological order
        score = _extract_score_from_log(f)
        if score is not None:
            history.append((_parse_log_date(f), score))
    return history


def _render_score_chart(history: "list[tuple[str, int]]", t) -> "list[str]":
    """Return lines of an ASCII bar chart of score history."""
    if not history:
        return []

    shown = history[-20:]  # at most the 20 most recent
    count = len(shown)
    label = t("manage_logs.history_title", count=count)
    sep = "─" * 50
    lines = [f"  {label}", f"  {sep}"]
    for date_str, score in shown:
        bar = "█" * score + "░" * (10 - score)
        lines.append(f"  {date_str}  [{score:2}/10]  {bar}")
    lines.append(f"  {sep}")
    return lines


# ---------------------------------------------------------------------------
# Path prompt helper
# ---------------------------------------------------------------------------

def prompt_path(prompt_label: str, default: Path, allow_cancel: bool = False) -> Path | None:
    """Prompt for a filesystem path with TAB autocompletion via readline.

    When *allow_cancel* is True, entering 'q' or 'quit' returns None so
    the caller can abort without modifying anything.
    """
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

    if allow_cancel and raw.lower() in ("q", "quit"):
        return None

    # resolve() normalises ".." components and follows symlinks,
    # preventing path traversal sequences in user-supplied paths.
    return Path(raw).expanduser().resolve() if raw else default


# ---------------------------------------------------------------------------
# Log directory resolution
# ---------------------------------------------------------------------------

def get_or_prompt_log_dir(user_config, config, t) -> Path:
    """Return the configured log directory, prompting at first use.

    Priority: --output-dir CLI flag > saved config > interactive prompt.
    In non-interactive contexts (cron, pipes) the default path is used
    silently so that the process never hangs waiting for input.
    """
    # --output-dir takes highest priority — no prompt, no save
    if getattr(config, "output_dir", ""):
        d = Path(config.output_dir)
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print(f"  ✖ Cannot create directory {d}: {exc} — falling back to cwd")
            d = Path.cwd()
        return d

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
# Extra directories helpers
# ---------------------------------------------------------------------------

def _get_extra_dirs(user_config) -> list[Path]:
    """Return the list of previous log directories tracked in user_config."""
    raw = user_config.get("log_dirs_extra")
    if not raw:
        return []
    try:
        return [Path(p) for p in json.loads(raw) if p]
    except Exception:
        return []


def _set_extra_dirs(user_config, dirs: list[Path]) -> None:
    user_config.set("log_dirs_extra", json.dumps([str(d) for d in dirs]))


def _add_extra_dir(user_config, path: Path) -> None:
    """Add *path* to the extras list if not already present."""
    extras = _get_extra_dirs(user_config)
    if path not in extras:
        extras.append(path)
        _set_extra_dirs(user_config, extras)


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
    """Standalone log management UI — list, multi-delete, and change storage location.

    Loops until the user explicitly quits (empty input or 'q').
    Reports from the current directory AND any previously configured
    directories are shown together with a continuous index so that
    all files are reachable regardless of which path is currently active.
    """
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

    while True:
        # Refresh current directory on every iteration
        log_dir_str = user_config.get("log_dir") or log_dir_str
        log_dir = Path(log_dir_str)

        if not log_dir.exists():
            log_dir.mkdir(parents=True, exist_ok=True)

        cur_logs = sorted(log_dir.glob("ufw_audit_*.log"), reverse=True)

        # Collect extra (previous) directories that still contain logs;
        # auto-drop those that are empty or no longer exist.
        extra_dirs = _get_extra_dirs(user_config)
        extra_sections: list[tuple[Path, list[Path]]] = []
        live_extras: list[Path] = []
        for extra in extra_dirs:
            if extra == log_dir:
                continue
            if extra.exists():
                ex_logs = sorted(extra.glob("ufw_audit_*.log"), reverse=True)
                if ex_logs:
                    extra_sections.append((extra, ex_logs))
                    live_extras.append(extra)
        if live_extras != extra_dirs:
            _set_extra_dirs(user_config, live_extras)

        # Flat list for unified index (current dir first, then extras in order)
        all_logs: list[Path] = list(cur_logs)
        for _, ex_logs in extra_sections:
            all_logs.extend(ex_logs)

        # ── Score history chart ───────────────────────────────────────────
        if all_logs:
            history = _build_score_history(all_logs)
            for line in _render_score_chart(history, t):
                print(line)
            print()

        # ── Display ──────────────────────────────────────────────────────
        size_label = t("manage_logs.size_label")
        current_label = t("manage_logs.current_label")
        print(f"  {t('manage_logs.stored_in', path=str(log_dir))}  [{current_label}]")
        print()

        idx = 1
        if not cur_logs:
            print(f"  ℹ {t('manage_logs.no_logs', path=str(log_dir))}")
        else:
            for f in cur_logs:
                size_kb = max(1, f.stat().st_size // 1024)
                from datetime import datetime as _dt
                mtime = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                print(f"  [{idx:2}]  {f.name}  ({size_kb} {size_label})  {mtime}")
                idx += 1

        for extra_path, ex_logs in extra_sections:
            print()
            print(f"  ─── {t('manage_logs.previous_label')}: {extra_path} ───")
            print()
            for f in ex_logs:
                size_kb = max(1, f.stat().st_size // 1024)
                from datetime import datetime as _dt
                mtime = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                print(f"  [{idx:2}]  {f.name}  ({size_kb} {size_label})  {mtime}")
                idx += 1

        print()
        print(f"  {t('manage_logs.prompt')}")
        answer = input("  > ").strip().lower()

        if answer in ("", "q", "quit"):
            return 0

        elif answer in ("c", "change"):
            chosen = prompt_path(t("manage_logs.change_prompt"), log_dir, allow_cancel=True)
            if chosen is None:
                print(f"  {t('manage_logs.cancelled')}")
            else:
                try:
                    chosen.mkdir(parents=True, exist_ok=True)
                except OSError as exc:
                    print(f"  ✖ Cannot create directory {chosen}: {exc}")
                    print()
                    continue
                # Register current dir as "previous" before switching
                if cur_logs and chosen != log_dir:
                    _add_extra_dir(user_config, log_dir)
                # Offer to move all visible reports to the new location
                if all_logs and chosen != log_dir:
                    move_confirm = input(
                        f"  {t('manage_logs.move_logs_prompt', count=len(all_logs))} [y/N] "
                    ).strip().lower()
                    if move_confirm == "y":
                        import shutil as _shutil
                        moved = 0
                        for f in all_logs:
                            try:
                                _shutil.move(str(f), str(chosen / f.name))
                                moved += 1
                            except OSError as exc:
                                print(f"  ✖ Cannot move {f.name}: {exc}")
                        print(f"  ✔ {t('manage_logs.move_logs_done', count=moved)}")
                user_config.set("log_dir", str(chosen))
                log_dir_str = str(chosen)
                print(f"  ✔ {t('manage_logs.location_updated', path=str(chosen))}")

        elif answer == "all":
            confirm = input(
                f"  {t('manage_logs.confirm_all', count=len(all_logs))} [y/N] "
            ).strip().lower()
            if confirm != "y":
                print(f"  {t('manage_logs.cancelled')}")
            else:
                deleted = 0
                for f in all_logs:
                    try:
                        f.unlink()
                        deleted += 1
                    except OSError as exc:
                        print(f"  ✖ Cannot delete {f.name}: {exc}")
                print(f"  ✔ {t('manage_logs.deleted_all', count=deleted)}")

        else:
            selected = parse_log_selection(answer, len(all_logs))
            if not selected:
                print(f"  ✖ {t('manage_logs.invalid')}")
            elif len(selected) == 1:
                f = all_logs[selected[0] - 1]
                try:
                    f.unlink()
                    print(f"  ✔ {t('manage_logs.deleted_one', name=f.name)}")
                except OSError as exc:
                    print(f"  ✖ Cannot delete {f.name}: {exc}")
            else:
                deleted = 0
                for sel_idx in selected:
                    f = all_logs[sel_idx - 1]
                    try:
                        f.unlink()
                        deleted += 1
                    except OSError as exc:
                        print(f"  ✖ Cannot delete {f.name}: {exc}")
                print(f"  ✔ {t('manage_logs.deleted_multi', count=deleted)}")

        print()
