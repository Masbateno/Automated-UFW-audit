"""
Fix mode UI for ufw-audit.

Handles the --fix / --yes flow: displays actionable findings, prompts
the user to apply each fix, and runs the suggested commands.
"""

from __future__ import annotations

import re
import shlex
import subprocess

from ufw_audit.display import _SUMMARY_MSG_LEN, _truncate


def run_fixes(engine, config, t) -> None:
    """Display and optionally apply automatic fixes."""
    auto_items   = [(f.message, f.cmd) for f in engine.findings
                    if f.nature == "action" and f.cmd]
    manual_items = [f.message for f in engine.findings
                    if f.nature == "action" and not f.cmd]

    W = 62
    print()
    print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
    label = t("fixes.title")
    pad = W - 4 - len(label)
    print(f"\033[1;34m║\033[0m  \033[1m{label}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
    print(f"\033[1;34m╠{'═'*(W-2)}╣\033[0m")

    if not auto_items and not manual_items:
        none_msg = t("fixes.none")
        pad = W - 4 - len(none_msg)
        print(f"\033[1;34m║\033[0m    {none_msg}{' '*max(0,pad)}\033[1;34m║\033[0m")
    else:
        count = len(auto_items)
        count_msg = t("fixes.count", count=count)
        pad = W - 4 - len(count_msg)
        print(f"\033[1;34m║\033[0m    ✔  {count_msg}{' '*max(0,pad)}\033[1;34m║\033[0m")
    print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")

    if not auto_items and not manual_items:
        return

    # Sort ufw delete commands descending to avoid renumbering
    ufw_deletes = [(m, c) for m, c in auto_items
                   if re.search(r"ufw.*--force delete \d+$", c)]
    others      = [(m, c) for m, c in auto_items
                   if not re.search(r"ufw.*--force delete \d+$", c)]

    def sort_key(item):
        match = re.search(r"delete (\d+)$", item[1])
        return int(match.group(1)) if match else 0

    sorted_items = sorted(ufw_deletes, key=sort_key, reverse=True) + others

    # Auto-fix mode banner — visible warning so the user knows what's happening
    if config.yes:
        auto_msg = t("fixes.auto_mode_banner", count=len(sorted_items))
        print(f"\033[1;33m  ⚠  {auto_msg}\033[0m")
        print()

    applied_cmds = []

    print()
    for msg, cmd in sorted_items:
        short = _truncate(msg, _SUMMARY_MSG_LEN)
        print(f"  ✖  {short}")
        print(f"  → {cmd}")
        if config.yes:
            answer = "y"
        else:
            answer = input(f"  {t('fixes.apply_prompt')} ").strip().lower()

        if answer == "y":
            try:
                proc = subprocess.run(
                    shlex.split(cmd), stdin=subprocess.DEVNULL,
                    capture_output=True, timeout=30,
                )
                if proc.returncode == 0:
                    print(f"  ✔ {t('fixes.applied')}")
                    applied_cmds.append(cmd)
                else:
                    stderr = proc.stderr.decode(errors="replace").strip()
                    detail = f" — {stderr}" if stderr else ""
                    print(f"  ✖ {t('fixes.manual')} (exit {proc.returncode}{detail})")
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                print(f"  ✖ {t('fixes.manual')} ({type(exc).__name__})")
        else:
            print(f"  ✖ {t('fixes.manual')}")
        print()

    print(f"  {t('fixes.done')}")

    # Auto-fix summary — list every command that was applied
    if config.yes and applied_cmds:
        print()
        print(f"\033[1;34m  [{t('fixes.auto_summary_title')}]\033[0m")
        for cmd in applied_cmds:
            print(f"  ✔ {cmd}")
