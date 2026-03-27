"""
Shared subprocess helper for ufw-audit check modules.

All check modules that need to run system commands use this module
instead of duplicating the same _run() helper.
"""

from __future__ import annotations

import logging
import subprocess

_CMD_TIMEOUT = 10  # seconds — shared across all check modules

logger = logging.getLogger(__name__)


def _run(*args: str) -> str:
    """Run a command and return stdout. Returns empty string on error."""
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, timeout=_CMD_TIMEOUT,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Command %r failed: %s", args, exc)
        return ""
