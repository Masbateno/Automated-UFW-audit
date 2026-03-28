"""
Shared subprocess and utility helpers for ufw-audit check modules.

All check modules import from here instead of duplicating these helpers.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess

_CMD_TIMEOUT = 10  # seconds — shared across all check modules

logger = logging.getLogger(__name__)

# Force English output for all system commands so regexes work regardless
# of the system locale (e.g. French UFW outputs "État : actif" instead of
# "Status: active" when LC_ALL is not overridden).
_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}


def _run(*args: str) -> str:
    """Run a command and return stdout. Returns empty string on error."""
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, timeout=_CMD_TIMEOUT,
            env=_C_LOCALE_ENV,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Command %r failed: %s", args, exc)
        return ""


def _command_exists(name: str) -> bool:
    """Return True if the command is available in PATH."""
    return shutil.which(name) is not None


def _identity_t(key: str, **kwargs) -> str:
    """Fallback translation function — returns the key itself."""
    return key
