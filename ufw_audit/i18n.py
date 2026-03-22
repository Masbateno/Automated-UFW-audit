"""
Internationalisation module for ufw-audit.

Usage:
    # Initialise once at startup
    from ufw_audit import i18n
    i18n.init(lang="fr")

    # Use anywhere in the codebase
    from ufw_audit.i18n import t
    t("sec_services")           # → "ANALYSE DES SERVICES RÉSEAU"
    t("samba.open_world")       # → "Samba est restreint à votre réseau local..."

Supported languages are determined by the locale files present in
the locales/ directory alongside this package. Each locale file is
a UTF-8 JSON file named <lang>.json (e.g. en.json, fr.json).

Missing keys return the key itself wrapped in brackets so they are
visible in output without causing a crash.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state — initialised once via init()
# ---------------------------------------------------------------------------

_translations: dict[str, Any] = {}
_lang: str = "en"
_initialized: bool = False

# Locale files location:
# - If UFW_AUDIT_SHARE env var is set (installed), use that share directory
# - Otherwise fall back to locales/ next to this module (development)
import os as _os
_share = _os.environ.get("UFW_AUDIT_SHARE", "")
if _share:
    _share_path = Path(_share)
    if (
        _share_path.is_absolute()
        and not _share_path.is_symlink()
        and _share_path.is_dir()
    ):
        _LOCALES_DIR = _share_path / "locales"
    else:
        logger.warning("UFW_AUDIT_SHARE is invalid or unsafe, ignoring: %r", _share)
        _LOCALES_DIR = Path(__file__).parent / "locales"
else:
    _LOCALES_DIR = Path(__file__).parent / "locales"

SUPPORTED_LANGS = ("en", "fr")
DEFAULT_LANG = "en"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init(lang: str = DEFAULT_LANG) -> None:
    """
    Load the locale file for the requested language.

    Must be called once before any call to t(). Calling init() a second
    time reloads the locale, allowing language switching in tests.

    Args:
        lang: Language code, e.g. "en" or "fr". Falls back to DEFAULT_LANG
              if the requested locale file does not exist.

    Raises:
        FileNotFoundError: If neither the requested nor the fallback locale
                           file can be found.
    """
    global _translations, _lang, _initialized

    locale_path = _LOCALES_DIR / f"{lang}.json"

    if not locale_path.exists():
        logger.warning(
            "Locale file not found for language %r, falling back to %r",
            lang,
            DEFAULT_LANG,
        )
        locale_path = _LOCALES_DIR / f"{DEFAULT_LANG}.json"

    if not locale_path.exists():
        raise FileNotFoundError(
            f"No locale file found at {locale_path}. "
            f"Expected files: {_LOCALES_DIR}/<lang>.json"
        )

    _MAX_LOCALE_SIZE = 512 * 1024  # 512 KB
    with locale_path.open(encoding="utf-8") as fh:
        content = fh.read(_MAX_LOCALE_SIZE + 1)
    if len(content) > _MAX_LOCALE_SIZE:
        raise ValueError(f"Locale file {locale_path} exceeds maximum allowed size (512 KB)")
    _translations = json.loads(content)

    _lang = lang
    _initialized = True
    logger.debug("Loaded locale %r from %s", lang, locale_path)


def t(key: str, **kwargs: Any) -> str:
    """
    Return the translated string for key.

    Supports dot-notation for nested keys:
        t("samba.open_world")  →  _translations["samba"]["open_world"]

    Supports optional str.format() interpolation:
        t("log.blocked_attempts", count=42)  →  "42 tentative(s) bloquée(s)"

    Args:
        key:    Dot-separated translation key.
        kwargs: Optional named placeholders for str.format().

    Returns:
        Translated string, or "[key]" if the key is not found.
    """
    if not _initialized:
        logger.warning("i18n.t() called before i18n.init() — returning key %r", key)
        return f"[{key}]"

    value = _resolve(key, _translations)

    if value is None:
        logger.debug("Missing translation key: %r (lang=%r)", key, _lang)
        return f"[{key}]"

    if not isinstance(value, str):
        logger.warning(
            "Translation key %r resolved to non-string type %s",
            key,
            type(value).__name__,
        )
        return f"[{key}]"

    if kwargs:
        try:
            return value.format(**kwargs)
        except KeyError as exc:
            logger.warning(
                "Missing placeholder %s in translation key %r", exc, key
            )
            return value

    return value


def current_lang() -> str:
    """Return the currently loaded language code."""
    return _lang


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve(key: str, data: dict[str, Any]) -> Any:
    """
    Walk a nested dict using dot-separated key segments.

    Args:
        key:  Dot-separated key string, e.g. "samba.open_world".
        data: Dictionary to search.

    Returns:
        The value at the resolved path, or None if any segment is missing.
    """
    segments = key.split(".")
    node: Any = data
    for segment in segments:
        if not isinstance(node, dict) or segment not in node:
            return None
        node = node[segment]
    return node
