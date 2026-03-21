"""
User configuration module for ufw-audit.

Manages persistent key=value settings stored between runs, primarily
used to remember port numbers for services that require manual input.

Configuration file location: ~/.config/ufw-audit/config.conf

File format (plain key=value, one per line):
    nginx_web_server_port=8080
    ssh_port=2222

No section headers, no comments written by the application.
The file is human-readable and human-editable.

Usage:
    from ufw_audit.config import UserConfig

    config = UserConfig.load()
    port = config.get("nginx_web_server_port")   # "8080" or None
    config.set("nginx_web_server_port", "8080")  # persists immediately
    config.delete("nginx_web_server_port")
    config.clear()
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Default config directory follows XDG Base Directory spec
_DEFAULT_CONFIG_DIR = Path.home() / ".config" / "ufw-audit"
_CONFIG_FILENAME = "config.conf"


class UserConfig:
    """
    Persistent key=value store for ufw-audit user settings.

    All write operations (set, delete, clear) persist to disk immediately.
    The in-memory dict is always kept in sync with the file.

    Args:
        path: Full path to the config file. Defaults to
              ~/.config/ufw-audit/config.conf.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path: Path = path or (_DEFAULT_CONFIG_DIR / _CONFIG_FILENAME)
        self._data: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: Path | None = None) -> "UserConfig":
        """
        Create a UserConfig instance and load existing settings from disk.

        Creates the config directory if it does not exist.
        Missing config file is treated as an empty configuration (no error).

        Args:
            path: Override the default config file path. Useful in tests.

        Returns:
            Populated UserConfig instance.
        """
        instance = cls(path=path)
        instance._ensure_dir()
        instance._load()
        return instance

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, key: str) -> Optional[str]:
        """
        Return the value for key, or None if not set.

        Args:
            key: Configuration key (e.g. "nginx_web_server_port").

        Returns:
            Stored string value, or None.
        """
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        """
        Store a key=value pair and persist to disk immediately.

        Args:
            key:   Configuration key.
            value: String value to store.

        Raises:
            OSError: If the config file cannot be written.
        """
        self._data[key] = value
        self._save()
        logger.debug("Config set: %s=%s", key, value)

    def delete(self, key: str) -> None:
        """
        Remove a key from the configuration and persist to disk.

        No-op if the key does not exist.

        Args:
            key: Configuration key to remove.
        """
        if key in self._data:
            del self._data[key]
            self._save()
            logger.debug("Config deleted: %s", key)

    def clear(self) -> None:
        """
        Remove all stored configuration and persist an empty file to disk.
        """
        self._data.clear()
        self._save()
        logger.debug("Config cleared")

    def all_keys(self) -> list[str]:
        """Return a sorted list of all stored keys."""
        return sorted(self._data.keys())

    def exists(self) -> bool:
        """Return True if the config file exists on disk."""
        return self._path.exists()

    @property
    def path(self) -> Path:
        """Path to the config file."""
        return self._path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_dir(self) -> None:
        """Create the config directory if it does not exist."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("Could not create config directory %s: %s", self._path.parent, exc)

    def _load(self) -> None:
        """
        Parse the config file into _data.

        Silently ignores missing files and malformed lines.
        Lines starting with # are treated as comments and skipped.
        """
        if not self._path.exists():
            logger.debug("Config file not found at %s — starting empty", self._path)
            return

        try:
            with self._path.open(encoding="utf-8") as fh:
                for line_number, raw in enumerate(fh, start=1):
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        logger.debug(
                            "Config line %d malformed (no '='): %r — skipped",
                            line_number,
                            line,
                        )
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()
                    if key:
                        self._data[key] = value
        except OSError as exc:
            logger.warning("Could not read config file %s: %s", self._path, exc)

    def _save(self) -> None:
        """
        Write _data to disk as key=value lines, sorted by key.

        Raises:
            OSError: If the file cannot be written.
        """
        self._ensure_dir()
        try:
            with self._path.open("w", encoding="utf-8") as fh:
                for key in sorted(self._data.keys()):
                    fh.write(f"{key}={self._data[key]}\n")
        except OSError as exc:
            logger.error("Could not write config file %s: %s", self._path, exc)
            raise
