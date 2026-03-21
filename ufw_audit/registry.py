"""
Service registry module for ufw-audit.

Loads service definitions from data/services.json and exposes them
as typed Python dataclasses. This is the single source of truth for
all known network services — no other module defines services inline.

Adding a new service requires only editing data/services.json.

Usage:
    from ufw_audit.registry import ServiceRegistry

    registry = ServiceRegistry.load()

    for service in registry.all():
        print(service.label, service.risk)

    ssh = registry.get("ssh")
    critical = registry.by_risk("critical")
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Service data location:
# - If UFW_AUDIT_SHARE env var is set (installed), use that share directory
# - Otherwise fall back to data/ next to this module (development)
import os as _os
_share = _os.environ.get("UFW_AUDIT_SHARE", "")
if _share:
    _DATA_DIR = Path(_share) / "data"
else:
    _DATA_DIR = Path(__file__).parent / "data"
_SERVICES_FILE = _DATA_DIR / "services.json"

# Valid values for the risk field
VALID_RISKS = frozenset({"low", "medium", "high", "critical"})

# Valid values for the config_key field
VALID_CONFIG_KEYS = frozenset({"fixed", "auto", "ask"})


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Detection:
    """
    Extended detection hints for services not installable via dpkg alone.

    Args:
        binary:       Absolute paths to check for binary installations.
        snap:         Snap package names to check via 'snap list'.
        config_files: Config file paths used to auto-detect the service port.
    """
    binary:       tuple[str, ...]
    snap:         tuple[str, ...]
    config_files: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict) -> "Detection":
        return cls(
            binary=tuple(data.get("binary", [])),
            snap=tuple(data.get("snap", [])),
            config_files=tuple(data.get("config_files", [])),
        )


@dataclass(frozen=True)
class Service:
    """
    Immutable representation of a network service known to ufw-audit.

    Args:
        id:         Unique identifier (e.g. "ssh", "nginx").
        label:      Human-readable display name (e.g. "SSH Server").
        packages:   dpkg package names to check for installation.
        services:   systemd service names to check for state.
        ports:      Default ports in "number/proto" format (e.g. "22/tcp").
        risk:       Risk classification: "low" | "medium" | "high" | "critical".
        config_key: Port resolution strategy:
                    - Named key (e.g. "ssh_port"): read from user config file.
                    - "ask":   prompt user and save to config.
                    - "auto":  auto-detect from service config file.
                    - "fixed": use ports as-is, no detection needed.
        detection:  Extended detection hints (snap, binary, config_files).
    """
    id:         str
    label:      str
    packages:   tuple[str, ...]
    services:   tuple[str, ...]
    ports:      tuple[str, ...]
    risk:       str
    config_key: str
    detection:  Detection

    @property
    def is_critical(self) -> bool:
        return self.risk == "critical"

    @property
    def is_high_or_critical(self) -> bool:
        return self.risk in ("high", "critical")

    @property
    def main_port(self) -> str:
        """Return the first port (used for display and remediation commands)."""
        return self.ports[0] if self.ports else ""

    @classmethod
    def from_dict(cls, data: dict) -> "Service":
        """
        Build a Service from a JSON-parsed dictionary.

        Args:
            data: Dict parsed from a services.json entry.

        Returns:
            Populated Service instance.

        Raises:
            ValueError: If required fields are missing or have invalid values.
        """
        required = ("id", "label", "packages", "services", "ports", "risk", "config_key")
        for field_name in required:
            if field_name not in data:
                raise ValueError(f"Service entry missing required field: {field_name!r}")

        risk = data["risk"]
        if risk not in VALID_RISKS:
            raise ValueError(
                f"Service {data['id']!r}: invalid risk {risk!r}. "
                f"Must be one of: {sorted(VALID_RISKS)}"
            )

        config_key = data["config_key"]
        # config_key is either one of the reserved words or a named key string
        if not config_key:
            raise ValueError(f"Service {data['id']!r}: config_key must not be empty")

        return cls(
            id=data["id"],
            label=data["label"],
            packages=tuple(data["packages"]),
            services=tuple(data["services"]),
            ports=tuple(data["ports"]),
            risk=risk,
            config_key=config_key,
            detection=Detection.from_dict(data.get("detection", {})),
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class ServiceRegistry:
    """
    Loaded collection of Service objects.

    Provides lookup by id and filtering by risk level.

    Args:
        services: Ordered list of Service objects.
    """

    def __init__(self, services: list[Service]) -> None:
        self._services: list[Service] = services
        self._by_id: dict[str, Service] = {s.id: s for s in services}

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: Path | None = None) -> "ServiceRegistry":
        """
        Load and validate the services registry from a JSON file.

        Args:
            path: Override the default services.json path. Useful in tests.

        Returns:
            Populated ServiceRegistry.

        Raises:
            FileNotFoundError: If the services file does not exist.
            ValueError:        If any service entry is invalid.
            json.JSONDecodeError: If the file is not valid JSON.
        """
        json_path = path or _SERVICES_FILE

        if not json_path.exists():
            raise FileNotFoundError(
                f"Services file not found: {json_path}"
            )

        with json_path.open(encoding="utf-8") as fh:
            raw = json.load(fh)

        if not isinstance(raw, list):
            raise ValueError(f"services.json must contain a JSON array, got {type(raw).__name__}")

        services: list[Service] = []
        ids_seen: set[str] = set()

        for i, entry in enumerate(raw):
            try:
                service = Service.from_dict(entry)
            except (ValueError, KeyError) as exc:
                raise ValueError(f"services.json entry #{i}: {exc}") from exc

            if service.id in ids_seen:
                raise ValueError(f"Duplicate service id: {service.id!r}")

            ids_seen.add(service.id)
            services.append(service)

        logger.debug("Loaded %d services from %s", len(services), json_path)
        return cls(services)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def all(self) -> list[Service]:
        """Return all services in definition order."""
        return list(self._services)

    def get(self, service_id: str) -> Optional[Service]:
        """
        Return the service with the given id, or None if not found.

        Args:
            service_id: The service id string (e.g. "ssh", "nginx").
        """
        return self._by_id.get(service_id)

    def by_risk(self, risk: str) -> list[Service]:
        """
        Return all services matching the given risk level.

        Args:
            risk: One of "low", "medium", "high", "critical".
        """
        return [s for s in self._services if s.risk == risk]

    def high_and_critical(self) -> list[Service]:
        """Return all services with risk level 'high' or 'critical'."""
        return [s for s in self._services if s.is_high_or_critical]

    def __len__(self) -> int:
        return len(self._services)

    def __iter__(self):
        return iter(self._services)
