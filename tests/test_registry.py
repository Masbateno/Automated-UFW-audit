"""
Unit tests for ufw_audit.registry module.

Run with: python -m pytest tests/test_registry.py -v
"""

import json
import pytest
from pathlib import Path
from ufw_audit.registry import Detection, Service, ServiceRegistry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_service_dict(**overrides) -> dict:
    """Return a minimal valid service dict, with optional overrides."""
    base = {
        "id": "test_svc",
        "label": "Test Service",
        "packages": ["test-pkg"],
        "services": ["test-svc"],
        "ports": ["1234/tcp"],
        "risk": "medium",
        "config_key": "fixed",
        "detection": {"binary": [], "snap": [], "config_files": []},
    }
    base.update(overrides)
    return base


def write_registry(tmp_path: Path, entries: list) -> Path:
    """Write a services.json file to tmp_path and return its path."""
    path = tmp_path / "services.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

class TestDetection:
    def test_from_dict_full(self):
        d = Detection.from_dict({
            "binary": ["/usr/bin/gitea"],
            "snap": ["nextcloud"],
            "config_files": ["/etc/gitea/app.ini"],
        })
        assert d.binary == ("/usr/bin/gitea",)
        assert d.snap == ("nextcloud",)
        assert d.config_files == ("/etc/gitea/app.ini",)

    def test_from_dict_empty(self):
        d = Detection.from_dict({})
        assert d.binary == ()
        assert d.snap == ()
        assert d.config_files == ()

    def test_immutable(self):
        d = Detection.from_dict({"binary": ["/bin/foo"]})
        with pytest.raises((AttributeError, TypeError)):
            d.binary = ("/bin/bar",)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class TestService:
    def test_from_dict_valid(self):
        s = Service.from_dict(make_service_dict())
        assert s.id == "test_svc"
        assert s.label == "Test Service"
        assert s.packages == ("test-pkg",)
        assert s.ports == ("1234/tcp",)
        assert s.risk == "medium"
        assert s.config_key == "fixed"

    def test_missing_required_field_raises(self):
        data = make_service_dict()
        del data["label"]
        with pytest.raises(ValueError, match="missing required field"):
            Service.from_dict(data)

    def test_invalid_risk_raises(self):
        with pytest.raises(ValueError, match="invalid risk"):
            Service.from_dict(make_service_dict(risk="extreme"))

    def test_empty_config_key_raises(self):
        with pytest.raises(ValueError, match="config_key"):
            Service.from_dict(make_service_dict(config_key=""))

    def test_valid_risks_accepted(self):
        for risk in ("low", "medium", "high", "critical"):
            s = Service.from_dict(make_service_dict(risk=risk))
            assert s.risk == risk

    def test_is_critical(self):
        s = Service.from_dict(make_service_dict(risk="critical"))
        assert s.is_critical is True
        s2 = Service.from_dict(make_service_dict(risk="high"))
        assert s2.is_critical is False

    def test_is_high_or_critical(self):
        for risk in ("high", "critical"):
            s = Service.from_dict(make_service_dict(risk=risk))
            assert s.is_high_or_critical is True
        for risk in ("low", "medium"):
            s = Service.from_dict(make_service_dict(risk=risk))
            assert s.is_high_or_critical is False

    def test_main_port(self):
        s = Service.from_dict(make_service_dict(ports=["22/tcp", "2222/tcp"]))
        assert s.main_port == "22/tcp"

    def test_main_port_empty(self):
        s = Service.from_dict(make_service_dict(ports=[]))
        assert s.main_port == ""

    def test_immutable(self):
        s = Service.from_dict(make_service_dict())
        with pytest.raises((AttributeError, TypeError)):
            s.risk = "low"


# ---------------------------------------------------------------------------
# ServiceRegistry
# ---------------------------------------------------------------------------

class TestServiceRegistryLoad:
    def test_load_default_file(self):
        """Default services.json must load without errors."""
        registry = ServiceRegistry.load()
        assert len(registry) > 0

    def test_load_custom_path(self, tmp_path):
        entries = [make_service_dict(id="svc1"), make_service_dict(id="svc2")]
        path = write_registry(tmp_path, entries)
        registry = ServiceRegistry.load(path=path)
        assert len(registry) == 2

    def test_load_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ServiceRegistry.load(path=tmp_path / "nonexistent.json")

    def test_load_invalid_json_raises(self, tmp_path):
        path = tmp_path / "services.json"
        path.write_text("not valid json", encoding="utf-8")
        with pytest.raises(Exception):
            ServiceRegistry.load(path=path)

    def test_load_non_array_raises(self, tmp_path):
        path = tmp_path / "services.json"
        path.write_text('{"key": "value"}', encoding="utf-8")
        with pytest.raises(ValueError, match="array"):
            ServiceRegistry.load(path=path)

    def test_load_duplicate_id_raises(self, tmp_path):
        entries = [make_service_dict(id="dup"), make_service_dict(id="dup")]
        path = write_registry(tmp_path, entries)
        with pytest.raises(ValueError, match="Duplicate"):
            ServiceRegistry.load(path=path)

    def test_load_invalid_entry_raises(self, tmp_path):
        entries = [{"id": "broken"}]  # missing required fields
        path = write_registry(tmp_path, entries)
        with pytest.raises(ValueError):
            ServiceRegistry.load(path=path)


class TestServiceRegistryAccess:
    @pytest.fixture
    def registry(self, tmp_path):
        entries = [
            make_service_dict(id="ssh",   risk="critical", config_key="ssh_port"),
            make_service_dict(id="nginx", risk="medium"),
            make_service_dict(id="redis", risk="critical"),
            make_service_dict(id="cups",  risk="low"),
            make_service_dict(id="ha",    risk="high"),
        ]
        path = write_registry(tmp_path, entries)
        return ServiceRegistry.load(path=path)

    def test_all_returns_all(self, registry):
        assert len(registry.all()) == 5

    def test_get_existing(self, registry):
        s = registry.get("ssh")
        assert s is not None
        assert s.id == "ssh"

    def test_get_missing_returns_none(self, registry):
        assert registry.get("nonexistent") is None

    def test_by_risk_critical(self, registry):
        critical = registry.by_risk("critical")
        assert len(critical) == 2
        assert all(s.risk == "critical" for s in critical)

    def test_by_risk_low(self, registry):
        low = registry.by_risk("low")
        assert len(low) == 1
        assert low[0].id == "cups"

    def test_by_risk_empty(self, registry):
        assert registry.by_risk("medium_plus") == []

    def test_high_and_critical(self, registry):
        hc = registry.high_and_critical()
        assert len(hc) == 3  # ssh, redis (critical) + ha (high)
        assert all(s.is_high_or_critical for s in hc)

    def test_len(self, registry):
        assert len(registry) == 5

    def test_iter(self, registry):
        ids = [s.id for s in registry]
        assert ids == ["ssh", "nginx", "redis", "cups", "ha"]

    def test_order_preserved(self, registry):
        """Services must be returned in definition order."""
        all_services = registry.all()
        assert all_services[0].id == "ssh"
        assert all_services[-1].id == "ha"


class TestDefaultRegistry:
    def test_all_known_services_present(self):
        registry = ServiceRegistry.load()
        expected_ids = {
            "ssh", "vnc", "samba", "ftp", "apache", "nginx",
            "mysql", "postgresql", "transmission", "qbittorrent",
            "avahi", "cups", "cockpit", "wireguard", "redis",
            "jellyfin", "plex", "homeassistant", "nextcloud",
            "gitea", "mosquitto", "syncthing",
        }
        actual_ids = {s.id for s in registry}
        assert expected_ids == actual_ids

    def test_all_services_have_valid_risk(self):
        registry = ServiceRegistry.load()
        for service in registry:
            assert service.risk in ("low", "medium", "high", "critical"), (
                f"Service {service.id!r} has invalid risk: {service.risk!r}"
            )

    def test_all_services_have_ports(self):
        registry = ServiceRegistry.load()
        for service in registry:
            assert len(service.ports) > 0, (
                f"Service {service.id!r} has no ports defined"
            )

    def test_ssh_is_critical(self):
        registry = ServiceRegistry.load()
        ssh = registry.get("ssh")
        assert ssh is not None
        assert ssh.risk == "critical"

    def test_avahi_is_low(self):
        registry = ServiceRegistry.load()
        avahi = registry.get("avahi")
        assert avahi is not None
        assert avahi.risk == "low"
