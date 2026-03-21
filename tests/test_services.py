"""
Unit tests for ufw_audit.checks.services module.

All tests build ServiceSnapshot instances directly — no subprocess calls.

Run with: python -m pytest tests/test_services.py -v
"""

import pytest
from ufw_audit.checks.services import (
    Exposure,
    ServiceSnapshot,
    ServiceState,
    _classify_exposure,
    check_services,
)
from ufw_audit.registry import Detection, Service
from ufw_audit.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_service(
    id="ssh",
    label="SSH Server",
    packages=("openssh-server",),
    services=("ssh",),
    ports=("22/tcp",),
    risk="critical",
    config_key="fixed",
    detection=None,
) -> Service:
    if detection is None:
        detection = Detection(binary=(), snap=(), config_files=())
    return Service(
        id=id, label=label, packages=tuple(packages),
        services=tuple(services), ports=tuple(ports),
        risk=risk, config_key=config_key, detection=detection,
    )


def make_snapshot(
    service=None,
    state=ServiceState.ACTIVE_ENABLED,
    ports=None,
    exposures=None,
    install_via="dpkg",
) -> ServiceSnapshot:
    if service is None:
        service = make_service()
    if ports is None:
        ports = list(service.ports)
    if exposures is None:
        exposures = {p: Exposure.NO_RULE for p in ports}
    return ServiceSnapshot(
        service=service,
        installed=True,
        install_via=install_via,
        state=state,
        ports=ports,
        exposures=exposures,
    )


def levels(result) -> list[str]:
    return [f.level.value for f in result.findings]


def has_level(result, level: str) -> bool:
    return level in levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# ServiceState properties
# ---------------------------------------------------------------------------

class TestServiceState:
    def test_active_enabled_is_active(self):
        assert ServiceState.ACTIVE_ENABLED.is_active is True

    def test_active_disabled_is_active(self):
        assert ServiceState.ACTIVE_DISABLED.is_active is True

    def test_inactive_enabled_is_not_active(self):
        assert ServiceState.INACTIVE_ENABLED.is_active is False

    def test_inactive_disabled_is_inactive(self):
        assert ServiceState.INACTIVE_DISABLED.is_inactive is True

    def test_unknown_not_active_not_inactive(self):
        assert ServiceState.UNKNOWN.is_active is False
        assert ServiceState.UNKNOWN.is_inactive is False


# ---------------------------------------------------------------------------
# _classify_exposure
# ---------------------------------------------------------------------------

class TestClassifyExposure:
    UFW_ALLOW_ANY = """
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""
    UFW_ALLOW_LOCAL = """
[ 1] 22/tcp                     ALLOW IN    192.168.1.0/24
"""
    UFW_DENY = """
[ 1] 22/tcp                     DENY IN     Anywhere
"""
    UFW_NO_RULE = """
[ 1] 80/tcp                     ALLOW IN    Anywhere
"""
    UFW_EMPTY = ""

    def test_open_world(self):
        assert _classify_exposure("22/tcp", self.UFW_ALLOW_ANY) == Exposure.OPEN_WORLD

    def test_open_local(self):
        assert _classify_exposure("22/tcp", self.UFW_ALLOW_LOCAL) == Exposure.OPEN_LOCAL

    def test_deny(self):
        assert _classify_exposure("22/tcp", self.UFW_DENY) == Exposure.DENY

    def test_no_rule(self):
        assert _classify_exposure("22/tcp", self.UFW_NO_RULE) == Exposure.NO_RULE

    def test_no_rule_empty_ufw(self):
        assert _classify_exposure("22/tcp", self.UFW_EMPTY) == Exposure.NO_RULE

    def test_private_range_10(self):
        rules = "[ 1] 22/tcp  ALLOW IN  10.0.0.0/8\n"
        assert _classify_exposure("22/tcp", rules) == Exposure.OPEN_LOCAL

    def test_private_range_172(self):
        rules = "[ 1] 22/tcp  ALLOW IN  172.16.0.0/12\n"
        assert _classify_exposure("22/tcp", rules) == Exposure.OPEN_LOCAL

    def test_deny_takes_precedence_over_allow_local(self):
        rules = (
            "[ 1] 22/tcp  DENY IN   Anywhere\n"
            "[ 2] 22/tcp  ALLOW IN  192.168.1.0/24\n"
        )
        # deny + local allow → DENY wins (no open world rule)
        result = _classify_exposure("22/tcp", rules)
        assert result == Exposure.DENY

    def test_udp_port(self):
        rules = "[ 1] 5353/udp  ALLOW IN  Anywhere\n"
        assert _classify_exposure("5353/udp", rules) == Exposure.OPEN_WORLD


# ---------------------------------------------------------------------------
# check_services — inactive_disabled
# ---------------------------------------------------------------------------

class TestInactiveDisabled:
    def test_info_finding_for_inactive(self):
        snap = make_snapshot(state=ServiceState.INACTIVE_DISABLED)
        result = check_services([snap])
        assert has_level(result, "info")

    def test_no_deduction_for_inactive(self):
        snap = make_snapshot(state=ServiceState.INACTIVE_DISABLED)
        result = check_services([snap])
        assert total_deductions(result) == 0

    def test_no_port_check_for_inactive(self):
        """No port exposure findings for inactive_disabled services."""
        snap = make_snapshot(
            state=ServiceState.INACTIVE_DISABLED,
            exposures={"22/tcp": Exposure.OPEN_WORLD},
        )
        result = check_services([snap])
        # Only 1 finding: the inactive info
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# check_services — active states
# ---------------------------------------------------------------------------

class TestActiveStates:
    def test_ok_for_active_enabled(self):
        snap = make_snapshot(state=ServiceState.ACTIVE_ENABLED)
        result = check_services([snap])
        assert has_level(result, "ok")

    def test_warn_for_active_disabled(self):
        snap = make_snapshot(state=ServiceState.ACTIVE_DISABLED)
        result = check_services([snap])
        assert has_level(result, "warn")

    def test_info_for_unknown_state(self):
        snap = make_snapshot(state=ServiceState.UNKNOWN)
        result = check_services([snap])
        assert has_level(result, "info")


# ---------------------------------------------------------------------------
# check_services — port exposure findings
# ---------------------------------------------------------------------------

class TestPortExposureFindings:
    def test_open_world_adds_warn(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_WORLD},
        )
        result = check_services([snap])
        assert has_level(result, "warn")

    def test_open_world_adds_deduction(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_WORLD},
        )
        result = check_services([snap])
        assert total_deductions(result) > 0

    def test_open_world_critical_public_higher_deduction(self):
        svc = make_service(risk="critical")
        snap = make_snapshot(
            service=svc,
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_WORLD},
        )
        result_local  = check_services([snap], network_context="local")
        result_public = check_services([snap], network_context="public")
        assert total_deductions(result_public) > total_deductions(result_local)

    def test_open_local_adds_warn(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_LOCAL},
        )
        result = check_services([snap])
        assert has_level(result, "warn")

    def test_open_local_no_deduction(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_LOCAL},
        )
        result = check_services([snap])
        assert total_deductions(result) == 0

    def test_deny_adds_ok(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.DENY},
        )
        result = check_services([snap])
        assert has_level(result, "ok")

    def test_no_rule_adds_info(self):
        snap = make_snapshot(
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.NO_RULE},
        )
        result = check_services([snap])
        assert has_level(result, "info")

    def test_multiple_ports(self):
        snap = make_snapshot(
            service=make_service(ports=("445/tcp", "139/tcp")),
            state=ServiceState.ACTIVE_ENABLED,
            ports=["445/tcp", "139/tcp"],
            exposures={
                "445/tcp": Exposure.OPEN_WORLD,
                "139/tcp": Exposure.NO_RULE,
            },
        )
        result = check_services([snap])
        assert has_level(result, "warn")   # from 445
        assert has_level(result, "info")   # from 139


# ---------------------------------------------------------------------------
# check_services — multiple services
# ---------------------------------------------------------------------------

class TestMultipleServices:
    def test_multiple_snapshots_aggregated(self):
        snap1 = make_snapshot(
            service=make_service(id="ssh"),
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"22/tcp": Exposure.OPEN_WORLD},
        )
        snap2 = make_snapshot(
            service=make_service(id="redis"),
            state=ServiceState.ACTIVE_ENABLED,
            exposures={"6379/tcp": Exposure.NO_RULE},
        )
        result = check_services([snap1, snap2])
        assert len(result.findings) >= 2

    def test_empty_snapshots_empty_result(self):
        result = check_services([])
        assert result.findings == []
        assert result.deductions == []


# ---------------------------------------------------------------------------
# check_services — translation
# ---------------------------------------------------------------------------

class TestTranslation:
    def test_translation_function_used(self):
        def my_t(key, **kwargs):
            return f"T:{key}"

        snap = make_snapshot(state=ServiceState.ACTIVE_ENABLED)
        result = check_services([snap], t=my_t)
        assert any("T:" in f.message for f in result.findings)


# ---------------------------------------------------------------------------
# ServiceSnapshot properties
# ---------------------------------------------------------------------------

class TestServiceSnapshotProperties:
    def test_label(self):
        snap = make_snapshot(service=make_service(label="SSH Server"))
        assert snap.label == "SSH Server"

    def test_risk(self):
        snap = make_snapshot(service=make_service(risk="critical"))
        assert snap.risk == "critical"

    def test_is_active(self):
        snap = make_snapshot(state=ServiceState.ACTIVE_ENABLED)
        assert snap.is_active is True

    def test_is_not_active(self):
        snap = make_snapshot(state=ServiceState.INACTIVE_DISABLED)
        assert snap.is_active is False
