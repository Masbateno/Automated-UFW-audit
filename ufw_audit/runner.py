"""Audit runner — sequentially executes all 8 checks."""

from __future__ import annotations

from typing import NamedTuple

from ufw_audit import output
from ufw_audit.cli import AuditConfig
from ufw_audit.config import UserConfig
from ufw_audit.display import (
    check_single_service_display,
    display_geoip_notice,
    display_log_results,
    display_ports_overview,
    display_result,
    display_risk_context,
    display_services_panorama,
)
from ufw_audit.output import print_section, print_service_header
from ufw_audit.registry import ServiceRegistry
from ufw_audit.report import AuditReport
from ufw_audit.scoring import ScoreEngine
from ufw_audit.checks.ddns import DdnsSnapshot, check_ddns
from ufw_audit.checks.docker import DockerSnapshot, check_docker
from ufw_audit.checks.firewall import FirewallStatus, check_firewall, check_rules
from ufw_audit.checks.logs import LogsSnapshot, check_logs, geoip2_status
from ufw_audit.checks.ports import PortsSnapshot, check_ports
from ufw_audit.checks.services import ServiceSnapshot
from ufw_audit.checks.virtualization import VirtSnapshot, check_virtualization


class ChecksResult(NamedTuple):
    snapshots: list
    ports_snapshot: PortsSnapshot


def init_report(config: AuditConfig, user_config: UserConfig, t, version: str) -> AuditReport:
    """Open a timestamped report file, or return a null (no-op) report."""
    if config.detailed:
        from ufw_audit.manage_logs import get_or_prompt_log_dir
        log_dir = get_or_prompt_log_dir(user_config, config, t)
        report  = AuditReport.open(directory=log_dir, version=version)
        output.print_ok(t("audit.report_saved", path=report.path))
        if not config.quiet:
            print()
        return report
    return AuditReport.null()


def run_checks(
    config: AuditConfig,
    t,
    engine: ScoreEngine,
    report: AuditReport,
    registry: ServiceRegistry,
    network_context: str,
) -> ChecksResult:
    """Run all 8 audit checks in sequence."""

    # ---- CHECK 1 — Firewall status ----
    if not config.quiet:
        print_section(t("sections.firewall"))
    report.write_section(t("sections.firewall"))

    fw_status  = FirewallStatus.from_system()
    fw_result  = check_firewall(fw_status, t=t)
    engine.apply(fw_result)
    display_result(fw_result, report, config.verbose, quiet=config.quiet)

    if fw_status.ufw_output:
        report.write_section("UFW STATUS")
        report.write_raw(fw_status.ufw_output)

    # ---- CHECK 2 — UFW rules ----
    ufw_numbered = fw_status.numbered_output
    ufw_verbose  = fw_status.ufw_output

    if not config.quiet:
        print_section(t("sections.rules"))
    report.write_section(t("sections.rules"))

    rules_result = check_rules(ufw_verbose, ufw_numbered, t, fw_status.ipv6_ufw_enabled)
    engine.apply(rules_result)
    display_result(rules_result, report, config.verbose, quiet=config.quiet)

    # ---- CHECK 3 — Network services ----
    ports_snapshot        = PortsSnapshot.from_system()
    loopback_only_ports   = ports_snapshot.loopback_only_ports
    active_external_ports = ports_snapshot.active_external_ports
    all_listening_ports   = loopback_only_ports | active_external_ports

    if not config.quiet:
        print_section(t("sections.services"))
    report.write_section(t("sections.services"))

    snapshots     = ServiceSnapshot.collect(
        registry, ufw_rules=ufw_numbered, loopback_ports=loopback_only_ports,
        all_listening_ports=all_listening_ports,
    )
    audited_ports: set[str] = set()

    for snap in snapshots:
        if not config.quiet:
            print_service_header(snap.label)
        report.write_raw(f"\n  > {snap.label}")
        if snap.service.is_high_or_critical and snap.is_active:
            display_risk_context(snap.service.label, config.lang, t, report)
        svc_result = check_single_service_display(
            snap, network_context, t, report, config.verbose, quiet=config.quiet,
        )
        engine.apply(svc_result)
        audited_ports.update(snap.ports)

    if not config.quiet:
        display_services_panorama(registry, ufw_numbered, loopback_only_ports,
                                   all_listening_ports, config, t)

    # ---- CHECK 4 — Listening ports ----
    if not config.quiet:
        print_section(t("sections.ports_analysis"))
    report.write_section(t("sections.ports_analysis"))

    ports_result = check_ports(
        ports_snapshot,
        audited_ports=audited_ports,
        network_context=network_context,
        default_incoming_policy=fw_status.incoming_policy,
        t=t,
    )
    engine.apply(ports_result)
    display_result(ports_result, report, config.verbose, quiet=config.quiet)
    display_ports_overview(ports_snapshot, config, t, report, output)

    # ---- CHECK 5 — UFW log analysis ----
    if not config.quiet:
        print_section(t("sections.logs"))

    logs_snapshot = LogsSnapshot.from_system(log_days=config.log_days)
    display_geoip_notice(geoip2_status(), t, output)
    logs_result = check_logs(logs_snapshot, audited_ports=audited_ports, t=t)
    engine.apply(logs_result)
    display_log_results(logs_result, logs_snapshot, config, t, report)

    # ---- CHECK 6 — DDNS / external exposure ----
    if not config.quiet:
        print_section(t("sections.ddns"))
    report.write_section(t("sections.ddns"))

    ddns_snapshot = DdnsSnapshot.from_system()
    ddns_result   = check_ddns(
        ddns_snapshot, ufw_rules=ufw_numbered, t=t,
        loopback_ports=loopback_only_ports,
        active_ports=active_external_ports,
    )
    engine.apply(ddns_result)
    display_result(ddns_result, report, config.verbose, quiet=config.quiet)
    for port in ddns_result.open_ports:
        output.print_dim(f"  → {port}")

    # ---- CHECK 7 — Docker ----
    if not config.quiet:
        print_section(t("sections.docker"))
    report.write_section(t("sections.docker"))

    docker_snapshot = DockerSnapshot.from_system()
    docker_result   = check_docker(docker_snapshot, network_context=network_context, t=t)
    engine.apply(docker_result)
    display_result(docker_result, report, config.verbose, quiet=config.quiet)

    if docker_snapshot.exposed_ports:
        output.print_dim(t("docker.exposed_ports") + " :")
        for port in docker_snapshot.exposed_ports:
            safe_name = output.sanitize(port.container_name, max_len=128)
            output.print_dim(
                f"  {safe_name}: {port.port_proto} → "
                f"{port.container_port}/{port.proto}"
            )
    if not config.quiet:
        print()

    # ---- CHECK 8 — Virtualisation ----
    if not config.quiet:
        print_section(t("sections.virtualization"))
    report.write_section(t("sections.virtualization"))

    virt_snapshot = VirtSnapshot.from_system()
    virt_result   = check_virtualization(virt_snapshot, t=t)
    engine.apply(virt_result)
    display_result(virt_result, report, config.verbose, quiet=config.quiet)
    if not config.quiet:
        print()

    return ChecksResult(snapshots=snapshots, ports_snapshot=ports_snapshot)
