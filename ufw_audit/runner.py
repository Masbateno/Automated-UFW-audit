"""Audit runner — sequentially executes all audit checks."""

from __future__ import annotations

from typing import NamedTuple

from ufw_audit import output
from ufw_audit.cli import AuditConfig
from ufw_audit.config import UserConfig
from ufw_audit.profiles import AuditProfile, apply_profile
from ufw_audit.display import (
    check_single_service_display,
    display_geoip_notice,
    display_log_results,
    display_network_context,
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
from ufw_audit.checks.firewall_stack import FirewallStackSnapshot, check_firewall_stack
from ufw_audit.checks.network_context import NetworkContextSnapshot, check_network_context
from ufw_audit.checks.logs import LogsSnapshot, check_logs, geoip2_status
from ufw_audit.checks.ports import PortsSnapshot, check_ports
from ufw_audit.checks.services import ServiceSnapshot
from ufw_audit.checks.virtualization import VirtSnapshot, check_virtualization
from ufw_audit.checks.hardening import HardeningSnapshot, check_hardening
from ufw_audit.checks.ipv6 import IPv6Snapshot, check_ipv6
from ufw_audit.checks.ssh import SSHSnapshot, check_ssh
from ufw_audit.checks.file_perms import FilePermsSnapshot, check_file_perms
from ufw_audit.checks.updates import UpdatesSnapshot, check_updates
from ufw_audit.checks.kernel_modules import KernelModulesSnapshot, check_kernel_modules
from ufw_audit.checks.cron_audit import CronAuditSnapshot, check_cron_audit
from ufw_audit.checks.services_state import ServicesStateSnapshot, check_services_state
from ufw_audit.plugin_checks import load_plugin_checks


class ChecksResult(NamedTuple):
    snapshots:          list
    ports_snapshot:     PortsSnapshot
    stack_snapshot:     FirewallStackSnapshot
    net_snapshot:       NetworkContextSnapshot
    hardening_snapshot: HardeningSnapshot
    ipv6_snapshot:      IPv6Snapshot


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
    profile: AuditProfile | None = None,
) -> ChecksResult:
    """Run all audit checks in sequence."""

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

    # ---- CHECK 2b — Firewall stack analysis ----
    if not config.quiet:
        print_section(t("sections.firewall_stack"))
    report.write_section(t("sections.firewall_stack"))

    stack_snapshot = FirewallStackSnapshot.from_system()
    stack_result   = check_firewall_stack(stack_snapshot, t=t)
    engine.apply(stack_result)
    display_result(stack_result, report, config.verbose, quiet=config.quiet)
    if not config.quiet:
        print()

    # ---- CHECK 2c — Network context (interfaces + connections) ----
    if not config.quiet:
        print_section(t("sections.network_context"))
    report.write_section(t("sections.network_context"))

    net_snapshot = NetworkContextSnapshot.from_system()
    net_result   = check_network_context(net_snapshot, t=t)
    engine.apply(net_result)
    display_result(net_result, report, config.verbose, quiet=config.quiet)
    if not config.quiet:
        display_network_context(net_snapshot, t, output)

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

    # ---- CHECK 9 — System hardening ----
    hardening_snapshot = HardeningSnapshot.from_system()
    if profile is None or not profile.should_skip_section("hardening"):
        if not config.quiet:
            print_section(t("sections.hardening"))
        report.write_section(t("sections.hardening"))
        hardening_result = check_hardening(hardening_snapshot, t=t)
        if profile is not None:
            apply_profile(hardening_result, profile)
        engine.apply(hardening_result)
        display_result(hardening_result, report, config.verbose, quiet=config.quiet)
        if not config.quiet:
            print()

    # ---- CHECK 10 — IPv6 consistency ----
    ipv6_snapshot = IPv6Snapshot.from_system()
    if profile is None or not profile.should_skip_section("ipv6"):
        if not config.quiet:
            print_section(t("sections.ipv6"))
        report.write_section(t("sections.ipv6"))
        ipv6_result = check_ipv6(ipv6_snapshot, t=t)
        if profile is not None:
            apply_profile(ipv6_result, profile)
        engine.apply(ipv6_result)
        display_result(ipv6_result, report, config.verbose, quiet=config.quiet)
        if not config.quiet:
            print()

    # ---- CHECK 11 — SSH security ----
    ssh_snapshot = SSHSnapshot.from_system()
    if profile is None or not profile.should_skip_section("ssh"):
        if not config.quiet:
            print_section(t("sections.ssh"))
        report.write_section(t("sections.ssh"))
        ssh_result = check_ssh(ssh_snapshot, t=t)
        if profile is not None:
            apply_profile(ssh_result, profile)
        engine.apply(ssh_result)
        display_result(ssh_result, report, config.verbose, quiet=config.quiet)
        if not config.quiet:
            print()

    # ---- CHECK 12 — Sensitive file permissions + sudoers ----
    file_perms_snapshot = FilePermsSnapshot.from_system()
    if profile is None or not profile.should_skip_section("file_perms"):
        if not config.quiet:
            print_section(t("sections.file_perms"))
        report.write_section(t("sections.file_perms"))
        file_perms_result = check_file_perms(file_perms_snapshot, t=t)
        if profile is not None:
            apply_profile(file_perms_result, profile)
        engine.apply(file_perms_result)
        display_result(file_perms_result, report, config.verbose, quiet=config.quiet)
        if not config.quiet:
            print()

    # ---- CHECK 13 — System updates ----
    updates_snapshot = UpdatesSnapshot.from_system()
    if profile is None or not profile.should_skip_section("updates"):
        if not config.quiet:
            print_section(t("sections.updates"))
        report.write_section(t("sections.updates"))
        updates_result = check_updates(updates_snapshot, t=t)
        if profile is not None:
            apply_profile(updates_result, profile)
        engine.apply(updates_result)
        display_result(updates_result, report, config.verbose, quiet=config.quiet)
        if not config.quiet:
            print()

    # ---- CHECK 14 — Kernel module audit ----
    kernel_modules_snapshot = KernelModulesSnapshot.from_system()
    if profile is None or not profile.should_skip_section("kernel_modules"):
        if not config.quiet:
            print_section(t("sections.kernel_modules"))
        report.write_section(t("sections.kernel_modules"))
        kernel_modules_result = check_kernel_modules(kernel_modules_snapshot, t=t)
        if profile is not None:
            apply_profile(kernel_modules_result, profile)
        engine.apply(kernel_modules_result)
        display_result(kernel_modules_result, report, config.verbose, quiet=config.quiet)
        if not config.quiet:
            print()

    # ---- CHECK 15 — Cron job audit ----
    cron_audit_snapshot = CronAuditSnapshot.from_system()
    if profile is None or not profile.should_skip_section("cron_audit"):
        if not config.quiet:
            print_section(t("sections.cron_audit"))
        report.write_section(t("sections.cron_audit"))
        cron_audit_result = check_cron_audit(cron_audit_snapshot, t=t)
        if profile is not None:
            apply_profile(cron_audit_result, profile)
        engine.apply(cron_audit_result)
        display_result(cron_audit_result, report, config.verbose, quiet=config.quiet)
        if not config.quiet:
            print()

    # ---- CHECK 16 — Service state audit ----
    services_state_snapshot = ServicesStateSnapshot.from_system()
    if profile is None or not profile.should_skip_section("services_state"):
        if not config.quiet:
            print_section(t("sections.services_state"))
        report.write_section(t("sections.services_state"))
        services_state_result = check_services_state(services_state_snapshot, t=t)
        if profile is not None:
            apply_profile(services_state_result, profile)
        engine.apply(services_state_result)
        display_result(services_state_result, report, config.verbose, quiet=config.quiet)
        if not config.quiet:
            print()

    # ---- Plugin checks (user-defined, checks.d/) ----
    for plugin in load_plugin_checks():
        if profile is not None and profile.should_skip_section(plugin.name.lower()):
            continue
        if not config.quiet:
            print_section(plugin.name)
        report.write_section(plugin.name)
        plugin_result = plugin.run(t)
        if profile is not None:
            apply_profile(plugin_result, profile)
        engine.apply(plugin_result)
        display_result(plugin_result, report, config.verbose, quiet=config.quiet)
        if not config.quiet:
            print()

    return ChecksResult(
        snapshots=snapshots,
        ports_snapshot=ports_snapshot,
        stack_snapshot=stack_snapshot,
        net_snapshot=net_snapshot,
        hardening_snapshot=hardening_snapshot,
        ipv6_snapshot=ipv6_snapshot,
    )
