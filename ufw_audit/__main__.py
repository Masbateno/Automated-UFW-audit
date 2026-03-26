"""
ufw-audit entry point and audit orchestrator.

Initialises all modules, runs checks in sequence, and coordinates
output to the terminal and the optional detailed report file.

Run as:
    sudo ufw-audit [OPTIONS]
    sudo python -m ufw_audit [OPTIONS]
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

VERSION = "0.15"

# Exit codes
EXIT_OK       = 0  # clean audit — no alerts, no warnings
EXIT_WARNINGS = 1  # warnings detected
EXIT_ALERTS   = 2  # alerts detected (action required)
EXIT_ERROR    = 3  # technical error


# ---------------------------------------------------------------------------
# Bootstrap — must happen before any other import that uses these modules
# ---------------------------------------------------------------------------

def _bootstrap() -> None:
    """Ensure we are running as root."""
    if os.geteuid() != 0:
        print("This script must be run as root: sudo ufw-audit", file=sys.stderr)
        sys.exit(EXIT_ERROR)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    """
    Main audit orchestrator.

    Args:
        argv: Argument list. Defaults to sys.argv[1:].

    Returns:
        Exit code: 0 on success, 1 on error.
    """
    # --- Parse arguments ---
    from ufw_audit.cli import AuditConfig, CLIError, parse_args
    try:
        config = parse_args(argv)
    except CLIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # --- Handle --version and --help before root check ---
    if config.show_version:
        print(f"ufw-audit v{VERSION}")
        return 0

    if config.show_help:
        from ufw_audit import i18n, output
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        _print_help(i18n.t)
        return 0

    # --- Root check — required for all modes ---
    _bootstrap()

    # --- Initialise i18n ---
    from ufw_audit import i18n
    i18n.init(lang=config.lang)
    t = i18n.t

    # --- Initialise output ---
    from ufw_audit import output
    output.init(no_color=config.no_color, quiet=config.quiet)

    # --- Load registry ---
    from ufw_audit.registry import ServiceRegistry
    registry = ServiceRegistry.load()

    # --- Load user config ---
    from ufw_audit.config import UserConfig
    user_config = UserConfig.load()

    # --- Standalone modes ---
    if config.manage_logs:
        from ufw_audit.manage_logs import run_manage_logs
        return run_manage_logs(user_config, config, t)

    if config.install_cron:
        from ufw_audit.cron import run_install_cron
        return run_install_cron(user_config, config, t)

    if config.manage_cron:
        from ufw_audit.cron import run_manage_cron
        return run_manage_cron(config, t)

    if user_config.exists():
        output.print_info(t("config.found", path=str(user_config.path)))
        output.print_dim(t("config.reconfigure_hint"))
    print()

    # --- Initialise report ---
    from ufw_audit.report import AuditReport, SystemInfo
    if config.detailed:
        from ufw_audit.manage_logs import get_or_prompt_log_dir
        log_dir = get_or_prompt_log_dir(user_config, config, t)
        report = AuditReport.open(directory=log_dir, version=VERSION)
        output.print_ok(f"Rapport détaillé : {report.path}" if config.lang == "fr"
                        else f"Detailed report: {report.path}")
        print()
    else:
        report = AuditReport.null()

    # --- Initialise scoring engine ---
    from ufw_audit.scoring import ScoreEngine
    engine = ScoreEngine()

    # --- System information ---
    from ufw_audit.sysinfo import collect_system_info
    sys_info = collect_system_info(VERSION, config.lang)
    report.write_header(sys_info)

    # --- Print banner (suppressed in quiet mode) ---
    if not config.quiet:
        from ufw_audit.output import print_banner
        print_banner(
            version=f"v{VERSION}",
            subtitle=t("banner.subtitle"),
            system=sys_info.os_name,
            host=sys_info.hostname,
            ufw_version=sys_info.ufw_version,
            user=sys_info.user,
            date=datetime.now().strftime("%d/%m/%Y %H:%M"),
            labels={k: t(f"banner.{k}") for k in
                    ("system", "host", "ufw", "user", "date")},
        )
        output.print_info("Démarrage de l'audit" if config.lang == "fr" else "Starting audit")
        print()

    report.write_finding("INFO", "Starting audit")

    # --- Detect network context ---
    from ufw_audit.sysinfo import detect_network_context
    network_context, public_ip = detect_network_context()

    # ======================================================================
    # CHECK 1 — Firewall status
    # ======================================================================
    from ufw_audit.output import print_section
    from ufw_audit.checks.firewall import FirewallStatus, check_firewall

    if not config.quiet:
        print_section(t("sections.firewall"))
    report.write_section(t("sections.firewall"))

    fw_status = FirewallStatus.from_system()
    fw_result = check_firewall(fw_status, t=t)
    engine.apply(fw_result)

    # Handle firewall inactive cap
    if getattr(fw_result, "_firewall_inactive", False):
        engine.cap(maximum=3, reason=t("firewall.inactive"))

    from ufw_audit.display import display_result
    display_result(fw_result, report, config.verbose, quiet=config.quiet)

    # Write UFW status output to report
    if fw_status.ufw_output:
        report.write_section("UFW STATUS")
        report.write_raw(fw_status.ufw_output)

    # ======================================================================
    # CHECK 2 — UFW rules
    # ======================================================================
    from ufw_audit.checks.firewall import _run as fw_run
    ufw_numbered = fw_run("ufw", "status", "numbered")
    ufw_verbose  = fw_run("ufw", "status", "verbose")

    if not config.quiet:
        print_section(t("sections.rules"))
    report.write_section(t("sections.rules"))

    from ufw_audit.checks.firewall import check_rules
    rules_result = check_rules(ufw_verbose, ufw_numbered, t)
    engine.apply(rules_result)
    from ufw_audit.display import display_result
    display_result(rules_result, report, config.verbose, quiet=config.quiet)

    # ======================================================================
    # CHECK 3 — Network services
    # ======================================================================
    from ufw_audit.checks.services import ServiceSnapshot, check_services
    from ufw_audit.output import (
        print_service_header, print_port_detail, print_risk_context,
    )

    # Collect listening ports early so we can cross-check actual socket
    # bindings before classifying service exposure — prevents false positives
    # for services bound only to 127.0.0.1 with an open UFW rule.
    from ufw_audit.checks.ports import PortsSnapshot, check_ports
    from collections import defaultdict as _defaultdict
    ports_snapshot = PortsSnapshot.from_system()
    _port_bindings: dict = _defaultdict(list)
    for _lp in ports_snapshot.ports:
        _port_bindings[f"{_lp.port}/{_lp.proto}"].append(_lp)
    loopback_only_ports: set = {
        pp for pp, lps in _port_bindings.items()
        if all(lp.is_loopback for lp in lps)
    }
    # Ports with at least one non-loopback listener — used to exclude
    # dangling UFW rules (no active service) from DDNS exposure reporting.
    active_external_ports: set = {
        f"{_lp.port}/{_lp.proto}"
        for _lp in ports_snapshot.ports
        if not _lp.is_loopback
    }

    if not config.quiet:
        print_section(t("sections.services"))
    report.write_section(t("sections.services"))

    snapshots = ServiceSnapshot.collect(
        registry, ufw_rules=ufw_numbered, loopback_ports=loopback_only_ports
    )
    audited_ports: set[str] = set()

    for snap in snapshots:
        if not config.quiet:
            print_service_header(snap.label)
        report.write_raw(f"\n  > {snap.label}")

        # Risk context for high/critical active services
        if snap.service.is_high_or_critical and snap.is_active:
            from ufw_audit.checks.logs import get_ip_geo  # reuse geo module
            from ufw_audit.display import display_risk_context
            display_risk_context(snap.service.label, config.lang, t, report)

        # Per-service result
        from ufw_audit.display import check_single_service_display
        svc_result = check_single_service_display(
            snap, network_context, t, report, config.verbose, quiet=config.quiet
        )
        engine.apply(svc_result)

        # Track audited ports
        for port in snap.ports:
            audited_ports.add(port)

    # --- Services panorama (all known services, installed or not) ---
    if not config.quiet:
        from ufw_audit.output import print_services_panorama
        from ufw_audit.checks.services import ServiceSnapshot as _SS, Exposure, ServiceState
        print_section(t("sections.services_panorama"))
        all_snaps = _SS.collect_all(registry, ufw_rules=ufw_numbered, loopback_ports=loopback_only_ports)
        from ufw_audit.panorama import build_panorama_rows
        panorama_rows = build_panorama_rows(all_snaps)
        panorama_labels = {
            "header_service": t("services.panorama.header_service"),
            "header_status":  t("services.panorama.header_status"),
            "header_ports":   t("services.panorama.header_ports"),
            "header_ufw":     t("services.panorama.header_ufw"),
            "active":         t("services.panorama.active"),
            "inactive":       t("services.panorama.inactive"),
            "not_installed":  t("services.panorama.not_installed"),
            "unknown":        t("services.panorama.unknown"),
        }
        print_services_panorama(panorama_rows, panorama_labels)
        print()

    # ======================================================================
    # CHECK 4 — Listening ports
    # ======================================================================
    # ports_snapshot was already collected before CHECK 3 for loopback detection

    if not config.quiet:
        print_section(t("sections.ports_analysis"))
    report.write_section(t("sections.ports_analysis"))

    ports_result   = check_ports(
        ports_snapshot,
        audited_ports=audited_ports,
        network_context=network_context,
        t=t,
    )
    engine.apply(ports_result)
    from ufw_audit.display import display_result
    display_result(ports_result, report, config.verbose, quiet=config.quiet)

    print_section(t("sections.ports_overview"))
    report.write_section(t("sections.ports_overview"))
    output.print_info(t("ports.listening_count", count=len(ports_snapshot.ports)))
    report.write_finding("INFO", t("ports.listening_count",
                                   count=len(ports_snapshot.ports)))
    if ports_snapshot.ss_output:
        report.write_raw("")
        report.write_raw(ports_snapshot.ss_output)
        if config.verbose:
            output.print_dim(t("ports.listening_detail"))
            print()
            print(ports_snapshot.ss_output)
        else:
            output.print_dim(t("ports.listening_verbose_hint"))
    print()

    # ======================================================================
    # CHECK 5 — UFW log analysis
    # ======================================================================
    from ufw_audit.checks.logs import LogsSnapshot, check_logs, get_ip_geo

    if not config.quiet:
        print_section(t("sections.logs"))

    logs_snapshot = LogsSnapshot.from_system(log_days=config.log_days)

    # One-time GeoIP2 availability notice
    from ufw_audit.checks.logs import geoip2_status
    geo_status = geoip2_status()
    if geo_status == "unavailable":
        output.print_info(
            t("logs.geoip2_unavailable") if not t("logs.geoip2_unavailable").startswith("[")
            else "GeoIP2 not available — install python3-geoip2 for IP geolocation"
        )
    elif geo_status == "no_database":
        output.print_info(
            t("logs.geoip2_no_db") if not t("logs.geoip2_no_db").startswith("[")
            else "GeoIP2 installed but no GeoLite2 database found"
        )

    logs_result   = check_logs(logs_snapshot, audited_ports=audited_ports, t=t)
    engine.apply(logs_result)

    from ufw_audit.display import display_log_results
    display_log_results(logs_result, logs_snapshot, config, t, report)

    # ======================================================================
    # CHECK 6 — DDNS / external exposure
    # ======================================================================
    from ufw_audit.checks.ddns import DdnsSnapshot, check_ddns

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
    from ufw_audit.display import display_result
    display_result(ddns_result, report, config.verbose, quiet=config.quiet)

    if hasattr(ddns_result, "_ddns_open_ports") and ddns_result._ddns_open_ports:
        for port in ddns_result._ddns_open_ports:
            output.print_dim(f"  → {port}")

    # ======================================================================
    # CHECK 7 — Docker
    # ======================================================================
    from ufw_audit.checks.docker import DockerSnapshot, check_docker

    if not config.quiet:
        print_section(t("sections.docker"))
    report.write_section(t("sections.docker"))

    docker_snapshot = DockerSnapshot.from_system()
    docker_result   = check_docker(docker_snapshot,
                                   network_context=network_context, t=t)
    engine.apply(docker_result)
    from ufw_audit.display import display_result
    display_result(docker_result, report, config.verbose, quiet=config.quiet)

    if docker_snapshot.exposed_ports:
        output.print_dim(t("docker.exposed_ports") + " :")
        for port in docker_snapshot.exposed_ports:
            safe_name = output.sanitize(port.container_name, max_len=128)
            output.print_dim(
                f"  {safe_name}: {port.port_proto} → "
                f"{port.container_port}/{port.proto}"
            )
    print()

    # ======================================================================
    # --- Virtualisation check ---
    from ufw_audit.checks.virtualization import VirtSnapshot, check_virtualization
    from ufw_audit.output import print_section as _print_section
    virt_snapshot = VirtSnapshot.from_system()
    virt_result   = check_virtualization(virt_snapshot, t=t)
    engine.apply(virt_result)
    if not config.quiet:
        _print_section(t("sections.virtualization"))
    report.write_section(t("sections.virtualization"))
    from ufw_audit.display import display_result
    display_result(virt_result, report, config.verbose, quiet=config.quiet)
    if not config.quiet:
        print()

    # Summary
    # ======================================================================
    engine.finalize()
    if not config.quiet:
        from ufw_audit.display import print_audit_summary
        print_audit_summary(engine, network_context, public_ip, config, t, report, snapshots)

    # Finalise report
    from ufw_audit.display import build_risk_context_entries
    report.write_risk_context_section(
        section_title=t("sections.risk_context"),
        entries=build_risk_context_entries(snapshots, config.lang, t),
    )
    report.write_next_steps([
        t("report.next_1"),
        t("report.next_2"),
        t("report.next_3"),
    ])
    report.close()

    # --fix mode
    if config.fix:
        from ufw_audit.fixes import run_fixes
        run_fixes(engine, config, t)

    # Exit code based on audit results
    if engine.alert_count > 0:
        return EXIT_ALERTS
    elif engine.warn_count > 0:
        return EXIT_WARNINGS
    else:
        return EXIT_OK



# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------


def _print_help(t) -> None:
    W = 62
    print(f"ufw-audit v{VERSION} — UFW firewall audit tool")
    print()
    print("Usage: sudo ufw-audit [OPTIONS]")
    print()
    print("Options:")
    opts = [
        ("-v, --verbose",      "Show detailed port exposure for each service"),
        ("-d, --detailed",     "Save full audit report to a log file"),
        ("-q, --quiet",        "Suppress all output — use exit code to detect issues"),
        ("-f, --fix",          "Offer to apply automatic corrections after the audit"),
        ("-y, --yes",          "Auto-confirm all fixes with audit trail (use with -f)"),
        ("-r, --reconfigure",  "Reset saved port configuration and re-ask"),
        ("-n, --no-color",     "Disable colour output"),
        ("-j, --json",         "Export summary as JSON"),
        ("--json-full",        "Export full audit details as JSON"),
        ("-l N, --log-days=N", "Analyse the last N days of UFW logs (default: 7)"),
        ("-m, --manage-logs",  "List and delete saved audit reports"),
        ("-c, --install-cron", "Install an automated audit cron job (schedule wizard)"),
        ("--manage-cron",      "List, edit or delete installed cron jobs"),
        ("--french",           "Switch interface to French"),
        ("-V, --version",      "Show version and exit (no sudo required)"),
        ("-h, --help",         "Show this help message (no sudo required)"),
    ]
    col = 22
    for flag, desc in opts:
        print(f"  {flag:<{col}}  {desc}")
    print()
    print("Examples:")
    print("  sudo ufw-audit                  Standard audit")
    print("  sudo ufw-audit -v -d            Verbose + save report")
    print("  sudo ufw-audit --french -d      French + save report")
    print("  sudo ufw-audit -f               Audit + fix mode")
    print("  sudo ufw-audit --log-days=14    Analyse 14 days of logs")
    print()
    print("Exit codes (--quiet mode):")
    print("  0   Clean audit — no alerts, no warnings")
    print("  1   Warnings detected")
    print("  2   Alerts detected (action required)")
    print("  3   Technical error")
    print()
    print("Documentation: https://github.com/Masbateno/ufw-audit")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())