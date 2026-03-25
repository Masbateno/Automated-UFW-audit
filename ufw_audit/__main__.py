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

VERSION = "0.13.0b"

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


# Global quiet flag — set after parse_args, used by output helpers
_QUIET = False


def _out(*args, **kwargs):
    """Print only if not in quiet mode."""
    if not _QUIET:
        print(*args, **kwargs)


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

    # --- Set quiet mode globally ---
    global _QUIET
    _QUIET = config.quiet

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

    if config.remove_cron:
        from ufw_audit.cron import run_remove_cron
        return run_remove_cron(config, t)

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
        output.print_info(t("report.title") if False else "Démarrage de l'audit"
                          if config.lang == "fr" else "Starting audit")
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

    _display_result(fw_result, report, config.verbose)

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
    _display_result(rules_result, report, config.verbose)

    # ======================================================================
    # CHECK 3 — Network services
    # ======================================================================
    from ufw_audit.checks.services import ServiceSnapshot, check_services
    from ufw_audit.output import (
        print_service_header, print_port_detail, print_risk_context,
    )

    if not config.quiet:
        print_section(t("sections.services"))
    report.write_section(t("sections.services"))

    snapshots = ServiceSnapshot.collect(registry, ufw_rules=ufw_numbered)
    audited_ports: set[str] = set()

    for snap in snapshots:
        if not config.quiet:
            print_service_header(snap.label)
        report.write_raw(f"\n  > {snap.label}")

        # Risk context for high/critical active services
        if snap.service.is_high_or_critical and snap.is_active:
            from ufw_audit.checks.logs import get_ip_geo  # reuse geo module
            _display_risk_context(snap.service.label, config.lang, t, report)

        # Per-service result
        svc_result = _check_single_service_display(
            snap, network_context, t, report, config.verbose
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
        all_snaps = _SS.collect_all(registry, ufw_rules=ufw_numbered)
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
    from ufw_audit.checks.ports import PortsSnapshot, check_ports

    if not config.quiet:
        print_section(t("sections.ports_analysis"))
    report.write_section(t("sections.ports_analysis"))

    ports_snapshot = PortsSnapshot.from_system()
    ports_result   = check_ports(
        ports_snapshot,
        audited_ports=audited_ports,
        network_context=network_context,
        t=t,
    )
    engine.apply(ports_result)
    _display_result(ports_result, report, config.verbose)

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

    _display_log_results(logs_result, logs_snapshot, config, t, report)

    # ======================================================================
    # CHECK 6 — DDNS / external exposure
    # ======================================================================
    from ufw_audit.checks.ddns import DdnsSnapshot, check_ddns

    if not config.quiet:
        print_section(t("sections.ddns"))
    report.write_section(t("sections.ddns"))

    ddns_snapshot = DdnsSnapshot.from_system()
    ddns_result   = check_ddns(ddns_snapshot, ufw_rules=ufw_numbered, t=t)
    engine.apply(ddns_result)
    _display_result(ddns_result, report, config.verbose)

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
    _display_result(docker_result, report, config.verbose)

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
    _display_result(virt_result, report, config.verbose)
    if not config.quiet:
        print()

    # Summary
    # ======================================================================
    engine.finalize()
    if not config.quiet:
        _print_summary(engine, network_context, public_ip, config, t, report, snapshots)

    # Finalise report
    report.write_risk_context_section(
        section_title=t("sections.risk_context"),
        entries=_build_risk_context_entries(snapshots, config.lang, t),
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
# Display helpers
# ---------------------------------------------------------------------------

def _display_result(result, report, verbose: bool) -> None:
    """Print all findings from a CheckResult to terminal and report."""
    from ufw_audit.scoring import FindingLevel
    from ufw_audit.output import (
        print_ok, print_warn, print_alert, print_info, print_recommendation,
    )

    for finding in result.findings:
        if _QUIET:
            # In quiet mode only write to report, no terminal output
            level_str = finding.level.value.upper()
            report.write_finding(level_str, finding.message)
            continue
        if finding.level == FindingLevel.OK:
            print_ok(finding.message)
            report.write_finding("OK", finding.message)
        elif finding.level == FindingLevel.WARN:
            print_warn(finding.message)
            report.write_finding("WARN", finding.message)
            if finding.detail and verbose:
                print_recommendation(finding.detail)
        elif finding.level == FindingLevel.ALERT:
            print_alert(finding.message)
            report.write_finding("ALERT", finding.message)
            if finding.detail:
                print_recommendation(finding.detail)
            elif finding.cmd and verbose:
                print_recommendation(finding.cmd)
        elif finding.level == FindingLevel.INFO:
            print_info(finding.message)
            report.write_finding("INFO", finding.message)


def _display_risk_context(label: str, lang: str, t, report) -> None:
    """Display two-axis risk context for a high/critical service."""
    from ufw_audit.checks.services import _identity_t

    # Build context strings inline using the risk_context data from registry
    # (same data as bash's get_risk_context())
    # For now delegate to the service-specific strings in locales
    exposure_key = f"risk_context.exposure"
    threat_key   = f"risk_context.threat"

    # We store risk context text in locales under service-specific keys
    # e.g. "service_risk.ssh.exposure" — fall back gracefully if not found
    svc_id = label.lower().replace(" ", "_").replace("/", "_").replace("(", "").replace(")", "")
    exposure = t(f"service_risk.{svc_id}.exposure")
    threat   = t(f"service_risk.{svc_id}.threat")
    level    = t(f"service_risk.{svc_id}.level")

    # If keys not yet in locales, skip display
    if exposure.startswith("["):
        return

    is_critical = "critical" in level.lower() or "critique" in level.lower()
    from ufw_audit.output import print_risk_context
    print_risk_context(
        title=t("risk_context.title"),
        level=level,
        exposure_label=t("risk_context.exposure"),
        exposure=exposure,
        threat_label=t("risk_context.threat"),
        threat=threat,
        is_critical=is_critical,
    )
    report.write_finding("INFO",
                         f"[{t('risk_context.title')} — {level}] {exposure}")


def _check_single_service_display(snap, network_context, t, report, verbose):
    """Run check for a single service and return its CheckResult."""
    from ufw_audit.checks.services import check_services
    result = check_services([snap], network_context=network_context, t=t)
    _display_result(result, report, verbose)
    return result


def _display_log_results(logs_result, snapshot, config, t, report) -> None:
    """Display structured log analysis results."""
    from ufw_audit.checks.logs import get_ip_geo
    from ufw_audit.output import print_ok, print_warn, print_info, print_dim

    if not hasattr(logs_result, "_log_data"):
        _display_result(logs_result, report, config.verbose)
        return

    data = logs_result._log_data

    print_dim(
        f"{t('logs.period')} : {data['log_days']} {t('logs.days_unit')} "
        f"— {data['days_available']} {t('logs.days_available')}"
    )
    print()

    total = data["total"]
    if total == 0:
        print_ok(t("logs.empty"))
        return

    # Verdict line — one clear sentence before the details
    brute_hits = data.get("brute_hits", [])
    if brute_hits:
        print_warn(t("logs.verdict_warn", total=total, days=data["log_days"]))
    else:
        print_ok(t("logs.verdict_ok", total=total, days=data["log_days"]))

    # Bruteforce findings
    for finding in logs_result.findings:
        from ufw_audit.scoring import FindingLevel
        if finding.level == FindingLevel.WARN:
            print_warn(finding.message)

    # Top IP
    if data["top_ips"]:
        top_ip, top_count = data["top_ips"][0]
        geo = get_ip_geo(top_ip, lang=config.lang)
        geo_str = f" ({geo})" if geo else ""
        print_info(
            f"{t('logs.top_ips')} : {top_ip}{geo_str} "
            f"— {top_count} {t('logs.attempts')}"
        )

    # Top port
    if data["top_ports"]:
        top_port, top_count = data["top_ports"][0]
        print_info(
            f"{t('logs.top_ports')} : {top_port} "
            f"— {top_count} {t('logs.attempts')}"
        )

    # Service hits
    if data["svc_hits"]:
        print()
        print_warn(t("logs.svc_hits") + " :")
        for pp, count in data["svc_hits"].items():
            print_dim(f"  → {pp} — {count} {t('logs.attempts')}")

    print()

    # Detailed report
    if config.detailed:
        report.write_section(
            f"{t('sections.logs')} — {t('logs.period')} : "
            f"{data['log_days']} {t('logs.days_unit')}"
        )
        report.write_raw(f"{t('logs.total_blocks')} : {total}")
        report.write_raw(f"{t('logs.days_available')}    : {data['days_available']}")
        report.write_raw("")
        report.write_raw(f"--- {t('logs.top_ips')} ---")
        for ip, count in data["top_ips"]:
            geo = get_ip_geo(ip, lang=config.lang)
            geo_str = f" ({geo})" if geo else ""
            report.write_raw(f"  {ip:<20}{geo_str:<30} {count} {t('logs.attempts')}")
        report.write_raw("")
        report.write_raw(f"--- {t('logs.top_ports')} ---")
        for port, count in data["top_ports"]:
            report.write_raw(f"  {port:<12} {count} {t('logs.attempts')}")
        report.write_raw("")
        report.write_raw(f"--- {t('logs.brute_title')} ---")
        if data["brute_hits"]:
            for hit in data["brute_hits"]:
                geo = get_ip_geo(hit.src_ip, lang=config.lang)
                geo_str = f" ({geo})" if geo else ""
                report.write_raw(
                    f"  {hit.src_ip:<20}{geo_str:<30}"
                    f" {hit.port_proto:<12} {hit.count} {t('logs.attempts')}"
                )
        else:
            report.write_raw(f"  {t('logs.brute_none')}")
        report.write_raw("")
        report.write_raw(f"--- {t('logs.svc_hits')} ---")
        if data["svc_hits"]:
            for pp, count in data["svc_hits"].items():
                report.write_raw(f"  {pp} {count} {t('logs.attempts')}")
        else:
            report.write_raw(f"  {t('logs.svc_hits_none')}")
        report.write_raw("")


def _print_summary(engine, network_context, public_ip, config, t, report, snapshots) -> None:
    """Print the audit summary box and write to report."""
    from ufw_audit.output import print_summary_box
    from ufw_audit.scoring import RiskLevel

    score = engine.score
    level = engine.level

    level_str = t(f"scoring.level.{level.value}")
    ctx_str   = t(f"scoring.context.{network_context}")

    # Risk icon
    icon = "✔" if level == RiskLevel.LOW else "✖"

    lines = [
        (t("scoring.score_label"), f"{score}/10"),
        (t("scoring.risk_label"),  f"{icon} {level_str}"),
        (t("scoring.network_context"), f"{'🏠' if network_context == 'local' else '🌐'} {ctx_str}"),
    ]

    # Categorise findings
    action_items      = [f for f in engine.findings
                         if f.nature == "action"]
    improvement_items = [f for f in engine.findings
                         if f.nature == "improvement"]
    structural_items  = [f for f in engine.findings
                         if f.nature == "structural"]

    if action_items or improvement_items or structural_items:
        if action_items:
            lines.append(("---", ""))
            lines.append((f"✖ {t('summary.block_action')}", ""))
            for item in action_items:
                msg = item.message[:48] + "…" if len(item.message) > 48 else item.message
                lines.append((f"  ✖  {msg}", ""))
        if improvement_items:
            lines.append(("---", ""))
            lines.append((f"⚠ {t('summary.block_improve')}", ""))
            for item in improvement_items:
                msg = item.message[:48] + "…" if len(item.message) > 48 else item.message
                lines.append((f"  ⚠  {msg}", ""))
        if structural_items:
            lines.append(("---", ""))
            lines.append((f"ℹ {t('summary.block_normal')}", ""))
            for item in structural_items:
                msg = item.message[:48] + "…" if len(item.message) > 48 else item.message
                lines.append((f"  ℹ  {msg}", ""))

    if engine.breakdown or engine.cap_info:
        lines.append(("---", ""))
        lines.append((t("scoring.breakdown_title"), ""))
        for ded in engine.breakdown:
            if ded.points == 0:
                continue  # skip zero-point sentinel deductions
            reason = ded.reason[:44] + "…" if len(ded.reason) > 44 else ded.reason
            lines.append((f"  -{ded.points}  {reason}", ""))
        if engine.cap_info:
            cap_note = t("scoring.cap_note", max=engine.cap_info.maximum)
            lines.append((f"  ⚠  {cap_note}", ""))

    print_summary_box(lines)
    print()

    # Interpretation phrase
    if not action_items and not improvement_items:
        print(f"  {t('summary.clean')}")
    elif not action_items:
        print(f"  {t('summary.warnings')}")
    else:
        print(f"  {t('summary.alerts')}")

    # Implicit policy note
    implicit_svcs = [
        snap.label for snap in snapshots
        if snap.is_active
        and snap.service.is_high_or_critical
        and all(e.value == "no_rule" for e in snap.exposures.values())
    ]
    if implicit_svcs:
        print()
        print(f"  ℹ {t('summary.implicit_policy')}")
        print(f"    {t('summary.implicit_svcs')} : {', '.join(implicit_svcs)}")

    # Scope disclaimer — always displayed regardless of score
    print()
    print(f"  ℹ {t('summary.scope_line1')}")
    print(f"  ℹ {t('summary.scope_line2')}")

    if config.detailed:
        from ufw_audit.report import AuditReport
        # report path already printed at start

    # Write summary to report
    report.write_summary(
        score=score,
        risk_level=level_str,
        network_context=ctx_str,
        public_ip=public_ip or "",
        ok_count=engine.ok_count,
        warn_count=engine.warn_count,
        alert_count=engine.alert_count,
        breakdown=engine.breakdown,
        labels={
            "summary":   "AUDIT SUMMARY",
            "breakdown": t("scoring.breakdown_title"),
        },
    )


def _build_risk_context_entries(snapshots, lang: str, t) -> list[dict]:
    """Build risk context entries for the report from active high/critical services."""
    entries = []
    for snap in snapshots:
        if not snap.service.is_high_or_critical:
            continue
        if not snap.is_active:
            continue
        svc_id = (snap.service.label.lower()
                  .replace(" ", "_").replace("/", "_")
                  .replace("(", "").replace(")", ""))
        exposure = t(f"service_risk.{svc_id}.exposure")
        threat   = t(f"service_risk.{svc_id}.threat")
        level    = t(f"service_risk.{svc_id}.level")
        if exposure.startswith("["):
            continue
        entries.append({
            "label":          snap.service.label,
            "level":          level,
            "exposure_label": t("risk_context.exposure"),
            "exposure":       exposure,
            "threat_label":   t("risk_context.threat"),
            "threat":         threat,
        })
    return entries



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
        ("--remove-cron",      "Deprecated — use --manage-cron instead"),
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