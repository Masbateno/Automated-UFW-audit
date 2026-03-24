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
        return _run_manage_logs(user_config, config, t)

    if config.install_cron:
        return _run_install_cron(user_config, config, t)

    if config.remove_cron:
        return _run_remove_cron(config, t)

    if config.manage_cron:
        return _run_manage_cron(config, t)

    if user_config.exists():
        output.print_info(t("config.found", path=str(user_config.path)))
        output.print_dim(t("config.reconfigure_hint"))
    print()

    # --- Initialise report ---
    from ufw_audit.report import AuditReport, SystemInfo
    if config.detailed:
        log_dir = _get_or_prompt_log_dir(user_config, config, t)
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
    sys_info = _collect_system_info(VERSION, config.lang)
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
    network_context, public_ip = _detect_network_context()

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

    rules_result = _check_rules(ufw_verbose, ufw_numbered, t)
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
        panorama_rows = _build_panorama_rows(all_snaps)
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
        _run_fixes(engine, config, t)

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
# UFW rules check (inline — lightweight, no separate module needed)
# ---------------------------------------------------------------------------

def _check_rules(ufw_verbose: str, ufw_numbered: str, t) -> "CheckResult":
    """Check UFW rules for duplicates, open-any, and IPv6 consistency."""
    from ufw_audit.scoring import CheckResult
    import re
    result = CheckResult()

    lines = [l for l in ufw_numbered.splitlines()
             if re.match(r"\s*\[\s*\d+\]", l)]

    # Duplicate check — exact and semantic (PORT/proto redundant when PORT exists)
    def _strip_comment(text: str) -> str:
        return re.sub(r"\s*#.*$", "", text).strip()

    def _rule_without_index(line: str) -> str:
        return re.sub(r"\[\s*\d+\]\s*", "", line).strip()

    # First pass: collect all comment-stripped proto-less rule texts
    # (rules whose destination port has no /tcp or /udp suffix)
    # Whitespace normalized to single spaces for reliable comparison.
    proto_less_rules: set[str] = set()
    for line in lines:
        tokens = _strip_comment(_rule_without_index(line)).split()
        if tokens and re.match(r"^\d+$", tokens[0]):
            # Port token has no /proto — this is a protocol-agnostic rule
            proto_less_rules.add(" ".join(tokens))

    # Second pass: flag exact duplicates and semantic duplicates
    # Whitespace normalized to single spaces for reliable comparison.
    seen_clean: dict[str, int] = {}  # comment-stripped, normalized rule -> real UFW index
    for line in lines:
        idx_match = re.match(r"\[\s*(\d+)\]", line)
        real_index = int(idx_match.group(1)) if idx_match else None
        clean = " ".join(_strip_comment(_rule_without_index(line)).split())

        is_dup = False
        if clean in seen_clean:
            # Exact duplicate (comments ignored)
            del_index = real_index if real_index else seen_clean[clean]
            result.alert(
                message=t("rules.duplicate_found", rule=clean),
                nature="action",
                cmd=f"sudo ufw --force delete {del_index}",
            )
            result.add_deduction(reason=t("rules.duplicate_found", rule=clean),
                                 points=1)
            is_dup = True
        else:
            # Semantic duplicate: PORT/proto where PORT (no proto) also exists
            tokens = clean.split()
            if tokens:
                m = re.match(r"^(\d+)/(tcp|udp)$", tokens[0])
                if m:
                    proto_less_clean = " ".join([m.group(1)] + tokens[1:])
                    if proto_less_clean in proto_less_rules:
                        result.alert(
                            message=t("rules.duplicate_found", rule=clean),
                            nature="action",
                            cmd=f"sudo ufw --force delete {real_index}",
                        )
                        result.add_deduction(
                            reason=t("rules.duplicate_found", rule=clean),
                            points=1)
                        is_dup = True

        if not is_dup and real_index is not None:
            seen_clean[clean] = real_index

    if not any(f.message.startswith(t("rules.duplicate_found")[:20])
               for f in result.findings):
        result.ok(message=t("rules.no_duplicates"))

    # Open-any check (ALLOW IN Anywhere without port restriction — entire rule)
    # Matches: "Anywhere", "Anywhere/tcp", "Anywhere/udp" on both sides
    open_any_pattern = re.compile(
        r"Anywhere(?:/\w+)?\s+ALLOW\s+IN\s+Anywhere(?:/\w+)?\s*$", re.IGNORECASE
    )
    found_open_any = False
    for line in lines:
        if open_any_pattern.search(line):
            idx_match = re.match(r"\[\s*(\d+)\]", line)
            real_index = int(idx_match.group(1)) if idx_match else "?"
            result.alert(
                message=t("rules.open_any_found", rule=line.strip()),
                nature="action",
                cmd=f"sudo ufw --force delete {real_index}",
            )
            result.add_deduction(
                reason=t("rules.open_any_found", rule=""),
                points=2,
            )
            found_open_any = True

    if not found_open_any:
        result.ok(message=t("rules.no_open_any"))

    # IPv6 consistency
    ipv4_count = sum(1 for l in lines if "(v6)" not in l)
    ipv6_count = sum(1 for l in lines if "(v6)" in l)
    if ipv4_count > 0 and ipv6_count == 0:
        result.warn(message=t("rules.ipv6_missing"), nature="improvement")
        result.add_deduction(reason=t("rules.ipv6_missing"), points=1)
    elif ipv4_count > 0:
        result.ok(message=t("rules.ipv6_ok"))

    return result


# ---------------------------------------------------------------------------
# Fix mode
# ---------------------------------------------------------------------------

def _run_fixes(engine, config, t) -> None:
    """Display and optionally apply automatic fixes."""
    from ufw_audit.output import print_summary_box
    from ufw_audit.scoring import FindingLevel
    import shlex, subprocess, re

    auto_items   = [(f.message, f.cmd) for f in engine.findings
                    if f.nature == "action" and f.cmd]
    manual_items = [f.message for f in engine.findings
                    if f.nature == "action" and not f.cmd]

    W = 62
    print()
    print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
    label = t("fixes.title")
    pad = W - 4 - len(label)
    print(f"\033[1;34m║\033[0m  \033[1m{label}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
    print(f"\033[1;34m╠{'═'*(W-2)}╣\033[0m")

    if not auto_items and not manual_items:
        none_msg = t("fixes.none")
        pad = W - 4 - len(none_msg)
        print(f"\033[1;34m║\033[0m    {none_msg}{' '*max(0,pad)}\033[1;34m║\033[0m")
    else:
        count = len(auto_items)
        count_msg = t("fixes.count", count=count)
        pad = W - 4 - len(count_msg)
        print(f"\033[1;34m║\033[0m    ✔  {count_msg}{' '*max(0,pad)}\033[1;34m║\033[0m")
    print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")

    if not auto_items and not manual_items:
        return

    # Sort ufw delete commands descending to avoid renumbering
    ufw_deletes = [(m, c) for m, c in auto_items
                   if re.search(r"ufw.*--force delete \d+$", c)]
    others      = [(m, c) for m, c in auto_items
                   if not re.search(r"ufw.*--force delete \d+$", c)]

    def sort_key(item):
        match = re.search(r"delete (\d+)$", item[1])
        return int(match.group(1)) if match else 0

    sorted_items = sorted(ufw_deletes, key=sort_key, reverse=True) + others

    # Auto-fix mode banner — visible warning so the user knows what's happening
    if config.yes:
        auto_msg = t("fixes.auto_mode_banner", count=len(sorted_items))
        print(f"\033[1;33m  ⚠  {auto_msg}\033[0m")
        print()

    applied_cmds = []

    print()
    for msg, cmd in sorted_items:
        short = msg[:48] + "…" if len(msg) > 48 else msg
        print(f"  ✖  {short}")
        print(f"  → {cmd}")
        if config.yes:
            answer = "y"
        else:
            answer = input(f"  {t('fixes.apply_prompt')} ").strip().lower()

        if answer == "y":
            try:
                proc = subprocess.run(shlex.split(cmd), stdin=subprocess.DEVNULL)
                if proc.returncode == 0:
                    print(f"  ✔ {t('fixes.applied')}")
                    applied_cmds.append(cmd)
                else:
                    print(f"  ✖ {t('fixes.manual')} (exit {proc.returncode})")
            except (OSError, ValueError) as exc:
                print(f"  ✖ {t('fixes.manual')} ({type(exc).__name__})")
        else:
            print(f"  ✖ {t('fixes.manual')}")
        print()

    print(f"  {t('fixes.done')}")

    # Auto-fix summary — list every command that was applied
    if config.yes and applied_cmds:
        print()
        print(f"\033[1;34m  [{t('fixes.auto_summary_title')}]\033[0m")
        for cmd in applied_cmds:
            print(f"  ✔ {cmd}")


# ---------------------------------------------------------------------------
# System information collection
# ---------------------------------------------------------------------------

def _collect_system_info(version: str, lang: str) -> "SystemInfo":
    """Collect system information for the report header."""
    import subprocess, re
    from ufw_audit.report import SystemInfo

    def run(*args):
        try:
            r = subprocess.run(list(args), capture_output=True, text=True, timeout=5)
            return r.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return "N/A"

    # OS name
    from ufw_audit.output import sanitize as _sanitize
    os_name = "N/A"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line[:512]  # cap line length before any processing
                if line.startswith("PRETTY_NAME="):
                    os_name = _sanitize(
                        line.split("=", 1)[1].strip().strip('"'), max_len=64
                    )
                    break
    except OSError:
        pass

    # UFW version
    ufw_ver_raw = run("ufw", "version")
    ufw_match = re.search(r"[\d.]+", ufw_ver_raw)
    ufw_version = ufw_match.group(0) if ufw_match else "N/A"

    return SystemInfo(
        os_name=os_name,
        hostname=_sanitize(run("hostname"), max_len=64),
        kernel=run("uname", "-r"),
        ufw_version=ufw_version,
        user=os.environ.get("SUDO_USER") or os.environ.get("USER", "unknown"),
        config_path=str(_get_user_home() / ".config" / "ufw-audit" / "config.conf"),
        language=lang,
        version=version,
    )


def _detect_network_context() -> tuple[str, str]:
    """
    Detect whether the machine has a direct public IP.

    Returns:
        Tuple of (context: "local"|"public", public_ip: str).
    """
    import subprocess, re

    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        # Check for private gateway
        if re.search(r"via\s+(10\.|192\.168\.|172\.)", result.stdout):
            # Behind NAT — try to get public IP
            public_ip = _get_public_ip()
            return "local", public_ip
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Try to detect direct public IP on interfaces
    try:
        result = subprocess.run(
            ["ip", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        # Look for non-private, non-loopback IP
        for match in re.finditer(r"inet\s+([\d.]+)/", result.stdout):
            ip = match.group(1)
            if not re.match(r"^(10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)", ip):
                return "public", ip
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    public_ip = _get_public_ip()
    return "local", public_ip


def _get_public_ip() -> str:
    """Attempt to determine public IP via a lightweight HTTP request."""
    import re, urllib.error, urllib.request
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=3) as resp:
            ip = resp.read(64).decode().strip()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return ip
        return ""
    except (OSError, urllib.error.URLError, ValueError):
        return ""


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def _get_user_home() -> Path:
    """Return the real user home directory, respecting SUDO_USER."""
    import re
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user and re.match(r"^[a-zA-Z0-9_.-]{1,256}$", sudo_user):
        import pwd
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


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
        ("--remove-cron",      "Remove the installed cron job (legacy)"),
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
# Log directory helpers
# ---------------------------------------------------------------------------

def _prompt_path(prompt_label: str, default: Path) -> Path:
    """Prompt for a filesystem path with TAB autocompletion via readline."""
    import glob as _glob

    def _path_completer(text, state):
        options = _glob.glob(text + "*")
        options = [o + "/" if os.path.isdir(o) else o for o in options]
        try:
            return options[state]
        except IndexError:
            return None

    try:
        import readline
        readline.set_completer_delims(" \t\n;")
        readline.set_completer(_path_completer)
        readline.parse_and_bind("tab: complete")
    except ImportError:
        pass

    try:
        raw = input(f"  {prompt_label} [{default}] : ").strip()
    finally:
        try:
            import readline
            readline.set_completer(None)
        except ImportError:
            pass

    return Path(raw).expanduser() if raw else default


def _get_or_prompt_log_dir(user_config, config, t) -> Path:
    """Return the configured log directory, prompting at first use.

    In non-interactive contexts (cron, pipes) the default path is used
    silently so that the process never hangs waiting for input.
    """
    saved = user_config.get("log_dir")
    if saved:
        d = Path(saved)
        d.mkdir(parents=True, exist_ok=True)
        return d

    home = _get_user_home()
    default_dir = home / ".local" / "share" / "ufw-audit" / "logs"

    # Non-interactive context (cron, piped stdin) — skip the prompt
    if not sys.stdin.isatty():
        default_dir.mkdir(parents=True, exist_ok=True)
        user_config.set("log_dir", str(default_dir))
        return default_dir

    chosen = _prompt_path(t("log_dir.prompt"), default_dir)

    try:
        chosen.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"  ✖ Cannot create directory {chosen}: {exc} — falling back to cwd")
        chosen = Path.cwd()

    user_config.set("log_dir", str(chosen))
    print(f"  ✔ {t('log_dir.saved', path=str(chosen))}")
    print()
    return chosen


# ---------------------------------------------------------------------------
# --manage-logs
# ---------------------------------------------------------------------------

def _parse_log_selection(answer: str, max_idx: int) -> list[int]:
    """Parse user input into a sorted list of 1-based indices.

    Accepted formats:
        1          → [1]
        1,3,5      → [1, 3, 5]
        2-4        → [2, 3, 4]
        1,3-5      → [1, 3, 4, 5]
    """
    indices: set[int] = set()
    for part in answer.split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit():
                lo_i, hi_i = int(lo), int(hi)
                if 1 <= lo_i <= max_idx and 1 <= hi_i <= max_idx:
                    indices.update(range(lo_i, hi_i + 1))
        elif part.isdigit():
            n = int(part)
            if 1 <= n <= max_idx:
                indices.add(n)
    return sorted(indices)


def _run_manage_logs(user_config, config, t) -> int:
    """Standalone log management UI — list, multi-delete, and change storage location."""
    from ufw_audit import output
    output.init(no_color=config.no_color)

    W = 62
    title = t("manage_logs.title")
    pad = W - 4 - len(title)
    print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
    print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
    print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
    print()

    log_dir_str = user_config.get("log_dir")
    if not log_dir_str:
        print(f"  ℹ {t('manage_logs.no_dir')}")
        return 0

    log_dir = Path(log_dir_str)

    # Handle missing directory gracefully
    if not log_dir.exists():
        log_dir.mkdir(parents=True, exist_ok=True)

    logs = sorted(log_dir.glob("ufw_audit_*.log"), reverse=True)

    print(f"  {t('manage_logs.stored_in', path=str(log_dir))}")
    print()

    if not logs:
        print(f"  ℹ {t('manage_logs.no_logs', path=str(log_dir))}")
    else:
        size_label = t("manage_logs.size_label")
        for i, f in enumerate(logs, 1):
            size_kb = max(1, f.stat().st_size // 1024)
            from datetime import datetime as _dt
            mtime = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            print(f"  [{i:2}]  {f.name}  ({size_kb} {size_label})  {mtime}")

    print()
    print(f"  {t('manage_logs.prompt')}")
    answer = input("  > ").strip().lower()

    if answer == "":
        return 0

    elif answer in ("c", "change"):
        home = _get_user_home()
        default_dir = Path(log_dir_str)
        chosen = _prompt_path(t("manage_logs.change_prompt"), default_dir)
        try:
            chosen.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print(f"  ✖ Cannot create directory {chosen}: {exc}")
            return 1
        user_config.set("log_dir", str(chosen))
        print(f"  ✔ {t('manage_logs.location_updated', path=str(chosen))}")

    elif answer == "all":
        for f in logs:
            f.unlink()
        print(f"  ✔ {t('manage_logs.deleted_all', count=len(logs))}")

    else:
        selected = _parse_log_selection(answer, len(logs))
        if not selected:
            print(f"  ✖ {t('manage_logs.invalid')}")
        elif len(selected) == 1:
            f = logs[selected[0] - 1]
            f.unlink()
            print(f"  ✔ {t('manage_logs.deleted_one', name=f.name)}")
        else:
            for idx in selected:
                logs[idx - 1].unlink()
            print(f"  ✔ {t('manage_logs.deleted_multi', count=len(selected))}")

    return 0


# ---------------------------------------------------------------------------
# --install-cron
# ---------------------------------------------------------------------------

def _run_install_cron(user_config, config, t) -> int:
    """Install a cron job for automated audits using the schedule wizard."""
    import re, shutil
    from ufw_audit import output
    from ufw_audit.cron import (
        build_schedule_expr, cron_to_human, list_installed_crons,
        make_slug, suggest_name, CRON_DIR, SCRIPT_DIR,
    )
    output.init(no_color=config.no_color)

    W = 62
    title = t("install_cron.title")
    pad = W - 4 - len(title)
    print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
    print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
    print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
    print()

    # Log directory guard
    log_dir_str = user_config.get("log_dir")
    if not log_dir_str:
        print(f"  ✖ {t('install_cron.no_log_dir')}")
        return 1
    log_dir = Path(log_dir_str)

    # --- Step 1: Name ---
    existing_names = [e.name for e in list_installed_crons()]
    suggestion = suggest_name(existing_names)
    raw_name = input(f"  {t('install_cron.prompt_name', suggestion=suggestion)} : ").strip()
    if not raw_name:
        raw_name = suggestion
    slug = make_slug(raw_name)
    if not slug:
        print(f"  ✖ {t('install_cron.invalid_name')}")
        return 1

    # --- Step 2: Schedule type ---
    print()
    print(f"  {t('install_cron.prompt_schedule')}")
    print(f"    1. {t('install_cron.schedule_daily')}")
    print(f"    2. {t('install_cron.schedule_weekdays')}")
    print(f"    3. {t('install_cron.schedule_monthdays')}")
    print(f"    4. {t('install_cron.schedule_custom')}")
    print()
    raw_choice = input("  > ").strip()
    if not raw_choice:
        raw_choice = "1"
    if raw_choice not in ("1", "2", "3", "4"):
        print(f"  ✖ {t('install_cron.invalid_schedule')}")
        return 1
    choice = int(raw_choice)

    week_days = None
    month_days = None
    custom_expr = None
    hour = 3
    minute = 0

    if choice == 2:
        print()
        print(f"  {t('install_cron.prompt_weekdays')}")
        raw_days = input("  > ").strip()
        parts = re.split(r"[\s,]+", raw_days)
        week_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 7]
        if not week_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return 1

    elif choice == 3:
        print()
        print(f"  {t('install_cron.prompt_monthdays')}")
        raw_days = input("  > ").strip()
        parts = re.split(r"[\s,]+", raw_days)
        month_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 31]
        if not month_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return 1

    elif choice == 4:
        print()
        print(f"  {t('install_cron.prompt_custom')}")
        custom_expr = input("  > ").strip()
        if not re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+$", custom_expr):
            print(f"  ✖ {t('install_cron.invalid_schedule')}")
            return 1

    # --- Step 3: Time (not needed for custom — time is embedded in the expression) ---
    if choice != 4:
        print()
        raw_time = input(f"  {t('install_cron.prompt_time')} : ").strip()
        if not raw_time:
            raw_time = "03:00"
        if not re.match(r"^\d{1,2}:\d{2}$", raw_time):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return 1
        h, m = raw_time.split(":")
        hour, minute = int(h), int(m)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return 1

    # Build expression and show preview
    schedule_expr = build_schedule_expr(
        choice, hour, minute,
        week_days=week_days, month_days=month_days, custom_expr=custom_expr,
    )
    human = cron_to_human(schedule_expr, lang=config.lang)
    print()
    print(f"  {t('install_cron.preview', schedule=human)}")
    print()

    # --- Step 4: Notification email ---
    notify_email = input(f"  {t('install_cron.prompt_email')} : ").strip()
    if notify_email and not shutil.which("mail"):
        print(f"  ⚠ {t('install_cron.mail_missing')}")

    # --- Paths ---
    cron_path   = CRON_DIR / f"ufw-audit-{slug}"
    script_path = SCRIPT_DIR / f"ufw-audit-{slug}"

    if cron_path.exists():
        ans = input(f"\n  {t('install_cron.overwrite', path=str(cron_path))} ").strip().lower()
        if ans != "y":
            return 0

    # --- Write wrapper script ---
    audit_bin = shutil.which("ufw-audit") or "/usr/local/bin/ufw-audit"
    now_str   = datetime.now().strftime("%Y-%m-%d")
    # Use __file__ from this module (always set) rather than ufw_audit.__file__
    # which can be None when __init__.py is empty (Python 3.12+).
    try:
        ufw_audit_path = str(Path(__file__).parent.parent)
    except (TypeError, AttributeError):
        ufw_audit_path = "/usr/local/lib"

    script_content = (
        "#!/bin/bash\n"
        f"# UFW-AUDIT script — generated {now_str} by ufw-audit --install-cron\n"
        "# Re-generate: sudo ufw-audit --install-cron\n\n"
        f'NOTIFY_EMAIL="{notify_email}"\n'
        f'LOG_DIR="{str(log_dir)}"\n'
        f'export PYTHONPATH="{ufw_audit_path}:$PYTHONPATH"\n\n'
        f'"{audit_bin}" --quiet --detailed\n'
        "RC=$?\n\n"
        'if [ "$RC" -gt 0 ] && [ -n "$NOTIFY_EMAIL" ]; then\n'
        '    LOG=$(ls -t "$LOG_DIR"/ufw_audit_*.log 2>/dev/null | head -1)\n'
        '    if [ -n "$LOG" ]; then\n'
        "        export AUDIT_LOG=\"$LOG\"\n"
        "        export AUDIT_EMAIL=\"$NOTIFY_EMAIL\"\n"
        "        export AUDIT_RC=\"$RC\"\n"
        "        python3 << 'PYTHON_EOF'\n"
        "import os\n"
        "from ufw_audit.report_markdown import send_audit_log_as_html_email\n\n"
        "hostname = os.uname().nodename\n"
        "log_file = os.environ.get('AUDIT_LOG')\n"
        "email = os.environ.get('AUDIT_EMAIL')\n"
        "rc = os.environ.get('AUDIT_RC')\n"
        "subject = f'UFW-AUDIT [{rc}] {hostname}'\n"
        "if log_file and email:\n"
        "    send_audit_log_as_html_email(log_file, email, subject)\n"
        "PYTHON_EOF\n"
        "    fi\n"
        "fi\n"
    )

    try:
        fd = os.open(str(script_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o755)
        with os.fdopen(fd, "w") as fh:
            fh.write(script_content)
    except OSError as exc:
        print(f"  ✖ Cannot write {script_path}: {exc}")
        return 1

    print(f"  ✔ {t('install_cron.script_written', path=str(script_path))}")

    # --- Write cron file with metadata comments ---
    cron_content = (
        f"# UFW-AUDIT cron — generated {now_str} by ufw-audit --install-cron\n"
        f"# name: {raw_name}\n"
        f"# email: {notify_email}\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
        f"{schedule_expr}  root  {script_path}\n"
    )

    try:
        fd = os.open(str(cron_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w") as fh:
            fh.write(cron_content)
    except OSError as exc:
        print(f"  ✖ Cannot write {cron_path}: {exc}")
        return 1

    print(f"  ✔ {t('install_cron.cron_written', path=str(cron_path))}")

    # Ensure root's config has log_dir so the cron (running as root) never hangs
    root_config_path = Path("/root/.config/ufw-audit/config.conf")
    try:
        from ufw_audit.config import UserConfig as _UC
        root_cfg = _UC.load(path=root_config_path)
        if not root_cfg.get("log_dir"):
            root_cfg.set("log_dir", str(log_dir))
    except OSError:
        pass

    print()
    print(f"  ✔ {t('install_cron.done_schedule', name=raw_name, schedule=human)}")
    return 0


# ---------------------------------------------------------------------------
# --remove-cron
# ---------------------------------------------------------------------------

def _run_remove_cron(config, t) -> int:
    """Remove all installed ufw-audit cron jobs (v0.12 legacy and v0.13+)."""
    from ufw_audit import output
    from ufw_audit.cron import list_installed_crons
    output.init(no_color=config.no_color)

    W = 62
    title = t("remove_cron.title")
    pad = W - 4 - len(title)
    print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
    print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
    print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
    print()

    crons = list_installed_crons()

    if not crons:
        print(f"  ℹ {t('remove_cron.none_found')}")
        return 0

    for entry in crons:
        try:
            entry.cron_path.unlink()
            print(f"  ✔ {t('remove_cron.removed_cron', path=str(entry.cron_path))}")
        except OSError as exc:
            print(f"  ✖ Cannot remove {entry.cron_path}: {exc}")
            continue

        if entry.script_path.exists():
            try:
                entry.script_path.unlink()
                print(f"  ✔ {t('remove_cron.removed_script', path=str(entry.script_path))}")
            except OSError as exc:
                print(f"  ✖ Cannot remove {entry.script_path}: {exc}")
        else:
            print(f"  ℹ {t('remove_cron.script_not_found', path=str(entry.script_path))}")

    print()
    print(f"  ✔ {t('remove_cron.done')}")
    return 0


# ---------------------------------------------------------------------------
# --manage-cron
# ---------------------------------------------------------------------------

def _run_manage_cron(config, t) -> int:
    """Manage installed cron jobs — list, edit schedule, delete."""
    import re
    from ufw_audit import output
    from ufw_audit.cron import list_installed_crons, cron_to_human
    output.init(no_color=config.no_color)

    W = 62
    title = t("manage_cron.title")
    pad = W - 4 - len(title)
    print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
    print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
    print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
    print()

    crons = list_installed_crons()

    if not crons:
        print(f"  ℹ {t('manage_cron.no_crons')}")
        return 0

    lang = config.lang
    for i, entry in enumerate(crons, 1):
        human = cron_to_human(entry.schedule_expr, lang)
        legacy_tag = f"  [{t('manage_cron.legacy_tag')}]" if entry.legacy else ""
        print(f"  {i}. {entry.name:<20} {human}{legacy_tag}")
        if entry.email:
            print(f"     → {t('manage_cron.email_label')}: {entry.email}")

    print()
    print(f"  {t('manage_cron.prompt')}")
    answer = input("  > ").strip().lower()

    if not answer or answer in ("q", "quit"):
        return 0

    # "d:1" or "d1" → delete; plain number → edit schedule
    delete_match = re.match(r"^d:?(\d+)$", answer)
    edit_match   = re.match(r"^(\d+)$", answer)

    if delete_match:
        idx = int(delete_match.group(1)) - 1
        if not (0 <= idx < len(crons)):
            print(f"  ✖ {t('manage_cron.invalid')}")
            return 0
        entry = crons[idx]
        ans = input(f"  {t('manage_cron.confirm_delete', name=entry.name)} ").strip().lower()
        if ans == "y":
            try:
                entry.cron_path.unlink()
            except OSError:
                pass
            if entry.script_path.exists():
                try:
                    entry.script_path.unlink()
                except OSError:
                    pass
            print(f"  ✔ {t('manage_cron.deleted', name=entry.name)}")

    elif edit_match:
        idx = int(edit_match.group(1)) - 1
        if not (0 <= idx < len(crons)):
            print(f"  ✖ {t('manage_cron.invalid')}")
            return 0
        entry = crons[idx]
        print()
        print(f"  {t('manage_cron.edit_schedule', name=entry.name)}")
        _edit_cron_schedule(entry, config, t)

    else:
        print(f"  ✖ {t('manage_cron.invalid')}")

    return 0


def _edit_cron_schedule(entry, config, t) -> None:
    """Re-run the schedule wizard for an existing cron entry and patch its cron file."""
    import re, os as _os
    from ufw_audit.cron import build_schedule_expr, cron_to_human

    print()
    print(f"  {t('install_cron.prompt_schedule')}")
    print(f"    1. {t('install_cron.schedule_daily')}")
    print(f"    2. {t('install_cron.schedule_weekdays')}")
    print(f"    3. {t('install_cron.schedule_monthdays')}")
    print(f"    4. {t('install_cron.schedule_custom')}")
    print()
    raw_choice = input("  > ").strip()
    if not raw_choice:
        raw_choice = "1"
    if raw_choice not in ("1", "2", "3", "4"):
        print(f"  ✖ {t('install_cron.invalid_schedule')}")
        return
    choice = int(raw_choice)

    week_days   = None
    month_days  = None
    custom_expr = None
    hour   = entry.hour
    minute = entry.minute

    if choice == 2:
        print()
        print(f"  {t('install_cron.prompt_weekdays')}")
        raw_days = input("  > ").strip()
        parts = re.split(r"[\s,]+", raw_days)
        week_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 7]
        if not week_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return

    elif choice == 3:
        print()
        print(f"  {t('install_cron.prompt_monthdays')}")
        raw_days = input("  > ").strip()
        parts = re.split(r"[\s,]+", raw_days)
        month_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 31]
        if not month_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return

    elif choice == 4:
        print()
        print(f"  {t('install_cron.prompt_custom')}")
        custom_expr = input("  > ").strip()
        if not re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+$", custom_expr):
            print(f"  ✖ {t('install_cron.invalid_schedule')}")
            return

    if choice != 4:
        print()
        raw_time = input(f"  {t('install_cron.prompt_time')} : ").strip()
        if not raw_time:
            raw_time = f"{entry.hour:02d}:{entry.minute:02d}"
        if not re.match(r"^\d{1,2}:\d{2}$", raw_time):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return
        h, m = raw_time.split(":")
        hour, minute = int(h), int(m)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return

    schedule_expr = build_schedule_expr(
        choice, hour, minute,
        week_days=week_days, month_days=month_days, custom_expr=custom_expr,
    )
    human = cron_to_human(schedule_expr, lang=config.lang)
    print()
    print(f"  {t('install_cron.preview', schedule=human)}")
    print()

    ans = input(f"  {t('manage_cron.confirm_update')} ").strip().lower()
    if ans != "y":
        return

    # Patch the cron file: replace the schedule expression line
    try:
        text = entry.cron_path.read_text()
    except OSError as exc:
        print(f"  ✖ Cannot read {entry.cron_path}: {exc}")
        return

    new_line = f"{schedule_expr}  root  {entry.script_path}"
    new_text = re.sub(
        r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+root\s+\S+.*$",
        new_line,
        text,
        flags=re.MULTILINE,
    )

    try:
        fd = _os.open(str(entry.cron_path), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o644)
        with _os.fdopen(fd, "w") as fh:
            fh.write(new_text)
    except OSError as exc:
        print(f"  ✖ Cannot write {entry.cron_path}: {exc}")
        return

    print(f"  ✔ {t('manage_cron.updated', name=entry.name, schedule=human)}")


# ---------------------------------------------------------------------------
# Panorama helpers
# ---------------------------------------------------------------------------

def _build_panorama_rows(all_snapshots) -> list[dict]:
    """Convert ServiceSnapshot list to display dicts for print_services_panorama()."""
    from ufw_audit.checks.services import Exposure, ServiceState

    rows = []
    for snap in all_snapshots:
        if not snap.installed:
            status = "not_installed"
        elif snap.state.is_active:
            status = "active"
        elif snap.state.is_inactive:
            status = "inactive"
        else:
            status = "unknown"

        # Port string
        if snap.installed and snap.state.is_active and snap.ports:
            ports_str = ", ".join(snap.ports)
        elif snap.installed and snap.ports:
            ports_str = ", ".join(snap.ports)
        else:
            ports_str = "—"

        # UFW indicator
        if not snap.installed or not snap.exposures:
            ufw = "na"
        else:
            has_open_world = any(e == Exposure.OPEN_WORLD for e in snap.exposures.values())
            has_no_rule    = any(e == Exposure.NO_RULE    for e in snap.exposures.values())
            if has_open_world:
                ufw = "warn"
            elif has_no_rule:
                ufw = "none"
            else:
                ufw = "ok"

        rows.append({
            "label":  snap.label,
            "risk":   snap.risk,
            "status": status,
            "ports":  ports_str,
            "ufw":    ufw,
        })
    return rows


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())