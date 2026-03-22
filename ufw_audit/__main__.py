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

VERSION = "0.10"


# ---------------------------------------------------------------------------
# Bootstrap — must happen before any other import that uses these modules
# ---------------------------------------------------------------------------

def _bootstrap() -> None:
    """Ensure we are running as root."""
    if os.geteuid() != 0:
        # Import i18n lazily to avoid importing before path is set
        print("This script must be run as root: sudo ufw-audit", file=sys.stderr)
        sys.exit(1)


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

    # --- Root check — only needed for actual audit ---
    _bootstrap()

    # --- Initialise i18n ---
    from ufw_audit import i18n
    i18n.init(lang=config.lang)
    t = i18n.t

    # --- Initialise output ---
    from ufw_audit import output
    output.init(no_color=config.no_color)

    # --- Load registry ---
    from ufw_audit.registry import ServiceRegistry
    registry = ServiceRegistry.load()

    # --- Load user config ---
    from ufw_audit.config import UserConfig
    user_config = UserConfig.load()

    if user_config.exists():
        output.print_info(t("config.found", path=str(user_config.path)))
        output.print_dim(t("config.reconfigure_hint"))
    print()

    # --- Initialise report ---
    from ufw_audit.report import AuditReport, SystemInfo
    if config.detailed:
        report = AuditReport.open(directory=Path.cwd(), version=VERSION)
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

    # --- Print banner ---
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
    report.write_finding("INFO", "Starting audit")
    print()

    # --- Detect network context ---
    network_context, public_ip = _detect_network_context()

    # ======================================================================
    # CHECK 1 — Firewall status
    # ======================================================================
    from ufw_audit.output import print_section
    from ufw_audit.checks.firewall import FirewallStatus, check_firewall

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

    print_section(t("sections.services"))
    report.write_section(t("sections.services"))

    snapshots = ServiceSnapshot.collect(registry, ufw_rules=ufw_numbered)
    audited_ports: set[str] = set()

    for snap in snapshots:
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

    # ======================================================================
    # CHECK 4 — Listening ports
    # ======================================================================
    from ufw_audit.checks.ports import PortsSnapshot, check_ports

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
        print()
        print(ports_snapshot.ss_output)
        report.write_section("LISTENING PORTS")
        report.write_raw(ports_snapshot.ss_output)
    print()

    # ======================================================================
    # CHECK 5 — UFW log analysis
    # ======================================================================
    from ufw_audit.checks.logs import LogsSnapshot, check_logs, get_ip_geo

    print_section(t("sections.logs"))
    report.write_section(t("sections.logs"))

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
            output.print_dim(
                f"  {port.container_name}: {port.port_proto} → "
                f"{port.container_port}/{port.proto}"
            )
    print()

    # ======================================================================
    # Summary
    # ======================================================================
    engine.finalize()
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

    return 0


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

    if verbose:
        from ufw_audit.output import print_port_detail
        for port, exposure in snap.exposures.items():
            print_port_detail(
                t("services.port_exposure", port=port,
                  exposure=t(f"services.exposure.{exposure.value}"))
            )
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

    from ufw_audit.output import _c
    color = _c.cyan_bold
    if total > 5000:
        color = _c.red_bold
    elif total > 1000:
        color = _c.yellow_bold

    print(f"  {color}✖ {total} {t('logs.total_blocks')}{_c.reset}")

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
        print_dim(
            f"ℹ {t('logs.top_ips')} : {top_ip}{geo_str} "
            f"— {top_count} {t('logs.attempts')}"
        )

    # Top port
    if data["top_ports"]:
        top_port, top_count = data["top_ports"][0]
        print_dim(
            f"ℹ {t('logs.top_ports')} : {top_port} "
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

    if engine.breakdown:
        lines.append(("---", ""))
        lines.append((t("scoring.breakdown_title"), ""))
        for ded in engine.breakdown:
            reason = ded.reason[:44] + "…" if len(ded.reason) > 44 else ded.reason
            lines.append((f"  -{ded.points}  {reason}", ""))

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

    print()
    print(f"  {t('config.found', path=str(_get_user_home() / '.config/ufw-audit/config.conf'))}")
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

    # Duplicate check
    seen: dict[str, int] = {}
    for line in lines:
        rule = re.sub(r"\[\s*\d+\]\s*", "", line).strip()
        if rule in seen:
            result.alert(
                message=t("rules.duplicate_found", rule=rule),
                nature="action",
                cmd=f"sudo ufw --force delete {seen[rule]}",
            )
            result.add_deduction(reason=t("rules.duplicate_found", rule=rule),
                                 points=1)
        else:
            seen[rule] = len(seen) + 1

    if not any(f.message.startswith(t("rules.duplicate_found")[:20])
               for f in result.findings):
        result.ok(message=t("rules.no_duplicates"))

    # Open-any check (ALLOW IN Anywhere without port restriction — entire rule)
    open_any_pattern = re.compile(
        r"Anywhere\s+ALLOW\s+IN\s+Anywhere$", re.IGNORECASE
    )
    found_open_any = False
    for i, line in enumerate(lines):
        if open_any_pattern.search(line):
            result.alert(
                message=t("rules.open_any_found", rule=line.strip()),
                nature="action",
                cmd=f"sudo ufw --force delete {len(lines) - i}",
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
    import subprocess, re

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
                subprocess.run(cmd, shell=True, stdin=subprocess.DEVNULL)
                print(f"  ✔ {t('fixes.applied')}")
            except Exception as exc:
                print(f"  ✖ {exc}")
        else:
            print(f"  ✖ {t('fixes.manual')}")
        print()

    print(f"  {t('fixes.done')}")


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
        except Exception:
            return "N/A"

    # OS name
    os_name = "N/A"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip().strip('"')
                    break
    except OSError:
        pass

    # UFW version
    ufw_ver_raw = run("ufw", "version")
    ufw_match = re.search(r"[\d.]+", ufw_ver_raw)
    ufw_version = ufw_match.group(0) if ufw_match else "N/A"

    return SystemInfo(
        os_name=os_name,
        hostname=run("hostname"),
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
    except Exception:
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
            if not re.match(r"^(10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.)", ip):
                return "public", ip
    except Exception:
        pass

    public_ip = _get_public_ip()
    return "local", public_ip


def _get_public_ip() -> str:
    """Attempt to determine public IP via a lightweight HTTP request."""
    import urllib.request
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=3) as resp:
            return resp.read().decode().strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def _get_user_home() -> Path:
    """Return the real user home directory, respecting SUDO_USER."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
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
        ("-f, --fix",          "Offer to apply automatic corrections after the audit"),
        ("-y, --yes",          "Auto-confirm all fixes (use with -f)"),
        ("-r, --reconfigure",  "Reset saved port configuration and re-ask"),
        ("-n, --no-color",     "Disable colour output"),
        ("--json",             "Export summary as JSON"),
        ("--json-full",        "Export full audit details as JSON"),
        ("--log-days=N",       "Analyse the last N days of UFW logs (default: 7)"),
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
    print("Documentation: https://github.com/Masbateno/ufw-audit")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())