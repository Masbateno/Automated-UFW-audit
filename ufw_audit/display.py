"""
Display helpers for ufw-audit.

Terminal output and report writing for check results, risk context,
log analysis, and the final audit summary.
"""

from __future__ import annotations

# Maximum display width for summary box entries
_SUMMARY_MSG_LEN    = 48   # finding messages (action / improvement / structural)
_SUMMARY_REASON_LEN = 44   # score deduction reasons


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max_len characters, appending ellipsis if needed."""
    return text[:max_len] + "…" if len(text) > max_len else text


# ---------------------------------------------------------------------------
# Check result display
# ---------------------------------------------------------------------------

def display_result(result, report, verbose: bool, quiet: bool = False) -> None:
    """Print all findings from a CheckResult to terminal and report."""
    from ufw_audit.scoring import FindingLevel
    from ufw_audit.output import (
        print_ok, print_warn, print_alert, print_info, print_recommendation,
    )

    for finding in result.findings:
        if quiet:
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


# ---------------------------------------------------------------------------
# Risk context display
# ---------------------------------------------------------------------------

def display_risk_context(label: str, lang: str, t, report) -> None:
    """Display two-axis risk context for a high/critical service."""
    svc_id = (label.lower()
              .replace(" ", "_").replace("/", "_")
              .replace("(", "").replace(")", ""))
    exposure = t(f"service_risk.{svc_id}.exposure")
    threat   = t(f"service_risk.{svc_id}.threat")
    level    = t(f"service_risk.{svc_id}.level")

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


# ---------------------------------------------------------------------------
# Single service check + display
# ---------------------------------------------------------------------------

def check_single_service_display(snap, network_context, t, report, verbose,
                                  quiet: bool = False):
    """Run check for a single service and return its CheckResult."""
    from ufw_audit.checks.services import check_services
    result = check_services([snap], network_context=network_context, t=t)
    display_result(result, report, verbose, quiet=quiet)
    return result


# ---------------------------------------------------------------------------
# Log results display
# ---------------------------------------------------------------------------

def display_log_results(logs_result, snapshot, config, t, report) -> None:
    """Display structured log analysis results."""
    from ufw_audit.checks.logs import get_ip_geo
    from ufw_audit.output import print_ok, print_warn, print_info, print_dim

    if not hasattr(logs_result, "_log_data"):
        display_result(logs_result, report, config.verbose, quiet=config.quiet)
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


# ---------------------------------------------------------------------------
# Audit summary
# ---------------------------------------------------------------------------

def print_audit_summary(engine, network_context, public_ip, config, t,
                         report, snapshots) -> None:
    """Print the audit summary box and write to report."""
    from ufw_audit.output import print_summary_box
    from ufw_audit.scoring import RiskLevel

    score = engine.score
    level = engine.level

    level_str = t(f"scoring.level.{level.value}")
    ctx_str   = t(f"scoring.context.{network_context}")

    icon = "✔" if level == RiskLevel.LOW else "✖"

    lines = [
        (t("scoring.score_label"), f"{score}/10"),
        (t("scoring.risk_label"),  f"{icon} {level_str}"),
        (t("scoring.network_context"), ctx_str),
    ]

    action_items      = [f for f in engine.findings if f.nature == "action"]
    improvement_items = [f for f in engine.findings if f.nature == "improvement"]
    structural_items  = [f for f in engine.findings if f.nature == "structural"]

    if action_items or improvement_items or structural_items:
        if action_items:
            lines.append(("---", ""))
            lines.append((f"✖ {t('summary.block_action')}", ""))
            for item in action_items:
                msg = _truncate(item.message, _SUMMARY_MSG_LEN)
                lines.append((f"  ✖  {msg}", ""))
        if improvement_items:
            lines.append(("---", ""))
            lines.append((f"⚠ {t('summary.block_improve')}", ""))
            for item in improvement_items:
                msg = _truncate(item.message, _SUMMARY_MSG_LEN)
                lines.append((f"  ⚠  {msg}", ""))
        if structural_items:
            lines.append(("---", ""))
            lines.append((f"ℹ {t('summary.block_normal')}", ""))
            for item in structural_items:
                msg = _truncate(item.message, _SUMMARY_MSG_LEN)
                lines.append((f"  ℹ  {msg}", ""))

    if engine.breakdown or engine.cap_info:
        lines.append(("---", ""))
        lines.append((t("scoring.breakdown_title"), ""))
        for ded in engine.breakdown:
            if ded.points == 0:
                continue
            reason = _truncate(ded.reason, _SUMMARY_REASON_LEN)
            lines.append((f"  -{ded.points}  {reason}", ""))
        if engine.cap_info:
            cap_note = t("scoring.cap_note", max=engine.cap_info.maximum)
            lines.append((f"  ⚠  {cap_note}", ""))

    print_summary_box(lines)
    print()

    if not action_items and not improvement_items:
        print(f"  {t('summary.clean')}")
    elif not action_items:
        print(f"  {t('summary.warnings')}")
    else:
        print(f"  {t('summary.alerts')}")

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

    print()
    print(f"  ℹ {t('summary.scope_line1')}")
    print(f"  ℹ {t('summary.scope_line2')}")

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


# ---------------------------------------------------------------------------
# Risk context report entries
# ---------------------------------------------------------------------------

def build_risk_context_entries(snapshots, lang: str, t) -> list[dict]:
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
# GeoIP availability notice
# ---------------------------------------------------------------------------

def display_geoip_notice(geo_status: str, t, output) -> None:
    """Print a one-time notice if GeoIP2 is unavailable or has no database."""
    if geo_status == "unavailable":
        msg = t("logs.geoip2_unavailable")
        if msg.startswith("["):
            msg = "GeoIP2 not available — install python3-geoip2 for IP geolocation"
        output.print_info(msg)
    elif geo_status == "no_database":
        msg = t("logs.geoip2_no_db")
        if msg.startswith("["):
            msg = "GeoIP2 installed but no GeoLite2 database found"
        output.print_info(msg)


# ---------------------------------------------------------------------------
# Ports overview section
# ---------------------------------------------------------------------------

def display_ports_overview(ports_snapshot, config, t, report, output) -> None:
    """Print the listening ports count and optional ss table."""
    from ufw_audit.output import print_section
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


# ---------------------------------------------------------------------------
# Services panorama section
# ---------------------------------------------------------------------------

def display_services_panorama(registry, ufw_numbered: str,
                               loopback_only_ports: set, all_listening_ports: set,
                               config, t) -> None:
    """Print the compact services panorama table (all 22 known services)."""
    from ufw_audit.output import print_section, print_services_panorama
    from ufw_audit.checks.services import ServiceSnapshot
    from ufw_audit.panorama import build_panorama_rows

    print_section(t("sections.services_panorama"))
    all_snaps = ServiceSnapshot.collect_all(
        registry, ufw_rules=ufw_numbered, loopback_ports=loopback_only_ports,
        all_listening_ports=all_listening_ports,
    )
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
