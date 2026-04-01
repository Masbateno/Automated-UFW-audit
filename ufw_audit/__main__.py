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
import shutil
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Version — single source of truth in ufw_audit/__init__.py
# ---------------------------------------------------------------------------

from ufw_audit import __version__ as VERSION

# Exit codes
EXIT_OK       = 0  # clean audit — no alerts, no warnings
EXIT_WARNINGS = 1  # warnings detected
EXIT_ALERTS   = 2  # alerts detected (action required)
EXIT_ERROR    = 3  # technical error

# ---------------------------------------------------------------------------
# Top-level imports (non-optional modules)
# ---------------------------------------------------------------------------

from ufw_audit import i18n, output
from ufw_audit.cli import AuditConfig, CLIError, parse_args, print_help  # noqa: F401
from ufw_audit.config import UserConfig
from ufw_audit.display import (
    build_risk_context_entries,
    check_single_service_display,
    display_geoip_notice,
    display_log_results,
    display_ports_overview,
    display_result,
    display_risk_context,
    display_services_panorama,
    print_audit_summary,
)
from ufw_audit.output import print_banner, print_section, print_service_header
from ufw_audit.registry import ServiceRegistry
from ufw_audit.report import AuditReport
from ufw_audit.scoring import ScoreEngine
from ufw_audit.sysinfo import collect_system_info, detect_network_context
from ufw_audit.checks.ddns import DdnsSnapshot, check_ddns
from ufw_audit.checks.docker import DockerSnapshot, check_docker
from ufw_audit.checks.firewall import (
    FirewallStatus,
    check_firewall,
    check_rules,
)
from ufw_audit.checks.logs import LogsSnapshot, check_logs, geoip2_status
from ufw_audit.checks.ports import PortsSnapshot, check_ports
from ufw_audit.checks.services import ServiceSnapshot
from ufw_audit.checks.virtualization import VirtSnapshot, check_virtualization


# ---------------------------------------------------------------------------
# Root guard
# ---------------------------------------------------------------------------

def require_root() -> None:
    """Raise PermissionError if the process is not running as root."""
    if os.geteuid() != 0:
        raise PermissionError("This script must be run as root: sudo ufw-audit")


# ---------------------------------------------------------------------------
# Audit implementation
# ---------------------------------------------------------------------------

def _run(argv=None) -> int:
    """Full audit implementation — separated from main() for global error handling."""

    # --- Parse arguments ---
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
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        print_help(i18n.t, VERSION)
        return 0

    # --- Handle --install-completion (requires root) ---
    if config.install_completion:
        require_root()
        ok = True

        # 1. Install bash completion script
        src = Path(__file__).parent / "data" / "ufw-audit.bash-completion"
        dst_comp = Path("/etc/bash_completion.d/ufw-audit")
        try:
            shutil.copy2(src, dst_comp)
            print(f"✔ Bash completion installed: {dst_comp}")
        except OSError as exc:
            print(f"✖ Failed to install completion script: {exc}", file=sys.stderr)
            ok = False

        # 2. Symlink binary to /usr/local/bin so sudo can find it
        dst_bin = Path("/usr/local/bin/ufw-audit")
        sudo_user = os.environ.get("SUDO_USER")
        bin_src = None
        if sudo_user:
            import pwd
            home = Path(pwd.getpwnam(sudo_user).pw_dir)
            candidate = home / ".local" / "bin" / "ufw-audit"
            if candidate.exists():
                bin_src = candidate
        if bin_src:
            try:
                if dst_bin.exists() or dst_bin.is_symlink():
                    dst_bin.unlink()
                dst_bin.symlink_to(bin_src)
                print(f"✔ Symlink created: {dst_bin} → {bin_src}")
            except OSError as exc:
                print(f"✖ Failed to create symlink: {exc}", file=sys.stderr)
                ok = False
        else:
            print("ℹ  Symlink skipped — binary not found in ~/.local/bin")

        if ok:
            print("  Open a new shell or run: source /etc/bash_completion.d/ufw-audit")
        return EXIT_OK if ok else EXIT_ERROR

    # --- Root check — required for all modes ---
    require_root()

    # --- Initialise i18n ---
    i18n.init(lang=config.lang)
    t = i18n.t

    # JSON mode suppresses all terminal output — only JSON is printed
    if config.json_mode:
        config.quiet = True
        _devnull = open(os.devnull, "w")
        sys.stdout = _devnull

    # --- Initialise output ---
    output.init(no_color=config.no_color, quiet=config.quiet)

    # --- Load registry ---
    registry = ServiceRegistry.load()

    # --- Load user config ---
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
    if not config.quiet:
        print()

    # --- Initialise report ---
    if config.detailed:
        from ufw_audit.manage_logs import get_or_prompt_log_dir
        log_dir = get_or_prompt_log_dir(user_config, config, t)
        report = AuditReport.open(directory=log_dir, version=VERSION)
        output.print_ok(t("audit.report_saved", path=report.path))
        if not config.quiet:
            print()
    else:
        report = AuditReport.null()

    # --- Initialise scoring engine ---
    engine = ScoreEngine()

    # --- System information ---
    sys_info = collect_system_info(VERSION, config.lang)
    report.write_header(sys_info)

    # --- Print banner (suppressed in quiet mode) ---
    if not config.quiet:
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
        output.print_info(t("audit.starting"))
        print()

    report.write_finding("INFO", "Starting audit")

    # --- Detect network context ---
    network_context, public_ip = detect_network_context(offline=config.offline)

    # ======================================================================
    # CHECK 1 — Firewall status
    # ======================================================================
    if not config.quiet:
        print_section(t("sections.firewall"))
    report.write_section(t("sections.firewall"))

    fw_status = FirewallStatus.from_system()
    fw_result = check_firewall(fw_status, t=t)
    engine.apply(fw_result)  # caps in fw_result (e.g. firewall inactive) applied here

    display_result(fw_result, report, config.verbose, quiet=config.quiet)

    if fw_status.ufw_output:
        report.write_section("UFW STATUS")
        report.write_raw(fw_status.ufw_output)

    # ======================================================================
    # CHECK 2 — UFW rules
    # ======================================================================
    # Reuse the outputs already fetched by FirewallStatus.from_system()
    ufw_numbered = fw_status.numbered_output
    ufw_verbose  = fw_status.ufw_output

    if not config.quiet:
        print_section(t("sections.rules"))
    report.write_section(t("sections.rules"))

    rules_result = check_rules(ufw_verbose, ufw_numbered, t, fw_status.ipv6_ufw_enabled)
    engine.apply(rules_result)
    display_result(rules_result, report, config.verbose, quiet=config.quiet)

    # ======================================================================
    # CHECK 3 — Network services
    # ======================================================================

    # Collect ports early to detect loopback-only services and dangling rules
    ports_snapshot = PortsSnapshot.from_system()
    loopback_only_ports = ports_snapshot.loopback_only_ports
    active_external_ports = ports_snapshot.active_external_ports
    all_listening_ports = loopback_only_ports | active_external_ports

    if not config.quiet:
        print_section(t("sections.services"))
    report.write_section(t("sections.services"))

    snapshots = ServiceSnapshot.collect(
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
            snap, network_context, t, report, config.verbose, quiet=config.quiet
        )
        engine.apply(svc_result)

        for port in snap.ports:
            audited_ports.add(port)

    # --- Services panorama ---
    if not config.quiet:
        display_services_panorama(registry, ufw_numbered, loopback_only_ports,
                                   all_listening_ports, config, t)

    # ======================================================================
    # CHECK 4 — Listening ports
    # ======================================================================
    if not config.quiet:
        print_section(t("sections.ports_analysis"))
    report.write_section(t("sections.ports_analysis"))

    ports_result = check_ports(
        ports_snapshot,
        audited_ports=audited_ports,
        network_context=network_context,
        t=t,
    )
    engine.apply(ports_result)
    display_result(ports_result, report, config.verbose, quiet=config.quiet)

    display_ports_overview(ports_snapshot, config, t, report, output)

    # ======================================================================
    # CHECK 5 — UFW log analysis
    # ======================================================================
    if not config.quiet:
        print_section(t("sections.logs"))

    logs_snapshot = LogsSnapshot.from_system(log_days=config.log_days)

    display_geoip_notice(geoip2_status(), t, output)

    logs_result = check_logs(logs_snapshot, audited_ports=audited_ports, t=t)
    engine.apply(logs_result)

    display_log_results(logs_result, logs_snapshot, config, t, report)

    # ======================================================================
    # CHECK 6 — DDNS / external exposure
    # ======================================================================
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

    # ======================================================================
    # CHECK 7 — Docker
    # ======================================================================
    if not config.quiet:
        print_section(t("sections.docker"))
    report.write_section(t("sections.docker"))

    docker_snapshot = DockerSnapshot.from_system()
    docker_result   = check_docker(docker_snapshot,
                                   network_context=network_context, t=t)
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

    # ======================================================================
    # CHECK 8 — Virtualisation
    # ======================================================================
    if not config.quiet:
        print_section(t("sections.virtualization"))
    report.write_section(t("sections.virtualization"))

    virt_snapshot = VirtSnapshot.from_system()
    virt_result   = check_virtualization(virt_snapshot, t=t)
    engine.apply(virt_result)
    display_result(virt_result, report, config.verbose, quiet=config.quiet)
    if not config.quiet:
        print()

    # ======================================================================
    # Summary
    # ======================================================================
    engine.finalize()
    if not config.quiet:
        print_audit_summary(engine, network_context, public_ip, config, t, report, snapshots)

    # Finalise report
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

    # JSON output — restore stdout before printing
    if config.json_mode:
        sys.stdout = sys.__stdout__
    if config.json_mode:
        import json as _json
        data: dict = {
            "version":         VERSION,
            "host":            sys_info.hostname,
            "timestamp":       datetime.now().isoformat(timespec="seconds"),
            "score":           engine.score,
            "score_max":       10,
            "risk":            engine.level.value,
            "network_context": network_context,
            "public_ip":       public_ip,
            "alerts":          engine.alert_count,
            "warnings":        engine.warn_count,
            "deductions": [
                {"reason": d.reason, "points": d.points}
                for d in engine.breakdown if d.points > 0
            ],
        }
        if config.json_full:
            data["findings"] = [
                {
                    "level":   f.level.value,
                    "message": f.message,
                    "nature":  f.nature,
                    "cmd":     f.cmd,
                    "note":    f.note,
                }
                for f in engine.findings
            ]
            data["services"] = [
                {
                    "name":      snap.service.label,
                    "installed": snap.installed,
                    "active":    snap.state.is_active,
                    "risk":      snap.risk,
                    "ports": {
                        port: {"exposure": exp.value}
                        for port, exp in snap.exposures.items()
                    },
                }
                for snap in snapshots if snap.installed
            ]
            data["open_ports"] = [
                {
                    "port":    lp.port_proto,
                    "address": lp.address,
                    "process": lp.process,
                }
                for lp in ports_snapshot.ports if lp.is_all_interfaces
            ]
        print(_json.dumps(data, ensure_ascii=False, indent=2))

    # Exit code based on audit results
    if engine.alert_count > 0:
        return EXIT_ALERTS
    elif engine.warn_count > 0:
        return EXIT_WARNINGS
    else:
        return EXIT_OK


# ---------------------------------------------------------------------------
# Main — global error guard
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    try:
        return _run(argv)
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        print(f"Fatal error: {exc}", file=sys.stderr)
        return EXIT_ERROR


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())
