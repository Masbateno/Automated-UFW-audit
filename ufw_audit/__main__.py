"""
ufw-audit entry point.

Run as:
    sudo ufw-audit [OPTIONS]
    sudo python -m ufw_audit [OPTIONS]
"""

from __future__ import annotations

import json as _json
import os
import sys
from datetime import datetime
from pathlib import Path

from ufw_audit import __version__ as VERSION
from ufw_audit import i18n, output
from ufw_audit.cli import AuditConfig, CLIError, parse_args, print_help  # noqa: F401
from ufw_audit.completion import install_completion
from ufw_audit.config import UserConfig
from ufw_audit.display import build_risk_context_entries, print_audit_summary
from ufw_audit.compare import build_baseline, compute_delta, display_delta, load_baseline, save_baseline, _BASELINE_PATH
from ufw_audit.json_output import build_json_data
from ufw_audit.output import print_banner
from ufw_audit.profiles import load_profile
from ufw_audit.registry import ServiceRegistry
from ufw_audit.runner import init_report, run_checks
from ufw_audit.scoring import ScoreEngine
from ufw_audit.sysinfo import collect_system_info, detect_network_context

EXIT_OK           = 0  # clean audit — no alerts, no warnings
EXIT_WARNINGS     = 1  # warnings detected
EXIT_ALERTS       = 2  # alerts detected (action required)
EXIT_ERROR        = 3  # technical error
EXIT_TARGET_MISSED = 4  # --target N specified and score < N


def require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("This script must be run as root: sudo ufw-audit")


def _run(argv=None) -> int:
    try:
        config = parse_args(argv)
    except CLIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if config.show_version:
        print(f"ufw-audit v{VERSION}")
        return EXIT_OK

    if config.show_help:
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        print_help(i18n.t, VERSION)
        return EXIT_OK

    if config.explain_key:
        i18n.init(lang=config.lang)
        output.init(no_color=config.no_color)
        from ufw_audit.explain import run_explain, run_explain_interactive
        if config.explain_key == "__interactive__":
            run_explain_interactive(i18n.t)
        else:
            run_explain(config.explain_key, i18n.t)
        return EXIT_OK

    if config.install_completion:
        if os.geteuid() != 0:
            self_path = Path(sys.argv[0]).resolve()
            print(
                f"✖ --install-completion requires root. Run:\n"
                f"  sudo {self_path} --install-completion",
                file=sys.stderr,
            )
            return EXIT_ERROR
        return install_completion()

    if config.reset_baseline:
        require_root()
        if _BASELINE_PATH.exists():
            try:
                _BASELINE_PATH.unlink()
                print(f"Baseline deleted: {_BASELINE_PATH}")
            except OSError as exc:
                print(f"Error: could not delete baseline: {exc}", file=sys.stderr)
                return EXIT_ERROR
        else:
            print(f"No baseline found at {_BASELINE_PATH}")
        return EXIT_OK

    require_root()
    i18n.init(lang=config.lang)
    t = i18n.t

    # --diff runs the audit silently and shows only the baseline delta
    if config.diff_mode:
        config.quiet = True

    _devnull = None
    if config.json_mode or config.csv_mode or config.markdown_mode:
        config.quiet = True
        _devnull     = open(os.devnull, "w")
        sys.stdout   = _devnull

    try:
        output.init(no_color=config.no_color, quiet=config.quiet, min_level=config.min_level)
        registry    = ServiceRegistry.load()
        user_config = UserConfig.load()

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

        # Resolve audit profile: CLI flag > saved config > default
        profile_name = config.profile or user_config.get_profile() or "server"
        if config.profile:
            user_config.set_profile(config.profile)
        active_profile = load_profile(profile_name)

        if config.watch_mode:
            from ufw_audit.watch import run_watch
            return run_watch(
                config, config.watch_interval, t, output,
                registry, active_profile, VERSION,
            )

        prev_baseline = load_baseline()

        report   = init_report(config, user_config, t, VERSION)
        engine   = ScoreEngine()
        sys_info = collect_system_info(VERSION, config.lang)
        report.write_header(sys_info)

        if not config.quiet:
            not_installed = t("banner.not_installed")
            print_banner(
                version=f"v{VERSION}",
                subtitle=t("banner.subtitle"),
                system=sys_info.os_name,
                host=sys_info.hostname,
                kernel=sys_info.kernel,
                ufw_version=sys_info.ufw_version,
                iptables=sys_info.iptables_version or not_installed,
                nftables=sys_info.nftables_version or not_installed,
                user=sys_info.user,
                date=datetime.now().strftime("%d/%m/%Y %H:%M"),
                labels={k: t(f"banner.{k}") for k in
                        ("system", "host", "kernel", "ufw", "iptables", "nftables", "user", "date")},
            )
            output.print_info(t("audit.starting"))
            print()

        report.write_finding("INFO", "Starting audit")
        network_context, public_ip = detect_network_context(offline=config.offline)

        result             = run_checks(config, t, engine, report, registry, network_context,
                                       profile=active_profile)
        snapshots          = result.snapshots
        ports_snapshot     = result.ports_snapshot
        stack_snapshot     = result.stack_snapshot
        net_snapshot       = result.net_snapshot
        hardening_snapshot = result.hardening_snapshot
        ipv6_snapshot      = result.ipv6_snapshot

        engine.finalize()

        # ---- Webhook notification (non-fatal) ----------------------------------
        _webhook_url = config.webhook_url or user_config.get_webhook_url()
        if _webhook_url and not config.offline:
            # Persist URL if supplied via CLI flag (keeps it for future runs)
            if config.webhook_url and config.webhook_url != user_config.get_webhook_url():
                try:
                    user_config.set_webhook_url(config.webhook_url)
                except ValueError:
                    pass  # invalid URL — will be caught by send_webhook below
            _webhook_fmt = config.webhook_format if config.webhook_format != "auto" \
                else user_config.get_webhook_format()
            try:
                from ufw_audit.webhook import WebhookError, send_webhook
                _status = send_webhook(
                    _webhook_url, engine, sys_info, VERSION,
                    fmt=_webhook_fmt,
                )
                if not config.quiet:
                    output.print_info(f"Webhook: POST → {_webhook_url} [{_status}]")
            except Exception as _exc:  # noqa: BLE001
                import sys as _sys
                print(f"Warning: webhook failed: {_exc}", file=_sys.stderr)
        # ------------------------------------------------------------------------

        curr_baseline = build_baseline(engine, ports_snapshot, snapshots)
        save_baseline(curr_baseline)

        if not config.quiet:
            print_audit_summary(engine, network_context, public_ip, config, t, report, snapshots,
                                profile_name=active_profile.name,
                                prev_score=prev_baseline.score if prev_baseline else None)
            from ufw_audit.domain_scores import compute_domain_scores, render_domain_scores
            _domain_scores = compute_domain_scores(engine)
            for _line in render_domain_scores(_domain_scores, t):
                print(_line)
            print()
            if prev_baseline:
                print()
                display_delta(compute_delta(prev_baseline, curr_baseline), t, output)

        # --diff: restore stdout and show the delta only
        if config.diff_mode:
            sys.stdout = sys.__stdout__
            if not prev_baseline:
                print("No previous baseline found — run a full audit first to establish a baseline.")
            else:
                _delta = compute_delta(prev_baseline, curr_baseline)
                display_delta(_delta, t, output)

        report.write_risk_context_section(
            section_title=t("sections.risk_context"),
            entries=build_risk_context_entries(snapshots, config.lang, t),
        )
        report.write_next_steps([t("report.next_1"), t("report.next_2"), t("report.next_3")])
        report.close()

        if config.fix:
            from ufw_audit.fixes import run_fixes
            run_fixes(engine, config, t)

        if config.json_mode:
            sys.stdout = sys.__stdout__
            _devnull.close()
            _devnull = None
            data = build_json_data(
                engine, sys_info, network_context, public_ip,
                snapshots, ports_snapshot,
                stack_snapshot, net_snapshot,
                full=config.json_full, version=VERSION,
                hardening_snapshot=hardening_snapshot,
                ipv6_snapshot=ipv6_snapshot,
            )
            print(_json.dumps(data, ensure_ascii=False, indent=2))

        if config.csv_mode:
            sys.stdout = sys.__stdout__
            _devnull.close()
            _devnull = None
            from ufw_audit.csv_output import build_csv_output
            print(build_csv_output(engine, sys_info), end="")

        if config.markdown_mode:
            sys.stdout = sys.__stdout__
            _devnull.close()
            _devnull = None
            from ufw_audit.markdown_output import build_markdown_output
            print(build_markdown_output(engine, sys_info), end="")

        if config.target > 0 and engine.score < config.target:
            return EXIT_TARGET_MISSED
        if engine.alert_count > 0:
            return EXIT_ALERTS
        if engine.warn_count > 0:
            return EXIT_WARNINGS
        return EXIT_OK

    finally:
        if _devnull is not None:
            sys.stdout = sys.__stdout__
            _devnull.close()


def main(argv=None) -> int:
    try:
        return _run(argv)
    except PermissionError as exc:
        sys.stdout = sys.__stdout__
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        sys.stdout = sys.__stdout__
        print(f"Fatal error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
