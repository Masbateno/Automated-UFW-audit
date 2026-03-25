"""
Services panorama builder for ufw-audit.

Converts ServiceSnapshot lists into display-ready row dicts consumed
by output.print_services_panorama().
"""

from __future__ import annotations

from ufw_audit.checks.services import Exposure


def build_panorama_rows(all_snapshots) -> list[dict]:
    """Convert ServiceSnapshot list to display dicts for print_services_panorama()."""
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
        if snap.installed and snap.ports:
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
