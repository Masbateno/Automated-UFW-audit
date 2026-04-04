"""JSON serialization of audit results."""

from __future__ import annotations

from datetime import datetime, timezone

from ufw_audit.checks.ports import PortsSnapshot
from ufw_audit.checks.services import ServiceSnapshot
from ufw_audit.report import SystemInfo
from ufw_audit.scoring import ScoreEngine

_SCHEMA_VERSION = "1"


def build_json_data(
    engine: ScoreEngine,
    sys_info: SystemInfo,
    network_context: str,
    public_ip: str,
    snapshots: list[ServiceSnapshot],
    ports_snapshot: PortsSnapshot,
    full: bool,
    version: str,
) -> dict:
    """Serialize audit results to a JSON-ready dict."""
    data: dict = {
        "schema_version":  _SCHEMA_VERSION,
        "version":         version,
        "host":            sys_info.hostname,
        "timestamp":       datetime.now(timezone.utc).isoformat(timespec="seconds"),
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
    if full:
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
    return data
