"""
Tests for ufw_audit/checks/kernel_modules.py — kernel module security audit.

Coverage:
  - check_kernel_modules(): all branches (lsmod unavailable, risky fs,
    risky net, combined, all-OK)
  - Deduction values and keys
  - _unload_cmd() helper
  - KernelModulesSnapshot dataclass construction
  - Edge cases: empty list, None, duplicates, unknown modules, case sensitivity

Note on deduction sign convention:
  Deduction.points is stored as a positive integer throughout the codebase
  (e.g. points=1 means "subtract 1 from the score"). _deduction_points()
  returns the sum of these positive values; comments indicating "-1 pt"
  describe the score effect, not the stored value.
"""

from __future__ import annotations

import pytest

from ufw_audit.checks.kernel_modules import (
    KernelModulesSnapshot,
    check_kernel_modules,
    _unload_cmd,
    RISKY_MODULES,
    _RISKY_FS,
    _RISKY_NET,
)
from ufw_audit.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_finding(result, key: str, level: FindingLevel) -> bool:
    return any(f.key == key and f.level == level for f in result.findings)


def _finding_keys(result) -> list[str]:
    return [f.key for f in result.findings]


def _deduction_keys(result) -> list[str]:
    return [d.key for d in result.deductions]


def _deduction_points(result) -> int:
    """Return total deduction points (positive convention: 1 means score −1)."""
    return sum(d.points for d in result.deductions)


def _get_finding(result, key: str):
    """Return the first finding with the given key, or None."""
    return next((f for f in result.findings if f.key == key), None)


def base_snapshot(**kwargs) -> KernelModulesSnapshot:
    """Return a clean KernelModulesSnapshot with lsmod available and no risky modules."""
    defaults = dict(
        lsmod_available=True,
        loaded_modules=[],
    )
    defaults.update(kwargs)
    return KernelModulesSnapshot(**defaults)


# ---------------------------------------------------------------------------
# lsmod not available
# ---------------------------------------------------------------------------

class TestNoLsmod:
    def test_no_lsmod_returns_info(self):
        snap = base_snapshot(lsmod_available=False)
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.no_lsmod", FindingLevel.INFO)

    def test_no_lsmod_returns_early(self):
        """No other findings when lsmod is unavailable, even with risky modules listed."""
        snap = base_snapshot(lsmod_available=False, loaded_modules=["dccp", "cramfs"])
        result = check_kernel_modules(snap)
        assert len(result.findings) == 1
        assert result.findings[0].key == "kernel_modules.no_lsmod"

    def test_no_lsmod_no_deduction(self):
        snap = base_snapshot(lsmod_available=False)
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# All OK
# ---------------------------------------------------------------------------

class TestAllOk:
    def test_no_risky_modules_returns_ok(self):
        result = check_kernel_modules(base_snapshot())
        assert _has_finding(result, "kernel_modules.ok", FindingLevel.OK)

    def test_no_risky_modules_no_deduction(self):
        result = check_kernel_modules(base_snapshot())
        assert _deduction_points(result) == 0

    def test_ok_not_emitted_when_findings_present(self):
        snap = base_snapshot(loaded_modules=["dccp"])
        result = check_kernel_modules(snap)
        assert not _has_finding(result, "kernel_modules.ok", FindingLevel.OK)

    def test_safe_modules_do_not_trigger_findings(self):
        snap = base_snapshot(loaded_modules=["ext4", "btrfs", "tcp_bbr", "iptable_filter"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.ok", FindingLevel.OK)


# ---------------------------------------------------------------------------
# Risky filesystem modules
# ---------------------------------------------------------------------------

class TestRiskyFsModules:
    def test_cramfs_produces_warn(self):
        snap = base_snapshot(loaded_modules=["cramfs"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_fs", FindingLevel.WARN)

    def test_risky_fs_deducts_1_point(self):
        # business rule: penalty is applied once per category regardless of count
        snap = base_snapshot(loaded_modules=["cramfs"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 1  # stored as +1, effect is score −1

    def test_risky_fs_deduction_key(self):
        snap = base_snapshot(loaded_modules=["hfs"])
        result = check_kernel_modules(snap)
        assert "kernel_modules.risky_fs" in _deduction_keys(result)

    def test_multiple_risky_fs_still_one_deduction(self):
        # business rule: flat penalty per category regardless of how many modules
        snap = base_snapshot(loaded_modules=["cramfs", "hfs", "hfsplus", "jffs2"])
        result = check_kernel_modules(snap)
        fs_findings = [f for f in result.findings if f.key == "kernel_modules.risky_fs"]
        assert len(fs_findings) == 1
        assert _deduction_points(result) == 1

    def test_usb_storage_detected(self):
        """lsmod uses underscores: usb_storage, not usb-storage."""
        snap = base_snapshot(loaded_modules=["usb_storage"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_fs", FindingLevel.WARN)

    def test_risky_fs_nature_is_improvement(self):
        snap = base_snapshot(loaded_modules=["squashfs"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_fs")
        assert finding is not None
        assert finding.nature == "improvement"

    def test_risky_fs_cmd_references_module(self):
        snap = base_snapshot(loaded_modules=["cramfs"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_fs")
        assert finding is not None
        assert "cramfs" in finding.cmd

    def test_risky_fs_cmd_is_non_empty(self):
        snap = base_snapshot(loaded_modules=["hfs"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_fs")
        assert finding is not None
        assert finding.cmd


# ---------------------------------------------------------------------------
# Risky network protocol modules
# ---------------------------------------------------------------------------

class TestRiskyNetModules:
    def test_dccp_produces_warn(self):
        snap = base_snapshot(loaded_modules=["dccp"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_net", FindingLevel.WARN)

    def test_sctp_produces_warn(self):
        snap = base_snapshot(loaded_modules=["sctp"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_net", FindingLevel.WARN)

    def test_rds_produces_warn(self):
        snap = base_snapshot(loaded_modules=["rds"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_net", FindingLevel.WARN)

    def test_tipc_produces_warn(self):
        snap = base_snapshot(loaded_modules=["tipc"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_net", FindingLevel.WARN)

    def test_risky_net_deducts_1_point(self):
        # business rule: flat penalty per category
        snap = base_snapshot(loaded_modules=["dccp"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 1  # stored as +1, effect is score −1

    def test_risky_net_deduction_key(self):
        snap = base_snapshot(loaded_modules=["sctp"])
        result = check_kernel_modules(snap)
        assert "kernel_modules.risky_net" in _deduction_keys(result)

    def test_multiple_risky_net_still_one_deduction(self):
        # business rule: flat penalty per category regardless of count
        snap = base_snapshot(loaded_modules=["dccp", "sctp", "rds", "tipc"])
        result = check_kernel_modules(snap)
        net_findings = [f for f in result.findings if f.key == "kernel_modules.risky_net"]
        assert len(net_findings) == 1
        assert _deduction_points(result) == 1

    def test_risky_net_nature_is_improvement(self):
        snap = base_snapshot(loaded_modules=["dccp"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_net")
        assert finding is not None
        assert finding.nature == "improvement"

    def test_risky_net_cmd_references_module(self):
        snap = base_snapshot(loaded_modules=["dccp"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_net")
        assert finding is not None
        assert "dccp" in finding.cmd


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombined:
    def test_risky_fs_and_net_total_deduction(self):
        # risky FS (score −1) + risky net (score −1) = score −2
        snap = base_snapshot(loaded_modules=["cramfs", "dccp"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 2

    def test_risky_fs_and_net_both_findings(self):
        snap = base_snapshot(loaded_modules=["hfs", "sctp"])
        result = check_kernel_modules(snap)
        keys = set(_finding_keys(result))
        assert "kernel_modules.risky_fs" in keys
        assert "kernel_modules.risky_net" in keys

    def test_mixed_safe_and_risky(self):
        snap = base_snapshot(loaded_modules=["ext4", "cramfs", "btrfs", "dccp"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 2
        assert not _has_finding(result, "kernel_modules.ok", FindingLevel.OK)

    def test_risky_with_unknown_module(self):
        """An unknown module alongside a risky one must not prevent detection."""
        snap = base_snapshot(loaded_modules=["cramfs", "totally_unknown_mod"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.risky_fs", FindingLevel.WARN)
        assert _deduction_points(result) == 1


# ---------------------------------------------------------------------------
# _unload_cmd helper
# ---------------------------------------------------------------------------

class TestUnloadCmd:
    def test_single_module(self):
        assert _unload_cmd(["cramfs"]) == "sudo modprobe -r cramfs"

    def test_multiple_modules(self):
        assert _unload_cmd(["cramfs", "dccp"]) == "sudo modprobe -r cramfs dccp"

    def test_empty_list_returns_empty_string(self):
        """An empty list must not produce an invalid shell command."""
        assert _unload_cmd([]) == ""

    def test_cmd_quotes_module_with_special_chars(self):
        """Shell metacharacters in module names must be quoted — prevent injection."""
        cmd = _unload_cmd(["cramfs; rm -rf /"])
        assert cmd == "sudo modprobe -r 'cramfs; rm -rf /'"

    def test_cmd_references_module_in_finding(self):
        snap = base_snapshot(loaded_modules=["cramfs"])
        result = check_kernel_modules(snap)
        finding = _get_finding(result, "kernel_modules.risky_fs")
        assert finding is not None
        assert "cramfs" in finding.cmd


# ---------------------------------------------------------------------------
# KernelModulesSnapshot dataclass
# ---------------------------------------------------------------------------

class TestKernelModulesSnapshot:
    def test_defaults(self):
        snap = KernelModulesSnapshot()
        assert snap.lsmod_available is False
        assert snap.loaded_modules == []

    def test_custom_values(self):
        snap = KernelModulesSnapshot(lsmod_available=True, loaded_modules=["ext4"])
        assert snap.lsmod_available is True
        assert "ext4" in snap.loaded_modules


# ---------------------------------------------------------------------------
# RISKY_MODULES set — structural invariants only
# ---------------------------------------------------------------------------

class TestRiskyModulesSets:
    def test_risky_fs_and_net_are_disjoint(self):
        """No module should belong to both the FS and net categories."""
        assert _RISKY_FS.isdisjoint(_RISKY_NET)

    def test_risky_modules_is_union_of_fs_and_net(self):
        assert RISKY_MODULES == _RISKY_FS | _RISKY_NET

    def test_all_sets_are_non_empty(self):
        assert len(_RISKY_FS) > 0
        assert len(_RISKY_NET) > 0

    def test_cramfs_triggers_fs_finding(self):
        """Spot-check: cramfs (a well-known risky FS module) is detected."""
        snap = base_snapshot(loaded_modules=["cramfs"])
        assert _has_finding(check_kernel_modules(snap), "kernel_modules.risky_fs", FindingLevel.WARN)

    def test_dccp_triggers_net_finding(self):
        """Spot-check: dccp (a well-known risky net module) is detected."""
        snap = base_snapshot(loaded_modules=["dccp"])
        assert _has_finding(check_kernel_modules(snap), "kernel_modules.risky_net", FindingLevel.WARN)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_none_loaded_modules_produce_ok_finding(self):
        """None instead of a list must not crash check_kernel_modules()."""
        snap = KernelModulesSnapshot(lsmod_available=True, loaded_modules=None)
        result = check_kernel_modules(snap)
        assert isinstance(result.findings, list)
        assert _has_finding(result, "kernel_modules.ok", FindingLevel.OK)

    def test_none_loaded_modules_no_deduction(self):
        snap = KernelModulesSnapshot(lsmod_available=True, loaded_modules=None)
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 0

    def test_duplicate_modules_single_deduction(self):
        """Duplicates in loaded_modules must not inflate deductions."""
        snap = base_snapshot(loaded_modules=["cramfs", "cramfs", "cramfs"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 1

    def test_duplicate_mixed_fs_net_correct_total(self):
        """Duplicates across both categories still cap at 2 pts total."""
        snap = base_snapshot(loaded_modules=["cramfs", "cramfs", "dccp", "dccp"])
        result = check_kernel_modules(snap)
        assert _deduction_points(result) == 2

    def test_snapshot_not_mutated(self):
        """check_kernel_modules() must not modify the snapshot."""
        snap = base_snapshot(loaded_modules=["cramfs", "dccp"])
        original = list(snap.loaded_modules)
        check_kernel_modules(snap)
        assert snap.loaded_modules == original

    def test_max_deduction_is_two(self):
        """Maximum total deduction is 2 pts (fs −1 + net −1)."""
        snap = base_snapshot(loaded_modules=list(_RISKY_FS | _RISKY_NET))
        result = check_kernel_modules(snap)
        assert _deduction_points(result) <= 2

    def test_finding_order_independent(self):
        """Both risky keys present regardless of module order in the list."""
        snap = base_snapshot(loaded_modules=["tipc", "hfs"])
        result = check_kernel_modules(snap)
        keys = set(_finding_keys(result))
        assert "kernel_modules.risky_fs" in keys
        assert "kernel_modules.risky_net" in keys

    def test_uppercase_module_not_detected(self):
        """lsmod always outputs lowercase on Linux; uppercase entries are not risky modules."""
        snap = base_snapshot(loaded_modules=["CRAMFS", "DCCP"])
        result = check_kernel_modules(snap)
        assert _has_finding(result, "kernel_modules.ok", FindingLevel.OK)
        assert _deduction_points(result) == 0
