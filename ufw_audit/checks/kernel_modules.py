"""
Kernel module security audit for ufw-audit.

Checks whether known-risky kernel modules are currently loaded.
These modules are rarely needed on a server and present an unnecessary
attack surface: file-system modules that can be used to mount malicious
media, and network protocol modules that are exploitable or superseded.

The check is split into two parts:
  1. KernelModulesSnapshot.from_system() — collects raw data via ``lsmod``.
  2. check_kernel_modules(snapshot)       — pure logic, returns a CheckResult.

Usage:
    from ufw_audit.checks.kernel_modules import KernelModulesSnapshot, check_kernel_modules

    snapshot = KernelModulesSnapshot.from_system()
    result   = check_kernel_modules(snapshot)
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import List

from ufw_audit.checks._run import _command_exists, _identity_t, _run
from ufw_audit.scoring import CheckResult


# ---------------------------------------------------------------------------
# Modules considered risky on a hardened server
# ---------------------------------------------------------------------------

# Filesystem modules — rarely needed; can be used to mount rogue media
_RISKY_FS: frozenset[str] = frozenset({
    "cramfs",
    "freevxfs",
    "jffs2",
    "hfs",
    "hfsplus",
    "squashfs",
    "udf",
    "usb_storage",   # lsmod uses underscores, not hyphens
})

# Network protocol modules — rarely needed, historically exploited or redundant
_RISKY_NET: frozenset[str] = frozenset({
    "dccp",
    "sctp",
    "rds",
    "tipc",
})

RISKY_MODULES: frozenset[str] = _RISKY_FS | _RISKY_NET


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class KernelModulesSnapshot:
    """
    Raw snapshot of loaded kernel modules relevant to security hardening.

    Args:
        lsmod_available:  True if the ``lsmod`` command exists on this system.
        loaded_modules:   Full set of currently loaded module names (from lsmod).
    """
    lsmod_available:  bool       = False
    loaded_modules:   List[str]  = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "KernelModulesSnapshot":
        """
        Collect loaded kernel modules from the live system.

        Returns:
            Populated KernelModulesSnapshot. Never raises — errors reflected as defaults.
        """
        snap = cls()

        if not _command_exists("lsmod"):
            return snap

        snap.lsmod_available = True
        out = _run("lsmod", timeout=10)
        if not out:
            return snap

        modules: list[str] = []
        for line in out.splitlines()[1:]:  # skip header row
            parts = line.split()
            if parts:
                modules.append(parts[0].lower())

        snap.loaded_modules = modules
        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_kernel_modules(snapshot: KernelModulesSnapshot, *, t=None) -> CheckResult:
    """
    Audit currently loaded kernel modules for known-risky entries.

    Scoring:
      - Any risky filesystem module loaded:   −1 pt per category (flat, max −1)
      - Any risky network protocol loaded:    −1 pt (flat, regardless of count)
      - lsmod unavailable:                    INFO only, no deduction

    Args:
        snapshot: KernelModulesSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()

    if not snapshot.lsmod_available:
        result.info(
            message=_t("kernel_modules.no_lsmod"),
            key="kernel_modules.no_lsmod",
        )
        return result

    loaded: set[str] = set(snapshot.loaded_modules or [])

    # --- Risky filesystem modules -------------------------------------------
    risky_fs = sorted(loaded & _RISKY_FS)
    if risky_fs:
        pkgs = ", ".join(risky_fs)
        result.warn(
            message=_t("kernel_modules.risky_fs", modules=pkgs),
            detail=_t("kernel_modules.risky_fs_detail"),
            cmd=_unload_cmd(risky_fs),
            nature="improvement",
            key="kernel_modules.risky_fs",
        )
        result.add_deduction(
            reason=_t("kernel_modules.risky_fs_reason", modules=pkgs),
            points=1,
            context="local",
            key="kernel_modules.risky_fs",
        )

    # --- Risky network protocol modules -------------------------------------
    risky_net = sorted(loaded & _RISKY_NET)
    if risky_net:
        pkgs = ", ".join(risky_net)
        result.warn(
            message=_t("kernel_modules.risky_net", modules=pkgs),
            detail=_t("kernel_modules.risky_net_detail"),
            cmd=_unload_cmd(risky_net),
            nature="improvement",
            key="kernel_modules.risky_net",
        )
        result.add_deduction(
            reason=_t("kernel_modules.risky_net_reason", modules=pkgs),
            points=1,
            context="local",
            key="kernel_modules.risky_net",
        )

    # --- All clear ----------------------------------------------------------
    if not result.findings:
        result.ok(
            message=_t("kernel_modules.ok"),
            key="kernel_modules.ok",
        )

    return result


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _unload_cmd(modules: list[str]) -> str:
    """Build a ``modprobe -r`` command for the given module list. Returns '' for empty list."""
    if not modules:
        return ""
    return "sudo modprobe -r " + " ".join(shlex.quote(m) for m in modules)
