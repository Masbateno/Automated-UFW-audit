"""
--explain KEY implementation for ufw-audit.

Prints a structured explanation for a given finding key:
  - what the finding means (title)
  - why it is a security risk (why)
  - how to fix it step by step (how)

Key normalisation strips file-specific middle segments so that e.g.
'file_perms.shadow.world_writable' resolves to 'file_perms.world_writable'.

Usage:
    from ufw_audit.explain import run_explain
    run_explain("ssh.password_auth", t)
    run_explain("list", t)          # prints all available keys
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Available explain keys (canonical list)
# ---------------------------------------------------------------------------

EXPLAIN_KEYS: list[str] = [
    # SSH — authentication
    "ssh.password_auth",
    "ssh.permit_root_login",
    "ssh.permit_empty_passwords",
    "ssh.pubkey_auth_disabled",
    "ssh.no_passphrase",
    "ssh.dsa_key",
    # SSH — access control
    "ssh.max_auth_tries",
    "ssh.allow_tcp_forwarding",
    "ssh.x11_forwarding",
    "ssh.permit_user_env",
    "ssh.ignore_rhosts_disabled",
    "ssh.host_based_auth",
    "ssh.strict_modes_disabled",
    "ssh.client_strict_host_no",
    # SSH — cryptography
    "ssh.weak_ciphers",
    "ssh.weak_macs",
    "ssh.weak_kex",
    # Files & access
    "file_perms.world_writable",
    "file_perms.too_permissive",
    "file_perms.sudoers_nopasswd_all",
    "file_perms.ssh_host_key_perms",
    # Updates
    "updates.security_pending",
    "updates.unattended_not_configured",
    # Hardening
    "hardening.rp_filter_disabled",
    "hardening.rp_filter_loose",
    "hardening.redirects_enabled",
    "hardening.log_martians_disabled",
    "hardening.fail2ban_missing",
    # Kernel modules
    "kernel_modules.risky_fs",
    "kernel_modules.risky_net",
    # Cron
    "cron_audit.pipe_to_shell",
    "cron_audit.world_writable",
    # Services
    "services_state.enabled_inactive",
]

# ---------------------------------------------------------------------------
# Key normalisation
# ---------------------------------------------------------------------------

# file_perms findings sometimes carry one or more intermediate path segments
# (e.g. 'file_perms.shadow.world_writable', 'file_perms.a.b.c.world_writable').
# Strip all intermediate segments so the explain lookup always resolves.
_NORMALIZE_RE = re.compile(
    r"^(file_perms)\.(?:[^.]+\.)+"
    r"(world_writable|too_permissive|ssh_host_key_perms"
    r"|sudoers_nopasswd_all|sudoers_nopasswd_specific)$"
)


def normalize_key(key: str) -> str:
    """
    Return the canonical explain-lookup key.

    'file_perms.shadow.world_writable'  →  'file_perms.world_writable'
    'ssh.password_auth'                 →  'ssh.password_auth'   (unchanged)
    """
    m = _NORMALIZE_RE.match(key)
    if m:
        return f"{m.group(1)}.{m.group(2)}"
    return key


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

_DIVIDER_WIDE  = "─" * 60
_DIVIDER_SHORT = "─" * 10


def run_explain(key: str, t) -> None:
    """
    Print a structured explanation for *key*.

    Pass key="list" to print all available keys.

    Args:
        key: Finding key (e.g. "ssh.password_auth") or "list".
        t:   Translation function from ufw_audit.i18n.
    """
    key = key.strip()

    # ---- list mode ---------------------------------------------------------
    if key == "list":
        print("Available --explain keys:")
        print()
        for k in EXPLAIN_KEYS:
            title = t(f"explain.{k}.title")
            print(f"  {k:<42}  {title}")
        print()
        return

    # ---- single key mode ---------------------------------------------------
    norm = normalize_key(key)

    title_val = t(f"explain.{norm}.title")
    why_val   = t(f"explain.{norm}.why")
    how_val   = t(f"explain.{norm}.how")

    # The i18n t() function returns the key path itself when the key is missing
    key_unknown = title_val == f"explain.{norm}.title"

    if key_unknown:
        print(f"No explanation available for: {key!r}")
        print()
        print("Run 'sudo ufw-audit --explain list' to see all available keys.")
        return

    cis_val = t(f"explain_cis.{norm}")
    cis_unknown = cis_val == f"explain_cis.{norm}"

    print()
    print(_DIVIDER_WIDE)
    print(f"  Key:   {norm}")
    print(f"  Title: {title_val}")
    if not cis_unknown:
        print(f"  CIS:   {cis_val}")
    print(_DIVIDER_WIDE)
    print()
    print("WHY IT IS A RISK")
    print(_DIVIDER_SHORT)
    print(why_val)
    print()
    print("HOW TO FIX")
    print(_DIVIDER_SHORT)
    print(how_val)
    print()
