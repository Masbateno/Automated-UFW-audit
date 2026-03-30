"""
System information helpers for ufw-audit.

Collects OS/kernel/UFW metadata, detects network context (NAT vs public IP),
and resolves the real user home directory when running under sudo.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


# ---------------------------------------------------------------------------
# User home
# ---------------------------------------------------------------------------

def get_user_home() -> Path:
    """Return the real user home directory, respecting SUDO_USER."""
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user and re.match(r"^[a-zA-Z0-9_.-]{1,256}$", sudo_user):
        import pwd
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


# ---------------------------------------------------------------------------
# System info
# ---------------------------------------------------------------------------

def collect_system_info(version: str, lang: str):
    """Collect system information for the report header."""
    from ufw_audit.report import SystemInfo
    from ufw_audit.output import sanitize as _sanitize

    def run(*args):
        try:
            r = subprocess.run(list(args), capture_output=True, text=True, timeout=5)
            return r.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return "N/A"

    # OS name
    os_name = "N/A"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line[:512]
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
        kernel=_sanitize(run("uname", "-r"), max_len=64),
        ufw_version=ufw_version,
        user=_sanitize(
            os.environ.get("SUDO_USER") or os.environ.get("USER", "unknown"),
            max_len=32,
        ),
        config_path=str(get_user_home() / ".config" / "ufw-audit" / "config.conf"),
        language=lang,
        version=version,
    )


# ---------------------------------------------------------------------------
# Network context
# ---------------------------------------------------------------------------

# Private IPv4 ranges (RFC 1918 + loopback + CGNAT)
_PRIVATE_IPV4_RE = re.compile(
    r"^(10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)"
)


def get_public_ip() -> str:
    """Attempt to determine public IP via a lightweight HTTP request."""
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=3) as resp:
            ip = resp.read(64).decode().strip()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return ip
        return ""
    except (OSError, urllib.error.URLError, ValueError):
        return ""


def detect_network_context() -> tuple[str, str]:
    """
    Detect whether the machine has a direct public IP.

    Returns:
        Tuple of (context: "local"|"public", public_ip: str).
    """
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        if re.search(r"via\s+" + _PRIVATE_IPV4_RE.pattern.lstrip("^"), result.stdout):
            public_ip = get_public_ip()
            return "local", public_ip
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    try:
        result = subprocess.run(
            ["ip", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for match in re.finditer(r"inet\s+([\d.]+)/", result.stdout):
            ip = match.group(1)
            if not _PRIVATE_IPV4_RE.match(ip):
                return "public", ip
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    public_ip = get_public_ip()
    return "local", public_ip
