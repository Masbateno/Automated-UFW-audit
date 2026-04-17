"""
Per-domain security sub-scores for ufw-audit.

Groups deductions from a finalized ScoreEngine by security domain and
computes a score (0–10) for each domain independently.

Domains:
  ssh        — SSH server/client configuration (checks/ssh.py)
  samba      — Samba security audit (checks/samba.py)
  file_perms — Sensitive file permissions and sudoers (checks/file_perms.py)
  updates    — System package updates (checks/updates.py)
  hardening  — Kernel hardening and security tools (checks/hardening.py)
  disk       — Disk health: SMART + partition usage (checks/disk.py)
  firewall   — Firewall rules, ports, services, logs (everything else)

Usage:
    from ufw_audit.domain_scores import compute_domain_scores, DOMAINS

    scores = compute_domain_scores(engine)
    for domain in DOMAINS:
        info = scores[domain]
        print(f"{info['label']}: {info['score']}/10")
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ufw_audit.scoring import ScoreEngine

from ufw_audit.scoring import MAX_SCORE

# ---------------------------------------------------------------------------
# Domain definitions
# ---------------------------------------------------------------------------

# Ordered list of canonical domain identifiers (display order).
DOMAINS: list[str] = ["ssh", "samba", "file_perms", "updates", "hardening", "disk", "firewall"]

# Human-readable English labels for each domain.
_LABELS: dict[str, str] = {
    "ssh":        "SSH",
    "samba":      "Samba Security",
    "file_perms": "Files & Access",
    "updates":    "Updates",
    "hardening":  "Hardening",
    "disk":       "Disk Health",
    "firewall":   "Firewall & Services",
}

# Known key prefixes that map to specific domains.
# Any prefix not listed here → "firewall" (catch-all).
_PREFIX_TO_DOMAIN: dict[str, str] = {
    "ssh":             "ssh",
    "samba":           "samba",
    "file_perms":      "file_perms",
    "updates":         "updates",
    "hardening":       "hardening",
    "kernel_modules":  "hardening",
    "cron_audit":      "hardening",
    "services_state":  "hardening",
    "user_accounts":    "file_perms",
    "password_policy":  "hardening",
    "memory":           "hardening",
    "clamav":           "hardening",
    "disk":             "disk",
}


def _key_to_domain(key: str | None) -> str | None:
    """
    Map a deduction key (e.g. 'ssh.password_auth') to its domain.

    Returns None for synthetic/cap deductions (empty key), which are
    excluded from per-domain scoring.
    """
    if not key or not isinstance(key, str):
        return None
    prefix = key.split(".", 1)[0]
    return _PREFIX_TO_DOMAIN.get(prefix, "firewall")


# ---------------------------------------------------------------------------
# Main computation
# ---------------------------------------------------------------------------

def compute_domain_scores(engine: "ScoreEngine") -> dict[str, dict]:
    """
    Compute per-domain security sub-scores from a finalized ScoreEngine.

    Each domain score is computed independently as:
        max(0, MAX_SCORE - sum_of_deductions_for_domain)

    Deductions without a key (synthetic/cap) are excluded.

    Args:
        engine: A finalized ScoreEngine (engine.finalize() must have been called).

    Returns:
        Dict mapping domain identifier → {
            "score":      int  — 0 to 10,
            "deductions": int  — total points deducted in this domain,
            "label":      str  — human-readable English label,
        }
    """
    domain_deductions: dict[str, int] = {d: 0 for d in DOMAINS}

    for deduction in getattr(engine, "breakdown", []):
        domain = _key_to_domain(getattr(deduction, "key", None))
        if domain is None:
            continue
        domain_deductions[domain] += getattr(deduction, "points", 0)

    return {
        domain: {
            "score":      max(0, min(MAX_SCORE, MAX_SCORE - domain_deductions[domain])),
            "deductions": domain_deductions[domain],
            "label":      _LABELS.get(domain, domain.capitalize()),
        }
        for domain in DOMAINS
    }


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------

_BAR_WIDTH  = 10   # total bar characters
_BAR_FILLED = "█"
_BAR_EMPTY  = "░"


def render_domain_scores(scores: dict[str, dict], t=None) -> list[str]:
    """
    Render domain scores as a list of indented text lines.

    Args:
        scores: Output of compute_domain_scores().
        t:      Optional translation function.  When provided the title line
                uses the locale key 'domain_scores.title'; otherwise the
                English default is used.

    Returns:
        List of strings (one per line), ready for print().
    """
    title = (t("domain_scores.title") if t else None) or "Domain Scores"

    lines: list[str] = [f"  {title}"]
    lines.append("  " + "─" * 40)

    if not scores:
        lines.append("  (no data)")
        return lines

    def _label(domain: str, fallback: str) -> str:
        if not t:
            return fallback
        translated = t(f"domain_scores.{domain}")
        return translated if translated != f"domain_scores.{domain}" else fallback

    labels = {d: _label(d, scores[d]["label"]) for d in DOMAINS if d in scores}
    label_width = max(len(lbl) for lbl in labels.values())

    for domain in DOMAINS:
        if domain not in scores:
            continue
        info   = scores[domain]
        score  = info["score"]
        label  = labels[domain]
        filled = int(score * _BAR_WIDTH / MAX_SCORE)
        empty  = _BAR_WIDTH - filled
        bar    = _BAR_FILLED * filled + _BAR_EMPTY * empty
        lines.append(
            f"  {label:<{label_width}}  {score:>2}/10  {bar}"
        )

    return lines
