"""
Scoring engine for ufw-audit.

Maintains the security score (0-10), accumulates deductions from
individual checks, and derives the risk level from the final score.

No display logic lives here. All findings are plain data structures
consumed by output.py and report.py.

Usage:
    from ufw_audit.scoring import ScoreEngine, CheckResult, Deduction, Finding, FindingLevel

    engine = ScoreEngine()

    # Each check returns a CheckResult
    result = CheckResult(
        deductions=[Deduction(reason="Open port", points=2, context="public")],
        findings=[Finding(level=FindingLevel.ALERT, message="Port 22 open to internet")],
    )
    engine.apply(result)

    print(engine.score)    # 8
    print(engine.level)    # "low"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class FindingLevel(Enum):
    """Severity level of a finding reported by a check."""
    OK      = "ok"
    INFO    = "info"
    WARN    = "warn"
    ALERT   = "alert"


class RiskLevel(Enum):
    """Overall risk level derived from the final score."""
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# Score thresholds — inclusive lower bound for each level
_RISK_THRESHOLDS: list[tuple[int, RiskLevel]] = [
    (8, RiskLevel.LOW),
    (5, RiskLevel.MEDIUM),
    (3, RiskLevel.HIGH),
    (0, RiskLevel.CRITICAL),
]

# Maximum achievable score
MAX_SCORE: int = 10


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Deduction:
    """
    A single score deduction with its justification.

    Args:
        reason:  Human-readable explanation (already translated by caller).
        points:  Number of points deducted (positive integer).
        context: Network context at time of deduction — "local" or "public".
                 Used for display in the score breakdown.
    """
    reason:  str
    points:  int
    context: str = "local"

    def __post_init__(self) -> None:
        if self.points < 0:
            raise ValueError(f"Deduction points must be non-negative, got {self.points}")


@dataclass
class Finding:
    """
    A single audit finding for display in the terminal and report.

    Args:
        level:   Severity level (OK, INFO, WARN, ALERT).
        message: Main finding message (already translated by caller).
        detail:  Optional secondary detail or recommendation text.
        nature:  Category used by --fix mode: "action" | "improvement" | "structural" | "".
        cmd:     Shell command for --fix mode. Empty string if not automatable.
    """
    level:   FindingLevel
    message: str
    detail:  str = ""
    nature:  str = ""
    cmd:     str = ""


@dataclass
class CheckResult:
    """
    The complete output of a single check function.

    Returned by every check_* function and consumed by ScoreEngine.apply().

    Args:
        deductions: List of score deductions to apply.
        findings:   List of findings to display.
    """
    deductions: List[Deduction] = field(default_factory=list)
    findings:   List[Finding]   = field(default_factory=list)

    def add_deduction(self, reason: str, points: int, context: str = "local") -> None:
        """Convenience method to append a deduction."""
        self.deductions.append(Deduction(reason=reason, points=points, context=context))

    def add_finding(
        self,
        level: FindingLevel,
        message: str,
        detail: str = "",
        nature: str = "",
        cmd: str = "",
    ) -> None:
        """Convenience method to append a finding."""
        self.findings.append(
            Finding(level=level, message=message, detail=detail, nature=nature, cmd=cmd)
        )

    def ok(self, message: str, detail: str = "") -> None:
        """Shorthand for adding an OK finding."""
        self.add_finding(FindingLevel.OK, message, detail)

    def info(self, message: str, detail: str = "") -> None:
        """Shorthand for adding an INFO finding."""
        self.add_finding(FindingLevel.INFO, message, detail)

    def warn(self, message: str, detail: str = "", nature: str = "improvement", cmd: str = "") -> None:
        """Shorthand for adding a WARN finding."""
        self.add_finding(FindingLevel.WARN, message, detail, nature, cmd)

    def alert(self, message: str, detail: str = "", nature: str = "action", cmd: str = "") -> None:
        """Shorthand for adding an ALERT finding."""
        self.add_finding(FindingLevel.ALERT, message, detail, nature, cmd)


# ---------------------------------------------------------------------------
# Score engine
# ---------------------------------------------------------------------------

@dataclass
class _Cap:
    """Internal record of a score cap applied via ScoreEngine.cap()."""
    maximum: int
    reason:  str


class ScoreEngine:
    """
    Accumulates deductions from check results and computes the final score.

    The score starts at MAX_SCORE (10) and decreases with each deduction.
    A cap can be applied to enforce an absolute ceiling (e.g. firewall inactive → max 3).
    The cap is applied once, after all deductions, in finalize().

    Attributes:
        score:     Current score (0–10). Updated by apply() and finalize().
        breakdown: Ordered list of all applied deductions.
        findings:  Flat list of all findings from all applied CheckResults.
    """

    def __init__(self) -> None:
        self._raw_score: int = MAX_SCORE
        self._cap: _Cap | None = None
        self.breakdown: list[Deduction] = []
        self.findings:  list[Finding]   = []
        self._finalized: bool = False

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def apply(self, result: CheckResult) -> None:
        """
        Apply all deductions and collect all findings from a CheckResult.

        Args:
            result: Output of a check_* function.
        """
        for deduction in result.deductions:
            self._apply_deduction(deduction)
        self.findings.extend(result.findings)

    def deduct(self, reason: str, points: int, context: str = "local") -> None:
        """
        Apply a single deduction directly (without a CheckResult wrapper).

        Useful for deductions that arise from cross-check logic in the
        orchestrator rather than from a single check function.

        Args:
            reason:  Explanation string.
            points:  Points to deduct (positive integer).
            context: "local" or "public".
        """
        self._apply_deduction(Deduction(reason=reason, points=points, context=context))

    def cap(self, maximum: int, reason: str) -> None:
        """
        Register a score ceiling to be enforced during finalize().

        Only the lowest cap wins if cap() is called multiple times.

        Args:
            maximum: Score will not exceed this value after finalize().
            reason:  Explanation string displayed in the breakdown.
        """
        if self._cap is None or maximum < self._cap.maximum:
            self._cap = _Cap(maximum=maximum, reason=reason)

    def finalize(self) -> None:
        """
        Apply the registered cap (if any) and clamp the score to [0, MAX_SCORE].

        Should be called once, after all checks have run.
        Safe to call multiple times — subsequent calls are no-ops.
        """
        if self._finalized:
            return
        if self._cap is not None and self._raw_score > self._cap.maximum:
            self._raw_score = self._cap.maximum
        self._raw_score = max(0, min(MAX_SCORE, self._raw_score))
        self._finalized = True

    # ------------------------------------------------------------------
    # Read-only properties
    # ------------------------------------------------------------------

    @property
    def score(self) -> int:
        """
        Current score after all deductions and cap.

        Calls finalize() implicitly if not yet called.
        """
        if not self._finalized:
            self.finalize()
        return self._raw_score

    @property
    def level(self) -> RiskLevel:
        """Risk level derived from the current score."""
        s = self.score
        for threshold, risk in _RISK_THRESHOLDS:
            if s >= threshold:
                return risk
        return RiskLevel.CRITICAL  # fallback — should never be reached

    @property
    def cap_info(self) -> _Cap | None:
        """The registered cap, or None if no cap was set."""
        return self._cap

    @property
    def alert_count(self) -> int:
        """Number of ALERT-level findings."""
        return sum(1 for f in self.findings if f.level == FindingLevel.ALERT)

    @property
    def warn_count(self) -> int:
        """Number of WARN-level findings."""
        return sum(1 for f in self.findings if f.level == FindingLevel.WARN)

    @property
    def ok_count(self) -> int:
        """Number of OK-level findings."""
        return sum(1 for f in self.findings if f.level == FindingLevel.OK)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_deduction(self, deduction: Deduction) -> None:
        self._raw_score -= deduction.points
        self.breakdown.append(deduction)
