"""
Tests for ``calculate_health_score()``.

Algorithm (from ``checks/base.py``):
    - Start at 100.
    - Each ``critical`` result deducts 10 points (15 for security/privacy/system).
    - Each ``warning``  result deducts  3 points ( 3 for security/privacy/system;
      ``int(3 * 1.2) = 3`` — truncation means no practical difference here).
    - ``info``, ``pass``, ``skip``, ``error`` → 0 deduction.
    - Final score is clamped to ``[0, 100]``.

Covers:
    - Neutral statuses contribute zero penalty.
    - Single and multiple critical/warning deductions for non-security categories.
    - Security multiplier applied correctly for ``security``, ``privacy``, ``system``.
    - Mixed-category scenarios accumulate correctly.
    - Clamping: score never goes below 0 or above 100.

Design:
    The ``_r()`` helper constructs minimal ``CheckResult`` instances so each
    test can specify only the two fields that matter (``status`` and
    ``category``), keeping the assertions readable and the intent clear.
"""

import pytest

from macaudit.checks.base import CheckResult, calculate_health_score


def _r(status: str, category: str = "disk") -> CheckResult:
    """Build a minimal ``CheckResult`` with the given status and category.

    All other fields are set to harmless defaults so that only the two
    arguments that affect ``calculate_health_score()`` vary between tests.

    Args:
        status:   The result status string (e.g. ``"critical"``, ``"warning"``).
        category: The check category string.  Defaults to ``"disk"`` (a
            non-security category) so security-multiplier tests must pass
            ``"security"`` or ``"system"`` explicitly.

    Returns:
        A fully-populated ``CheckResult`` instance ready for passing to
        ``calculate_health_score()``.
    """
    return CheckResult(
        id="t", name="T", category=category, category_icon="✅",
        status=status, message="",
        scan_description="", finding_explanation="", recommendation="",
        fix_level="none", fix_description="",
    )


class TestCalculateHealthScore:
    """Tests for ``calculate_health_score()`` — the scoring algorithm.

    Organised into neutral statuses, critical deductions, warning deductions,
    mixed scenarios, and clamping.  Each test verifies exactly one arithmetic
    property so a regression immediately identifies which branch is broken.
    """

    def test_empty_list_returns_100(self):
        """No results → perfect score; there is nothing wrong to report."""
        assert calculate_health_score([]) == 100

    def test_all_pass_returns_100(self):
        """Ten passing results → perfect score; ``pass`` adds zero penalty."""
        assert calculate_health_score([_r("pass")] * 10) == 100

    def test_all_info_returns_100(self):
        """``info`` status is informational only — zero penalty."""
        assert calculate_health_score([_r("info")] * 5) == 100

    def test_all_skip_returns_100(self):
        """Suppressed checks (``skip``) must not penalise the score."""
        assert calculate_health_score([_r("skip")] * 5) == 100

    def test_all_error_returns_100(self):
        """Failed checks (``error``) are not penalised — the check itself broke,
        not the system under audit."""
        assert calculate_health_score([_r("error")] * 5) == 100

    # ── Critical deductions ───────────────────────────────────────────────────

    def test_single_critical_non_security_deducts_10(self):
        """One critical in a non-security category → 100 - 10 = 90."""
        assert calculate_health_score([_r("critical", "disk")]) == 90

    def test_single_critical_security_deducts_15(self):
        """One critical in ``security`` → 100 - 15 = 85 (security multiplier)."""
        assert calculate_health_score([_r("critical", "security")]) == 85

    def test_single_critical_privacy_deducts_15(self):
        """``privacy`` category also carries the 1.5× multiplier → 100 - 15 = 85."""
        assert calculate_health_score([_r("critical", "privacy")]) == 85

    def test_single_critical_system_deducts_15(self):
        """``system`` category also carries the 1.5× multiplier → 100 - 15 = 85."""
        assert calculate_health_score([_r("critical", "system")]) == 85

    def test_two_criticals_non_security(self):
        """Two disk criticals → 100 - 20 = 80 (penalties are additive)."""
        assert calculate_health_score([_r("critical", "disk")] * 2) == 80

    def test_two_criticals_security(self):
        """Two security criticals → 100 - 30 = 70."""
        assert calculate_health_score([_r("critical", "security")] * 2) == 70

    # ── Warning deductions ────────────────────────────────────────────────────

    def test_single_warning_non_security_deducts_3(self):
        """One disk warning → 100 - 3 = 97."""
        assert calculate_health_score([_r("warning", "disk")]) == 97

    def test_single_warning_security_deducts_3(self):
        """Security warning uses ``int(3 * 1.2) = int(3.6) = 3`` — truncates to 3.

        The security multiplier is applied via ``int()`` (floor) rather than
        ``round()``, so the effective penalty for a security warning equals the
        penalty for a non-security warning at the current multiplier.
        """
        assert calculate_health_score([_r("warning", "security")]) == 97

    def test_single_warning_privacy_deducts_3(self):
        """``privacy`` warning → 100 - 3 = 97 (same truncation applies)."""
        assert calculate_health_score([_r("warning", "privacy")]) == 97

    def test_five_warnings_non_security(self):
        """Five disk warnings → 100 - 15 = 85."""
        assert calculate_health_score([_r("warning", "disk")] * 5) == 85

    # ── Mixed scenarios ───────────────────────────────────────────────────────

    def test_critical_plus_warnings(self):
        """Security critical + two disk warnings + pass + info → 100 - 15 - 6 = 79."""
        results = [
            _r("critical", "security"),   # -15
            _r("warning", "disk"),        # -3
            _r("warning", "disk"),        # -3
            _r("pass", "disk"),           # 0
            _r("info", "disk"),           # 0
        ]
        assert calculate_health_score(results) == 100 - 15 - 3 - 3  # 79

    def test_mixed_categories(self):
        """Disk critical + system critical + homebrew warning + security pass → 72."""
        results = [
            _r("critical", "disk"),       # -10
            _r("critical", "system"),     # -15
            _r("warning", "homebrew"),    # -3
            _r("pass", "security"),       # 0
        ]
        assert calculate_health_score(results) == 100 - 10 - 15 - 3  # 72

    # ── Clamping ──────────────────────────────────────────────────────────────

    def test_clamps_to_zero_on_many_criticals(self):
        """20 security criticals → 300 points deducted → clamped to 0, not negative."""
        results = [_r("critical", "security")] * 20
        assert calculate_health_score(results) == 0

    def test_never_below_zero(self):
        """Score is always non-negative regardless of how many criticals accumulate."""
        results = [_r("critical")] * 100
        assert calculate_health_score(results) >= 0

    def test_never_above_100(self):
        """Score cannot exceed 100 even with an all-passing result set."""
        assert calculate_health_score([_r("pass")] * 50) == 100
