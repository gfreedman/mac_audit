"""
Tests for macaudit/diff.py — pure diff logic.

Covers:
    - Identical scans → ``None`` (no diff output generated).
    - Score delta calculation: positive, negative, and zero.
    - Status-change classification: ``improved`` (lower severity) and
      ``regressed`` (higher severity).
    - New / removed check detection when checks appear or disappear.
    - Schema version mismatch → ``None`` (incompatible history file rejected).
    - Mixed changes in a single diff (simultaneous improve + regress).
    - Filter-mismatch suppression: when ``>50%`` of checks are new or removed,
      the ``new_checks`` / ``removed_checks`` sections are suppressed to avoid
      noise after a profile switch.
    - ``is_empty_diff()`` edge cases.

Design:
    ``compute_diff`` operates entirely on plain dicts, so no macaudit imports
    beyond ``diff.py`` are needed.  The ``_payload()`` and ``_check()``
    helpers build minimal but structurally valid dicts that match the schema
    used by ``history._build_payload()``.
"""

from macaudit.diff import compute_diff, is_empty_diff


# ── Helpers ──────────────────────────────────────────────────────────────────

def _payload(results: list[dict], score: int = 80, schema_version: int = 1,
             scan_time: str = "2026-02-26T14:00:00+00:00") -> dict:
    """Build a minimal scan payload dict suitable for passing to ``compute_diff``.

    The structure mirrors ``history._build_payload()`` output so that tests
    exercise the same schema consumed by the real diff engine.

    Args:
        results:        List of check-result dicts (build with ``_check()``).
        score:          Health score (0–100) for this scan.
        schema_version: Payload schema version; use a value other than ``1``
            to trigger the schema-mismatch rejection path.
        scan_time:      ISO-8601 timestamp string for the scan.

    Returns:
        A dict with all top-level keys required by ``compute_diff``.
    """
    return {
        "schema_version": schema_version,
        "macaudit_version": "1.8.0",
        "scan_time": scan_time,
        "system": {"macos_version": "15.3", "architecture": "Apple Silicon", "model": "Mac"},
        "score": score,
        "summary": {},
        "results": results,
    }


def _check(id: str, status: str = "pass", name: str = "", message: str = "",
           category: str = "system") -> dict:
    """Build a minimal check-result dict for use inside a ``_payload()``.

    Args:
        id:       Unique check identifier (e.g. ``"filevault"``).
        status:   Status string (``"pass"``, ``"warning"``, ``"critical"``, …).
        name:     Human-readable check name; defaults to a title-cased version
            of ``id`` if omitted.
        message:  Result message; defaults to ``"<status> message"`` if omitted.
        category: Check category string (e.g. ``"security"``, ``"system"``).

    Returns:
        A dict with the fields read by ``compute_diff`` during status-change
        and new/removed detection.
    """
    return {
        "id": id,
        "name": name or id.replace("_", " ").title(),
        "category": category,
        "status": status,
        "message": message or f"{status} message",
    }


# ── Identical scans ─────────────────────────────────────────────────────────

class TestIdenticalScans:
    """``compute_diff`` returns ``None`` when there are no meaningful changes."""
    def test_identical_scans_return_none(self):
        """Two identical payloads → None (nothing changed)."""
        checks = [_check("sip", "pass"), _check("filevault", "pass")]
        p = _payload(checks, score=95)
        assert compute_diff(p, p) is None

    def test_same_checks_same_statuses_return_none(self):
        """Same checks with same statuses but different payloads → None."""
        prev = _payload([_check("sip", "pass")], score=95,
                        scan_time="2026-02-25T10:00:00+00:00")
        curr = _payload([_check("sip", "pass")], score=95,
                        scan_time="2026-02-26T10:00:00+00:00")
        assert compute_diff(curr, prev) is None


# ── Score delta ──────────────────────────────────────────────────────────────

class TestScoreDelta:
    """Score delta (``score_after - score_before``) is positive on improvement and negative on regression."""

    def test_score_improved(self):
        """Score rising from 70 → 95 → ``score_delta = +25``."""
        prev = _payload([_check("sip", "critical")], score=70)
        curr = _payload([_check("sip", "pass")], score=95)
        diff = compute_diff(curr, prev)
        assert diff is not None
        assert diff["score_delta"] == 25
        assert diff["score_before"] == 70
        assert diff["score_after"] == 95

    def test_score_regressed(self):
        """Score falling from 95 → 70 → ``score_delta = -25``."""
        prev = _payload([_check("sip", "pass")], score=95)
        curr = _payload([_check("sip", "critical")], score=70)
        diff = compute_diff(curr, prev)
        assert diff is not None
        assert diff["score_delta"] == -25


# ── Improved / regressed detection ───────────────────────────────────────────

class TestStatusChanges:
    """Status-change classification: improved (lower severity) vs. regressed (higher severity)."""

    def test_critical_to_pass_is_improved(self):
        prev = _payload([_check("filevault", "critical")])
        curr = _payload([_check("filevault", "pass")])
        diff = compute_diff(curr, prev)
        assert len(diff["improved"]) == 1
        assert diff["improved"][0]["id"] == "filevault"
        assert diff["improved"][0]["before_status"] == "critical"
        assert diff["improved"][0]["after_status"] == "pass"

    def test_pass_to_warning_is_regressed(self):
        """``pass`` → ``warning`` classifies the check as ``regressed``."""
        prev = _payload([_check("screen_lock", "pass")])
        curr = _payload([_check("screen_lock", "warning")])
        diff = compute_diff(curr, prev)
        assert len(diff["regressed"]) == 1
        assert diff["regressed"][0]["id"] == "screen_lock"
        assert diff["regressed"][0]["before_status"] == "pass"
        assert diff["regressed"][0]["after_status"] == "warning"

    def test_warning_to_info_is_improved(self):
        """``warning`` → ``info`` is an improvement (severity decreased)."""
        prev = _payload([_check("brew_outdated", "warning")], score=97)
        curr = _payload([_check("brew_outdated", "info")], score=100)
        diff = compute_diff(curr, prev)
        assert len(diff["improved"]) == 1
        assert diff["improved"][0]["before_status"] == "warning"
        assert diff["improved"][0]["after_status"] == "info"


# ── New / removed checks ────────────────────────────────────────────────────

class TestNewRemoved:
    """Checks that appear or disappear between scans are tracked separately."""
    def test_new_check_detected(self):
        """Check in current but not previous shows as new."""
        prev = _payload([_check("sip", "pass")], score=95)
        curr = _payload([_check("sip", "pass"), _check("new_check", "warning")], score=90)
        diff = compute_diff(curr, prev)
        assert diff is not None
        assert len(diff["new_checks"]) == 1
        assert diff["new_checks"][0]["id"] == "new_check"

    def test_removed_check_detected(self):
        """Check in previous but not current shows as removed."""
        prev = _payload([_check("sip", "pass"), _check("old_check", "pass")], score=95)
        curr = _payload([_check("sip", "pass")], score=90)
        diff = compute_diff(curr, prev)
        assert diff is not None
        assert len(diff["removed_checks"]) == 1
        assert diff["removed_checks"][0]["id"] == "old_check"


# ── Schema mismatch ─────────────────────────────────────────────────────────

class TestSchemaMismatch:
    """Schema version mismatch → ``None`` (history file from an incompatible release)."""

    def test_schema_version_mismatch_returns_none(self):
        """Different ``schema_version`` values → diff aborted; history is unreadable."""
        prev = _payload([_check("sip", "critical")], score=70, schema_version=1)
        curr = _payload([_check("sip", "pass")], score=95, schema_version=2)
        assert compute_diff(curr, prev) is None

    def test_missing_schema_version_returns_none(self):
        """Missing ``schema_version`` key (corrupt or very old file) → diff aborted."""
        prev = _payload([_check("sip", "pass")])
        del prev["schema_version"]
        curr = _payload([_check("sip", "pass")])
        assert compute_diff(curr, prev) is None


# ── Mixed changes ────────────────────────────────────────────────────────────

class TestMixedChanges:
    """Multiple simultaneous changes are all captured in the same diff."""
    def test_mixed_improved_and_regressed(self):
        """One check improves, another regresses in the same diff."""
        prev = _payload([
            _check("filevault", "critical"),
            _check("screen_lock", "pass"),
        ], score=80)
        curr = _payload([
            _check("filevault", "pass"),
            _check("screen_lock", "warning"),
        ], score=85)
        diff = compute_diff(curr, prev)
        assert diff is not None
        assert len(diff["improved"]) == 1
        assert len(diff["regressed"]) == 1
        assert diff["improved"][0]["id"] == "filevault"
        assert diff["regressed"][0]["id"] == "screen_lock"


# ── Filter mismatch suppression ─────────────────────────────────────────────

class TestFilterSuppression:
    """Filter-mismatch suppression: large check-set churn hides noise from new/removed sections."""
    def test_suppresses_when_over_50pct_new_or_removed(self):
        """When >50% of checks are new/removed, suppress those sections."""
        # Previous: 2 checks. Current: 1 same + 3 new = 4 total.
        # 3 new / 4 total = 75% → suppress
        prev = _payload([
            _check("sip", "pass"),
            _check("old1", "pass"),
        ], score=95)
        curr = _payload([
            _check("sip", "warning"),
            _check("new1", "pass"),
            _check("new2", "pass"),
            _check("new3", "pass"),
        ], score=90)
        diff = compute_diff(curr, prev)
        assert diff is not None
        assert diff["new_checks"] == []
        assert diff["removed_checks"] == []
        # But status change still shows
        assert len(diff["regressed"]) == 1

    def test_no_suppression_when_under_50pct(self):
        """When ≤50% are new/removed, they show normally."""
        # Previous: 4 checks. Current: 4 same + 1 new = 5. 1/5 = 20% → no suppression
        checks = [_check(f"c{i}", "pass") for i in range(4)]
        prev = _payload(checks, score=90)
        curr_checks = checks + [_check("new_one", "warning")]
        curr = _payload(curr_checks, score=87)
        diff = compute_diff(curr, prev)
        assert diff is not None
        assert len(diff["new_checks"]) == 1


# ── is_empty_diff ────────────────────────────────────────────────────────────

class TestIsEmptyDiff:
    """``is_empty_diff`` returns ``True`` only when every field is zero / empty."""

    def test_empty_diff(self):
        """All lists empty and score_delta zero → truly empty diff."""
        assert is_empty_diff({
            "score_delta": 0,
            "improved": [],
            "regressed": [],
            "new_checks": [],
            "removed_checks": [],
        }) is True

    def test_non_empty_with_score_delta(self):
        """A non-zero ``score_delta`` alone makes the diff non-empty."""
        assert is_empty_diff({
            "score_delta": 5,
            "improved": [],
            "regressed": [],
            "new_checks": [],
            "removed_checks": [],
        }) is False

    def test_non_empty_with_improved(self):
        """A non-empty ``improved`` list makes the diff non-empty even with delta=0."""
        assert is_empty_diff({
            "score_delta": 0,
            "improved": [{"id": "x"}],
            "regressed": [],
            "new_checks": [],
            "removed_checks": [],
        }) is False
