"""
Tests for ui/report.py — Rich rendering of scan results and diffs.

Covers:
    - ``_render_issue()`` MDM badge: shown when ``mdm_enrolled=True`` and the
      check ID is in ``MDM_CHECK_IDS``; hidden otherwise.
    - ``_compact_table()`` MDM tag: ``"managed"`` appears for MDM checks when
      enrolled; absent for non-MDM checks or when not enrolled.
    - ``_score_verdict()`` contextual copy: per-critical-count behaviour
      (0, 1, 2, 3+ criticals), message normalisation (lowercase, strip period),
      and backward-compatibility without ``critical_results``.
    - ``build_summary_panel()`` integration: verdict text flows through to the
      rendered panel.
    - ``build_diff_panel()``: score delta display (positive, negative, zero),
      improved/regressed/new/removed sections, section omission when empty,
      previous scan timestamp.
    - ``print_report()`` with and without a diff dict.

Design:
    All rendering tests use a ``Console`` backed by a ``StringIO`` buffer
    (via ``_console()`` / ``_render_to_text()``) so assertions can search
    plain text without parsing ANSI escape codes.  ``_result()`` and
    ``TestDiffPanel._diff()`` build minimal but complete data structures
    to keep each test focused on the property under test.
"""

from io import StringIO

from rich.console import Console

from macaudit.checks.base import CheckResult
from macaudit.ui.report import (
    _compact_table,
    _render_issue,
    _score_verdict,
    build_diff_panel,
    build_summary_panel,
    print_report,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _console() -> tuple[Console, StringIO]:
    """Return a Rich ``Console`` wired to a ``StringIO`` buffer.

    ``highlight=False`` and ``no_color=True`` strip markup and colour codes so
    assertions compare plain text without ANSI escape sequences.

    Returns:
        A ``(Console, StringIO)`` tuple — pass the console to the function
        under test and read ``buf.getvalue()`` for assertions.
    """
    buf = StringIO()
    con = Console(file=buf, highlight=False, no_color=True)
    return con, buf


def _result(**kwargs) -> CheckResult:
    """Build a minimal ``CheckResult`` with sensible defaults.

    All required ``CheckResult`` fields are populated.  Pass keyword arguments
    to override any subset of fields needed for a specific test scenario.

    Args:
        **kwargs: Any ``CheckResult`` field to override.  Common overrides:
            ``id``, ``name``, ``status``, ``message``.

    Returns:
        A fully-initialised ``CheckResult`` instance.
    """
    defaults = dict(
        id="test_check",
        name="Test Check",
        category="system",
        category_icon="🖥️",
        status="warning",
        message="something is off",
        scan_description="",
        finding_explanation="",
        recommendation="",
        fix_level="none",
        fix_description="",
    )
    defaults.update(kwargs)
    return CheckResult(**defaults)


def _render_to_text(renderables: list) -> str:
    """Render a list of Rich renderable objects to a plain-text string.

    Args:
        renderables: Any sequence of Rich-renderable objects (``Panel``,
            ``Text``, ``Table``, plain strings, etc.).

    Returns:
        The combined plain-text output of all rendered objects, suitable
        for substring assertions.
    """
    con, buf = _console()
    for r in renderables:
        con.print(r)
    return buf.getvalue()


# ── MDM inline badges: _render_issue ─────────────────────────────────────────

class TestRenderIssueMDM:
    """MDM badge visibility in ``_render_issue()`` based on enrollment and check ID."""
    def test_mdm_badge_shown_for_mdm_check(self):
        """MDM-relevant check shows badge when mdm_enrolled=True."""
        r = _result(id="filevault", name="FileVault", status="critical",
                     message="Disk encryption is disabled")
        parts = _render_issue(r, mdm_enrolled=True)
        text = _render_to_text(parts)
        assert "may be managed by your org" in text

    def test_mdm_badge_hidden_when_not_enrolled(self):
        """MDM-relevant check does NOT show badge when mdm_enrolled=False."""
        r = _result(id="filevault", name="FileVault", status="critical",
                     message="Disk encryption is disabled")
        parts = _render_issue(r, mdm_enrolled=False)
        text = _render_to_text(parts)
        assert "may be managed by your org" not in text

    def test_mdm_badge_hidden_for_non_mdm_check(self):
        """Non-MDM check never shows badge even when mdm_enrolled=True."""
        r = _result(id="disk_space", name="Disk Space", status="warning",
                     message="14 GB free")
        parts = _render_issue(r, mdm_enrolled=True)
        text = _render_to_text(parts)
        assert "may be managed by your org" not in text

    def test_all_mdm_check_ids_show_badge(self):
        """Every check ID in MDM_CHECK_IDS produces a badge."""
        from macaudit.ui.theme import MDM_CHECK_IDS
        for check_id in MDM_CHECK_IDS:
            r = _result(id=check_id, status="warning", message="test")
            parts = _render_issue(r, mdm_enrolled=True)
            text = _render_to_text(parts)
            assert "may be managed by your org" in text, (
                f"MDM badge missing for check ID '{check_id}'"
            )


# ── MDM inline badges: _compact_table ────────────────────────────────────────

class TestCompactTableMDM:
    """MDM ``"managed"`` tag visibility in ``_compact_table()``."""
    def test_mdm_managed_tag_shown_for_mdm_check(self):
        """Compact table appends 'managed' tag for MDM checks when enrolled."""
        r = _result(id="firewall", name="Firewall", status="pass",
                     message="Firewall is enabled")
        con, buf = _console()
        table = _compact_table([r], mdm_enrolled=True)
        con.print(table)
        assert "managed" in buf.getvalue()

    def test_mdm_managed_tag_hidden_when_not_enrolled(self):
        """Compact table does NOT append 'managed' tag when not enrolled."""
        r = _result(id="firewall", name="Firewall", status="pass",
                     message="Firewall is enabled")
        con, buf = _console()
        table = _compact_table([r], mdm_enrolled=False)
        con.print(table)
        assert "managed" not in buf.getvalue()

    def test_mdm_managed_tag_hidden_for_non_mdm_check(self):
        """Compact table does NOT append 'managed' for non-MDM checks."""
        r = _result(id="battery", name="Battery", status="info",
                     message="342 cycles")
        con, buf = _console()
        table = _compact_table([r], mdm_enrolled=True)
        con.print(table)
        assert "managed" not in buf.getvalue()


# ── Contextual verdicts: _score_verdict ──────────────────────────────────────

class TestScoreVerdict:
    """Contextual verdict copy from ``_score_verdict()`` across all critical-count branches."""
    def test_one_critical_names_the_finding(self):
        """With 1 critical, verdict names the specific finding."""
        r = _result(id="filevault", name="FileVault Disk Encryption",
                     status="critical", message="Disk encryption is disabled")
        verdict = _score_verdict(70, 1, 0, critical_results=[r])
        assert "FileVault Disk Encryption" in verdict
        assert "disk encryption is disabled" in verdict
        assert "Address this first" in verdict

    def test_two_criticals_names_both(self):
        """With 2 criticals, verdict names both findings."""
        r1 = _result(id="filevault", name="FileVault", status="critical",
                      message="Disabled")
        r2 = _result(id="firewall", name="Firewall", status="critical",
                      message="Disabled")
        verdict = _score_verdict(60, 2, 0, critical_results=[r1, r2])
        assert "FileVault" in verdict
        assert "Firewall" in verdict
        assert "2 critical issues" in verdict

    def test_three_criticals_uses_generic_count(self):
        """With 3+ criticals, verdict uses generic count, not names."""
        rs = [
            _result(id="a", name="Check A", status="critical", message="bad"),
            _result(id="b", name="Check B", status="critical", message="bad"),
            _result(id="c", name="Check C", status="critical", message="bad"),
        ]
        verdict = _score_verdict(40, 3, 0, critical_results=rs)
        assert "3 critical issues detected" in verdict
        assert "Check A" not in verdict

    def test_zero_criticals_high_score(self):
        """With no criticals and high score, verdict is positive."""
        verdict = _score_verdict(96, 0, 0)
        assert "Excellent" in verdict

    def test_zero_criticals_mid_score(self):
        """With no criticals and mid score, verdict reflects warnings."""
        verdict = _score_verdict(80, 0, 3)
        assert "Good" in verdict

    def test_one_critical_strips_trailing_period(self):
        """Message with trailing period is stripped in the verdict."""
        r = _result(id="x", name="Some Check", status="critical",
                     message="Something is wrong.")
        verdict = _score_verdict(70, 1, 0, critical_results=[r])
        # Should not have double period: "wrong.. Address"
        assert ".." not in verdict
        assert "something is wrong. Address" in verdict

    def test_one_critical_lowercases_message(self):
        """Message is lowercased in the contextual verdict."""
        r = _result(id="x", name="Check", status="critical",
                     message="DISK ENCRYPTION IS OFF")
        verdict = _score_verdict(70, 1, 0, critical_results=[r])
        assert "disk encryption is off" in verdict

    def test_backward_compat_without_critical_results(self):
        """Calling without critical_results still works (generic message)."""
        verdict = _score_verdict(40, 4, 0)
        assert "4 critical issues detected" in verdict


# ── Contextual verdicts: build_summary_panel integration ─────────────────────

class TestSummaryPanelVerdict:
    """Integration test: contextual verdict flows from ``_score_verdict`` into ``build_summary_panel``."""
    def test_summary_panel_includes_critical_name(self):
        """build_summary_panel verdict names the critical finding."""
        r_crit = _result(id="firewall", name="Firewall", status="critical",
                          message="Firewall is disabled")
        r_pass = _result(id="sip", name="SIP", status="pass",
                          message="Enabled")
        con, buf = _console()
        panel = build_summary_panel([r_crit, r_pass])
        con.print(panel)
        output = buf.getvalue()
        assert "Firewall" in output
        assert "firewall is disabled" in output


# ── Diff panel: build_diff_panel ─────────────────────────────────────────────

class TestDiffPanel:
    """Tests for ``build_diff_panel()`` and ``print_report()`` diff integration."""

    def _diff(self, **overrides) -> dict:
        """Build a minimal diff dict compatible with ``build_diff_panel()``.

        All required keys are populated with sensible defaults.  Pass keyword
        arguments to override specific fields for individual test scenarios.

        Args:
            **overrides: Any top-level key in the diff dict to override.
                Common overrides: ``score_delta``, ``score_before``,
                ``score_after``, ``improved``, ``regressed``.

        Returns:
            A dict with all keys consumed by ``build_diff_panel()``.
        """
        base = {
            "previous_scan_time": "2026-02-25T18:30:00+00:00",
            "score_before": 72,
            "score_after": 85,
            "score_delta": 13,
            "improved": [],
            "regressed": [],
            "new_checks": [],
            "removed_checks": [],
        }
        base.update(overrides)
        return base

    def test_panel_renders_score_delta_positive(self):
        """Panel shows score before, after, and positive delta in green."""
        con, buf = _console()
        panel = build_diff_panel(self._diff(score_before=72, score_after=85, score_delta=13))
        con.print(panel)
        output = buf.getvalue()
        assert "72" in output
        assert "85" in output
        assert "(+13)" in output

    def test_panel_renders_score_delta_negative(self):
        """Panel shows negative delta."""
        con, buf = _console()
        panel = build_diff_panel(self._diff(score_before=90, score_after=75, score_delta=-15))
        con.print(panel)
        output = buf.getvalue()
        assert "(-15)" in output

    def test_panel_renders_score_delta_zero(self):
        """Panel shows ±0 for no change."""
        con, buf = _console()
        panel = build_diff_panel(self._diff(score_delta=0, score_before=80, score_after=80))
        con.print(panel)
        assert "±0" in buf.getvalue()

    def test_panel_shows_improved_items(self):
        """Improved section lists items with before→after status."""
        diff = self._diff(improved=[{
            "id": "filevault", "name": "FileVault", "category": "security",
            "before_status": "critical", "after_status": "pass",
            "message": "Encryption enabled",
        }])
        con, buf = _console()
        con.print(build_diff_panel(diff))
        output = buf.getvalue()
        assert "Improved" in output
        assert "FileVault" in output
        assert "critical" in output
        assert "pass" in output

    def test_panel_shows_regressed_items(self):
        """Regressed section lists items."""
        diff = self._diff(score_delta=-5, regressed=[{
            "id": "screen_lock", "name": "Screen Lock", "category": "security",
            "before_status": "pass", "after_status": "critical",
            "message": "15 min delay",
        }])
        con, buf = _console()
        con.print(build_diff_panel(diff))
        output = buf.getvalue()
        assert "Regressed" in output
        assert "Screen Lock" in output

    def test_panel_omits_empty_sections(self):
        """Sections with no items don't appear."""
        diff = self._diff(improved=[], regressed=[], new_checks=[], removed_checks=[])
        con, buf = _console()
        con.print(build_diff_panel(diff))
        output = buf.getvalue()
        assert "Improved" not in output
        assert "Regressed" not in output
        assert "New checks" not in output
        assert "Removed checks" not in output

    def test_panel_shows_previous_scan_time(self):
        """Panel displays the previous scan timestamp."""
        diff = self._diff(previous_scan_time="2026-02-25T18:30:00+00:00")
        con, buf = _console()
        con.print(build_diff_panel(diff))
        assert "Previous scan:" in buf.getvalue()

    def test_print_report_hides_diff_when_none(self):
        """print_report with diff=None does not render diff panel."""
        r = _result(status="pass", message="ok")
        con, buf = _console()
        print_report([r], con, diff=None)
        assert "Changes Since Last Scan" not in buf.getvalue()

    def test_print_report_shows_diff_when_present(self):
        """print_report with diff renders the diff panel."""
        r = _result(status="pass", message="ok")
        diff = self._diff()
        con, buf = _console()
        print_report([r], con, diff=diff)
        assert "Changes Since Last Scan" in buf.getvalue()
