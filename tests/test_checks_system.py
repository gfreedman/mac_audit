"""
Tests for checks/system.py.

Covers:
    - ``_parse_update_lines()``: the pure-function parser that extracts
      pending update names from raw ``softwareupdate -l`` output.  All
      relevant output patterns (``*`` prefix, ``-`` prefix, bare separator,
      no-update banner) are exercised without spawning a subprocess.
    - ``MacOSVersionCheck``: metadata contract (category, id, profile tags,
      ``min_macos``, ``requires_tool``) and the guarantee that ``execute()``
      returns a valid ``CheckResult`` with a non-empty message.

Design:
    ``_parse_update_lines`` has no side effects and is testable with plain
    strings, so no mocking is required.  The ``MacOSVersionCheck`` metadata
    tests instantiate the check and inspect class attributes; they intentionally
    do *not* call ``run()`` because ``run()`` invokes real macOS system calls
    (``platform.mac_ver()``, ``softwareupdate``) that are environment-specific.
    The ``execute()`` smoke test at the end calls the real implementation to
    catch import errors and obvious runtime failures.

Note:
    Full ``run()`` coverage across the macOS 13/14/15 × Intel/ARM matrix is
    handled by manual integration testing, not automated unit tests.
"""

from unittest.mock import patch

import pytest

from macaudit.checks.system import (
    MacOSVersionCheck,
    _parse_update_lines,
)


# ── _parse_update_lines() — pure parser, no subprocess ───────────────────────

class TestParseUpdateLines:
    """Tests for the ``_parse_update_lines()`` pure parser.

    ``softwareupdate -l`` output mixes header lines, ``*``-prefixed update
    entries, ``-`` detail lines, and bare separator dashes.  The parser must
    extract only the meaningful lines for display in the report.
    """

    def test_asterisk_prefixed_lines_included(self):
        """``*``-prefixed lines are the primary update entries — all must be returned."""
        output = "Software Update Tool\n* macOS 15.4\n* Safari 18.0\n"
        lines = _parse_update_lines(output)
        assert len(lines) == 2

    def test_asterisk_lines_stripped(self):
        """Leading whitespace around the ``*`` is stripped; the ``*`` itself is kept."""
        output = "  * macOS 15.4 (Label: macOS15.4)\n"
        lines = _parse_update_lines(output)
        assert lines[0].startswith("*")

    def test_dash_lines_included(self):
        """``-``-prefixed detail lines (e.g. ``- Label:``) are included."""
        output = "- Label: macOS 15.4\n"
        lines = _parse_update_lines(output)
        assert any("macOS 15.4" in l for l in lines)

    def test_bare_dash_excluded(self):
        """A line that is only ``-`` (a separator, not a detail line) must be filtered.

        ``softwareupdate`` emits bare dashes between update blocks as visual
        separators.  Including them in the output would confuse the report.
        """
        output = "- \n* macOS 15.4\n"
        lines = _parse_update_lines(output)
        assert "-" not in lines

    def test_no_updates_returns_empty(self):
        """The "No new software available" banner → empty list (no updates pending)."""
        output = "No new software available.\n"
        assert _parse_update_lines(output) == []

    def test_empty_output_returns_empty(self):
        """Empty string input (e.g. command timed out) → empty list."""
        assert _parse_update_lines("") == []

    def test_multiple_updates_all_captured(self):
        """Three ``*``-prefixed updates → all three returned."""
        output = (
            "* macOS 15.4 Sequoia\n"
            "* Safari 18.3\n"
            "* XProtect Remediator 1.2.3\n"
        )
        assert len(_parse_update_lines(output)) == 3


# ── MacOSVersionCheck.execute() — gate layer ─────────────────────────────────

class TestMacOSVersionCheck:
    """Metadata and smoke tests for ``MacOSVersionCheck``.

    The metadata tests verify the class contract (category, id, descriptions,
    profile tags, version gate, tool requirement) without invoking real system
    calls.  The smoke tests call ``execute()`` live to catch import failures
    and obvious runtime errors.
    """

    def test_has_expected_metadata(self):
        """Category, id, and all human-readable description fields are populated."""
        check = MacOSVersionCheck()
        assert check.category == "system"
        assert check.id == "macos_version"
        assert check.scan_description  # non-empty
        assert check.finding_explanation
        assert check.recommendation

    def test_has_all_three_profile_tags(self):
        """macOS version is a universal concern — all three profiles must include it."""
        check = MacOSVersionCheck()
        assert "developer" in check.profile_tags
        assert "creative" in check.profile_tags
        assert "standard" in check.profile_tags

    def test_min_macos_is_13(self):
        """The check runs on macOS 13 (Ventura) and later — the minimum supported OS."""
        check = MacOSVersionCheck()
        assert check.min_macos[0] <= 13

    def test_does_not_require_external_tool(self):
        """macOS version is available via ``platform.mac_ver()`` — no external tool needed."""
        check = MacOSVersionCheck()
        assert check.requires_tool is None

    def test_execute_returns_checkresult(self):
        """``execute()`` returns a ``CheckResult`` with a valid status string."""
        from macaudit.checks.base import CheckResult
        result = MacOSVersionCheck().execute()
        assert isinstance(result, CheckResult)
        assert result.status in ("pass", "info", "warning", "critical", "skip", "error")

    def test_result_message_is_non_empty(self):
        """The result message is always a non-empty string for display in the report."""
        result = MacOSVersionCheck().execute()
        assert result.message.strip()
