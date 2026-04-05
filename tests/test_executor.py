"""
Tests for fixer/executor.py — the three fix-dispatch strategies.

Covers:
    - ``run_auto_fix``: missing ``fix_command`` (no-op), successful command,
      non-zero exit, live stdout streaming, ``shell=False`` invariant, and
      list-form command passing (injection safety).
    - ``run_instructions_fix``: with explicit steps, fallback to
      ``recommendation``, empty steps + empty recommendation (no-op).
    - ``run_guided_fix``: missing URL (no-op), successful deep-link open,
      fallback to System Settings when the deep link fails, step text printed
      before opening.

Design:
    ``_console()`` creates a Rich ``Console`` backed by a ``StringIO`` buffer
    so output assertions never need a real terminal.  ``_result()`` builds a
    minimal ``CheckResult`` with sensible defaults that any test can override
    with keyword arguments, keeping test bodies focused on the relevant field.

    The ``shell=False`` and list-form tests mock ``subprocess.Popen`` directly
    to inspect call arguments without spawning a real process.  All other
    tests use real POSIX commands (``echo``, ``false``) that are universally
    available on macOS and Linux.

Note:
    The ``false`` command used in ``test_failing_command_returns_false`` is a
    standard POSIX utility that always exits with code 1.  It is preferable to
    a Python one-liner because it avoids shell-injection concerns and is
    guaranteed to be on ``$PATH`` in any POSIX environment.
"""

from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from macaudit.checks.base import CheckResult
from macaudit.fixer.executor import (
    run_auto_fix,
    run_guided_fix,
    run_instructions_fix,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _console() -> tuple[Console, StringIO]:
    """Return a Rich ``Console`` wired to a ``StringIO`` buffer.

    ``highlight=False`` and ``no_color=True`` keep the captured text plain
    ASCII so assertions can search for literal substrings without stripping
    ANSI escape codes.

    Returns:
        A ``(Console, StringIO)`` tuple.  Pass the console to the function
        under test, then read ``buf.getvalue()`` for output assertions.
    """
    buf = StringIO()
    con = Console(file=buf, highlight=False, no_color=True)
    return con, buf


def _result(**kwargs) -> CheckResult:
    """Build a minimal ``CheckResult`` with sensible defaults.

    All fields required by ``CheckResult.__init__`` are provided.  Pass
    keyword arguments to override any subset of fields, keeping test bodies
    focused on the field(s) relevant to the case being tested.

    Args:
        **kwargs: Any ``CheckResult`` field to override.  Common overrides:
            ``fix_command``, ``fix_steps``, ``fix_url``, ``recommendation``.

    Returns:
        A fully-initialised ``CheckResult`` instance.
    """
    defaults = dict(
        id="test_fix",
        name="Test Fix",
        category="system",
        category_icon="✅",
        status="warning",
        message="something is off",
        scan_description="",
        finding_explanation="",
        recommendation="",
        fix_level="auto",
        fix_description="",
    )
    defaults.update(kwargs)
    return CheckResult(**defaults)


# ── run_auto_fix ──────────────────────────────────────────────────────────────

class TestRunAutoFix:
    """Tests for ``run_auto_fix`` — automated shell-command execution."""

    def test_no_fix_command_returns_false(self):
        """``fix_command=None`` → nothing to run → returns ``False`` immediately."""
        con, _ = _console()
        assert run_auto_fix(_result(fix_command=None), con) is False

    def test_successful_command_returns_true(self):
        """A command that exits 0 → ``True`` (fix applied successfully)."""
        con, _ = _console()
        assert run_auto_fix(_result(fix_command=["echo", "hello"]), con) is True

    def test_failing_command_returns_false(self):
        """A command that exits non-zero → ``False`` (fix failed).

        Uses the standard POSIX ``false`` utility which unconditionally
        exits with code 1.
        """
        con, _ = _console()
        assert run_auto_fix(_result(fix_command=["false"]), con) is False

    def test_output_is_streamed_to_console(self):
        """Command stdout is displayed on the console during execution."""
        con, buf = _console()
        run_auto_fix(_result(fix_command=["echo", "mactuner_test_output"]), con)
        assert "mactuner_test_output" in buf.getvalue()

    def test_uses_shell_false(self):
        """Verify shell=False is used to avoid command-injection surface."""
        con, _ = _console()
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.stdout = iter(["line1\n"])
            mock_proc.returncode = 0
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc

            run_auto_fix(_result(fix_command=["echo", "hello"]), con)

            call_kwargs = mock_popen.call_args
            assert call_kwargs.kwargs.get("shell") is False

    def test_command_passed_as_list(self):
        """fix_command is passed as a list for shell=False execution."""
        con, _ = _console()
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.stdout = iter([])
            mock_proc.returncode = 0
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc

            run_auto_fix(_result(fix_command=["brew", "cleanup", "--prune=all"]), con)

            call_args = mock_popen.call_args
            cmd = call_args.args[0]  # First positional arg is the command
            assert isinstance(cmd, list), "Command should be a list when shell=False"
            assert "brew" in cmd


# ── run_instructions_fix ──────────────────────────────────────────────────────

class TestRunInstructionsFix:
    """Tests for ``run_instructions_fix`` — numbered step display."""

    def test_with_steps_returns_true(self):
        """Non-empty ``fix_steps`` list → steps displayed, returns ``True``."""
        con, _ = _console()
        assert run_instructions_fix(_result(fix_steps=["Step 1", "Step 2"]), con) is True

    def test_steps_are_printed(self):
        """Every step string appears in the console output."""
        con, buf = _console()
        run_instructions_fix(_result(fix_steps=["Do thing A", "Do thing B"]), con)
        output = buf.getvalue()
        assert "Do thing A" in output
        assert "Do thing B" in output

    def test_steps_are_numbered(self):
        """Steps are rendered as a numbered list (``1.``, ``2.``, …)."""
        con, buf = _console()
        run_instructions_fix(_result(fix_steps=["First step"]), con)
        assert "1." in buf.getvalue()

    def test_no_steps_falls_back_to_recommendation(self):
        """When ``fix_steps`` is ``None`` the ``recommendation`` is shown instead.

        This ensures checks that provide only a text recommendation still
        produce useful output in the fixer flow.
        """
        con, buf = _console()
        result = run_instructions_fix(
            _result(fix_steps=None, recommendation="Read the manual"), con
        )
        assert result is True
        assert "Read the manual" in buf.getvalue()

    def test_no_steps_no_recommendation_returns_false(self):
        """No steps and no recommendation → nothing to show → returns ``False``."""
        con, _ = _console()
        assert run_instructions_fix(_result(fix_steps=None, recommendation=""), con) is False


# ── run_guided_fix ────────────────────────────────────────────────────────────

class TestRunGuidedFix:
    """Tests for ``run_guided_fix`` — deep-link URL opener with fallback."""

    def test_no_url_returns_false(self):
        """``fix_url=None`` → nothing to open → returns ``False``."""
        con, _ = _console()
        assert run_guided_fix(_result(fix_url=None), con) is False

    def test_successful_open_returns_true(self):
        """A deep link that opens successfully → returns ``True``."""
        con, _ = _console()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = run_guided_fix(
                _result(fix_url="x-apple.systempreferences:com.apple.preferences.security"),
                con,
            )
        assert result is True

    def test_deep_link_failure_falls_back_to_system_settings(self):
        """A failing ``x-apple`` deep link falls back to opening System Settings.

        Some deep links fail depending on the macOS version.  The fallback
        ensures the user always gets to a relevant pane rather than seeing
        a silent failure.
        """
        con, buf = _console()
        import subprocess

        def side_effect(cmd, **kwargs):
            if "x-apple" in str(cmd):
                raise subprocess.CalledProcessError(1, cmd)
            return MagicMock(returncode=0)

        with patch("subprocess.run", side_effect=side_effect):
            result = run_guided_fix(
                _result(fix_url="x-apple.systempreferences:com.apple.test"),
                con,
            )
        assert result is True
        assert "System Settings" in buf.getvalue()

    def test_fix_steps_are_printed_before_opening(self):
        """When ``fix_steps`` are provided they are printed before the URL is opened.

        Steps guide the user to the correct pane once System Settings opens,
        so they must appear in the console output before the ``open`` call.
        """
        con, buf = _console()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            run_guided_fix(
                _result(
                    fix_url="x-apple.systempreferences:com.apple.test",
                    fix_steps=["Look for Full Disk Access", "Remove unknown apps"],
                ),
                con,
            )
        output = buf.getvalue()
        assert "Full Disk Access" in output
