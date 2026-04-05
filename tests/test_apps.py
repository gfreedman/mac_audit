"""
Tests for checks/apps.py.

Covers:
    - ``LoginItemsCheck.run()``: pass / info / warning status thresholds driven
      by the number of login items returned by mocked ``osascript`` output.
      Boundary conditions (exactly 8 items, osascript error) are exercised.
    - ``AppStoreUpdatesCheck.run()``: skip when ``mas`` CLI is absent; pass when
      no outdated apps; warning with count when apps need updating.

Design:
    Both checks shell out to macOS-specific tools (``osascript`` and ``mas``).
    Rather than spawning real subprocesses, ``patch.object(check, "shell", ...)``
    replaces the ``BaseCheck.shell()`` helper so the tests are fully hermetic
    and run on any platform.  For the tool-gate test, ``has_tool`` is patched
    to return ``False`` to trigger the ``requires_tool`` skip path.

Note:
    The ``_osascript_output`` helper mirrors the real osascript output format:
    a comma-separated string of login item names on a single line.  Tests
    that need a specific count build the list programmatically.
"""

from unittest.mock import patch

import pytest

from macaudit.checks.apps import AppStoreUpdatesCheck, LoginItemsCheck


# ── LoginItemsCheck.run() ─────────────────────────────────────────────────────

def _osascript_output(*names: str) -> str:
    """Build a fake ``osascript`` stdout string for a list of login item names.

    The real ``osascript`` command returns login items as a comma-separated
    string on a single line.  This helper replicates that format so
    ``LoginItemsCheck.run()`` can parse it without modification.

    Args:
        *names: Zero or more login item name strings (e.g. ``"Dropbox"``,
            ``"Spotify"``).

    Returns:
        A comma-separated string of names, or an empty string when called
        with no arguments.

    Example::

        _osascript_output("Dropbox", "Zoom")  # → "Dropbox, Zoom"
        _osascript_output()                   # → ""
    """
    return ", ".join(names)


class TestLoginItemsCheckRun:
    """Tests for ``LoginItemsCheck.run()`` across status threshold boundaries.

    The check uses three severity tiers: ``pass`` (0–8 items), ``info``
    (9–15), and ``warning`` (16+).  Boundary values and error handling are
    tested explicitly.
    """

    def _run_with_output(self, osascript_stdout: str, rc: int = 0):
        """Invoke ``LoginItemsCheck.run()`` with a controlled osascript response.

        Args:
            osascript_stdout: The stdout string that ``shell()`` will return.
                Build this with ``_osascript_output()`` for realistic format.
            rc: The return code for the mocked ``shell()`` call.  Defaults
                to ``0`` (success); pass ``1`` to simulate an osascript error.

        Returns:
            The ``CheckResult`` produced by ``LoginItemsCheck.run()``.
        """
        check = LoginItemsCheck()
        with patch.object(check, "shell", return_value=(rc, osascript_stdout, "")):
            return check.run()

    def test_no_items_returns_pass(self):
        """Empty osascript output (no login items) → ``pass``."""
        result = self._run_with_output("")
        assert result.status == "pass"

    def test_few_items_returns_pass(self):
        """Three login items — well under the ``>8`` info threshold → ``pass``."""
        output = _osascript_output("Dropbox", "Spotify", "Zoom")
        result = self._run_with_output(output)
        assert result.status == "pass"

    def test_moderate_items_returns_info(self):
        """Nine items — one above the ``>8`` info threshold → ``info``.

        This is the lower boundary test for the ``info`` tier.  The threshold
        is strict-greater-than so 8 items is still ``pass`` (see below).
        """
        names = [f"App{i}" for i in range(9)]
        output = _osascript_output(*names)
        result = self._run_with_output(output)
        assert result.status == "info"

    def test_many_items_returns_warning(self):
        """Sixteen items — one above the ``>15`` warning threshold → ``warning``."""
        names = [f"App{i}" for i in range(16)]
        output = _osascript_output(*names)
        result = self._run_with_output(output)
        assert result.status == "warning"

    def test_shell_error_returns_info(self):
        """Non-zero osascript exit code → ``info`` (cannot determine items).

        osascript can fail on locked systems or when Accessibility permissions
        are absent.  The check degrades to ``info`` rather than ``error`` to
        avoid alarming the user.
        """
        result = self._run_with_output("", rc=1)
        assert result.status == "info"

    def test_data_contains_count(self):
        """The ``data`` dict exposes ``count`` for downstream consumers (diff, JSON)."""
        names = [f"App{i}" for i in range(16)]
        output = _osascript_output(*names)
        result = self._run_with_output(output)
        assert result.data is not None
        assert result.data["count"] == 16

    def test_eight_items_returns_pass(self):
        """Exactly 8 items — at the boundary, should still be ``pass``.

        The threshold is strictly ``> 8``, so 8 items must NOT trigger
        ``info``.  This boundary test guards against an off-by-one regression.
        """
        names = [f"App{i}" for i in range(8)]
        output = _osascript_output(*names)
        result = self._run_with_output(output)
        assert result.status == "pass"


# ── AppStoreUpdatesCheck.run() ────────────────────────────────────────────────

class TestAppStoreUpdatesCheck:
    """Tests for ``AppStoreUpdatesCheck.run()``.

    The check requires the third-party ``mas`` CLI.  When it is absent the
    check must skip gracefully; when present, the ``mas outdated`` output is
    parsed and reflected as ``pass`` or ``warning``.
    """

    def test_skips_when_mas_not_installed(self):
        """``requires_tool = "mas"`` triggers a ``skip`` when ``mas`` is absent.

        Many users don't have ``mas`` installed.  The check must degrade
        silently rather than reporting an error or crashing.
        """
        check = AppStoreUpdatesCheck()
        with patch.object(check, "has_tool", return_value=False):
            result = check.execute()
        assert result.status == "skip"
        assert "mas" in result.message

    def test_pass_when_no_outdated_apps(self):
        """Empty ``mas outdated`` output → all App Store apps are current → ``pass``."""
        check = AppStoreUpdatesCheck()
        with patch.object(check, "shell", return_value=(0, "", "")):
            result = check.run()
        assert result.status == "pass"

    def test_warning_when_apps_outdated(self):
        """Three lines of ``mas outdated`` output → ``warning`` with count in message."""
        mas_output = (
            "497799835 Xcode (14.3.1)\n"
            "409183694 Keynote (13.2)\n"
            "409201541 Pages (13.2)\n"
        )
        check = AppStoreUpdatesCheck()
        with patch.object(check, "shell", return_value=(0, mas_output, "")):
            result = check.run()
        assert result.status == "warning"
        assert "3" in result.message

    def test_data_contains_outdated_list(self):
        """The ``data`` dict exposes ``outdated`` so the diff engine can track changes."""
        mas_output = "497799835 Xcode (14.3.1)\n"
        check = AppStoreUpdatesCheck()
        with patch.object(check, "shell", return_value=(0, mas_output, "")):
            result = check.run()
        assert "outdated" in result.data
        assert len(result.data["outdated"]) == 1
