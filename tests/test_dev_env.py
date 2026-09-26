"""
Tests for ``PythonConflictsCheck`` in checks/dev_env.py.

Covers:
    - Symlinks to the same interpreter count once (python.org links
      ``/usr/local/bin/python3`` into its framework).
    - The SIP-protected ``/usr/bin/python3`` is never counted as a conflict.
    - Two genuinely different interpreters still warn, listed in PATH order.

Design:
    ``shell()`` is patched to return canned ``which -a`` / ``--version``
    output, and ``os.path.realpath`` is patched with an explicit symlink map,
    so the tests are hermetic and independent of the machine's Pythons.
"""

from unittest.mock import patch

from macaudit.checks.dev_env import PythonConflictsCheck
from macaudit.enums import CheckStatus

HOMEBREW = "/opt/homebrew/bin/python3"
FRAMEWORK = "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3"
LOCAL_LINK = "/usr/local/bin/python3"
SYSTEM = "/usr/bin/python3"

# Symlink targets as the real machine resolves them.
REALPATHS = {
    HOMEBREW: "/opt/homebrew/Cellar/python@3.14/3.14.7/bin/python3.14",
    FRAMEWORK: "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13",
    LOCAL_LINK: "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13",
}


def _run_with(paths: list[str]):
    """Run the check as if ``which -a python3`` printed ``paths``.

    Args:
        paths: PATH-ordered python3 locations.

    Returns:
        CheckResult: The result produced by ``run()``.
    """
    def fake_shell(cmd, *args, **kwargs):
        if cmd[0] == "which":
            return (0, "\n".join(paths) + "\n", "") if paths else (1, "", "")
        return (0, "Python 3.14.7\n", "")

    with patch.object(PythonConflictsCheck, "shell", side_effect=fake_shell), \
         patch("macaudit.checks.dev_env.os.path.realpath", side_effect=lambda p: REALPATHS.get(p, p)):
        return PythonConflictsCheck().run()


class TestPythonConflictsCheck:
    """Tests for distinct-interpreter counting in ``PythonConflictsCheck``."""

    def test_homebrew_plus_system_python_passes(self):
        """The OS python3 alone is not a conflict with a Homebrew python3."""
        result = _run_with([HOMEBREW, SYSTEM])
        assert result.status == CheckStatus.PASS
        assert HOMEBREW in result.message

    def test_symlink_to_same_interpreter_counts_once(self):
        """``/usr/local/bin/python3`` → framework binary is the same Python."""
        result = _run_with([FRAMEWORK, LOCAL_LINK, SYSTEM])
        assert result.status == CheckStatus.PASS

    def test_real_conflict_still_warns(self):
        """The machine this was found on: Homebrew 3.14 + python.org 3.13 → 2, not 4."""
        result = _run_with([HOMEBREW, FRAMEWORK, LOCAL_LINK, SYSTEM])
        assert result.status == CheckStatus.WARNING
        assert result.message.startswith("2 python3 installations")
        assert result.data["python_paths"] == [HOMEBREW, FRAMEWORK]
        assert result.data["system_python"] == SYSTEM

    def test_only_system_python_passes(self):
        """A Mac with only the OS python3 passes and names it."""
        result = _run_with([SYSTEM])
        assert result.status == CheckStatus.PASS
        assert SYSTEM in result.message

    def test_no_python_is_info(self):
        """No python3 in PATH at all → ``info``."""
        assert _run_with([]).status == CheckStatus.INFO
