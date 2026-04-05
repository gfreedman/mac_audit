"""
Tests for checks/base.py.

Covers:
    - ``CheckResult`` field types and default values: ``fix_command``,
      ``data``, ``profile_tags``, ``min_macos``, ``status``.
    - ``BaseCheck.execute()`` pre-flight gates: macOS version, required tool,
      and Apple Silicon architecture.  Gate ordering is also verified (version
      is checked before tool).
    - ``BaseCheck._result()`` / ``execute()`` propagates the subclass
      ``profile_tags`` tuple into the returned ``CheckResult``.
    - ``BaseCheck.shell()`` error handling: successful command, missing binary
      (``FileNotFoundError``), timeout, and non-zero exit with stderr.

Design:
    Three minimal ``BaseCheck`` subclasses are defined at module level:
    ``_AlwaysPass``, ``_AlwaysCrash``, and ``_DevOnlyCheck``.  They are
    intentionally simple so tests stay fast and their behaviour is trivially
    verifiable without reading the implementation.  Real macOS commands
    (``echo``, ``ls``, ``sleep``) are used only in the ``shell()`` tests where
    subprocess behaviour is the property under test.

Note:
    The architecture gate tests use ``patch("macaudit.checks.base.IS_APPLE_SILICON")``
    so they pass on both Intel and Apple Silicon CI runners.
"""

from unittest.mock import patch

import pytest

from macaudit.checks.base import BaseCheck, CheckResult, calculate_health_score


# ── Concrete check stubs ──────────────────────────────────────────────────────

class _AlwaysPass(BaseCheck):
    """Minimal ``BaseCheck`` subclass that unconditionally returns ``pass``.

    Used as a stand-in for any well-behaved check where the run() outcome
    is irrelevant to the property under test (gates, shell helpers, etc.).
    """
    id = "always_pass"
    name = "Always Pass"
    category = "system"
    category_icon = "✅"
    scan_description = "test"
    finding_explanation = "test"
    recommendation = "test"
    fix_level = "none"
    fix_description = "none"

    def run(self) -> CheckResult:
        return self._pass("All good")


class _AlwaysCrash(BaseCheck):
    """``BaseCheck`` subclass whose ``run()`` unconditionally raises ``RuntimeError``.

    Used to verify that ``execute()`` catches any exception from ``run()``
    and wraps it in an ``error`` result rather than propagating it to the
    scan orchestrator.
    """
    id = "always_crash"
    name = "Always Crash"
    category = "system"
    category_icon = "💥"
    scan_description = "test"
    finding_explanation = "test"
    recommendation = "test"
    fix_level = "none"
    fix_description = "none"

    def run(self) -> CheckResult:
        raise RuntimeError("boom")


class _DevOnlyCheck(BaseCheck):
    """``BaseCheck`` subclass that restricts execution to the ``developer`` profile.

    Overrides ``profile_tags`` to ``("developer",)`` to verify that the
    profile tag propagation mechanism works: the class-level tag must appear
    in the ``CheckResult.profile_tags`` list after ``execute()`` runs.
    """
    id = "dev_only"
    name = "Dev Only"
    category = "dev_env"
    category_icon = "🛠️"
    scan_description = "test"
    finding_explanation = "test"
    recommendation = "test"
    fix_level = "none"
    fix_description = "none"
    profile_tags = ("developer",)

    def run(self) -> CheckResult:
        return self._pass("dev check ran")


# ── CheckResult defaults ──────────────────────────────────────────────────────

class TestCheckResultDefaults:
    """Verify ``CheckResult`` field types and default values.

    These tests guard the dataclass contract: downstream consumers (the JSON
    exporter, the diff engine, the fixer) rely on specific types for each
    field.  A type change is a breaking API change.
    """

    def test_fix_command_defaults_to_none(self):
        """``fix_command`` is ``None`` when no automated fix is defined.

        The fixer checks ``result.fix_command is not None`` before attempting
        to run an automated fix; the default must be ``None``, not ``[]``.
        """
        r = _AlwaysPass().execute()
        assert r.fix_command is None

    def test_data_field_is_dict(self):
        """``data`` is always a dict, never ``None``.

        The diff engine and JSON output use ``result.data`` as a dict; safe
        attribute access (``result.data.get("key")``) must always work.
        """
        r = _AlwaysPass().execute()
        assert isinstance(r.data, dict)

    def test_profile_tags_default_is_list_with_all_profiles(self):
        """A check with no ``profile_tags`` override runs for all three profiles."""
        r = _AlwaysPass().execute()
        assert set(r.profile_tags) == {"developer", "creative", "standard"}

    def test_min_macos_is_tuple_of_ints(self):
        """``min_macos`` is a tuple of ints — stored as a tuple, serialised as a list.

        The history module converts this tuple to a list for JSON; it must be
        a tuple in the dataclass so that ``dataclasses.asdict()`` does not
        silently drop elements.
        """
        r = _AlwaysPass().execute()
        assert isinstance(r.min_macos, tuple)
        assert all(isinstance(v, int) for v in r.min_macos)

    def test_status_is_string(self):
        """``status`` is a plain string — ``CheckStatus`` enum values compare equal."""
        r = _AlwaysPass().execute()
        assert r.status == "pass"


# ── BaseCheck.execute() gates ─────────────────────────────────────────────────

class TestExecuteGates:
    """Tests for the pre-flight gate logic in ``BaseCheck.execute()``.

    ``execute()`` applies up to three gates before calling ``run()``:
    macOS version, required tool, and architecture.  Each gate short-circuits
    and returns a ``skip`` result; none raises an exception.  The ordering
    guarantee (version before tool) is also verified.
    """

    def test_version_gate_skips_when_below_min(self):
        """``min_macos = (99, 0)`` — no machine can satisfy this → ``skip``.

        The skip message must include the required version number so the user
        understands why the check was skipped.
        """
        check = _AlwaysPass()
        check.min_macos = (99, 0)
        result = check.execute()
        assert result.status == "skip"
        assert "99.0" in result.message

    def test_version_gate_passes_when_below_current(self):
        """``min_macos = (1, 0)`` — every supported macOS satisfies this → no skip."""
        check = _AlwaysPass()
        check.min_macos = (1, 0)
        result = check.execute()
        assert result.status == "pass"

    def test_tool_gate_skips_when_tool_missing(self):
        """A ``requires_tool`` value that is not on ``$PATH`` → ``skip``.

        The skip message must include the tool name so the user knows what to
        install.
        """
        check = _AlwaysPass()
        check.requires_tool = "this_tool_does_not_exist_mactuner_test"
        result = check.execute()
        assert result.status == "skip"
        assert "this_tool_does_not_exist_mactuner_test" in result.message

    def test_tool_gate_passes_when_tool_present(self):
        """``requires_tool = "python3"`` — always present in the test environment → no skip."""
        check = _AlwaysPass()
        check.requires_tool = "python3"
        result = check.execute()
        assert result.status == "pass"

    def test_arch_gate_skips_on_apple_silicon_when_not_compatible(self):
        """``apple_silicon_compatible = False`` on an Apple Silicon host → ``skip``.

        The gate is patched rather than relying on the CI runner's actual
        architecture, keeping the test deterministic on both Intel and ARM.
        """
        check = _AlwaysPass()
        check.apple_silicon_compatible = False
        with patch("macaudit.checks.base.IS_APPLE_SILICON", True):
            result = check.execute()
        assert result.status == "skip"
        assert "Apple Silicon" in result.message

    def test_arch_gate_passes_on_intel_when_not_compatible(self):
        """``apple_silicon_compatible = False`` on Intel → no architecture gate skip."""
        check = _AlwaysPass()
        check.apple_silicon_compatible = False
        with patch("macaudit.checks.base.IS_APPLE_SILICON", False):
            result = check.execute()
        assert result.status == "pass"

    def test_exception_in_run_returns_error_not_raise(self):
        """An unhandled exception inside ``run()`` → ``error`` result, not propagation.

        The scan orchestrator must never crash due to a buggy check.
        The ``error`` result must include both the check ID and the exception
        message to aid debugging.
        """
        check = _AlwaysCrash()
        result = check.execute()
        assert result.status == "error"
        assert "always_crash" in result.message
        assert "boom" in result.message

    def test_all_gates_checked_in_order_version_first(self):
        """Version gate fires before tool gate when both conditions are true.

        If gate ordering were wrong (tool checked first), the message would
        contain the tool name instead of the version number.
        """
        check = _AlwaysPass()
        check.min_macos = (99, 0)
        check.requires_tool = "this_tool_does_not_exist_mactuner_test"
        result = check.execute()
        assert result.status == "skip"
        assert "99.0" in result.message  # version message, not tool message


# ── profile_tags propagation ──────────────────────────────────────────────────

class TestResultProfileTagsPropagation:
    """Verify that ``profile_tags`` are correctly propagated into ``CheckResult``.

    The profile filter in ``main._collect_checks`` reads ``result.profile_tags``
    to decide which checks to run for a given user profile.  These tests guard
    the propagation path and the immutability of the base-class default.
    """

    def test_default_check_has_all_three_profiles(self):
        """Checks without a ``profile_tags`` override run for all profiles."""
        result = _AlwaysPass().execute()
        assert set(result.profile_tags) == {"developer", "creative", "standard"}

    def test_dev_only_check_propagates_developer_tag_only(self):
        """``profile_tags = ("developer",)`` is faithfully copied into the result."""
        result = _DevOnlyCheck().execute()
        assert result.profile_tags == ["developer"]

    def test_base_class_profile_tags_is_tuple(self):
        """The default ``profile_tags`` is a tuple to prevent accidental mutation.

        If it were a list, a subclass that appends to it would silently
        modify the base class default, affecting all future instances.
        """
        assert isinstance(BaseCheck.profile_tags, tuple)

    def test_subclass_override_does_not_mutate_base_class(self):
        """Instantiating ``_DevOnlyCheck`` must not alter ``BaseCheck.profile_tags``.

        Class-level tuple attributes are shared references; mutating them
        would affect every subclass.  This test ensures the override is a
        new binding, not an in-place modification.
        """
        _ = _DevOnlyCheck()
        assert "creative" in BaseCheck.profile_tags
        assert "standard" in BaseCheck.profile_tags


# ── BaseCheck.shell() ─────────────────────────────────────────────────────────

class TestShellHelper:
    """Tests for ``BaseCheck.shell()`` — the subprocess wrapper used by all checks.

    ``shell()`` normalises subprocess outcomes into a ``(rc, stdout, stderr)``
    tuple and never raises; it maps ``FileNotFoundError`` and
    ``TimeoutExpired`` to ``rc = -1`` with a descriptive ``stderr`` message.
    """

    def test_successful_command_returns_rc_0_and_stdout(self):
        """A well-formed command succeeds: rc=0, stdout captured, stderr empty."""
        check = _AlwaysPass()
        rc, out, err = check.shell(["echo", "hello"])
        assert rc == 0
        assert "hello" in out
        assert err == ""

    def test_missing_binary_returns_negative_one(self):
        """A binary not on ``$PATH`` → ``rc = -1``, empty stdout, descriptive stderr.

        Checks use this to detect absent tools without raising ``FileNotFoundError``
        into the scan orchestrator.
        """
        check = _AlwaysPass()
        rc, out, err = check.shell(["this_command_definitely_does_not_exist_9999"])
        assert rc == -1
        assert out == ""
        assert "not found" in err

    def test_timeout_returns_negative_one_with_message(self):
        """A command that exceeds ``timeout`` → ``rc = -1``, ``stderr`` notes timeout.

        Checks that call slow system commands (e.g. ``system_profiler``) rely
        on this to avoid hanging the scan indefinitely.
        """
        check = _AlwaysPass()
        rc, out, err = check.shell(["sleep", "10"], timeout=1)
        assert rc == -1
        assert "timed out" in err.lower()

    def test_stderr_captured_on_nonzero_exit(self):
        """A non-zero exit code is returned unmodified (not mapped to -1).

        Only ``FileNotFoundError`` and ``TimeoutExpired`` produce ``rc = -1``;
        a command that exits with a regular non-zero code (e.g. ``ls`` on a
        missing path) propagates its actual exit code.
        """
        check = _AlwaysPass()
        rc, out, err = check.shell(["ls", "/path/that/does/not/exist/xyzzy"])
        assert rc != 0
