"""
Core data model and abstract base class for all Mac Audit checks.

This module defines two central abstractions:

``CheckResult``
    A frozen-field dataclass that represents the complete output of a
    single check.  Every check must return exactly one ``CheckResult``
    on every code path.  The fields cover the full contract: identity,
    status, educational copy, fix capability, compatibility metadata,
    and arbitrary structured data.

``BaseCheck``
    An abstract base class that all concrete check classes must inherit
    from.  It provides:

    - A set of class-level attribute defaults that subclasses override.
    - The ``execute()`` gate method, which enforces version, tool, and
      architecture requirements before delegating to ``run()``.
    - The ``shell()`` helper for safe subprocess execution.
    - Convenience factory methods (``_pass``, ``_warning``, etc.) that
      return pre-populated ``CheckResult`` instances.

``calculate_health_score``
    A standalone function that aggregates all check results into a
    0–100 health score, applying category-based severity multipliers.

Design invariants:
    - **This file is the single source of truth** for ``CheckResult``
      field names and types.  Every serialisation path (JSON output,
      history, diff) uses ``dataclasses.asdict()`` on a ``CheckResult``.
    - ``execute()`` is the only entry point the scan orchestrator calls.
      It must never be bypassed; calling ``run()`` directly skips the
      safety gates.
    - Every exception raised inside ``run()`` is caught by ``execute()``
      and returned as a ``CheckResult(status="error")``.  One bad check
      must never crash the entire scan.

Note:
    All modules in ``macaudit.checks.*`` import ``BaseCheck`` and
    ``CheckResult`` from here.  Changes to this file affect every check.
"""

import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from macaudit.system_info import IS_APPLE_SILICON, MACOS_VERSION


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    """Complete output of a single Mac Audit check.

    Every check's ``run()`` method must return a fully-populated
    ``CheckResult`` on every code path.  The ``BaseCheck._result()``
    convenience builder fills most fields from class-level defaults,
    so subclasses only need to set ``status`` and ``message``.

    Fields are grouped into logical sections below.

    Attributes:
        id (str): Unique, stable, machine-readable check identifier used
            for config suppression and JSON output. Use ``snake_case``
            (e.g. ``"homebrew_outdated"``).  Never change after release.
        name (str): Human-readable display name shown in the terminal
            report (e.g. ``"Outdated Homebrew Packages"``).
        category (str): Category slug, one of:
            ``"system"``, ``"security"``, ``"privacy"``, ``"homebrew"``,
            ``"disk"``, ``"hardware"``, ``"memory"``, ``"network"``,
            ``"dev_env"``, ``"apps"``.
        category_icon (str): Emoji icon for the category header row.

        status (Literal): One of:
            - ``"pass"``     — check succeeded, nothing to do.
            - ``"warning"``  — potential issue, action recommended.
            - ``"critical"`` — serious issue, action strongly required.
            - ``"info"``     — informational; no action required.
            - ``"skip"``     — check not applicable or suppressed.
            - ``"error"``    — unexpected exception during check execution.
        message (str): Short, one-line result summary shown in the scan
            narration and report, e.g. ``"14 packages are out of date"``.

        scan_description (str): Shown *during* the scan narration.
            Should explain what the check does AND why it matters, so
            the user learns something even if the check passes.
        finding_explanation (str): Shown in the report when the check is
            not a clean pass.  Explains the security or health implication
            of the finding in plain language.
        recommendation (str): Concrete action the user should take to
            resolve the finding.  Should include the exact UI path or
            command to run.

        fix_level (Literal): Capability tier for the automated fix system:
            - ``"auto"``         — safe shell command, no privileges needed.
            - ``"auto_sudo"``    — shell command requiring admin privileges
                                   (presented via a native macOS password dialog).
            - ``"guided"``       — opens the relevant System Settings pane.
            - ``"instructions"`` — prints numbered manual steps.
            - ``"none"``         — no automated fix available.
        fix_description (str): One sentence describing exactly what the
            fix does, shown in the fix-session card before the user approves.
        fix_command (list[str] | None): Argument list for ``auto`` and
            ``auto_sudo`` fixes.  Must never be constructed from user input.
        fix_url (str | None): System Settings deep-link URL for ``guided``
            fixes (e.g. ``"x-apple.systempreferences:com.apple.preference..."``)
        fix_steps (list[str] | None): Numbered manual steps for
            ``instructions`` fixes.
        fix_reversible (bool): ``True`` if the fix can be undone.
            ``False`` for destructive or one-way changes (e.g. software
            updates, Rosetta installation).  Irreversible fixes are
            highlighted with a warning in the fix-session card.
        fix_time_estimate (str): Human-readable time estimate shown in
            the fix-session card, e.g. ``"~30 seconds"``.
        requires_sudo (bool): ``True`` if the fix requires administrator
            privileges.  Used by ``--auto`` mode to filter out sudo fixes.

        min_macos (tuple[int, int]): Minimum macOS version required for
            this check, as ``(major, minor)``.  Checks below this
            threshold are skipped by ``execute()``.  Default ``(13, 0)``
            means "Ventura or later".
        requires_tool (str | None): Name of an external CLI tool that
            must be in ``PATH`` for the check to run, e.g. ``"brew"``.
            ``None`` means the check has no external tool dependency.
        apple_silicon_compatible (bool): ``False`` for checks that are
            only valid on Intel Macs (e.g. legacy T2 checks).

        data (dict[str, Any]): Arbitrary structured data attached to the
            result for downstream consumers (e.g. JSON output, tests).
            Keys are check-specific; common examples include counts,
            raw output excerpts, or boolean flags.
        profile_tags (list[str]): Profile names for which this check
            should run.  Defaults to ``["developer", "creative", "standard"]``
            (i.e. all profiles).  Developer-only checks override this with
            ``["developer"]``.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    id:            str   # Machine-readable stable identifier, e.g. "filevault"
    name:          str   # Human-readable display name, e.g. "FileVault Disk Encryption"
    category:      str   # Category slug, e.g. "system"
    category_icon: str   # Emoji displayed in category headers, e.g. "🖥️ "

    # ── Result ────────────────────────────────────────────────────────────────
    status:  Literal["pass", "warning", "critical", "info", "skip", "error"]
    message: str   # One-line result summary shown in narration and report

    # ── Educational layer — all three fields are required on every non-skip result ──
    scan_description:    str   # What this check does + why it matters (shown during scan)
    finding_explanation: str   # Security/health implication of the finding (shown in report)
    recommendation:      str   # Concrete action to resolve the finding (shown in report)

    # ── Fix capability ────────────────────────────────────────────────────────
    fix_level:       Literal["auto", "auto_sudo", "guided", "instructions", "none"]
    fix_description: str                  # One sentence describing what the fix does
    fix_command:     list[str] | None = None   # Arg list for auto/auto_sudo fixes
    fix_url:         str | None = None         # System Settings deep-link (guided)
    fix_steps:       list[str] | None = None   # Manual steps (instructions)
    fix_reversible:  bool = True               # Whether the fix can be undone
    fix_time_estimate: str = "~30 seconds"     # Human-readable duration estimate
    requires_sudo:   bool = False              # True if fix needs admin privileges

    # ── Version & compatibility ───────────────────────────────────────────────
    min_macos:                tuple[int, int] = (13, 0)   # Minimum macOS (major, minor)
    requires_tool:            str | None = None            # Required external CLI, e.g. "brew"
    apple_silicon_compatible: bool = True                  # False for Intel-only checks

    # ── Metadata ──────────────────────────────────────────────────────────────
    data: dict[str, Any] = field(default_factory=dict)
    """Arbitrary structured data for the result.

    Common keys used by checks include ``count``, ``version``,
    ``age_days``, ``enabled``, and ``items`` (a list of detail strings).
    External tools consuming ``--json`` output may read these fields.
    """

    profile_tags: list[str] = field(
        default_factory=lambda: ["developer", "creative", "standard"]
    )
    """Profile names for which this check is active.

    The scan orchestrator filters checks by the resolved profile (auto-
    detected or forced via ``--profile``).  Checks with a narrower tag
    list only run under the matching profile.
    """


# ── Base class ────────────────────────────────────────────────────────────────

class BaseCheck(ABC):
    """Abstract base class for all Mac Audit check implementations.

    Subclasses must:

      1. Declare class-level attributes (``id``, ``name``, ``category``,
         etc.) that describe the check's identity and default metadata.
      2. Override ``run()`` to implement the check logic and return a
         ``CheckResult`` on every code path.

    The ``execute()`` method is the only entry point for the scan
    orchestrator.  It enforces three prerequisite gates before calling
    ``run()``:

      - **macOS version gate**: If the running macOS is older than
        ``min_macos``, ``execute()`` returns a ``skip`` result.
      - **Tool availability gate**: If ``requires_tool`` is set and the
        tool is not in ``PATH``, ``execute()`` returns a ``skip`` result.
      - **Architecture gate**: If ``apple_silicon_compatible`` is
        ``False`` and the host is Apple Silicon, ``execute()`` skips.

    Any unhandled exception escaping from ``run()`` is caught by
    ``execute()`` and returned as a ``CheckResult(status="error")``,
    ensuring one failing check never crashes the whole scan.

    Attributes:
        id (str): Unique machine-readable check identifier.
        name (str): Human-readable check name for the report.
        category (str): Category slug (``"system"``, ``"security"``, etc.).
        category_icon (str): Emoji for the category header.
        scan_description (str): Narrated during the scan.
        finding_explanation (str): Educational explanation in the report.
        recommendation (str): Concrete remediation advice.
        fix_level (str): Automated-fix capability tier.
        fix_description (str): One-line description of what the fix does.
        fix_command (list[str] | None): Shell command for auto fixes.
        fix_url (str | None): Deep-link URL for guided fixes.
        fix_steps (list[str] | None): Manual steps for instruction fixes.
        fix_reversible (bool): Whether the fix can be undone.
        fix_time_estimate (str): Human-readable fix duration.
        requires_sudo (bool): Whether the fix needs admin privileges.
        min_macos (tuple[int, int]): Minimum required macOS version.
        requires_tool (str | None): External CLI tool required in PATH.
        apple_silicon_compatible (bool): False for Intel-only checks.
        profile_tags (tuple[str, ...]): Profiles for which the check runs.

    Example::

        class MyCheck(BaseCheck):
            id = "my_check"
            name = "My Check"
            category = "system"
            category_icon = "🖥️ "
            scan_description = "Checking something important..."
            finding_explanation = "This matters because..."
            recommendation = "Do X to fix it."
            fix_level = "none"
            fix_description = "No fix available"

            def run(self) -> CheckResult:
                rc, stdout, _ = self.shell(["some_tool", "--flag"])
                if "good" in stdout:
                    return self._pass("Everything is fine")
                return self._warning("Something needs attention")
    """

    # Subclasses override these as class attributes — not instance attributes.
    # Defaults here are placeholders; every real check must override them all.
    id:            str  = "base_check"
    name:          str  = "Base Check"
    category:      str  = "system"
    category_icon: str  = "🖥️ "

    scan_description:    str = "Running check..."
    finding_explanation: str = ""
    recommendation:      str = ""

    fix_level:         Literal["auto", "auto_sudo", "guided", "instructions", "none"] = "none"
    fix_description:   str             = "No fix available"
    fix_command:       list[str] | None = None
    fix_url:           str | None       = None
    fix_steps:         list[str] | None = None
    fix_reversible:    bool = True
    fix_time_estimate: str  = "~30 seconds"
    requires_sudo:     bool = False

    min_macos:                tuple[int, int] = (13, 0)
    requires_tool:            str | None      = None
    apple_silicon_compatible: bool            = True

    # An immutable tuple prevents accidental mutation of the shared class
    # attribute across check instances.  Subclasses targeting a specific
    # profile declare a smaller tuple, e.g. ``profile_tags = ("developer",)``.
    profile_tags: tuple[str, ...] = ("developer", "creative", "standard")

    # ── Public API ────────────────────────────────────────────────────────────

    def execute(self) -> CheckResult:
        """Evaluate prerequisite gates, then delegate to ``run()``.

        This is the **only** method the scan orchestrator should call.
        Calling ``run()`` directly bypasses the version, tool, and
        architecture gates and the top-level exception safety net.

        Gate evaluation order:
          1. macOS version — skips if ``MACOS_VERSION < min_macos``.
          2. Tool availability — skips if ``requires_tool`` is set but
             the tool is absent from ``PATH``.
          3. Architecture — skips if the check is marked Intel-only and
             the host is Apple Silicon.
          4. ``run()`` call — wrapped in a broad ``except Exception`` so
             any unhandled error becomes a ``CheckResult(status="error")``.

        Returns:
            CheckResult: A fully-populated result from ``run()``, or a
            ``skip`` result if a gate blocks execution, or an ``error``
            result if ``run()`` raises unexpectedly.
        """
        # ── Gate 1: macOS version ────────────────────────────────────────────
        if MACOS_VERSION < self.min_macos:
            return self._skip(
                f"Requires macOS {self.min_macos[0]}.{self.min_macos[1]}+"
            )

        # ── Gate 2: Required external tool ──────────────────────────────────
        if self.requires_tool and not self.has_tool(self.requires_tool):
            return self._skip(f"{self.requires_tool} not installed")

        # ── Gate 3: Architecture compatibility ──────────────────────────────
        if not self.apple_silicon_compatible and IS_APPLE_SILICON:
            return self._skip("Not compatible with Apple Silicon")

        # ── Gate 4: Run the check with a top-level exception safety net ─────
        # One bad check must never crash the whole scan.  Any unexpected
        # exception is captured and returned as a structured error result.
        try:
            return self.run()
        except Exception as e:
            return self._error(f"Unexpected error in {self.id}: {e}")

    @abstractmethod
    def run(self) -> CheckResult:
        """Implement the check's core inspection logic.

        This method is called by ``execute()`` after all gates pass.
        Subclasses **must** override this method.

        Implementation contract:
          - Wrap every ``subprocess`` call with ``self.shell()`` (handles
            timeout, locale, and exception safety).
          - Return a ``CheckResult`` on **every** code path — never raise.
          - Never write directly to ``stdout`` or ``stderr``; all output
            goes through the ``CheckResult`` fields.
          - Use the convenience methods ``_pass``, ``_warning``,
            ``_critical``, ``_info``, ``_skip``, ``_error`` to build
            results.

        Returns:
            CheckResult: The result of the check with an appropriate
            ``status`` and populated educational fields.

        Raises:
            Exception: Any unhandled exception is caught by ``execute()``
                and converted to a ``CheckResult(status="error")``.
                Subclasses should not intentionally raise.
        """
        ...

    # ── Helper methods ────────────────────────────────────────────────────────

    def has_tool(self, tool: str) -> bool:
        """Return ``True`` if *tool* is available in the system ``PATH``.

        Delegates to ``shutil.which()``, which searches the directories
        listed in ``PATH`` for an executable with the given name.

        Args:
            tool (str): The name of the executable to search for,
                e.g. ``"brew"``, ``"docker"``, ``"git"``.

        Returns:
            bool: ``True`` if the tool is found and executable,
            ``False`` otherwise.
        """
        return shutil.which(tool) is not None

    def shell(
        self,
        cmd: list[str],
        timeout: int = 10,
    ) -> tuple[int, str, str]:
        """Run a subprocess safely and return its exit code and output.

        This is the preferred way to invoke external tools from a check.
        It enforces the C locale so output is always in English (critical
        for string matching on non-English macOS systems), caps execution
        time with a timeout, and converts all error conditions into a
        structured return value rather than raising exceptions.

        Args:
            cmd (list[str]): The command and its arguments as a list,
                e.g. ``["fdesetup", "status"]``.  Must never be
                constructed from user-supplied input to prevent injection.
            timeout (int): Maximum seconds to wait before aborting.
                Defaults to 10.  Use a higher value only for known-slow
                commands like ``softwareupdate -l``.

        Returns:
            tuple[int, str, str]: A three-element tuple of:
                - ``returncode`` (int): The process exit code, or ``-1``
                  on timeout, binary not found, or other execution error.
                - ``stdout`` (str): Stripped standard output string.
                  Never ``None``.
                - ``stderr`` (str): Stripped standard error string, or
                  a human-readable error description on failure.
                  Never ``None``.

        Note:
            The C locale override (``LANG=C``, ``LC_ALL=C``) is critical
            for correctness.  Without it, commands like ``fdesetup status``
            may return ``"FileVault est activé"`` on French-locale macOS
            instead of ``"FileVault is On"``, breaking all string matches.

        Example::

            rc, stdout, stderr = self.shell(["fdesetup", "status"])
            if rc != 0:
                return self._error(f"fdesetup failed: {stderr[:80]}")
            if "is on" in stdout.lower():
                return self._pass("FileVault is enabled")
        """
        # Override locale variables to guarantee English output from system
        # tools, regardless of the user's configured system language.
        _env = {**os.environ, "LANG": "C", "LC_ALL": "C"}
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,   # Never raise on non-zero exit — we inspect returncode manually.
                env=_env,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
        except FileNotFoundError:
            return -1, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return -1, "", str(e)

    def _result(
        self,
        status: Literal["pass", "warning", "critical", "info", "skip", "error"],
        message: str,
        data: dict[str, Any] | None = None,
    ) -> CheckResult:
        """Build a ``CheckResult`` populated with this check's class-level defaults.

        This is an internal convenience method.  Check implementations
        should use the typed shortcuts (``_pass``, ``_warning``, etc.)
        rather than calling this directly.

        Args:
            status (str): One of ``"pass"``, ``"warning"``, ``"critical"``,
                ``"info"``, ``"skip"``, or ``"error"``.
            message (str): Short one-line result summary.
            data (dict[str, Any] | None): Optional structured data dict
                attached to the result.  Defaults to ``{}``.

        Returns:
            CheckResult: A fully-populated result with class-level
            defaults merged in.

        Note:
            ``profile_tags`` is converted from the class-level ``tuple``
            to a ``list`` here.  This ensures the resulting
            ``CheckResult`` is JSON-serialisable (lists are valid JSON;
            tuples are not) and that subclass ``tuple`` overrides are
            correctly propagated.
        """
        return CheckResult(
            id=self.id,
            name=self.name,
            category=self.category,
            category_icon=self.category_icon,
            status=status,
            message=message,
            scan_description=self.scan_description,
            finding_explanation=self.finding_explanation,
            recommendation=self.recommendation,
            fix_level=self.fix_level,
            fix_description=self.fix_description,
            fix_command=self.fix_command,
            fix_url=self.fix_url,
            fix_steps=self.fix_steps,
            fix_reversible=self.fix_reversible,
            fix_time_estimate=self.fix_time_estimate,
            requires_sudo=self.requires_sudo,
            min_macos=self.min_macos,
            requires_tool=self.requires_tool,
            apple_silicon_compatible=self.apple_silicon_compatible,
            data=data or {},
            # Convert tuple → list so CheckResult is JSON-serialisable and
            # so that subclass tuple overrides propagate correctly.
            profile_tags=list(self.profile_tags),
        )

    def _skip(self, reason: str) -> CheckResult:
        """Return a ``skip`` result indicating the check is not applicable.

        Args:
            reason (str): Human-readable explanation of why the check
                was skipped (e.g. ``"brew not installed"``).

        Returns:
            CheckResult: Result with ``status="skip"``.
        """
        return self._result("skip", reason)

    def _error(self, message: str) -> CheckResult:
        """Return an ``error`` result for unexpected check failures.

        Args:
            message (str): Description of the error that occurred.

        Returns:
            CheckResult: Result with ``status="error"``.
        """
        return self._result("error", message)

    def _pass(self, message: str, data: dict[str, Any] | None = None) -> CheckResult:
        """Return a ``pass`` result indicating the check found no issue.

        Args:
            message (str): Short confirmation message (e.g.
                ``"FileVault is enabled"``).
            data (dict[str, Any] | None): Optional structured data.

        Returns:
            CheckResult: Result with ``status="pass"``.
        """
        return self._result("pass", message, data=data)

    def _warning(
        self,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> CheckResult:
        """Return a ``warning`` result for potential issues.

        Args:
            message (str): Short description of the warning condition.
            data (dict[str, Any] | None): Optional structured data.

        Returns:
            CheckResult: Result with ``status="warning"``.
        """
        return self._result("warning", message, data=data)

    def _critical(
        self,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> CheckResult:
        """Return a ``critical`` result for serious security or health issues.

        Args:
            message (str): Short description of the critical condition.
            data (dict[str, Any] | None): Optional structured data.

        Returns:
            CheckResult: Result with ``status="critical"``.
        """
        return self._result("critical", message, data=data)

    def _info(self, message: str, data: dict[str, Any] | None = None) -> CheckResult:
        """Return an ``info`` result for informational findings.

        Use ``info`` for findings that do not require action but may
        be useful to the user (e.g. displaying a current version number,
        or noting that a feature is installed but optional).

        Args:
            message (str): Short informational message.
            data (dict[str, Any] | None): Optional structured data.

        Returns:
            CheckResult: Result with ``status="info"``.
        """
        return self._result("info", message, data=data)


# ── Health score ───────────────────────────────────────────────────────────────

# Categories that carry higher weight in the health score calculation.
# Security, privacy, and system issues are more impactful than performance
# or convenience issues in other categories.
_SECURITY_CATEGORIES = {"system", "privacy", "security"}


def calculate_health_score(checks: list[CheckResult]) -> int:
    """Calculate a 0–100 health score from a list of completed check results.

    The score starts at 100 and is decremented for each failing check.
    Security-related categories (``"system"``, ``"privacy"``,
    ``"security"``) carry a higher penalty multiplier than other
    categories, reflecting their greater impact on the user's safety.

    Scoring algorithm:
      - Start at ``score = 100``.
      - For each ``critical`` result:
          - Base penalty: ``-10`` points.
          - Security category multiplier: ``×1.5`` → ``-15`` points.
      - For each ``warning`` result:
          - Base penalty: ``-3`` points.
          - Security category multiplier: ``×1.2`` → ``-4`` points (rounded
            down via ``int()``).
      - ``info``, ``pass``, ``skip``, and ``error`` statuses: no penalty.
      - Clamp final score to ``[0, 100]``.

    Args:
        checks (list[CheckResult]): All ``CheckResult`` objects returned
            by a scan run, including ``skip`` and ``error`` results.

    Returns:
        int: Health score in the range ``[0, 100]`` inclusive.
        Higher values indicate a healthier system.

    Example::

        score = calculate_health_score(results)
        print(f"Health score: {score}/100")

    Note:
        The score is intentionally simple and rounded to avoid creating
        a false sense of precision.  It is a directional indicator, not
        a precise security audit grade.
    """
    score = 100

    for check in checks:
        if check.status == "critical":
            points = 10
            # Security, privacy, and system criticals carry a 50% higher penalty
            # because they directly expose the user to external threats.
            if check.category in _SECURITY_CATEGORIES:
                points = int(points * 1.5)  # → 15 points deducted
        elif check.status == "warning":
            points = 3
            # Security warnings carry a 20% higher penalty for the same reason.
            if check.category in _SECURITY_CATEGORIES:
                points = int(points * 1.2)  # → 3 or 4 points deducted
        else:
            # info / pass / skip / error — no health penalty.
            points = 0

        score -= points

    # Clamp to [0, 100]: a score cannot be negative or exceed the maximum.
    return max(0, min(100, score))
