"""Homebrew package manager health and maintenance checks.

This module audits the state of the Homebrew package manager across five
dimensions:

1. **Installation health** (``HomebrewDoctorCheck``) — Runs ``brew doctor``
   to detect broken symlinks, PATH conflicts, stale git state, and other
   issues that cause silent failures in package management.

2. **Outdated formulae** (``HomebrewOutdatedCheck``) — Identifies CLI tools
   and libraries with available updates. Stale packages may carry unpatched
   CVEs.

3. **Outdated casks** (``HomebrewOutdatedCasksCheck``) — Same concern for
   GUI applications managed as Homebrew casks (e.g. browsers, editors).

4. **Orphaned dependencies** (``HomebrewAutoremoveCheck``) — Packages
   installed as transitive dependencies that are no longer required by
   anything. Safe to remove; accumulate as disk waste over time.

5. **Cache cleanup** (``HomebrewCleanupCheck``) — Old package downloads in
   Homebrew's cache that are no longer needed. Can reach several gigabytes
   on active developer machines.

6. **Missing dependencies** (``HomebrewMissingCheck``) — Formulae whose
   declared dependencies are not installed, causing runtime failures that
   can be difficult to diagnose.

Design decisions:
    - All checks inherit from ``_HomebrewBase``, which sets ``requires_tool =
      "brew"``. The base class runner skips the check with a friendly message
      rather than erroring if ``brew`` is not on ``$PATH``.
    - MacPorts is detected by the base framework but no MacPorts-specific
      checks are implemented; the comment in ``_BREW_MISSING_MSG`` documents
      this deliberately limited scope.
    - Dry-run flags (``--dry-run``) are used wherever available to avoid
      side effects during an audit pass.
    - The ``import re`` inside ``HomebrewCleanupCheck.run`` is intentional:
      ``re`` is only needed in that one method, and keeping it local avoids
      polluting the module namespace given that most other checks don't use it.

Attributes:
    _BREW_MISSING_MSG (str): Standard skip message emitted by the base class
        runner when ``brew`` is not installed. Defined once here to ensure
        consistency across all subclasses if the wording ever needs to change.
    ALL_CHECKS (list[type[BaseCheck]]): Ordered list of check classes exported
        to the main runner. Consumed by ``macaudit/main.py`` at startup.
"""

from macaudit.checks.base import BaseCheck, CheckResult

# Shared skip message used by the base runner when brew is absent.
# All Homebrew checks inherit requires_tool = "brew", so they are automatically
# skipped with this message when Homebrew is not installed.
_BREW_MISSING_MSG = "Homebrew is not installed — skipping package checks"


class _HomebrewBase(BaseCheck):
    """Abstract base class shared by all Homebrew checks.

    Provides the common ``category``, ``category_icon``, ``requires_tool``,
    and ``profile_tags`` class attributes so that individual checks don't
    repeat this boilerplate. When the base runner detects that ``requires_tool``
    is absent from ``$PATH``, the check is automatically skipped.

    Attributes:
        category (str): Report grouping key; value ``"homebrew"``.
        category_icon (str): Emoji prefix rendered in the TUI beside the
            category name.
        requires_tool (str): CLI binary name that must be on ``$PATH`` for this
            check to run. Value: ``"brew"``.
        profile_tags (list[str]): User profile labels for which this check is
            relevant. Homebrew is used across developer, creative, and standard
            profiles, so all three are included.
    """

    category = "homebrew"
    category_icon = "🍺"
    requires_tool = "brew"
    profile_tags = ["developer", "creative", "standard"]


class HomebrewDoctorCheck(_HomebrewBase):
    """Verify Homebrew installation health by running ``brew doctor``.

    ``brew doctor`` is Homebrew's canonical self-diagnosis command. It checks
    for: stale symlinks in ``/opt/homebrew/bin`` (or ``/usr/local/bin``),
    conflicting ``$PATH`` entries, outdated Homebrew core tap state, invalid
    ``HOMEBREW_*`` environment variables, and other conditions that silently
    break package installs or cause hard-to-diagnose "command not found" errors.

    Detection mechanism:
        Shells out to ``brew doctor`` with a 30-second timeout. Exit code 0
        or the string ``"ready to brew"`` in the combined stdout/stderr output
        indicates health. Any line beginning with ``"Warning:"`` is extracted
        and counted to give an actionable issue count.

    Severity scale:
        - ``pass``: ``brew doctor`` exits 0 or reports "ready to brew".
        - ``warning``: One or more ``Warning:`` lines are found in the output.

    Attributes:
        id (str): ``"homebrew_doctor"``
        name (str): ``"Homebrew Health (brew doctor)"``
        fix_level (str): ``"auto"`` — the fix command is ``brew doctor`` itself;
            it prints specific remediation steps for each warning it finds.
        fix_command (list[str]): ``["brew", "doctor"]``
        fix_reversible (bool): ``True`` — running ``brew doctor`` makes no
            destructive changes; it only reports issues.
        fix_time_estimate (str): Typically completes in under 30 seconds.
    """

    id = "homebrew_doctor"
    name = "Homebrew Health (brew doctor)"

    scan_description = (
        "Running 'brew doctor' — checks for common Homebrew issues like "
        "broken symlinks, PATH conflicts, and stale installation state."
    )
    finding_explanation = (
        "Homebrew issues cause 'command not found' errors, broken installs, "
        "and conflicts between package versions. brew doctor is the canonical "
        "way to surface them."
    )
    recommendation = (
        "Follow the instructions from 'brew doctor' to fix each issue. "
        "Most fixes are one-liners it prints for you."
    )
    fix_level = "auto"
    fix_description = "Runs 'brew doctor' and follows its suggestions"
    fix_command = ["brew", "doctor"]
    fix_reversible = True
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Run ``brew doctor`` and count ``Warning:`` lines in the output.

        Merges stdout and stderr before checking for ``"ready to brew"`` and
        extracting warning lines. This handles Homebrew versions that write
        warnings to stderr and those that write them to stdout.

        Returns:
            CheckResult: One of:

            - ``pass`` — Exit code 0 or "ready to brew" present in output.
            - ``warning`` — One or more lines starting with ``"Warning:"``
              were found. ``result.data["warnings"]`` contains the extracted
              warning text list.
            - ``warning`` — Non-zero exit and no parseable warnings; a 300-
              character preview of raw output is included in ``result.data``.

        Example::

            check = HomebrewDoctorCheck()
            result = check.run()
            # pass: "Homebrew is healthy"
            # warning: "3 Homebrew issues found — run 'brew doctor'"
        """
        rc, stdout, stderr = self.shell(["brew", "doctor"], timeout=30)

        output = (stdout + stderr).strip()

        if rc == 0 or "ready to brew" in output.lower():
            return self._pass("Homebrew is healthy")

        # Collect warning lines — these are the actionable items.
        warnings = [
            ln.strip()
            for ln in output.splitlines()
            if ln.strip().startswith("Warning:")
        ]

        if warnings:
            n = len(warnings)
            return self._warning(
                f"{n} Homebrew issue{'s' if n != 1 else ''} found — run 'brew doctor'",
                data={"warnings": warnings},
            )

        return self._warning(
            "brew doctor reported issues",
            data={"output_preview": output[:300]},
        )


class HomebrewOutdatedCheck(_HomebrewBase):
    """Check for outdated Homebrew formulae with known updates available.

    Outdated CLI tools and libraries may carry unpatched CVEs. Running old
    versions of networked binaries (``curl``, ``git``, ``openssl``) leaves
    known vulnerabilities exploitable by local and remote attackers alike.

    Detection mechanism:
        Shells out to ``brew outdated`` (no ``--greedy`` flag — only reports
        formulae where the installed version is older than the latest stable
        release). Each non-empty line in stdout represents one outdated formula.

    Severity scale:
        - ``pass``: ``brew outdated`` produces no output (all formulae current).
        - ``warning``: One or more formulae are outdated. The message names up
          to four packages with ``…`` appended if there are more.
        - ``error``: ``brew outdated`` exits non-zero (Homebrew internal error).

    Attributes:
        id (str): ``"homebrew_outdated"``
        name (str): ``"Outdated Homebrew Formulae"``
        fix_level (str): ``"auto"`` — ``brew upgrade`` updates all outdated
            formulae.
        fix_command (list[str]): ``["brew", "upgrade"]``
        fix_reversible (bool): ``False`` — downgrading requires ``brew switch``
            and is not trivial.
        fix_time_estimate (str): Highly variable; depends on network speed and
            the number/size of outdated packages.
    """

    id = "homebrew_outdated"
    name = "Outdated Homebrew Formulae"

    scan_description = (
        "Checking for outdated Homebrew formulae — outdated packages may contain "
        "security vulnerabilities that have been patched in newer versions."
    )
    finding_explanation = (
        "CVEs in CLI tools and libraries are patched in package updates. "
        "Running old versions of git, curl, OpenSSL, or any networked tool "
        "leaves known vulnerabilities exploitable."
    )
    recommendation = (
        "Run 'brew upgrade' to update all outdated formulae. "
        "Or 'brew upgrade <name>' to update specific packages."
    )
    fix_level = "auto"
    fix_description = "Runs 'brew upgrade' to update all outdated formulae"
    fix_command = ["brew", "upgrade"]
    fix_reversible = False
    fix_time_estimate = "Varies — could be seconds or minutes"

    def run(self) -> CheckResult:
        """Run ``brew outdated`` and count output lines; each line is one outdated formula.

        ``brew outdated`` exits 0 and produces no output when everything is up
        to date. Each output line has the format ``<name> (<installed> < <latest>)``.
        Only the package name (first whitespace-delimited token) is extracted
        for display.

        Returns:
            CheckResult: One of:

            - ``pass`` — No outdated formulae.
            - ``warning`` — ``n`` formulae are outdated. Up to 4 names are
              shown; ``result.data["outdated"]`` contains the full list.
            - ``error`` — ``brew outdated`` returned a non-zero exit code.

        Example::

            check = HomebrewOutdatedCheck()
            result = check.run()
            # warning: "5 outdated formulae: curl, git, openssl@3, python@3.12…"
        """
        rc, stdout, stderr = self.shell(["brew", "outdated"], timeout=30)

        if rc != 0:
            return self._error(f"brew outdated failed: {(stdout + stderr)[:80]}")

        packages = [ln.strip() for ln in stdout.splitlines() if ln.strip()]

        if not packages:
            return self._pass("All Homebrew formulae are up to date")

        n = len(packages)
        # Show up to 4 package names to keep the summary line readable.
        names = ", ".join(p.split()[0] for p in packages[:4])
        suffix = "…" if n > 4 else ""
        return self._warning(
            f"{n} outdated formula{'e' if n != 1 else ''}: {names}{suffix}",
            data={"outdated": packages},
        )


class HomebrewOutdatedCasksCheck(_HomebrewBase):
    """Check for outdated Homebrew casks (GUI applications managed by Homebrew).

    Homebrew casks manage GUI apps such as Firefox, VS Code, and Slack.
    Like formulae, outdated casks may contain known security vulnerabilities.
    Some casks self-update via their own updater (e.g. Chrome, Firefox), but
    ``brew outdated --cask`` only shows casks that *don't* self-update and
    where a newer version is available through Homebrew.

    Detection mechanism:
        Shells out to ``brew outdated --cask``. Each non-empty line in stdout
        represents one outdated cask with an available update in the tap.

    Severity scale:
        - ``pass``: No casks are outdated.
        - ``warning``: One or more casks have updates available.
        - ``error``: ``brew outdated --cask`` exits non-zero.

    Attributes:
        id (str): ``"homebrew_outdated_casks"``
        name (str): ``"Outdated Homebrew Casks"``
        fix_level (str): ``"auto"`` — ``brew upgrade --cask`` updates all
            outdated casks.
        fix_command (list[str]): ``["brew", "upgrade", "--cask"]``
        fix_reversible (bool): ``False`` — older cask versions are typically
            deleted by Homebrew during upgrade.
        fix_time_estimate (str): Variable; depends on download sizes for each
            app bundle.
    """

    id = "homebrew_outdated_casks"
    name = "Outdated Homebrew Casks"

    scan_description = (
        "Checking for outdated Homebrew casks (GUI apps) — cask updates "
        "include security patches for apps like browsers and media players."
    )
    finding_explanation = (
        "Casks are GUI apps managed by Homebrew (e.g. Firefox, VS Code, Slack). "
        "Like formulae, outdated casks may have known security vulnerabilities."
    )
    recommendation = (
        "Run 'brew upgrade --cask' to update all outdated casks. "
        "Some casks self-update; 'brew outdated --cask' shows which don't."
    )
    fix_level = "auto"
    fix_description = "Runs 'brew upgrade --cask'"
    fix_command = ["brew", "upgrade", "--cask"]
    fix_reversible = False
    fix_time_estimate = "Varies — could be minutes"

    def run(self) -> CheckResult:
        """Run ``brew outdated --cask`` and count output lines.

        Each non-empty output line represents one outdated cask. Up to 4 cask
        names are included in the summary message.

        Returns:
            CheckResult: One of:

            - ``pass`` — All managed casks are up to date.
            - ``warning`` — ``n`` casks are outdated. Up to 4 names shown;
              ``result.data["outdated_casks"]`` contains the full list.
            - ``error`` — Command exited non-zero.

        Example::

            check = HomebrewOutdatedCasksCheck()
            result = check.run()
            # warning: "2 outdated casks: firefox, visual-studio-code"
        """
        rc, stdout, stderr = self.shell(
            ["brew", "outdated", "--cask"], timeout=30
        )

        if rc != 0:
            return self._error(f"brew outdated --cask failed: {(stdout + stderr)[:80]}")

        casks = [ln.strip() for ln in stdout.splitlines() if ln.strip()]

        if not casks:
            return self._pass("All Homebrew casks are up to date")

        n = len(casks)
        names = ", ".join(c.split()[0] for c in casks[:4])
        suffix = "…" if n > 4 else ""
        return self._warning(
            f"{n} outdated cask{'s' if n != 1 else ''}: {names}{suffix}",
            data={"outdated_casks": casks},
        )


class HomebrewAutoremoveCheck(_HomebrewBase):
    """Check for orphaned Homebrew dependencies that can be safely removed.

    When a Homebrew formula is uninstalled, its transitive dependencies are
    left behind unless they are required by another installed formula. Over
    time these orphaned packages accumulate, consuming disk space and adding
    clutter to the Homebrew installation graph. ``brew autoremove`` identifies
    and removes only packages that nothing else depends on, so it is safe to
    run without reviewing each package individually.

    Detection mechanism:
        Runs ``brew autoremove --dry-run``. This prints which packages *would*
        be removed without actually removing them. Header lines beginning with
        ``"==>"`` and lines starting with ``"would"`` are filtered out; the
        remaining lines are package names.

    Severity scale:
        - ``pass``: No orphaned packages found.
        - ``info``: One or more packages can be removed. This is ``info``
          (not ``warning``) because orphaned packages are a maintenance concern,
          not a security or stability risk.

    Attributes:
        id (str): ``"homebrew_autoremove"``
        name (str): ``"Homebrew Orphaned Dependencies"``
        fix_level (str): ``"auto"`` — ``brew autoremove`` removes all orphaned
            packages in one command.
        fix_command (list[str]): ``["brew", "autoremove"]``
        fix_reversible (bool): ``False`` — removed packages must be reinstalled
            individually if needed again.
        fix_time_estimate (str): Typically under 30 seconds.
    """

    id = "homebrew_autoremove"
    name = "Homebrew Orphaned Dependencies"

    scan_description = (
        "Checking for Homebrew packages that were installed as dependencies "
        "but are no longer needed by anything — safe to remove."
    )
    finding_explanation = (
        "When you uninstall a Homebrew formula, its dependencies may be left "
        "behind. Over time these orphaned packages accumulate, wasting disk "
        "space and cluttering your Homebrew installation."
    )
    recommendation = (
        "Run 'brew autoremove' to remove orphaned dependencies. "
        "This is safe — Homebrew only removes packages nothing else depends on."
    )
    fix_level = "auto"
    fix_description = "Runs 'brew autoremove' to remove orphaned dependencies"
    fix_command = ["brew", "autoremove"]
    fix_reversible = False
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Run ``brew autoremove --dry-run`` and count packages that would be removed.

        Filters ``"==>"`` header lines and lines starting with ``"would"``
        from the output; remaining non-empty lines are treated as package names.

        Returns:
            CheckResult: One of:

            - ``pass`` — No orphaned packages exist.
            - ``info`` — ``n`` packages can be safely removed. Full package
              list in ``result.data["removable"]``.
            - ``error`` — Command exited non-zero.

        Example::

            check = HomebrewAutoremoveCheck()
            result = check.run()
            # info: "4 orphaned dependencies can be removed with 'brew autoremove'"
        """
        rc, stdout, stderr = self.shell(
            ["brew", "autoremove", "--dry-run"], timeout=20
        )

        if rc != 0:
            return self._error(f"brew autoremove failed: {(stdout + stderr)[:80]}")

        lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]

        # Strip Homebrew UI decorators — "==>" section headers and "Would remove"
        # introductory lines are not package names.
        packages = [
            ln for ln in lines
            if not ln.startswith("==>") and not ln.lower().startswith("would")
        ]

        if not packages:
            return self._pass("No orphaned dependencies found")

        n = len(packages)
        return self._info(
            f"{n} orphaned dependenc{'ies' if n != 1 else 'y'} can be removed with 'brew autoremove'",
            data={"removable": packages},
        )


class HomebrewCleanupCheck(_HomebrewBase):
    """Measure reclaimable disk space from stale Homebrew package downloads.

    Homebrew retains previous package downloads in its local cache
    indefinitely. On active developer machines this cache grows silently — old
    bottles, source archives, and cask installers accumulate. ``brew cleanup``
    removes anything older than the current version of each installed formula.

    Detection mechanism:
        Runs ``brew cleanup --dry-run``, which prints a summary line of the
        form ``"This operation would free X.XGB of disk space."`` A regex
        extracts the numeric value and unit, converts to megabytes for
        threshold comparison, and chooses the appropriate severity.

    Severity scale:
        - ``pass``: No reclaimable space (output is empty or contains
          ``"nothing"``).
        - ``info``: Reclaimable space is below 500 MB.
        - ``warning``: Reclaimable space is >= 500 MB.

    Attributes:
        id (str): ``"homebrew_cleanup"``
        name (str): ``"Homebrew Cache Cleanup"``
        fix_level (str): ``"auto"`` — ``brew cleanup`` requires no arguments.
        fix_command (list[str]): ``["brew", "cleanup"]``
        fix_reversible (bool): ``False`` — deleted cache entries must be
            re-downloaded if the package needs to be reinstalled.
        fix_time_estimate (str): Typically under 30 seconds.
    """

    id = "homebrew_cleanup"
    name = "Homebrew Cache Cleanup"

    scan_description = (
        "Checking how much disk space Homebrew's cached downloads are using — "
        "old package downloads accumulate silently over time."
    )
    finding_explanation = (
        "Homebrew keeps previous package downloads in its cache indefinitely. "
        "Over time this can grow to gigabytes of stale installers and bottles "
        "you'll never need again."
    )
    recommendation = (
        "Run 'brew cleanup' to remove stale downloads. "
        "Homebrew will only keep the most recent version of each formula."
    )
    fix_level = "auto"
    fix_description = "Runs 'brew cleanup' to remove stale package downloads"
    fix_command = ["brew", "cleanup"]
    fix_reversible = False
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Run ``brew cleanup --dry-run`` and parse the reclaimable size from output.

        Uses a regex to extract the number and unit from Homebrew's summary
        line. Converts all units to megabytes for a consistent threshold
        comparison (warning threshold: 500 MB).

        Returns:
            CheckResult: One of:

            - ``pass`` — Cache is already clean (no output or "nothing" present).
            - ``info`` — Reclaimable space is below 500 MB.
            - ``warning`` — Reclaimable space is >= 500 MB.
            - ``info`` — Dry-run ran but the reclaimable size line could not be
              parsed (e.g. future Homebrew output format change).
            - ``error`` — Command exited non-zero.

        Note:
            The ``re`` module is imported inside this method (not at module
            level) because it is only needed here. All other checks in this
            module work with plain string operations.

        Example::

            check = HomebrewCleanupCheck()
            result = check.run()
            # warning: "Homebrew cache can free 2.3 GB — run 'brew cleanup'"
        """
        rc, stdout, stderr = self.shell(
            ["brew", "cleanup", "--dry-run"], timeout=20
        )

        if rc != 0:
            return self._error(f"brew cleanup check failed: {(stdout + stderr)[:80]}")

        output = stdout + stderr

        # Parse "This operation would free X.XGB of disk space."
        import re
        match = re.search(
            r"would free (\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)",
            output,
            re.IGNORECASE,
        )
        if match:
            size = f"{match.group(1)} {match.group(2)}"
            # Convert to MB to decide severity against the 500 MB threshold.
            n = float(match.group(1))
            unit = match.group(2).upper()
            mb = {"B": n / 1e6, "KB": n / 1e3, "MB": n, "GB": n * 1e3, "TB": n * 1e6}.get(unit, 0)

            if mb >= 500:
                return self._warning(
                    f"Homebrew cache can free {size} — run 'brew cleanup'",
                    data={"reclaimable": size},
                )
            return self._info(
                f"Homebrew cache can free {size} — run 'brew cleanup'",
                data={"reclaimable": size},
            )

        # Homebrew prints nothing (or says "nothing to do") when the cache is
        # already clean.
        if not output.strip() or "nothing" in output.lower():
            return self._pass("Homebrew cache is already clean")

        return self._info("Old Homebrew downloads found — run 'brew cleanup'")


class HomebrewMissingCheck(_HomebrewBase):
    """Check for Homebrew formulae whose declared dependencies are not installed.

    When a formula is removed or when Homebrew's dependency graph becomes
    inconsistent (e.g. after a partial uninstall or a tap removal), other
    formulae may be left with missing dependencies. These typically manifest
    as cryptic runtime errors: ``dyld: Library not loaded``, ``library not
    found``, or ``command not found`` for a binary that should be present.

    Detection mechanism:
        Runs ``brew missing``. Each line of output names a formula that is
        missing one or more of its declared dependencies. Empty output means
        the dependency graph is consistent.

    Severity scale:
        - ``pass``: No missing dependencies.
        - ``warning``: One or more formulae have missing dependencies. The
          full list is in ``result.data["missing"]``.
        - ``error``: ``brew missing`` exits non-zero with no stdout output
          (indicates a Homebrew internal error, distinct from the case where
          it exits 0 with output listing missing deps).

    Attributes:
        id (str): ``"homebrew_missing"``
        name (str): ``"Homebrew Missing Dependencies"``
        fix_level (str): ``"auto"`` — ``brew missing`` itself identifies the
            broken formulae; individual ``brew install`` or ``brew reinstall``
            commands resolve them.
        fix_command (list[str]): ``["brew", "missing"]``
        fix_reversible (bool): ``False`` — installing missing dependencies is
            additive; no existing files are removed.
        fix_time_estimate (str): Typically under 30 seconds to diagnose; fix
            time depends on what needs to be installed.
    """

    id = "homebrew_missing"
    name = "Homebrew Missing Dependencies"

    scan_description = (
        "Checking for Homebrew formulae with missing dependencies — broken "
        "links cause 'command not found' errors that are hard to diagnose."
    )
    finding_explanation = (
        "If a formula's dependencies were removed or not properly linked, "
        "the formula itself may fail silently or produce confusing errors "
        "like 'library not found' or 'dyld: Library not loaded'."
    )
    recommendation = (
        "Run 'brew missing' to see what's broken, then "
        "'brew install <missing-dep>' or 'brew reinstall <formula>'."
    )
    fix_level = "auto"
    fix_description = "Runs 'brew missing' to identify, then reinstalls broken formulae"
    fix_command = ["brew", "missing"]
    fix_reversible = False
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Run ``brew missing`` and count formulae with unresolved dependencies.

        ``brew missing`` exits 0 even when it finds missing dependencies; the
        signal is the presence of output lines. A non-zero exit *with no
        stdout* indicates a Homebrew error rather than missing deps.

        Returns:
            CheckResult: One of:

            - ``pass`` — No missing dependencies found.
            - ``warning`` — ``n`` formulae have missing dependencies.
              ``result.data["missing"]`` contains the output lines.
            - ``error`` — Command exited non-zero and produced no output.

        Example::

            check = HomebrewMissingCheck()
            result = check.run()
            # warning: "2 formulae with missing dependencies"
            # result.data["missing"] == ["ffmpeg: missing dep libvmaf", ...]
        """
        rc, stdout, stderr = self.shell(["brew", "missing"], timeout=30)

        # A non-zero exit with no output means Homebrew itself errored out —
        # distinct from "found missing deps" which uses stdout regardless of rc.
        if rc != 0 and not stdout.strip():
            return self._error(f"brew missing failed: {(stdout + stderr)[:80]}")

        lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]

        if not lines:
            return self._pass("No missing Homebrew dependencies")

        n = len(lines)
        return self._warning(
            f"{n} formula{'e' if n != 1 else ''} with missing dependencies",
            data={"missing": lines},
        )


# ── Public list for main.py ───────────────────────────────────────────────────
# Consumed by macaudit/main.py to discover and register all checks in this module.
# Order here determines the order checks appear within the "homebrew" category.

ALL_CHECKS: list[type[BaseCheck]] = [
    HomebrewDoctorCheck,
    HomebrewOutdatedCheck,
    HomebrewOutdatedCasksCheck,
    HomebrewAutoremoveCheck,
    HomebrewCleanupCheck,
    HomebrewMissingCheck,
]
