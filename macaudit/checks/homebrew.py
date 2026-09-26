"""Homebrew package manager health and maintenance checks.

This module audits the state of the Homebrew package manager across six
dimensions:

1. **Installation health** (``HomebrewDoctorCheck``) — Runs ``brew doctor``
   to detect broken symlinks, PATH conflicts, untrusted taps, stale git
   state, and other issues that cause silent failures in package management.
   Output is parsed into structured ``DoctorWarning`` blocks so that known
   warnings can be paired with exact remediation commands.

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
    - Output parsing lives in module-level pure functions
      (``_parse_doctor_warnings`` and friends) rather than inside ``run()``,
      so it can be unit-tested against captured ``brew doctor`` text without
      spawning a subprocess.
    - No check here ever *executes* a command built from ``brew`` output.
      Text lifted from that output is only shown to the user. All of it is
      stripped of ANSI escapes and control characters; tap and package names
      that are interpolated into suggested commands are additionally
      validated against strict allow-list regexes, so a suggested command
      cannot be altered by unexpected characters. Free-text warning titles
      are not allow-listed — the fix UI escapes them for display instead.

Attributes:
    _BREW_MISSING_MSG (str): Standard skip message emitted by the base class
        runner when ``brew`` is not installed. Defined once here to ensure
        consistency across all subclasses if the wording ever needs to change.
    ALL_CHECKS (list[type[BaseCheck]]): Ordered list of check classes exported
        to the main runner. Consumed by ``macaudit/main.py`` at startup.
"""

import re
from dataclasses import dataclass, replace
from typing import Any

from macaudit.checks.base import BaseCheck, CheckResult
from macaudit.constants import BREW_CACHE_WARNING_MB

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


@dataclass(frozen=True)
class DoctorWarning:
    """One ``Warning:`` block parsed out of ``brew doctor`` output.

    ``brew doctor`` prints each diagnostic as a ``Warning: <title>`` line
    followed by free-form explanatory lines (indented item lists, prose, and
    the commands Homebrew suggests). This record keeps the two parts separate
    so callers can match on the title and mine the body for specifics.

    Note:
        A block is one *diagnostic method*, not necessarily one problem:
        Homebrew joins every finding from a single method under one
        ``Warning:`` line (e.g. several broken symlinks, or several untrusted
        taps). Counting blocks therefore gives a lower bound on the number of
        underlying issues.

    Attributes:
        title (str): Text of the ``Warning:`` line with the prefix removed and
            control characters stripped, e.g.
            ``"The following taps are not trusted:"``.
        details (tuple[str, ...]): Every line after the title up to (but not
            including) the next block, right-stripped but with leading
            indentation preserved — indentation is how ``brew doctor``
            distinguishes item lists from prose. A tuple (not a list) so the
            frozen dataclass is genuinely immutable and hashable.
    """

    title: str
    details: tuple[str, ...]


# Prefix that opens every diagnostic block in `brew doctor` output. Homebrew
# prints it at column 0; an indented occurrence is body text, not a new block.
_DOCTOR_WARNING_PREFIX = "Warning:"

# Title of the tap-trust diagnostic (Homebrew's `check_for_untrusted_taps`,
# https://docs.brew.sh/Tap-Trust). Matched case-insensitively as a prefix so
# minor punctuation changes upstream do not break detection.
_UNTRUSTED_TAPS_TITLE = "the following taps are not trusted"

# Environment passed to `brew doctor`. Colour is disabled so warning labels
# arrive as plain "Warning:" rather than "\x1b[4;33mWarning\x1b[0m:"; the
# ANSI stripping in `_parse_doctor_warnings` is a second line of defence for
# Homebrew versions or configurations that ignore this variable.
_BREW_DOCTOR_ENV = {"HOMEBREW_NO_COLOR": "1"}

# Matches ANSI CSI escape sequences (colours, cursor movement) and any other
# C0 control character except tab. Applied to all `brew doctor` text before
# parsing so escape codes can neither defeat prefix matching nor leak into the
# report, the fix UI, or `--json` output.
_CONTROL_CHARS_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|[\x00-\x08\x0b-\x1f\x7f]")

# Allow-lists for names lifted from `brew doctor` output. These names are
# interpolated into commands we *display* to the user for copy-paste; they are
# never executed by macaudit. Validating them anyway guarantees that an
# unexpected name (containing `;`, spaces, `..`, or a leading `-` that would be
# parsed as a flag) can never turn a suggested command into something else.
# Each path component must start with an alphanumeric character.
#   Tap:    <user>/<repo>             e.g. gfreedman/mactuner
#   Item:   <user>/<repo>/<name>      e.g. gfreedman/mactuner/mactuner
# Formula names may contain `@` (versioned, e.g. python@3.12) and `+`.
_NAME_COMPONENT = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
_TAP_NAME_RE = re.compile(rf"^{_NAME_COMPONENT}/{_NAME_COMPONENT}$")
_ITEM_NAME_RE = re.compile(rf"^{_NAME_COMPONENT}/{_NAME_COMPONENT}/[A-Za-z0-9][A-Za-z0-9_.@+-]*$")

# A Homebrew-suggested trust command for installed items. Homebrew emits one
# such line per item kind, listing *every* installed item across all untrusted
# taps, space-separated and sorted:
#   brew trust --formula a/b/x a/b/y c/d/z
#   brew trust --cask    a/b/some-app
# Group 1 is the kind; group 2 is the raw, not-yet-validated name list.
_TRUST_ITEMS_RE = re.compile(r"^\s+brew trust --(formula|cask) (.+?)\s*$")

# Maximum characters of a single summary fragment in the one-line report
# message. Keeps the report row readable; full text is kept in `data`.
_SUMMARY_MAX = 60


def _clean(text: str) -> str:
    """Remove ANSI escape sequences and control characters from ``text``.

    Args:
        text (str): Raw text from a subprocess.

    Returns:
        str: ``text`` with every match of ``_CONTROL_CHARS_RE`` deleted.
        Newlines and tabs are preserved.
    """
    return _CONTROL_CHARS_RE.sub("", text)


def _truncate(text: str, limit: int = _SUMMARY_MAX) -> str:
    """Shorten ``text`` to at most ``limit`` characters, marking any cut with ``…``.

    Args:
        text (str): Text to shorten.
        limit (int): Maximum length of the returned string, including the
            ellipsis. Must be >= 1.

    Returns:
        str: ``text`` unchanged if it fits, else its first ``limit - 1``
        characters followed by ``"…"``.
    """
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _parse_doctor_warnings(output: str) -> list[DoctorWarning]:
    """Split raw ``brew doctor`` output into structured warning blocks.

    ``brew doctor`` writes its diagnostics to **stderr** in the shape::

        <preamble: "Please note that these warnings are just used ...">
        Warning: <title 1>
          <details 1 ...>
        Warning: <title 2>
          <details 2 ...>

    Any text before the first ``Warning:`` line is boilerplate and is
    discarded. Each column-0 ``Warning:`` line opens a new block; every
    following line belongs to that block until the next such line or end of
    input.

    This is a pure function (no I/O) so it can be unit-tested exhaustively
    against captured Homebrew output.

    Args:
        output (str): One stream of ``brew doctor`` output — normally stderr.
            Do not pass stdout and stderr concatenated: stdout carries an
            unrelated trailer (the support-tier notice) that would be
            appended to whichever block happened to come last.

    Returns:
        list[DoctorWarning]: One entry per ``Warning:`` line, in output order.
        Empty if the output contains no warnings.

    Complexity:
        O(n) in the length of ``output``: one regex pass to clean it, then a
        single pass over its lines with no backtracking.
    """
    warnings: list[DoctorWarning] = []

    # Accumulators for the block currently being read. `title is None` means
    # we are still in the preamble and have not seen a Warning: line yet.
    title: str | None = None
    details: list[str] = []

    # splitlines() also treats "\r\n" and lone "\r" as line breaks, so CRLF
    # output needs no special handling.
    for line in _clean(output).splitlines():
        if line.startswith(_DOCTOR_WARNING_PREFIX):
            # A new block begins — flush the previous one (if any) first.
            if title is not None:
                warnings.append(DoctorWarning(title, tuple(details)))
            title = line[len(_DOCTOR_WARNING_PREFIX):].strip()
            details = []
        elif title is not None:
            # rstrip only: leading indentation marks list items (see
            # `_parse_untrusted_taps`) and must survive.
            details.append(line.rstrip())

    # The loop flushes a block only when the *next* one starts, so the final
    # block is still pending here.
    if title is not None:
        warnings.append(DoctorWarning(title, tuple(details)))

    return warnings


def _is_untrusted_taps_warning(warning: DoctorWarning) -> bool:
    """Return ``True`` if ``warning`` is Homebrew's tap-trust diagnostic.

    Args:
        warning (DoctorWarning): A parsed ``brew doctor`` warning block.

    Returns:
        bool: Whether the block's title identifies it as the untrusted-taps
        warning.
    """
    return warning.title.lower().startswith(_UNTRUSTED_TAPS_TITLE)


def _parse_untrusted_taps(
    warning: DoctorWarning,
) -> tuple[list[str], dict[str, list[str]]]:
    """Extract untrusted tap names and the items installed from each.

    The tap-trust warning body looks like::

          gfreedman/mactuner                      <- tap list (indented)
                                                  <- blank line ends list
        Homebrew is currently ignoring ...
        Trust installed formulae from these taps with:
          brew trust --formula gfreedman/mactuner/mactuner
        Trust installed casks from these taps with:
          brew trust --cask gfreedman/mactuner/some-app
        ...

    Two facts are extracted:

    1. **Tap names** — the indented lines immediately after the title, up to
       the first blank or unindented line.
    2. **Installed items** — every fully-qualified name on the
       ``brew trust --formula`` and ``brew trust --cask`` lines. Homebrew
       emits these only for formulae/casks that are actually installed, and
       puts all installed items of one kind on a *single* line
       (``diagnostic.rb``: ``formulae.sort.join(" ")``). Placeholder lines
       such as ``brew trust --cask <user>/<tap>/<cask>`` fail validation and
       are ignored.

    Every extracted name is checked against a strict allow-list regex and
    silently dropped if it does not match (see ``_TAP_NAME_RE``).

    Args:
        warning (DoctorWarning): A block for which
            ``_is_untrusted_taps_warning`` returned ``True``.

    Returns:
        tuple[list[str], dict[str, list[str]]]: ``(taps, items_by_tap)``.
        ``taps`` preserves output order. ``items_by_tap`` maps each tap to
        the trust commands' arguments for it, as ``"--formula <full name>"``
        or ``"--cask <full name>"`` strings in output order; taps with nothing
        installed map to an empty list.
    """
    taps: list[str] = []
    for line in warning.details:
        if not line.strip() or not line[:1].isspace():
            break  # A blank or unindented line terminates the tap list.
        name = line.strip()
        if _TAP_NAME_RE.match(name):
            taps.append(name)

    items_by_tap: dict[str, list[str]] = {tap: [] for tap in taps}
    for line in warning.details:
        match = _TRUST_ITEMS_RE.match(line)
        if not match:
            continue
        kind, names = match.groups()
        for full_name in names.split():
            if not _ITEM_NAME_RE.match(full_name):
                continue
            # <user>/<repo>/<item>: everything before the last "/" is the tap.
            tap = full_name.rpartition("/")[0]
            if tap in items_by_tap:
                items_by_tap[tap].append(f"--{kind} {full_name}")

    return taps, items_by_tap


def _untrusted_tap_steps(taps: list[str], items_by_tap: dict[str, list[str]]) -> list[str]:
    """Build copy-pasteable remediation steps for untrusted taps.

    For each tap the user has two legitimate choices, and macaudit cannot know
    which one they want, so both are offered — removal first, because an
    untrusted tap is a security gate and removing unused code is the safer
    default:

    - **Remove it** — ``brew untap --force <tap>``, which (per
      ``brew untap --help``) uninstalls every formula and cask from the tap
      before untapping. Plain ``brew untap`` refuses while any are installed.
    - **Keep it** — trust only the specific installed items (Homebrew's own
      recommended least-privilege option). Omitted when nothing from the tap
      is installed: an unused tap has nothing worth trusting.

    Each step is formatted as prose, a newline, then the command indented to
    sit under the step text, so the command can be copied on its own.

    Args:
        taps (list[str]): Validated tap names, e.g. ``["gfreedman/mactuner"]``.
        items_by_tap (dict[str, list[str]]): Trust arguments per tap, as
            returned by ``_parse_untrusted_taps``.

    Returns:
        list[str]: Ordered steps — two per tap with installed items, one per
        tap without. The caller appends a shared verification step.
    """
    # Width of the "  N.  " step prefix used by the fix UI, so a continuation
    # line lines up under the step text.
    indent = " " * 6
    steps: list[str] = []
    for tap in taps:
        items = items_by_tap.get(tap, [])
        if items:
            steps.append(
                f"Remove {tap} and everything installed from it:\n"
                f"{indent}brew untap --force {tap}"
            )
            # One trust command per item keeps each line short and lets the
            # user trust some items without the others.
            trust_cmds = "\n".join(f"{indent}brew trust {item}" for item in items)
            steps.append(
                f"Or, to keep using it, trust only what you have installed:\n{trust_cmds}"
            )
        else:
            steps.append(f"Nothing from {tap} is installed — remove it:\n{indent}brew untap {tap}")
    return steps


class HomebrewDoctorCheck(_HomebrewBase):
    """Verify Homebrew installation health by running ``brew doctor``.

    ``brew doctor`` is Homebrew's canonical self-diagnosis command. It checks
    for: stale symlinks in ``/opt/homebrew/bin`` (or ``/usr/local/bin``),
    conflicting ``$PATH`` entries, outdated Homebrew core tap state, invalid
    ``HOMEBREW_*`` environment variables, untrusted third-party taps, and
    other conditions that silently break package installs or cause
    hard-to-diagnose "command not found" errors.

    Detection mechanism:
        Shells out to ``brew doctor`` (colour disabled) with a 30-second
        timeout. Exit status is authoritative: Homebrew exits non-zero if and
        only if at least one diagnostic fired. On failure, stderr — where
        Homebrew writes every warning — is parsed into ``Warning:`` blocks by
        ``_parse_doctor_warnings``.

    Remediation:
        ``brew doctor`` is purely diagnostic — re-running it changes nothing —
        so this check is ``instructions`` rather than ``auto``. (It was
        previously ``auto`` with ``fix_command = ["brew", "doctor"]``, which
        made ``macaudit --fix --auto`` report a successful "fix" that left
        every issue in place.) Known warnings get specific, per-result steps:

        - **Untrusted taps** — the exact ``brew untap`` / ``brew trust``
          commands for each tap and the items installed from it.
        - **Anything else** — a pointer to the named warning in
          ``brew doctor``'s output, which prints its own fix beneath it.

    Severity scale:
        - ``pass``: ``brew doctor`` exits 0.
        - ``warning``: Non-zero exit (one or more diagnostics fired).
        - ``error``: ``brew doctor`` could not be run to completion
          (timeout, or binary vanished after the ``requires_tool`` check).

    Attributes:
        id (str): ``"homebrew_doctor"``
        name (str): ``"Homebrew Health (brew doctor)"``
        fix_level (str): ``"instructions"`` — steps are printed; nothing is
            executed. Each fix changes Homebrew state in a way only the user
            can choose (e.g. trust vs. remove a tap).
        fix_steps (list[str]): Generic fallback steps. Replaced per-result
            with targeted steps when warnings are parsed.
        fix_reversible (bool): ``True`` — printing steps changes nothing.
        fix_time_estimate (str): Typical time to read and apply the steps.
    """

    id = "homebrew_doctor"
    name = "Homebrew Health (brew doctor)"

    scan_description = (
        "Running 'brew doctor' — checks for common Homebrew issues like "
        "broken symlinks, PATH conflicts, untrusted taps, and stale "
        "installation state."
    )
    finding_explanation = (
        "Homebrew issues cause 'command not found' errors, broken installs, "
        "and conflicts between package versions. brew doctor is the canonical "
        "way to surface them."
    )
    recommendation = (
        "Run 'brew doctor' and apply the command it prints beneath each "
        "warning. Most fixes are one-liners."
    )
    fix_level = "instructions"
    fix_description = "Shows the specific commands that resolve each brew doctor warning"
    fix_steps = [
        "Run 'brew doctor' in Terminal.",
        "For each 'Warning:' it prints, run the fix command shown beneath it.",
        "Re-run 'brew doctor' until it reports 'Your system is ready to brew.'",
    ]
    fix_reversible = True
    fix_time_estimate = "~2 minutes"

    def run(self) -> CheckResult:
        """Run ``brew doctor`` and turn its warnings into actionable steps.

        Returns:
            CheckResult: One of:

            - ``pass`` — ``brew doctor`` exited 0.
            - ``error`` — ``shell()`` reported rc ``-1`` (timeout or the
              binary could not be executed); this is a failure to *check*,
              not a finding about Homebrew.
            - ``warning`` — Non-zero exit. ``fix_steps`` is replaced with
              targeted steps when ``Warning:`` blocks were parsed; otherwise
              the generic class-level steps apply. ``result.data`` always
              carries the same three keys so ``--json`` consumers need no
              branching:

              - ``"warnings"`` (list[str]): each full ``Warning:`` line
                (format unchanged from earlier releases).
              - ``"untrusted_taps"`` (list[str]): untrusted tap names.
              - ``"output_preview"`` (str): first 300 cleaned characters of
                output; populated only when no warning could be parsed.

        Example::

            check = HomebrewDoctorCheck()
            result = check.run()
            # pass:    "Homebrew is healthy"
            # warning: "Homebrew: Untrusted tap gfreedman/mactuner"
            # warning: "2 Homebrew warnings — untrusted tap a/b; Broken symlinks…"
        """
        rc, stdout, stderr = self.shell(
            ["brew", "doctor"], timeout=30, env=_BREW_DOCTOR_ENV
        )

        if rc == 0:
            return self._pass("Homebrew is healthy")
        if rc == -1:
            # `shell()` uses -1 exclusively for "could not run"; stderr then
            # holds its own description (e.g. "Command timed out after 30s").
            return self._error(f"Could not run brew doctor: {_truncate(_clean(stderr))}")

        # Warnings are written to stderr. Fall back to stdout only if stderr
        # held none, to tolerate a hypothetical future change of stream.
        warnings = _parse_doctor_warnings(stderr) or _parse_doctor_warnings(stdout)

        data: dict[str, Any] = {"warnings": [], "untrusted_taps": [], "output_preview": ""}

        if not warnings:
            data["output_preview"] = _clean(f"{stderr}\n{stdout}".strip())[:300]
            return self._warning("brew doctor reported issues", data=data)

        # Build one short summary and one group of steps per warning block.
        # Untrusted taps are handled specifically; everything else defers to
        # the instructions `brew doctor` already printed under the warning.
        summaries: list[str] = []
        steps: list[str] = []

        for w in warnings:
            data["warnings"].append(f"{_DOCTOR_WARNING_PREFIX} {w.title}".rstrip())
            taps: list[str] = []
            items_by_tap: dict[str, list[str]] = {}
            if _is_untrusted_taps_warning(w):
                taps, items_by_tap = _parse_untrusted_taps(w)
            if taps:
                data["untrusted_taps"].extend(taps)
                plural = "s" if len(taps) != 1 else ""
                summaries.append(_truncate(f"untrusted tap{plural} {', '.join(taps)}"))
                steps.extend(_untrusted_tap_steps(taps, items_by_tap))
            else:
                # Unrecognised warning, or a tap warning whose names all
                # failed validation: point the user at it by title. The title
                # is control-character-free (`_clean`) but otherwise
                # unvalidated free text; the fix UI escapes it for display.
                summaries.append(_truncate(w.title.rstrip(":.")))
                steps.append(
                    f"Run 'brew doctor' and apply the fix it prints under "
                    f"\"Warning: {_truncate(w.title)}\""
                )
        steps.append("Re-run 'brew doctor' to confirm every warning is gone.")

        n = len(warnings)
        if n == 1:
            # Capitalise the first letter only; `str.capitalize` would
            # lowercase the rest and mangle names like "Org/Tap".
            message = f"Homebrew: {summaries[0][:1].upper()}{summaries[0][1:]}"
        else:
            # "warnings", not "issues": one block may hold several problems
            # (see `DoctorWarning`), so the block count is a lower bound.
            message = f"{n} Homebrew warnings — {'; '.join(summaries)}"

        result = self._warning(message, data=data)
        # `_result` copies class-level defaults; override just the fields
        # that depend on what this run actually found.
        return replace(
            result,
            fix_steps=steps,
            recommendation=(
                "Each Homebrew warning has a specific fix — follow the steps "
                "below, then re-run 'brew doctor'."
            ),
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
        match = re.search(
            r"would free (\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)",
            output,
            re.IGNORECASE,
        )
        if match:
            size = f"{match.group(1)} {match.group(2)}"
            # Convert to MB to compare against the warning threshold.
            n = float(match.group(1))
            unit = match.group(2).upper()
            mb = {"B": n / 1e6, "KB": n / 1e3, "MB": n, "GB": n * 1e3, "TB": n * 1e6}.get(unit, 0)

            if mb >= BREW_CACHE_WARNING_MB:
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
