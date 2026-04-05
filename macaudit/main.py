"""
Mac Audit — CLI entry point and scan orchestrator.

This module is the top-level command dispatcher for the ``macaudit`` tool.
It owns:

  - CLI definition (Click decorators, option parsing, help text).
  - Profile resolution and category filtering.
  - Check collection, config-based suppression, and the pre-scan prompt.
  - Parallel check execution via ``ThreadPoolExecutor``.
  - Scan history load/save and inter-scan diff computation.
  - Output dispatch: narrated report, quiet mode, or JSON.
  - Fix-mode entry.
  - Exit-code contract for CI integration (``--fail-on-critical``).

Architecture notes:
    - All heavy imports (``macaudit.checks.*``, ``macaudit.ui.*``,
      ``macaudit.fixer.*``) are deferred to the *inside* of functions to
      minimise startup latency.  Only the absolute minimum needed to parse
      CLI arguments is imported at module level.
    - ``console`` is a module-level ``rich.Console`` instance shared by all
      output functions.  Passing it explicitly avoids global state in the
      UI layer.
    - The MDM enrollment flag file (``_MDM_FLAG``) is touched on first
      detection so the advisory is shown exactly once per install.

Exit codes:
    - ``0`` — normal exit (scan completed, no criticals, or ``--fail-on-critical``
      not set).
    - ``1`` — bad arguments (e.g. ``--dry-run`` without ``--fix``).
    - ``2`` — ``--fail-on-critical`` flag is set and at least one critical
      finding was returned.

Attributes:
    console (rich.Console): Shared Rich console instance using
        ``MACTUNER_THEME``.  All output goes through this instance.
    _MDM_FLAG (pathlib.Path): Sentinel file path whose existence indicates
        the MDM advisory has already been shown to this user.
"""

import shutil
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from macaudit import __version__
from macaudit.checks.base import BaseCheck, CheckResult, calculate_health_score
from macaudit.ui.header import print_header
from macaudit.ui.theme import COLOR_DIM, COLOR_TEXT, MACTUNER_THEME


# ── Console (shared across the tool) ─────────────────────────────────────────

console = Console(theme=MACTUNER_THEME)


# ── MDM flag ─────────────────────────────────────────────────────────────────

_MDM_FLAG = Path.home() / ".config" / "macaudit" / ".mdm_warned"


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.command(name="macaudit", context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="macaudit")
# Profiles
@click.option(
    "--profile",
    type=click.Choice(["developer", "creative", "standard"], case_sensitive=False),
    default=None,
    help="Force a profile (auto-detected by default).",
)
# Category filters
@click.option(
    "--only",
    metavar="CATS",
    default=None,
    help="Comma-separated categories to run, e.g. homebrew,disk,security",
)
@click.option(
    "--skip",
    metavar="CATS",
    default=None,
    help="Comma-separated categories to skip.",
)
# Output modes
@click.option("--issues-only", is_flag=True, default=False, help="Show only warnings and criticals.")
@click.option("--explain", is_flag=True, default=False, help="Extra educational context for every finding.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output results as JSON.")
@click.option("--quiet", is_flag=True, default=False, help="Print only health score and critical count.")
# Fix modes
@click.option("--fix", is_flag=True, default=False, help="Enter interactive fix mode after scan.")
@click.option(
    "--auto",
    is_flag=True,
    default=False,
    help="With --fix: automatically apply all safe AUTO fixes without prompting for each one.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="With --fix: walk through the fix flow without executing any changes.",
)
# Skip prompts
@click.option("--yes", "-y", is_flag=True, default=False,
              help="Skip the pre-scan confirmation prompt.")
# Exit code contract
@click.option(
    "--fail-on-critical",
    is_flag=True,
    default=False,
    help="Exit with code 2 if any critical issues are found (useful in scripts and CI).",
)
# Opt-in checks
@click.option(
    "--check-shell-secrets",
    is_flag=True,
    default=False,
    help="Scan shell config files for accidentally committed credentials.",
)
# Shell completion
@click.option(
    "--show-completion",
    is_flag=True,
    default=False,
    help="Print shell completion setup instructions and exit.",
)
# Welcome screen
@click.option(
    "--welcome",
    is_flag=True,
    default=False,
    help="Show the welcome screen and exit.",
)
def cli(
    profile: Optional[str],
    only: Optional[str],
    skip: Optional[str],
    issues_only: bool,
    explain: bool,
    as_json: bool,
    quiet: bool,
    fix: bool,
    auto: bool,
    dry_run: bool,
    yes: bool,
    fail_on_critical: bool,
    check_shell_secrets: bool,
    show_completion: bool,
    welcome: bool,
) -> None:
    """Mac System Health Inspector & Tuner.

    Run a full narrated audit of your Mac. Explains every finding.
    Safe, read-only by default — use --fix to apply changes.

    \b
    Environment variables:
      NO_COLOR=1   Disable all colour output (ANSI-stripped plain text).
      TERM=dumb    Alternative way to suppress colour in some terminals.
    """
    # ── Shell completion ──────────────────────────────────────────────────────
    if show_completion:
        _print_completion_help(console)
        return

    # ── Welcome flag ──────────────────────────────────────────────────────────
    if welcome:
        if not quiet and not as_json:
            from macaudit.ui.welcome import show_welcome
            show_welcome(console, first_run=False)
        return

    # ── Validate --dry-run requires --fix ─────────────────────────────────────
    if dry_run and not fix:
        console.print("[red]Error:[/red] --dry-run requires --fix.")
        raise SystemExit(1)

    # ── Resolve category filters (needed for mode before header) ──────────────
    only_cats = {c.strip().lower() for c in only.split(",")} if only else None
    skip_cats = {c.strip().lower() for c in skip.split(",")} if skip else set()

    # ── Header / first-run welcome ────────────────────────────────────────────
    _first_run = False
    _mdm_enrolled = False
    if not quiet and not as_json:
        from macaudit.ui.welcome import is_first_run, show_welcome
        _mdm_enrolled = _is_mdm_enrolled()
        if is_first_run():
            _first_run = True
            ok = show_welcome(console, first_run=True)
            if not ok:
                return
            _warn_if_mdm_enrolled(console)
        else:
            print_header(console, mode=_resolve_mode(fix, only, skip), only_cats=only_cats)
            console.print()
            _warn_if_mdm_enrolled(console)

    # ── Warn: --check-shell-secrets + --json exposes redacted credential hints ──
    if check_shell_secrets and as_json:
        import sys
        print(
            "Warning: --check-shell-secrets with --json includes redacted credential "
            "hints in the JSON output. Treat the output file as sensitive.",
            file=sys.stderr,
        )

    # ── Resolve profile ───────────────────────────────────────────────────────
    resolved_profile = _resolve_profile(profile)

    # ── Collect checks ────────────────────────────────────────────────────────
    all_checks = _collect_checks(
        profile=resolved_profile,
        only_cats=only_cats,
        skip_cats=skip_cats,
        check_shell_secrets=check_shell_secrets,
    )

    if not all_checks:
        console.print("[dim]No checks match the specified filters.[/dim]")
        console.print()
        return

    # ── Apply config-based suppression ────────────────────────────────────────
    from macaudit.config import load_config

    config = load_config()
    suppressed_ids = config["suppress"]

    suppressed_results = []
    active_checks = []
    for check in all_checks:
        if check.id in suppressed_ids:
            suppressed_results.append(check._skip("Suppressed by config"))
        else:
            active_checks.append(check)

    # ── Pre-scan prompt ───────────────────────────────────────────────────────
    if not quiet and not as_json and not yes and not _first_run:
        n = len(active_checks)
        console.print(f"  [dim]Ready to run [bold text]{n}[/bold text] checks.[/dim]")
        console.print()
        console.print(
            "  [dim]Press [bold text]↵ \\[ENTER][/bold text] to begin  "
            "·  [bold text]Ctrl-C[/bold text] to cancel[/dim]"
        )
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            console.print("\n  [dim]Cancelled.[/dim]\n")
            return
        console.print()

    # ── Run checks (narrated) ─────────────────────────────────────────────────
    _scan_start = time.monotonic()
    results = _run_checks(active_checks, quiet=quiet, as_json=as_json) + suppressed_results
    _scan_elapsed = time.monotonic() - _scan_start

    # ── Diff (load previous BEFORE saving current) ────────────────────────────
    diff = None
    if not quiet:
        from macaudit.diff import compute_diff
        from macaudit.history import _build_payload, load_previous_scan, save_scan

        previous = load_previous_scan()
        if previous is not None:
            current_payload = _build_payload(results)
            diff = compute_diff(current_payload, previous)

        save_scan(results)

    # ── Persist last-scan summary for welcome screen ──────────────────────────
    if not as_json:
        from macaudit.ui.welcome import save_last_scan
        _counts: dict[str, int] = {}
        for r in results:
            _counts[r.status] = _counts.get(r.status, 0) + 1
        save_last_scan(calculate_health_score(results), _counts)

    # ── Output ────────────────────────────────────────────────────────────────
    if as_json:
        _output_json(results, diff=diff)
        return

    score = calculate_health_score(results)

    if quiet:
        criticals = sum(1 for r in results if r.status == "critical")
        console.print(f"Health score: {score}/100  |  Critical: {criticals}")
        return

    from macaudit.ui.report import print_report
    print_report(results, console, issues_only=issues_only, explain=explain,
                 scan_duration=_scan_elapsed, mode=_resolve_mode(fix, only, skip),
                 mdm_enrolled=_mdm_enrolled, diff=diff)

    # ── Fix mode ──────────────────────────────────────────────────────────────
    if fix:
        from macaudit.fixer.runner import run_fix_session
        run_fix_session(results, console, auto=auto, dry_run=dry_run)

    # ── Exit code contract ────────────────────────────────────────────────────
    if fail_on_critical:
        criticals = sum(1 for r in results if r.status == "critical")
        if criticals:
            raise SystemExit(2)


# ── Mode resolution ───────────────────────────────────────────────────────────

def _resolve_mode(fix: bool, only: Optional[str], skip: Optional[str]) -> str:
    """Determine the display mode label based on which CLI flags are active.

    The mode label is shown in the report header and in the mode badge on
    the summary panel so users can confirm which run type produced the report.

    Args:
        fix (bool): Whether ``--fix`` was passed.
        only (Optional[str]): The ``--only`` category filter string, or ``None``.
        skip (Optional[str]): The ``--skip`` category filter string, or ``None``.

    Returns:
        str: One of:
            - ``"fix"``      — fix mode is active.
            - ``"targeted"`` — a category filter is active (``--only`` or
              ``--skip``).
            - ``"scan"``     — full default scan with no filters.
    """
    if fix:
        return "fix"
    if only or skip:
        return "targeted"
    return "scan"


# ── Shell completion help ─────────────────────────────────────────────────────

def _print_completion_help(console: Console) -> None:
    """Print shell completion setup instructions and exit."""
    import os
    from rich.panel import Panel
    from rich.text import Text
    from macaudit.ui.theme import COLOR_BRAND

    shell = os.environ.get("SHELL", "").split("/")[-1]

    t = Text()
    t.append("\n  Shell completion for macaudit\n\n", style=f"bold {COLOR_TEXT}")

    # Primary shell (detected)
    if shell in ("zsh", ""):
        primary, primary_rc   = "zsh",  "~/.zshrc"
        secondary, secondary_rc = "bash", "~/.bash_profile"
    elif shell == "bash":
        primary, primary_rc   = "bash", "~/.bash_profile"
        secondary, secondary_rc = "zsh",  "~/.zshrc"
    else:
        primary, primary_rc   = shell, f"~/.{shell}rc"
        secondary, secondary_rc = "zsh", "~/.zshrc"

    t.append(f"  Add this to your {primary_rc}:\n", style=COLOR_TEXT)
    t.append(
        f'    eval "$(_MACAUDIT_COMPLETE={primary}_source macaudit)"\n\n',
        style=COLOR_DIM,
    )
    t.append(f"  For {secondary}, add to {secondary_rc}:\n", style=COLOR_DIM)
    t.append(
        f'    eval "$(_MACAUDIT_COMPLETE={secondary}_source macaudit)"\n\n',
        style=COLOR_DIM,
    )
    t.append(f"  Then restart your terminal or run: source {primary_rc}\n", style=COLOR_DIM)

    console.print(Panel(t, border_style=COLOR_BRAND))


# ── MDM enrollment advisory ───────────────────────────────────────────────────

def _is_mdm_enrolled() -> bool:
    """Detect whether this Mac is MDM-enrolled via the ``profiles`` command.

    Runs ``profiles status -type enrollment`` and inspects the combined stdout
    and stderr for enrollment indicators.  Two known strings are checked:
    ``"enrolled via dep"`` (Device Enrolment Programme) and
    ``"mdm enrollment: yes"`` (manual MDM enrolment).

    Returns:
        bool: ``True`` if the Mac appears to be MDM-enrolled, ``False``
        otherwise.  Returns ``False`` on any exception (including
        ``FileNotFoundError`` if ``profiles`` is unavailable).

    Note:
        The ``profiles`` binary requires no special permissions for the
        ``status`` subcommand.  It is available on all supported macOS versions.
    """
    import subprocess
    try:
        r = subprocess.run(
            ["profiles", "status", "-type", "enrollment"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        output = (r.stdout + r.stderr).lower()
        return "enrolled via dep" in output or "mdm enrollment: yes" in output
    except Exception:
        return False


def _warn_if_mdm_enrolled(console: Console) -> None:
    """
    Print a brief MDM advisory if the Mac is managed.

    The warning is shown at most once (flagged by ~/.config/macaudit/.mdm_warned).
    """
    if _MDM_FLAG.exists():
        return

    if not _is_mdm_enrolled():
        return

    from rich.panel import Panel
    from rich.text import Text
    note = Text()
    note.append("  This Mac appears to be MDM-enrolled.\n", style="bold yellow")
    note.append(
        "  Some settings (FileVault, auto-updates, profiles, sharing) may be\n"
        "  enforced by your organization. Warnings about these may reflect IT\n"
        "  policy rather than security issues — check with your administrator.\n",
        style=COLOR_DIM,
    )
    note.append("  This notice will not appear again.", style=COLOR_DIM)
    console.print(
        Panel(note, title="[yellow]Managed Device[/yellow]", border_style="yellow")
    )
    console.print()
    try:
        _MDM_FLAG.parent.mkdir(parents=True, exist_ok=True)
        _MDM_FLAG.touch()
    except OSError:
        pass


# ── Profile resolution ────────────────────────────────────────────────────────

def _resolve_profile(requested: Optional[str]) -> str:
    """Resolve the active check profile, auto-detecting when not explicitly specified.

    Profile semantics:
        - ``"developer"`` — Homebrew is installed; activates Homebrew checks,
          dev environment checks, and all standard checks.
        - ``"standard"``  — no Homebrew detected; dev environment checks are
          excluded.
        - ``"creative"``  — must be forced via ``--profile creative``; intended
          for creative professionals who use the standard check suite without
          developer-specific checks.

    Args:
        requested (Optional[str]): The value passed to ``--profile``, or
            ``None`` for auto-detection.

    Returns:
        str: The resolved profile name (lowercase): ``"developer"``,
        ``"standard"``, or ``"creative"``.

    Note:
        ``"creative"`` cannot currently be auto-detected; it is always an
        explicit override.  Future heuristics (e.g. detecting Adobe Creative
        Cloud) could be added here.
    """
    if requested:
        return requested.lower()

    if shutil.which("brew"):
        return "developer"
    return "standard"


# ── Check registry ────────────────────────────────────────────────────────────

def _collect_checks(
    profile: str,
    only_cats: Optional[set],
    skip_cats: set,
    check_shell_secrets: bool,
) -> list[BaseCheck]:
    """Collect and filter instantiated check objects to run in the current scan.

    All check classes from every category module are imported lazily inside
    this function to keep startup time fast.  They are concatenated in the
    canonical display order (matching the report section order in
    ``macaudit.ui.report``), then filtered in three passes:

    1. **Category filter** — if ``only_cats`` is set, only checks whose
       ``category`` is in that set are retained.  If ``skip_cats`` is
       non-empty, checks in those categories are removed.
    2. **Profile filter** — checks whose ``profile_tags`` does not include
       the resolved profile are removed.

    The ``secrets`` module is only imported when ``check_shell_secrets`` is
    ``True`` to avoid importing it on every scan.

    Args:
        profile (str): The resolved profile name (``"developer"``,
            ``"standard"``, or ``"creative"``).
        only_cats (Optional[set[str]]): If not ``None``, the set of category
            slugs to include exclusively.
        skip_cats (set[str]): Set of category slugs to exclude.  Empty set
            means no exclusions.
        check_shell_secrets (bool): Whether to append the opt-in secrets
            check to the collection.

    Returns:
        list[BaseCheck]: Ordered, filtered list of instantiated check objects
        ready for execution via ``execute()``.
    """
    from macaudit.checks.apps import ALL_CHECKS as APPS
    from macaudit.checks.dev_env import ALL_CHECKS as DEV_ENV
    from macaudit.checks.disk import ALL_CHECKS as DISK
    from macaudit.checks.hardware import ALL_CHECKS as HARDWARE
    from macaudit.checks.homebrew import ALL_CHECKS as HOMEBREW
    from macaudit.checks.malware import ALL_CHECKS as MALWARE
    from macaudit.checks.memory import ALL_CHECKS as MEMORY
    from macaudit.checks.network import ALL_CHECKS as NETWORK
    from macaudit.checks.privacy import ALL_CHECKS as PRIVACY
    from macaudit.checks.security import ALL_CHECKS as SECURITY
    from macaudit.checks.system import ALL_CHECKS as SYSTEM

    # Ordered for logical report flow (matches category panel order in report.py)
    all_classes = (
        SYSTEM + SECURITY + PRIVACY + MALWARE
        + HOMEBREW + DISK + HARDWARE
        + MEMORY + NETWORK + DEV_ENV + APPS
    )

    # Opt-in checks appended after standard suite
    if check_shell_secrets:
        from macaudit.checks.secrets import ALL_CHECKS as SECRETS
        all_classes = all_classes + SECRETS

    checks = [cls() for cls in all_classes]

    # Category filters
    if only_cats:
        checks = [c for c in checks if c.category in only_cats]
    if skip_cats:
        checks = [c for c in checks if c.category not in skip_cats]

    # Profile filter
    checks = [
        c for c in checks
        if profile in getattr(c, "profile_tags", [profile])
    ]

    return checks


# ── Scan loop ─────────────────────────────────────────────────────────────────

def _run_checks(checks: list, quiet: bool, as_json: bool) -> list[CheckResult]:
    """Execute checks, returning results in input order with optional live narration.

    **Quiet / JSON mode**: checks run serially via a simple list comprehension
    so there is no live UI overhead.

    **Narrated mode**: checks are submitted to a ``ThreadPoolExecutor`` with
    8 workers.  Results are stored in a pre-allocated list indexed by their
    original position so the output order is deterministic regardless of
    completion order.  A contiguous-flush loop prints results above the live
    progress area as soon as a leading run of consecutive indices completes.

    The 8-worker limit was chosen to balance concurrency (most checks block on
    ``subprocess`` calls) against not spawning so many processes that macOS
    rate-limits the terminal.

    Args:
        checks (list[BaseCheck]): Ordered list of instantiated check objects.
        quiet (bool): If ``True``, suppress the live narrator and progress bar.
        as_json (bool): If ``True``, suppress the live narrator (same as
            ``quiet`` for execution purposes).

    Returns:
        list[CheckResult]: Results in the same order as *checks*.  No result
        is ``None``; ``execute()`` guarantees a result on every code path.
    """
    import concurrent.futures

    from macaudit.ui.narrator import ScanNarrator

    if quiet or as_json:
        return [check.execute() for check in checks]

    results: list[CheckResult | None] = [None] * len(checks)
    with ScanNarrator(console, total=len(checks)) as narrator:
        narrator.print_scan_header()
        next_to_print = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            future_to_idx = {
                pool.submit(check.execute): i
                for i, check in enumerate(checks)
            }
            for future in concurrent.futures.as_completed(future_to_idx):
                idx = future_to_idx[future]
                results[idx] = future.result()
                narrator.increment()
                # Flush contiguous completed results in input order
                while next_to_print < len(results) and results[next_to_print] is not None:
                    narrator.print_result(results[next_to_print])
                    next_to_print += 1

    return results




# ── JSON output ───────────────────────────────────────────────────────────────

def _output_json(results: list[CheckResult], diff: Optional[dict] = None) -> None:
    """Serialise all check results, system metadata, and optional diff to JSON on stdout.

    Builds the canonical ``schema_version: 1`` JSON payload and writes it to
    stdout via ``click.echo`` (which handles newline buffering correctly).
    Each ``CheckResult`` dataclass is converted to a plain dict via
    ``dataclasses.asdict()``; the ``min_macos`` tuple is coerced to a list
    because JSON has no tuple type.

    The output schema is shared with the history module (``_build_payload`` in
    ``history.py``) so that ``--json`` output and history files are structurally
    identical.

    Args:
        results (list[CheckResult]): All results from the completed scan.
        diff (Optional[dict]): The computed inter-scan diff from
            ``compute_diff()``, or ``None`` when no previous scan exists or
            the diff is empty.

    Note:
        This function writes **only** to stdout.  All error output goes through
        the shared ``console`` (stderr-routed).
    """
    import dataclasses
    import json
    from datetime import datetime, timezone

    from macaudit.system_info import get_system_info

    info = get_system_info()

    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    serialised = []
    for r in results:
        d = dataclasses.asdict(r)
        d["min_macos"] = list(d["min_macos"])  # tuple → list for JSON
        serialised.append(d)

    payload = {
        "schema_version": 1,
        "macaudit_version": __version__,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "system": {
            "macos_version": info["macos_version"],
            "architecture": info["architecture"],
            "model": info["model_name"],
        },
        "score": calculate_health_score(results),
        "summary": counts,
        "results": serialised,
    }

    if diff is not None:
        payload["diff"] = diff

    click.echo(json.dumps(payload, indent=2))


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
