"""
Fix session orchestrator — interactive and automatic fix flow.

This module drives the fix-mode UX after a scan completes.  It filters fixable
results, sorts them by severity, and presents each one as a rich card with full
context before the user approves or skips it.

Session modes:

    **Interactive mode** (default ``--fix``)
        Each fixable result is displayed sequentially as a styled ``Panel``
        containing the status, finding explanation, fix description, command or
        steps, and metadata (time estimate, reversibility, sudo requirement).
        The user chooses Apply / Skip / Quit via a ``TerminalMenu`` before
        anything executes.

    **Auto mode** (``--fix --auto``)
        Bypasses the per-fix menu for checks whose ``fix_level == "auto"``
        *and* ``fix_reversible == True`` *and* ``requires_sudo == False``.
        This "safe AUTO" filter ensures no irreversible or privileged operations
        run without explicit approval.

    **Dry-run mode** (``--fix --dry-run``)
        Walks through the entire fix flow without executing any changes.
        Useful for previewing which fixes would be applied.

Sorting contract:
    Fixable results are sorted by severity (``critical`` → ``warning`` →
    ``error`` → ``info``) so the most important fixes are presented first.

Attributes:
    _FIXABLE_STATUSES (frozenset[str]): Set of check statuses that qualify a
        result for inclusion in the fix session.  ``pass`` and ``skip`` results
        are excluded because there is nothing to fix.
    _FIXABLE_LEVELS (frozenset[str]): Set of ``fix_level`` values that have an
        executor.  ``"none"`` results are excluded because no action is possible.
    _SEVERITY_ORDER (dict[str, int]): Maps status strings to sort keys for
        the severity-descending display order.
"""

from __future__ import annotations

import shlex

from simple_term_menu import TerminalMenu
from rich.console import Console, Group
from rich.panel import Panel
from rich.padding import Padding
from rich.text import Text

from macaudit.checks.base import CheckResult
from macaudit.fixer.executor import (
    run_auto_fix,
    run_auto_sudo_fix,
    run_guided_fix,
    run_instructions_fix,
)
from macaudit.ui.theme import (
    COLOR_BRAND,
    COLOR_DIM,
    COLOR_TEXT,
    FIX_LEVEL_EMOJI,
    FIX_LEVEL_LABELS,
    FIX_LEVEL_LABEL_SHORT,
    STATUS_ICONS,
    STATUS_STYLES,
)


# ── Constants ─────────────────────────────────────────────────────────────────

_FIXABLE_STATUSES = frozenset(("warning", "critical", "error", "info"))
_FIXABLE_LEVELS   = frozenset(("auto", "auto_sudo", "guided", "instructions"))

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "error": 2, "info": 3}



# ── Public API ────────────────────────────────────────────────────────────────

def run_fix_session(
    results: list[CheckResult],
    console: Console,
    auto: bool = False,
    dry_run: bool = False,
) -> None:
    """
    Run the interactive fix session.

    Args:
        results: All check results from the scan.
        console: Rich Console (shared with rest of tool).
        auto:    If True, apply reversible AUTO fixes without interactive menu or per-fix prompts.
        dry_run: If True, walk through the fix flow without executing any changes.
    """
    fixable = _get_fixable(results)

    if not fixable:
        console.print()
        console.print(
            "  [bright_green]✨  Nothing to fix — your system looks healthy![/bright_green]"
        )
        console.print()
        return

    _print_fix_mode_panel(fixable, console, dry_run=dry_run)

    if auto:
        _run_auto_mode(fixable, console, dry_run=dry_run)
    else:
        _run_interactive_mode(fixable, console, dry_run=dry_run)


# ── Interactive mode ──────────────────────────────────────────────────────────

def _run_interactive_mode(
    fixable: list[CheckResult], console: Console, dry_run: bool = False,
) -> None:
    """Pure sequential 1:1 loop — full context card, approve inline, run, next."""
    applied = skipped = 0
    total = len(fixable)

    for idx, result in enumerate(fixable, 1):
        _print_fix_card(console, result, idx, total)

        if result.fix_level in ("auto", "auto_sudo"):
            options = ["Skip", "Apply", "Quit"]
        else:
            options = ["Skip", "Continue", "Quit"]

        console.print("  [bold]Apply this fix?[/bold]")
        menu = TerminalMenu(
            options,
            menu_cursor="› ",
            menu_cursor_style=("fg_cyan", "bold"),
            menu_highlight_style=("fg_cyan", "bold"),
            cursor_index=0,
        )
        choice = menu.show()
        if choice is None or choice == 2:  # Quit
            console.print("\n  [dim]Fix mode cancelled.[/dim]\n")
            _print_session_summary(console, applied, skipped, total, dry_run=dry_run)
            return
        if choice == 0:  # Skip
            console.print("  [dim]Skipped.[/dim]\n")
            skipped += 1
            continue

        if dry_run:
            console.print("  [dim]Skipped (dry run)[/dim]\n")
            applied += 1
            continue

        console.print()
        success = _dispatch(result, console)
        applied += 1 if success else 0
        skipped += 0 if success else 1

    _print_session_summary(console, applied, skipped, total, dry_run=dry_run)


# ── Auto mode ─────────────────────────────────────────────────────────────────

def _run_auto_mode(
    fixable: list[CheckResult], console: Console, dry_run: bool = False,
) -> None:
    """Apply all safe AUTO fixes without interactive menu or per-fix prompts."""
    safe = [
        r for r in fixable
        if r.fix_level == "auto"
        and r.fix_reversible
        and not r.requires_sudo
    ]

    if not safe:
        console.print(
            "  [dim]No safe AUTO fixes available.\n"
            "  Run without --auto to see all fixable issues interactively.[/dim]\n"
        )
        return

    verb = "Would apply" if dry_run else "Applying"
    console.print(
        f"  {verb} [bold]{len(safe)}[/bold] safe, reversible "
        f"AUTO fix{'es' if len(safe) != 1 else ''}…"
    )
    console.print()

    if dry_run:
        for result in safe:
            console.print(f"  [dim]•[/dim] {result.name}")
        console.print()
        _print_session_summary(console, len(safe), 0, len(safe), dry_run=True)
        return

    applied = skipped = 0
    for result in safe:
        success = _dispatch(result, console)
        applied += 1 if success else 0
        skipped += 0 if success else 1

    _print_session_summary(console, applied, skipped, len(safe))


# ── Execution helpers ─────────────────────────────────────────────────────────

def _dispatch(result: CheckResult, console: Console) -> bool:
    """Route a fix result to the appropriate executor function.

    Looks up ``result.fix_level`` in a static dispatch map and calls the
    corresponding executor.  Returns ``False`` if the fix level has no
    registered executor (defensive guard; should not occur if ``_FIXABLE_LEVELS``
    is kept in sync with the dispatch map).

    Args:
        result (CheckResult): The check result whose fix should be executed.
        console (Console): Rich console for output streaming.

    Returns:
        bool: ``True`` if the executor reported success, ``False`` otherwise.
    """
    dispatch_map = {
        "auto":         run_auto_fix,
        "auto_sudo":    run_auto_sudo_fix,
        "guided":       run_guided_fix,
        "instructions": run_instructions_fix,
    }
    fn = dispatch_map.get(result.fix_level)
    if fn is None:
        console.print("  [dim]No executor for this fix level.[/dim]\n")
        return False
    return fn(result, console)


# ── UI helpers ────────────────────────────────────────────────────────────────

def _get_fixable(results: list[CheckResult]) -> list[CheckResult]:
    """Filter and sort results to the subset that can be acted on in the fix session.

    A result qualifies as fixable if its ``status`` is in ``_FIXABLE_STATUSES``
    **and** its ``fix_level`` is in ``_FIXABLE_LEVELS``.  Results with
    ``status="pass"`` or ``status="skip"`` are excluded because there is nothing
    to act on.  Results with ``fix_level="none"`` are excluded because no
    executor can handle them.

    The filtered list is sorted by ``_SEVERITY_ORDER`` so critical findings
    appear first, giving the most urgent fixes the highest priority.

    Args:
        results (list[CheckResult]): All results from a completed scan.

    Returns:
        list[CheckResult]: Filtered and severity-sorted list of actionable
        results.  Empty list if no fixable results exist.
    """
    fixable = [
        r for r in results
        if r.status in _FIXABLE_STATUSES
        and r.fix_level in _FIXABLE_LEVELS
    ]
    return sorted(fixable, key=lambda r: _SEVERITY_ORDER.get(r.status, 9))


def _print_fix_card(
    console: Console,
    result: CheckResult,
    idx: int,
    total: int,
) -> None:
    """Render a rich ``Panel`` containing the full context for a single fix.

    The card layout (top to bottom):
      1. Status badge + fix level label.
      2. Finding message + explanation (indented).
      3. "What this fix does" section with the fix description.
         For AUTO / AUTO_SUDO: the shell command is shown.
         For INSTRUCTIONS: the numbered steps are shown.
      4. Footer metadata: time estimate, reversibility badge, sudo indicator.

    The panel border colour reflects the severity:
      - ``"critical"`` → bright red.
      - ``"warning"``  → yellow.
      - ``"info"``     → cyan.
      - Other          → dim.

    Args:
        console (Console): Rich console for rendering.
        result (CheckResult): The check result for this fix card.
        idx (int): 1-based index of this fix in the session (for the title).
        total (int): Total number of fixable items in the session.
    """
    status_icon  = STATUS_ICONS.get(result.status, "?")
    status_style = STATUS_STYLES.get(result.status)
    level_emoji  = FIX_LEVEL_EMOJI.get(result.fix_level, "·")
    level_label  = FIX_LEVEL_LABELS.get(result.fix_level, result.fix_level)

    parts: list = []

    # ── Status badge + fix level ───────────────────────────────────────────────
    badge = Text()
    badge.append(f"  {status_icon}  ", style=str(status_style))
    badge.append(result.status.upper(), style=f"bold {str(status_style)}")
    badge.append("   ")
    badge.append(f"{level_emoji}  {level_label}", style=COLOR_DIM)
    parts.append(badge)
    parts.append(Text(""))

    # ── Message + finding explanation ─────────────────────────────────────────
    msg = Text()
    msg.append(f"  {result.message}", style=COLOR_TEXT)
    parts.append(msg)

    if result.finding_explanation:
        parts.append(
            Padding(Text(result.finding_explanation, style=COLOR_DIM), (0, 2, 0, 4))
        )

    parts.append(Text(""))

    # ── What this fix does ────────────────────────────────────────────────────
    what = Text()
    what.append("  What this fix does\n", style=f"bold {COLOR_TEXT}")
    what.append(f"  {result.fix_description}", style=COLOR_DIM)
    parts.append(what)

    if result.fix_level in ("auto", "auto_sudo") and result.fix_command:
        cmd = Text()
        cmd.append(f"\n  $ {shlex.join(result.fix_command)}", style="dim cyan")
        parts.append(cmd)
    elif result.fix_level == "instructions" and result.fix_steps:
        steps = Text()
        for i, step in enumerate(result.fix_steps, 1):
            steps.append(f"\n  {i}. {step}", style=COLOR_DIM)
        parts.append(steps)

    parts.append(Text(""))

    # ── Footer meta ───────────────────────────────────────────────────────────
    meta_parts = []
    if result.fix_time_estimate and result.fix_time_estimate not in ("N/A", ""):
        meta_parts.append(f"⏱ {result.fix_time_estimate}")
    meta_parts.append("reversible" if result.fix_reversible else "⚠️  irreversible")
    if result.requires_sudo:
        meta_parts.append("🔐 requires password")

    footer = Text()
    footer.append("  " + "  ·  ".join(meta_parts), style=COLOR_DIM)
    parts.append(footer)

    # Border colour follows status
    if result.status == "critical":
        border = "bright_red"
    elif result.status == "warning":
        border = "yellow"
    elif result.status == "info":
        border = "cyan"
    else:
        border = "dim"

    console.print()
    console.print(
        Panel(
            Group(*parts),
            title=f"[bold]Fix {idx} of {total}  —  {result.name}[/bold]",
            title_align="left",
            border_style=border,
            padding=(0, 1),
        )
    )


def _print_fix_mode_panel(
    fixable: list[CheckResult], console: Console, dry_run: bool = False,
) -> None:
    """Print the Fix Mode header panel — count, breakdown, one-line instruction."""
    counts: dict[str, int] = {}
    for r in fixable:
        counts[r.fix_level] = counts.get(r.fix_level, 0) + 1

    parts = []
    for level in ("auto", "auto_sudo", "guided", "instructions"):
        n = counts.get(level, 0)
        if n:
            parts.append(
                f"[bold]{n}[/bold] {FIX_LEVEL_EMOJI[level]} {FIX_LEVEL_LABEL_SHORT[level]}"
            )

    body = Text()
    body.append(f"\n  Found {len(fixable)} fixable item{'s' if len(fixable) != 1 else ''}:  ")
    body.append("  ".join(parts))
    body.append("\n\n  Each fix is shown one at a time. Approve or skip before anything runs.\n", style=COLOR_DIM)
    if dry_run:
        body.append("  [DRY RUN] No changes will be made.\n", style="bold yellow")

    console.print()
    console.print(
        Panel(body, title="[bold magenta]Fix Mode[/bold magenta]", title_align="left",
              border_style=COLOR_BRAND)
    )
    console.print()


def _print_session_summary(
    console: Console,
    applied: int,
    skipped: int,
    total: int,
    dry_run: bool = False,
) -> None:
    """Print a Panel summarising the fix session."""
    body = Text()

    if dry_run:
        if applied == 0:
            body.append("\n  No fixes would be applied.", style=COLOR_DIM)
        else:
            s = "es" if applied != 1 else ""
            body.append(f"\n  {applied} fix{s} would be applied", style="bold bright_green")
            if skipped:
                body.append(f"   ·   {skipped} skipped", style=COLOR_DIM)
    elif applied == 0:
        body.append("\n  No fixes were applied.", style=COLOR_DIM)
    else:
        s = "es" if applied != 1 else ""
        body.append(f"\n  ✅  {applied} fix{s} applied", style="bold bright_green")
        if skipped:
            body.append(f"   ·   {skipped} skipped", style=COLOR_DIM)

    body.append("\n\n  Run  ", style=COLOR_DIM)
    body.append("macaudit", style=f"bold {COLOR_TEXT}")
    body.append("  again to rescan and confirm changes took effect.\n", style=COLOR_DIM)

    border = "bright_green" if applied > 0 and not dry_run else "dim"

    console.print()
    console.print(
        Panel(body, title="[bold]Fix session complete[/bold]", title_align="left",
              border_style=border)
    )
    console.print()
