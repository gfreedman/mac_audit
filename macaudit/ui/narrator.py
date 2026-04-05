"""
ScanNarrator — live-updating scan UI for parallel check execution.

This module provides :class:`ScanNarrator`, a context manager that wraps
``rich.live.Live`` to maintain a two-layer terminal display during parallel
check execution:

  1. **Completed results** — printed above the live area in input order via
     ``rich.live.Live.console.print()``.  These scroll naturally and persist
     after the scan completes.
  2. **Live progress area** — an animated spinner and progress bar that updates
     in place while checks run, replaced by a static progress bar at 100% when
     all checks finish.

Concurrency model:
    The scan orchestrator (``main._run_checks``) submits all checks to a
    ``ThreadPoolExecutor`` and calls ``narrator.increment()`` and
    ``narrator.print_result()`` as each check completes.  Results must be
    printed in **input order** to avoid interleaving; the caller maintains a
    ``next_to_print`` pointer and only calls ``print_result`` when the leading
    contiguous block of completed results grows.

Usage::

    with ScanNarrator(console, total=len(checks)) as narrator:
        narrator.print_scan_header()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            future_to_idx = {pool.submit(check.execute): i
                             for i, check in enumerate(checks)}
            for future in concurrent.futures.as_completed(future_to_idx):
                idx = future_to_idx[future]
                results[idx] = future.result()
                narrator.increment()
                while next_to_print < len(results) and results[next_to_print]:
                    narrator.print_result(results[next_to_print])
                    next_to_print += 1

Attributes:
    None — this module exports only :class:`ScanNarrator` and the three
    module-level rendering helpers.
"""

from rich.console import Console, Group
from rich.live import Live
from rich.padding import Padding
from rich.spinner import Spinner
from rich.text import Text

from macaudit.checks.base import CheckResult
from macaudit.ui.progress import render_progress
from macaudit.ui.theme import CATEGORY_ICONS, COLOR_DIM, COLOR_TEXT, STATUS_ICONS, STATUS_STYLES


class ScanNarrator:
    """Context manager for live, narrated scan feedback during parallel check execution.

    Wraps ``rich.live.Live`` to display a two-layer UI: completed check results
    scroll above, and an animated progress area updates below.  The live area is
    replaced by a static final progress bar when the context exits.

    Attributes:
        console (Console): The Rich console shared with the rest of the tool.
        total (int): Total number of checks to run.  Used to compute the
            progress percentage and to determine when to show ``100%``.
        completed (int): Count of checks that have finished (regardless of
            status).  Incremented by each call to ``increment()``.
        _last_category (str | None): The ``category`` slug of the most recently
            printed result.  Used to detect category boundaries and inject
            category-header lines between groups.
        _live (rich.live.Live): The underlying Live rendering context.
            Configured to refresh at 12 fps for smooth spinner animation.
    """

    def __init__(self, console: Console, total: int) -> None:
        """Initialise the narrator with a console and expected total check count.

        Args:
            console (Console): The shared Rich console instance.
            total (int): Total number of checks that will be executed.
        """
        self.console = console
        self.total = total
        self.completed = 0
        self._last_category: str | None = None

        self._live = Live(
            console=console,
            refresh_per_second=12,
            transient=False,
        )

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "ScanNarrator":
        """Start the Live context and render the initial progress area.

        Returns:
            ScanNarrator: ``self``, enabling use as ``with ScanNarrator(...) as narrator``.
        """
        self._live.__enter__()
        self._live.update(self._render_parallel())
        return self

    def __exit__(self, *args) -> None:
        """Stop the Live context and replace the spinner with the final progress bar.

        Replaces the animated spinner+progress area with a static 100% progress
        bar, then exits the underlying ``rich.live.Live`` context.  A trailing
        blank line is printed for visual breathing room after the last result.
        """
        # Replace live area with final progress bar (100% if all ran)
        self._live.update(_idle_bar(self.completed, self.total))
        self._live.__exit__(*args)
        self.console.print()  # breathing room after last check

    # ── Public API ────────────────────────────────────────────────────────────

    def increment(self) -> None:
        """Increment the completed-check counter and refresh the live progress area.

        Must be called exactly once per check completion, regardless of the
        check's result status.  Triggers a re-render of the spinner+progress
        composite so the progress bar percentage updates in place.
        """
        self.completed += 1
        self._live.update(self._render_parallel())

    def print_result(self, result: CheckResult) -> None:
        """Print one completed check result above the live area, injecting category headers.

        Category section headers are printed whenever the result's ``category``
        differs from the previous result's category.  A blank line is inserted
        between consecutive category groups for visual separation.

        This method must be called **in input order** — i.e. results should be
        printed in the same sequence as the original ``checks`` list, not in
        completion order.  The caller (``_run_checks`` in ``main.py``) is
        responsible for maintaining this invariant.

        Args:
            result (CheckResult): The completed check result to print.
        """
        if result.category != self._last_category:
            if self._last_category is not None:
                self._live.console.print()  # spacing between categories
            self._live.console.print(_format_category_header(result.category, self.console.width))
            self._last_category = result.category
        self._live.console.print(_format_result(result))

    def print_scan_header(self) -> None:
        """Print the "Scanning — checks run in parallel" label before the first check.

        Should be called once immediately after entering the context manager,
        before any check futures are submitted.
        """
        self._live.console.print()
        label = Text()
        label.append("  Scanning", style="bold magenta")
        label.append("  —  ", style=COLOR_DIM)
        label.append("checks run in parallel", style=COLOR_DIM)
        self._live.console.print(label)
        self._live.console.print()

    # ── Internal rendering ────────────────────────────────────────────────────

    def _render_parallel(self) -> Group:
        """
        Live area while checks run in parallel:

          ⠋  Running checks…

          [████████░░░░░░░░░░░░░░] 34%  ·  8 of 23 checks
        """
        spinner = Spinner(
            "dots",
            text=Text("  Running checks…", style=COLOR_DIM),
            style="cyan",
        )
        spinner_indented = Padding(spinner, pad=(0, 0, 0, 4))

        progress = Padding(
            render_progress(self.completed, self.total),
            pad=(1, 0, 0, 0),
        )

        return Group(spinner_indented, progress)


# ── Module-level helpers ──────────────────────────────────────────────────────


def _idle_bar(completed: int, total: int) -> Padding:
    """Render a progress bar with a top blank-line margin.

    Used as the static final display when the Live context exits and as the
    inter-check idle state when no spinner is needed.

    Args:
        completed (int): Number of checks that have finished.
        total (int): Total number of checks.

    Returns:
        Padding: A Rich Padding wrapping the progress bar with 1-line top margin.
    """
    return Padding(render_progress(completed, total), pad=(1, 0, 0, 0))


def _format_category_header(category: str, console_width: int = 80) -> Group:
    """Render a bold category section header with an underline rule.

    Produces a two-line ``Group``:
      1. ``"  <icon>  <Name>"`` in bold.
      2. ``"  ─────────────────────────────────────────────"`` in dim.

    The rule width is capped at 44 characters or ``console_width - 6``,
    whichever is smaller, to prevent wrapping on narrow terminals.

    Args:
        category (str): The category slug (e.g. ``"system"``, ``"security"``).
            Underscores are replaced by spaces and the result is title-cased.
        console_width (int): The current terminal width in columns.  Defaults
            to 80 as a conservative fallback.

    Returns:
        Group: A Rich ``Group`` containing the header text and rule.
    """
    icon = CATEGORY_ICONS.get(category, "  ")
    name = category.replace("_", " ").title()
    header = Text()
    header.append(f"  {icon}  ", style="bold")
    header.append(name, style=f"bold {COLOR_TEXT}")
    rule_width = min(44, console_width - 6)
    rule = Text("  " + "─" * rule_width, style=COLOR_DIM)
    return Group(header, rule)


def _format_result(result: CheckResult) -> Text:
    """Render a single completed check result as a one-line Rich ``Text`` object.

    Format::

        ✅  macOS Version Check              macOS 15.3 is current
        ⚠️   FileVault                        Disk encryption is disabled

    The check name is left-padded to 38 characters so that all message texts
    align in a consistent column regardless of name length.

    Args:
        result (CheckResult): The completed check result to render.

    Returns:
        Text: A Rich ``Text`` object with appropriate status colour applied
        to the icon and name, and a dim style for the message suffix.
    """
    icon = STATUS_ICONS.get(result.status, "?")
    style = STATUS_STYLES.get(result.status)

    line = Text()
    line.append(f"  {icon}  ", style=str(style))
    line.append(result.name.ljust(38), style=str(style))
    line.append(f"  {result.message}", style=COLOR_DIM)

    return line
