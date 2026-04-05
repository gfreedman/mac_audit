"""
Fix executors — one function per ``fix_level``.

This module contains four executor functions, each implementing one tier of
the fix capability framework defined in :class:`~macaudit.checks.base.CheckResult`.
Every function shares the same contract:

  - Accepts a :class:`~macaudit.checks.base.CheckResult` and a
    :class:`rich.console.Console`.
  - Performs the fix action (or prints guidance).
  - Returns ``True`` on success or user-confirmed completion, ``False`` on
    failure, cancellation, or timeout.

Fix level registry:

    ``auto``
        Run ``result.fix_command`` as a subprocess.  Output is streamed line
        by line to the console so the user can see progress in real time.
        Shell injection is prevented by always using ``shell=False``; the
        command is an arg list hardcoded in the check definition.

    ``auto_sudo``
        Run ``result.fix_command`` with administrator privileges via
        ``osascript do shell script "…" with administrator privileges``.
        This approach presents the native macOS authentication dialog rather
        than a bare ``sudo`` prompt, which is the Apple-recommended pattern
        for GUI-adjacent tools needing privilege escalation.

    ``guided``
        Open the relevant System Settings pane via a deep-link URL stored in
        ``result.fix_url``.  Print the recommendation text and any
        ``fix_steps`` so the user knows exactly what to click.  Falls back to
        opening the top-level System Settings app if the deep link fails
        (deep links for specific panes were introduced in macOS Ventura 13).

    ``instructions``
        Print numbered manual steps from ``result.fix_steps``.  No commands
        are executed.  This level is used for fixes that require Recovery Mode,
        hardware actions, or sensitive multi-step procedures.

Security note:
    All ``fix_command`` lists are **static, hardcoded** in the check class
    definitions.  They are never constructed from user-supplied data.
    ``shell=False`` is always used in ``subprocess`` calls to prevent shell
    injection.

Attributes:
    None — this module exports only the four executor functions.
"""

from __future__ import annotations

import shlex
import subprocess

from rich.console import Console

from macaudit.checks.base import CheckResult


# ── AUTO — stream shell command output ────────────────────────────────────────

def run_auto_fix(result: CheckResult, console: Console) -> bool:
    """
    Run result.fix_command as a subprocess with live output streaming.

    fix_command is a list of arguments set by us in check definitions (not user
    input).  shell=False avoids any command-injection surface.
    """
    if not result.fix_command:
        console.print("  [red]No fix command defined.[/red]\n")
        return False

    display_cmd = shlex.join(result.fix_command)
    console.print(f"  [dim]$[/dim]  [cyan]{display_cmd}[/cyan]")
    console.print()

    try:
        proc = subprocess.Popen(
            result.fix_command,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        if proc.stdout is None:
            console.print("  [red]No output stream available.[/red]\n")
            return False
        for line in proc.stdout:
            stripped = line.rstrip()
            if stripped:
                console.print(f"  [dim]{stripped}[/dim]")

        proc.wait(timeout=120)

        if proc.returncode == 0:
            console.print("\n  [bright_green]✅  Completed successfully.[/bright_green]\n")
            return True
        else:
            console.print(
                f"\n  [yellow]⚠️   Finished with exit code {proc.returncode}.[/yellow]\n"
            )
            return False

    except subprocess.TimeoutExpired:
        proc.kill()
        console.print("\n  [red]❌  Command timed out (>120s).[/red]\n")
        return False
    except Exception as e:
        console.print(f"\n  [red]❌  Error: {e}[/red]\n")
        return False


# ── AUTO_SUDO — osascript for native macOS password dialog ────────────────────

def run_auto_sudo_fix(result: CheckResult, console: Console) -> bool:
    """
    Run result.fix_command with administrator privileges.

    Uses osascript rather than terminal sudo, which shows a native macOS
    authentication dialog. This is the Apple-recommended approach for
    GUI-adjacent tools that need privilege escalation.
    """
    if not result.fix_command:
        console.print("  [red]No fix command defined.[/red]\n")
        return False

    # shlex.join produces a properly-quoted shell string from the arg list.
    # Then escape double-quotes for embedding inside the AppleScript string.
    shell_cmd = shlex.join(result.fix_command)
    osa_safe = shell_cmd.replace("\\", "\\\\").replace('"', '\\"')
    osa_script = f'do shell script "{osa_safe}" with administrator privileges'

    display_cmd = shell_cmd
    console.print(
        "  [dim]A macOS password dialog will appear to grant administrator access.[/dim]"
    )
    console.print(f"  [dim]$[/dim]  [cyan]{display_cmd}[/cyan]")
    console.print()

    try:
        proc = subprocess.run(
            ["osascript", "-e", osa_script],
            capture_output=True,
            text=True,
            timeout=120,
        )

        output = proc.stdout.strip()
        if output:
            console.print(f"  [dim]{output}[/dim]")

        if proc.returncode == 0:
            console.print("\n  [bright_green]✅  Completed successfully.[/bright_green]\n")
            return True
        else:
            err = proc.stderr.strip()
            # osascript exit 1 when user clicks Cancel
            if "User canceled" in err or "cancelled" in err.lower():
                console.print("\n  [dim]Cancelled by user.[/dim]\n")
            else:
                console.print(
                    f"\n  [yellow]⚠️   Finished with issues: "
                    f"{err or f'exit {proc.returncode}'}[/yellow]\n"
                )
            return False

    except subprocess.TimeoutExpired:
        console.print("\n  [red]❌  Timed out waiting for authentication.[/red]\n")
        return False
    except FileNotFoundError:
        console.print("\n  [red]❌  osascript not found — cannot run privileged command.[/red]\n")
        return False
    except Exception as e:
        console.print(f"\n  [red]❌  Error: {e}[/red]\n")
        return False


# ── GUIDED — open System Settings deep link ───────────────────────────────────

def run_guided_fix(result: CheckResult, console: Console) -> bool:
    """
    Open the relevant System Settings pane and print guidance.

    The 'fix' for GUIDED items is showing the user exactly where to go
    and what to look for — macaudit can't change these settings itself.
    """
    if not result.fix_url:
        console.print("  [red]No System Settings URL defined.[/red]\n")
        return False

    # Print what to do inside Settings
    if result.recommendation:
        console.print(f"  [text]{result.recommendation}[/text]")
        console.print()

    if result.fix_steps:
        console.print("  [bold text]What to do:[/bold text]")
        for i, step in enumerate(result.fix_steps, 1):
            console.print(f"  [dim]{i}.[/dim]  {step}")
        console.print()

    # Open System Settings
    try:
        subprocess.run(
            ["open", result.fix_url],
            check=True,
            timeout=10,
            capture_output=True,
        )
        console.print(
            "  [bright_green]✅  System Settings opened.[/bright_green]\n"
        )
        return True

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        # Fall back to plain System Settings if deep link fails
        try:
            subprocess.run(
                ["open", "-a", "System Settings"],
                timeout=5,
                capture_output=True,
            )
            console.print(
                "  [yellow]⚠️   Opened System Settings "
                "(deep link unsupported on this macOS version).[/yellow]\n"
            )
            return True
        except Exception as e:
            console.print(f"  [red]❌  Could not open System Settings: {e}[/red]\n")
            return False

    except Exception as e:
        console.print(f"  [red]❌  Error: {e}[/red]\n")
        return False


# ── INSTRUCTIONS — print manual steps ────────────────────────────────────────

def run_instructions_fix(result: CheckResult, console: Console) -> bool:
    """
    Print numbered manual steps for the user to follow.

    No commands are executed — this is purely informational guidance.
    """
    steps = result.fix_steps

    if steps:
        console.print("  [bold text]Steps to follow:[/bold text]")
        for i, step in enumerate(steps, 1):
            console.print(f"  [dim]{i}.[/dim]  {step}")
        console.print()
        return True

    # Fall back to recommendation text if no explicit steps
    if result.recommendation:
        console.print(f"  [text]{result.recommendation}[/text]\n")
        return True

    console.print("  [dim]No instructions defined for this check.[/dim]\n")
    return False
