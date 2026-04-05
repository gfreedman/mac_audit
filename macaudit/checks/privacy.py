"""Privacy permission checks for macOS.

This module provides guided auditing of macOS TCC (Transparency, Consent and
Control) permission grants. Because macOS does not expose a stable public API
for enumerating TCC grants programmatically, and because reading ``TCC.db``
directly requires Full Disk Access and behaves inconsistently across macOS
versions, this module takes a different approach: it detects whether macaudit
itself has Full Disk Access (which reveals *something* about the current
permission state) and then guides the user to the exact System Settings pane
where they can review grants themselves.

Design decisions:
    - No attempt is made to parse ``TCC.db`` or call private system frameworks.
      This keeps the tool safe to run without elevated privileges and avoids
      breakage on future macOS releases.
    - The check always returns ``info`` severity, never ``pass`` or ``fail``,
      because it cannot make a binary determination — only the user can judge
      whether the apps they see in each permission list are trustworthy.
    - The ``fix_url`` uses Apple's ``x-apple.systempreferences:`` deep-link
      scheme to navigate the user directly to the Full Disk Access pane,
      avoiding the multi-click journey through nested settings panels.

Checks:
    TCCPermissionAuditCheck: Guided review of Full Disk Access, Screen
        Recording, and Accessibility grants in System Settings.

Attributes:
    ALL_CHECKS (list[type[BaseCheck]]): Ordered list of check classes exported
        to the main runner. Consumed by ``macaudit/main.py`` at startup.
"""

from __future__ import annotations

import os

from macaudit.checks.base import BaseCheck, CheckResult


class TCCPermissionAuditCheck(BaseCheck):
    """Guided TCC permission review for the three highest-risk permission categories.

    macOS TCC controls which apps can access sensitive resources: the full
    filesystem, screen contents, and accessibility APIs. This check detects
    whether macaudit itself currently holds Full Disk Access (by testing
    whether it can see the user-space ``TCC.db`` path), then surfaces
    educational context and opens the correct settings pane for manual review.

    Detection mechanism:
        Tests for the existence of ``~/Library/Application Support/com.apple.TCC/TCC.db``.
        Presence of this file is only visible to processes that hold Full Disk
        Access; the check intentionally does *not* open or read the file.

    Severity:
        Always ``info`` — the result is never a binary pass/fail because
        determining whether a specific app *should* have a permission requires
        human judgment, not automated heuristics.

    Attributes:
        id (str): Unique machine-readable identifier for this check.
        name (str): Human-readable display name shown in the audit report.
        category (str): Report grouping key; value ``"privacy"``.
        category_icon (str): Emoji prefix rendered in the TUI beside the category name.
        scan_description (str): One-sentence description shown while the check runs.
        finding_explanation (str): Extended prose explaining *why* these permissions
            are dangerous and what an attacker can do with each one.
        recommendation (str): Actionable instructions for what the user should
            review and which specific sub-sections of Privacy & Security to visit.
        fix_level (str): Remediation type; ``"guided"`` means the fix opens a
            System Settings URL rather than executing a command.
        fix_description (str): One-line summary of what the guided fix does.
        fix_url (str): ``x-apple.systempreferences:`` deep-link URL that navigates
            directly to the Full Disk Access privacy pane in System Settings.
        fix_reversible (bool): Whether the fix can be undone; ``True`` because
            opening System Settings causes no persistent change by itself.
        fix_time_estimate (str): Human-readable estimate of manual review time.
    """

    id = "tcc_permission_audit"
    name = "Privacy Permissions"
    category = "privacy"
    category_icon = "🔒"

    scan_description = (
        "Reviewing privacy & security permissions — "
        "macOS doesn't expose a public API to enumerate all app permissions, "
        "so we'll guide you through the most critical ones to review manually."
    )
    finding_explanation = (
        "Apps with Full Disk Access can read every file on your Mac — "
        "including password databases, private documents, and saved credentials. "
        "Apps with Screen Recording can silently capture everything on screen "
        "(passwords, messages, banking info). "
        "Apps with Accessibility can control your Mac, simulate keystrokes, and "
        "log everything you type. These three permissions should be reviewed regularly."
    )
    recommendation = (
        "Open System Settings → Privacy & Security and audit: "
        "Full Disk Access (only Terminal, backup apps, and essential system tools); "
        "Screen Recording (only screen-sharing apps you actively use); "
        "Accessibility (only automation tools you explicitly trust and recognise)."
    )

    fix_level = "guided"
    fix_description = "Opens Privacy & Security in System Settings for manual review."
    fix_url = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Check TCC.db visibility as a proxy for Full Disk Access; always returns info.

        Tests whether the user-space TCC database file is visible to the current
        process. Visibility requires Full Disk Access, so this is a lightweight
        proxy for the FDA grant state. The file is never opened or read — only
        its existence on the filesystem is tested.

        Two distinct info messages are returned depending on the FDA state, so
        that the user understands whether macaudit can see the permission list
        or whether they need to navigate to System Settings independently.

        Returns:
            CheckResult: Always an ``info``-level result. The message differs
            based on whether macaudit itself has Full Disk Access:

            - If FDA is detected: informs the user that macaudit has elevated
              access and directs them to review other apps' permissions.
            - If FDA is not detected: provides a direct call to action to open
              System Settings manually.

        Note:
            This method intentionally does NOT call ``os.open()`` or
            ``open()`` on ``TCC.db``. Doing so would raise ``PermissionError``
            without FDA and could be flagged by security software on systems
            that do have FDA. Existence-only testing is the correct approach.

        Example::

            check = TCCPermissionAuditCheck()
            result = check.run()
            # result.severity is always "info"
            # result.message guides the user toward System Settings
        """
        # Test visibility of the user-space TCC database.
        # Only processes with Full Disk Access can see this path at all;
        # os.path.exists() returns False (not raises) for permission-denied paths.
        tcc_path = os.path.expanduser(
            "~/Library/Application Support/com.apple.TCC/TCC.db"
        )
        has_fda = os.path.exists(tcc_path)

        if has_fda:
            # macaudit has FDA — the user granted it (or it inherited the grant).
            # Acknowledge this and steer them toward reviewing other apps.
            return self._info(
                "macaudit has Full Disk Access — review app permissions in System Settings"
            )

        # Without FDA, we can't inspect the database; give a direct call to action.
        return self._info(
            "Review Full Disk Access, Screen Recording & Accessibility in System Settings"
        )


# ── Export ────────────────────────────────────────────────────────────────────
# Consumed by macaudit/main.py to discover and register all checks in this module.

ALL_CHECKS = [
    TCCPermissionAuditCheck,
]
