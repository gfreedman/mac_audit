"""
Application-level health checks.

This module implements three checks that inspect application-level state:
pending App Store updates, iCloud account health, and startup login items.

Design decisions:
    - ``AppStoreUpdatesCheck`` requires the ``mas`` CLI tool (not installed by
      default).  The check is automatically skipped when ``mas`` is absent via
      the ``requires_tool = "mas"`` gate in ``BaseCheck.execute()``.
    - ``iCloudStatusCheck`` reads ``MobileMeAccounts`` preferences and probes
      the ``~/Library/Mobile Documents`` directory rather than querying the
      iCloud daemon directly.  The daemon interface is undocumented and subject
      to change; the directory approach is stable and does not require entitlements.
    - ``LoginItemsCheck`` uses ``osascript`` / System Events rather than
      ``launchctl list``, because launchctl enumerates all launchd session
      services (hundreds of XPC helpers and framework daemons) — far more than
      what users see in System Settings → Login Items.  The AppleScript query
      returns exactly the items shown in that UI.

Checks:
    - :class:`AppStoreUpdatesCheck` — outdated App Store apps via ``mas``.
    - :class:`iCloudStatusCheck`    — iCloud account configured and Drive active.
    - :class:`LoginItemsCheck`      — startup login items count; warns if > 15.

Attributes:
    ALL_CHECKS (list[type[BaseCheck]]): Ordered list of check classes exported
        to the scan orchestrator.

Note:
    All subprocess calls use ``self.shell()``, which enforces ``LANG=C`` and
    ``LC_ALL=C`` for consistent English output regardless of system locale.
"""

from __future__ import annotations

import os

from macaudit.checks.base import BaseCheck, CheckResult


# ── App Store updates ─────────────────────────────────────────────────────────

class AppStoreUpdatesCheck(BaseCheck):
    """Check for pending Mac App Store updates via the mas CLI tool."""

    id = "app_store_updates"
    name = "App Store Updates"
    category = "apps"
    category_icon = "🛍️ "

    requires_tool = "mas"

    scan_description = (
        "Checking for pending App Store updates via mas — "
        "apps don't always notify you, so outdated versions accumulate security "
        "vulnerabilities silently."
    )
    finding_explanation = (
        "Apps from the Mac App Store receive security and bug-fix updates regularly. "
        "Unlike Homebrew, App Store apps don't auto-update by default unless you "
        "enable automatic updates. Outdated apps can have unpatched vulnerabilities "
        "that attackers exploit — browsers and productivity apps are common targets."
    )
    recommendation = (
        "Run 'mas upgrade' to update all App Store apps at once, "
        "or open the App Store → Updates tab. "
        "Enable automatic updates: App Store → Settings → Automatic Updates."
    )

    fix_level = "auto"
    fix_description = "Update all outdated App Store apps via mas upgrade."
    fix_command = ["mas", "upgrade"]
    fix_reversible = False
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Run ``mas outdated`` and report the count and names of pending updates.

        ``mas outdated`` exits 0 regardless of whether updates exist; each
        output line represents one app with a pending update in the format
        ``<id> <current_version> (<new_version>) <name>``.  A 30-second timeout
        is used because ``mas`` contacts the App Store API, which can be slow on
        poor connections.

        The result message includes the first three app names for at-a-glance
        visibility.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — ``mas`` returned an error; typically means App Store
              is not reachable or ``mas`` needs re-authentication.
            - ``"pass"`` — all App Store apps are up to date.
            - ``"warning"`` — one or more apps have pending updates; names shown.
        """
        rc, out, err = self.shell(["mas", "outdated"], timeout=30)

        # mas exits 0 whether or not there are updates
        if rc != 0 and not out.strip():
            return self._info("Could not check App Store updates (try: mas list)")

        lines = [l.strip() for l in out.splitlines() if l.strip()]
        count = len(lines)

        if count == 0:
            return self._pass("All App Store apps are up to date")

        apps_preview = ", ".join(
            l.split(None, 2)[2].strip() if len(l.split(None, 2)) >= 3 else l
            for l in lines[:3]
        )
        suffix = f"  +{count - 3} more" if count > 3 else ""

        return self._warning(
            f"{count} App Store app{'s' if count != 1 else ''} need updates: "
            f"{apps_preview}{suffix}",
            data={"outdated": lines, "count": count},
        )


# ── iCloud status ─────────────────────────────────────────────────────────────

class iCloudStatusCheck(BaseCheck):
    """Verify iCloud account is signed in and Drive is syncing."""

    id = "icloud_status"
    name = "iCloud Sign-in"
    category = "apps"
    category_icon = "☁️ "

    scan_description = (
        "Checking iCloud account status — "
        "iCloud sync failures are silent: data may not be backed up to the cloud "
        "even though the icon appears normal."
    )
    finding_explanation = (
        "iCloud keeps your documents, photos, and settings synced across Apple devices. "
        "If the account is missing or in a broken state, files in iCloud Drive may "
        "become unavailable on other devices and new data won't upload. "
        "This often happens after a macOS upgrade or password change."
    )
    recommendation = (
        "Open System Settings → Apple Account to verify iCloud status. "
        "If there's a yellow warning icon, sign out and sign back in. "
        "Check iCloud Drive sync: Finder → iCloud Drive — look for the sync spinner."
    )

    fix_level = "guided"
    fix_description = "Check iCloud status in System Settings → Apple Account."
    fix_url = "x-apple.systempreferences:com.apple.preferences.AppleIDPrefPane"
    fix_reversible = True
    fix_time_estimate = "~2 minutes"

    def run(self) -> CheckResult:
        """Check iCloud account registration via ``MobileMeAccounts`` and Drive sync via directory probe.

        Two signals are queried in order:

        1. ``defaults read MobileMeAccounts Accounts`` — returns the iCloud
           account list as a plist array.  A non-zero exit code or an empty
           array means no iCloud account is configured on this Mac.
        2. ``~/Library/Mobile Documents`` — the container directory for iCloud
           Drive.  Its existence and the count of its subdirectories serve as a
           proxy for whether iCloud Drive is actively syncing.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — no iCloud account configured.
            - ``"pass"`` — iCloud is active; Drive sync directory found.
            - ``"info"`` — iCloud is configured but Drive directory is
              inaccessible (permission restricted) or not yet created.
        """
        # Check MobileMeAccounts preferences — present when iCloud account is configured
        rc, out, _ = self.shell(
            ["defaults", "read", "MobileMeAccounts", "Accounts"]
        )

        if rc != 0 or not out.strip() or out.strip() in ("()", "(\n)"):
            return self._info("No iCloud account configured on this Mac")

        # Check iCloud Drive directory presence as a proxy for active sync
        icloud_drive = os.path.expanduser("~/Library/Mobile Documents")
        if os.path.isdir(icloud_drive):
            try:
                count = len(os.listdir(icloud_drive))
                return self._pass(f"iCloud active — {count} apps syncing to Drive")
            except PermissionError:
                return self._info("iCloud configured (Drive access restricted)")

        return self._info("iCloud account configured")


# ── Login items (startup apps) ────────────────────────────────────────────────

class LoginItemsCheck(BaseCheck):
    """Count startup login items via System Events AppleScript and flag excessive counts."""

    id = "login_items"
    name = "Login Items"
    category = "apps"
    category_icon = "🚀"

    scan_description = (
        "Counting login items (apps that launch at startup) — "
        "each one adds to boot time and silently consumes RAM in the background."
    )
    finding_explanation = (
        "Login items are apps that launch automatically when you log in. "
        "Many apps add themselves without obvious disclosure — Dropbox, Google Drive, "
        "Zoom, browser helpers, and update daemons are common culprits. "
        "Too many login items slow startup and consume background RAM."
    )
    recommendation = (
        "Review System Settings → General → Login Items & Extensions. "
        "Disable any you don't need running at startup — most can be launched on demand. "
        "Also check the 'Allow in Background' section for hidden agents."
    )

    fix_level = "guided"
    fix_description = "Review and disable unnecessary login items in System Settings."
    fix_url = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Query startup login items via ``osascript`` / System Events and warn above threshold.

        Invokes AppleScript via ``osascript -e`` to retrieve the name of every
        login item registered with System Events — the same list shown in
        System Settings → General → Login Items & Extensions.  The query uses
        a 10-second timeout because System Events can be slow when the Automation
        permission has not been granted.

        Severity thresholds:
            - ``pass``    — 0–8 items (normal range).
            - ``info``    — 9–15 items (higher than average, worth knowing).
            - ``warning`` — 16+ items; startup is likely slow and background
              RAM consumption is high.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — could not enumerate items (Automation permission not
              granted or System Events unavailable).
            - ``"pass"`` — no login items configured.
            - ``"pass"`` — 1–8 items.
            - ``"info"`` — 9–15 items.
            - ``"warning"`` — 16+ items; names shown (first 5 + count).
        """
        # Query actual Login Items via System Events — the same list shown in
        # System Settings → General → Login Items. This is far more accurate
        # than launchctl list, which over-counts by including all launchd session
        # services (XPC helpers, framework daemons, etc.).
        rc, out, _ = self.shell(
            [
                "osascript", "-e",
                'tell application "System Events" to get the name of every login item',
            ],
            timeout=10,
        )

        if rc != 0:
            return self._info(
                "Could not enumerate login items — grant Automation access in "
                "System Settings → Privacy & Security → Automation if this persists"
            )

        # osascript returns comma-separated names, or empty string if none
        names_raw = out.strip()
        if not names_raw:
            return self._pass("No login items configured")

        names = [n.strip() for n in names_raw.split(",") if n.strip()]
        count = len(names)
        preview = ", ".join(names[:5]) + ("…" if count > 5 else "")

        if count > 15:
            return self._warning(
                f"{count} login items at startup — review and disable unneeded ones",
                data={"count": count, "items": names},
            )
        if count > 8:
            return self._info(
                f"{count} login items: {preview}",
                data={"count": count, "items": names},
            )
        return self._pass(
            f"{count} login item{'s' if count != 1 else ''}",
            data={"count": count},
        )


# ── Export ────────────────────────────────────────────────────────────────────

ALL_CHECKS = [
    AppStoreUpdatesCheck,
    iCloudStatusCheck,
    LoginItemsCheck,
]
