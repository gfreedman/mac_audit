"""Security hardening checks for macOS.

This module implements fifteen security checks covering the most impactful
configuration surfaces on a macOS system. Checks are grouped thematically:

**Authentication & access control**
    - ``AutoLoginCheck`` — Detects if the login screen is bypassed entirely.
    - ``GuestAccountCheck`` — Detects if the Guest account is enabled.
    - ``SSHAuthorizedKeysCheck`` — Audits passwordless SSH access grants.
    - ``SSHKeyStrengthCheck`` — Flags broken (DSA) and weak SSH key types.
    - ``SSHConfigCheck`` — Detects risky sshd settings (password auth, root login).

**Persistence mechanisms**
    - ``LaunchAgentsCheck`` — Scans launch agent/daemon directories for
      non-Apple and structurally suspicious entries.
    - ``LoginHooksCheck`` — Detects legacy login/logout hooks that run
      arbitrary scripts as root.
    - ``CronJobsCheck`` — Detects user cron jobs, a classic malware persistence
      mechanism.

**Network & traffic**
    - ``EtcHostsCheck`` — Scans ``/etc/hosts`` for rogue DNS-redirect entries.
    - ``SharingServicesCheck`` — Enumerates active network-listening services
      (SSH, Screen Sharing, SMB).

**Device security**
    - ``ActivationLockCheck`` — Verifies Find My / Activation Lock is configured.

**System integrity**
    - ``MDMProfilesCheck`` — Detects configuration profiles that could alter
      DNS, inject certificates, or modify security policies.
    - ``SystemRootCACheck`` — Audits the System keychain for unexpected root
      certificates and known traffic-inspection tool certificates.
    - ``SystemExtensionsCheck`` — Lists active kernel-adjacent system extensions.
    - ``XProtectCheck`` — Verifies XProtect malware signatures are recent.

Design decisions:
    - All checks use ``self.shell(...)`` (the base class shell wrapper) rather
      than direct ``subprocess`` calls. This keeps shell invocations testable
      and consistently handles timeout, capture, and error propagation.
    - The ``defaults read`` approach for login settings (AutoLogin, GuestEnabled,
      LoginHook) is preferred over reading plist files directly because
      ``defaults`` resolves the active value accounting for managed preferences
      and caching layers.
    - Launch agent scanning uses filename prefix heuristics (``com.apple.*``)
      rather than signature verification because the goal is user awareness,
      not forensic attribution.
    - ``SharingServicesCheck`` uses ``launchctl list`` rather than ``lsof`` or
      ``netstat`` because it gives a definitive "is this service registered?"
      answer without requiring elevated privileges.

Attributes:
    HOME (Path): Resolved home directory of the running process.
    _STANDARD_HOSTS (frozenset[str] | set[str]): Set of hostnames that are
        normal in any ``/etc/hosts`` file and should not be flagged.
    _LOOPBACK_PREFIXES (tuple[str, ...]): IP address prefixes that indicate
        a loopback or reserved address. Entries with these IPs are always
        skipped during ``/etc/hosts`` analysis.
    _LAUNCH_AGENT_DIRS (list[Path]): Ordered list of directories scanned for
        ``.plist`` persistence entries. Ordered user-level first, then system-
        level.
    _SSH_DIR (Path): Path to the current user's ``.ssh`` directory.
    _AUTHORIZED_KEYS (Path): Full path to the current user's
        ``~/.ssh/authorized_keys`` file.
    ALL_CHECKS (list[type[BaseCheck]]): Ordered list of check classes exported
        to the main runner.
"""

import plistlib
import re
from pathlib import Path

from macaudit.checks.base import BaseCheck, CheckResult

HOME = Path.home()

# Hostnames that are always legitimate in /etc/hosts and should never be flagged.
# These represent the default macOS /etc/hosts entries and common loop-back aliases.
_STANDARD_HOSTS = {
    "localhost", "broadcasthost", "ip6-localhost",
    "ip6-loopback", "local",
}

# IP address prefixes that identify loopback, unspecified, or reserved addresses.
# /etc/hosts entries pointing to these IPs are benign (e.g. 127.0.0.1 localhost)
# and are skipped during non-standard entry detection.
_LOOPBACK_PREFIXES = ("127.", "::1", "0.0.0.0", "255.")

# Launch agent and daemon directories, ordered from least- to most-privileged.
# ~/Library/LaunchDaemons is included because it should be empty for all normal
# users; its non-empty state is a structural red flag flagged at critical severity.
_LAUNCH_AGENT_DIRS = [
    HOME / "Library" / "LaunchAgents",
    HOME / "Library" / "LaunchDaemons",   # should be empty for normal users
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
]

# SSH directory and authorized keys paths for the current user.
_SSH_DIR = HOME / ".ssh"
_AUTHORIZED_KEYS = _SSH_DIR / "authorized_keys"


# ── Checks ────────────────────────────────────────────────────────────────────

class AutoLoginCheck(BaseCheck):
    """Detect if macOS auto-login is enabled, bypassing the login screen entirely.

    Auto-login causes macOS to log into a specific user account automatically
    on boot, without presenting a password prompt. This is a catastrophic
    physical security failure: anyone who powers on or restarts a Mac with
    auto-login enabled gets immediate, unencumbered access to the entire user
    account — files, browser sessions, saved passwords, and connected cloud
    services.

    Detection mechanism:
        Reads the ``autoLoginUser`` key from
        ``/Library/Preferences/com.apple.loginwindow`` using the ``defaults``
        command. A non-zero exit code from ``defaults read`` means the key does
        not exist, which is the normal (safe) state.

    Severity scale:
        - ``pass``: ``autoLoginUser`` key is absent (auto-login disabled).
        - ``critical``: Key is present and has a non-empty value (a specific
          username is configured for auto-login).

    Attributes:
        id (str): ``"auto_login"``
        name (str): ``"Auto-Login"``
        category (str): ``"security"``
        fix_level (str): ``"guided"`` — opens System Settings → Login Items &
            Extensions → Login Options via a deep-link URL.
        fix_url (str): Deep-link URL to the Login Items settings pane.
        fix_reversible (bool): ``True`` — auto-login can be re-enabled after
            being disabled.
        fix_time_estimate (str): About 30 seconds.
    """

    id = "auto_login"
    name = "Auto-Login"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking if auto-login is enabled — with auto-login on, anyone who "
        "picks up your Mac gets instant access without a password."
    )
    finding_explanation = (
        "Auto-login bypasses the login screen entirely. If your Mac is lost "
        "or stolen, the finder gets instant access to everything on it — "
        "files, browser sessions, passwords stored in apps."
    )
    recommendation = (
        "Disable auto-login in System Settings → General → Login Items & Extensions "
        "→ Login Options (or System Preferences → Security → disable auto-login)."
    )
    fix_level = "guided"
    fix_description = "Opens Login Items settings"
    fix_url = "x-apple.systempreferences:com.apple.LoginItems-Settings.Extension"
    fix_reversible = True
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Read ``autoLoginUser`` from com.apple.loginwindow; absent key means disabled.

        Uses ``defaults read`` rather than plist parsing because ``defaults``
        resolves managed preference overrides and handles the caching layer
        that can make direct plist reads unreliable.

        Returns:
            CheckResult: One of:

            - ``pass`` — Key absent (auto-login is disabled, which is the
              normal state on all modern macOS installations).
            - ``critical`` — Key present with a non-empty username value.
              ``result.data["auto_login_user"]`` contains the username.
            - ``pass`` — Key present but empty (treated as disabled).

        Example::

            check = AutoLoginCheck()
            result = check.run()
            # pass: "Auto-login is disabled"
            # critical: "Auto-login is enabled for user 'alice'"
        """
        rc, stdout, _ = self.shell(
            [
                "defaults",
                "read",
                "/Library/Preferences/com.apple.loginwindow",
                "autoLoginUser",
            ]
        )

        if rc != 0:
            # Non-zero exit from defaults read means the key is missing,
            # which is the desired (secure) state.
            return self._pass("Auto-login is disabled")

        username = stdout.strip()
        if username:
            return self._critical(
                f"Auto-login is enabled for user '{username}'",
                data={"auto_login_user": username},
            )

        return self._pass("Auto-login is disabled")


class SSHAuthorizedKeysCheck(BaseCheck):
    """Check for SSH authorized keys that grant passwordless remote access.

    Every line in ``~/.ssh/authorized_keys`` grants its corresponding private
    key holder the ability to log into this Mac over SSH without a password —
    permanently and silently. Old keys from previous employers, former
    contractors, decommissioned servers, and developers you no longer work
    with remain valid indefinitely unless explicitly removed.

    Detection mechanism:
        1. Queries ``systemsetup -getremotelogin`` to determine if the SSH
           server is currently running (contextual, not a blocker).
        2. Reads ``~/.ssh/authorized_keys`` and counts non-comment, non-empty
           lines. Each such line is one authorized key.

    Severity scale:
        - ``pass``: File absent, empty, or SSH server is off and file is absent.
        - ``info``: 1–5 keys found (common for developers; worth verifying).
        - ``warning``: > 5 keys (high count increases likelihood of stale/untrusted
          entries).

    Attributes:
        id (str): ``"ssh_authorized_keys"``
        name (str): ``"SSH Authorized Keys"``
        fix_level (str): ``"instructions"`` — requires manual review of each key
            entry; no automated command can safely decide which keys to remove.
        fix_steps (list[str]): Terminal commands to inspect keys and guidance on
            identifying each key's origin from its comment field.
        fix_reversible (bool): ``True`` — removed keys can be re-added from the
            corresponding public key file.
        fix_time_estimate (str): About 5 minutes for a small number of keys.
    """

    id = "ssh_authorized_keys"
    name = "SSH Authorized Keys"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking ~/.ssh/authorized_keys — old or forgotten SSH keys in this "
        "file give their holders permanent passwordless access to your Mac."
    )
    finding_explanation = (
        "Every key in authorized_keys grants its holder SSH access without a "
        "password. Old keys from previous employers, old computers, or "
        "developers you no longer work with are permanent backdoors."
    )
    recommendation = (
        "Review ~/.ssh/authorized_keys and remove any keys you don't recognize "
        "or that belong to people/machines no longer trusted."
    )
    fix_level = "instructions"
    fix_description = "Review and remove untrusted public keys"
    fix_steps = [
        "Open Terminal and run: cat ~/.ssh/authorized_keys",
        "For each key, check the comment at the end (usually user@host)",
        "Remove lines for machines or people you no longer trust",
        "Save the file",
    ]
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Check SSH server state, then read and count authorized key entries.

        Queries ``systemsetup -getremotelogin`` first for context: if SSH is
        off, an absent authorized_keys file is less urgent than if SSH is on.
        Non-comment key lines are counted to determine severity.

        Returns:
            CheckResult: One of:

            - ``pass`` — File absent (with or without SSH enabled).
            - ``pass`` — File is empty (no active key entries).
            - ``info`` — 1–5 keys found.
            - ``warning`` — > 5 keys found.
            - ``error`` — File exists but could not be read.

            ``result.data["key_count"]`` is populated for all non-error,
            non-pass results.

        Example::

            check = SSHAuthorizedKeysCheck()
            result = check.run()
            # info: "3 authorized SSH keys found — verify all are still trusted"
        """
        # Check if Remote Login (SSH server) is even running — used for
        # context in the pass message, not as a gate on the check itself.
        rc_ssh, ssh_out, _ = self.shell(
            ["systemsetup", "-getremotelogin"], timeout=5
        )
        ssh_on = rc_ssh == 0 and "on" in ssh_out.lower()

        if not _AUTHORIZED_KEYS.exists():
            if ssh_on:
                return self._pass(
                    "SSH is on, but no authorized_keys file exists"
                )
            return self._pass("No authorized_keys file (SSH server is off)")

        try:
            content = _AUTHORIZED_KEYS.read_text(errors="replace")
        except OSError as e:
            return self._error(f"Could not read authorized_keys: {e}")

        # Count valid key lines — exclude comment lines and blank lines.
        keys = [
            ln.strip()
            for ln in content.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]

        if not keys:
            return self._pass("authorized_keys is empty")

        n = len(keys)
        msg = f"{n} authorized SSH key{'s' if n != 1 else ''} found"

        if n > 5:
            return self._warning(
                f"{msg} — review for old or untrusted entries",
                data={"key_count": n},
            )

        return self._info(
            f"{msg} — verify all are still trusted",
            data={"key_count": n},
        )


class SSHKeyStrengthCheck(BaseCheck):
    """Verify that local SSH keys use strong cryptographic algorithms.

    DSA keys are mathematically broken (NIST deprecated DSA in 2023; OpenSSH
    dropped DSA support entirely in 9.8p1). RSA keys require at least 2048 bits
    to be considered minimally safe; 4096-bit RSA or Ed25519/ECDSA are the
    modern recommended alternatives.

    Detection mechanism:
        1. Globs all ``*.pub`` files in ``~/.ssh/`` and reads each one.
        2. Identifies key type from the leading token: ``ssh-dss`` (DSA,
           broken), ``ssh-rsa`` (RSA, potentially weak), or modern types
           (``ssh-ed25519``, ``ecdsa-sha2-*``).
        3. Also scans ``~/.ssh/authorized_keys`` for DSA entries.

    Severity scale:
        - ``pass``: Only Ed25519/ECDSA keys found, or no public key files exist.
        - ``info``: Only RSA keys found (may be fine but worth upgrading).
        - ``warning``: At least one DSA key found (cryptographically broken).

    Attributes:
        id (str): ``"ssh_key_strength"``
        name (str): ``"SSH Key Strength"``
        fix_level (str): ``"instructions"`` — generating a new key and updating
            remote servers requires manual steps.
        fix_steps (list[str]): Commands to generate an Ed25519 key, push it to
            servers, and retire old keys.
        fix_reversible (bool): ``True`` — old keys are not deleted automatically;
            they can continue to be used until explicitly removed.
        fix_time_estimate (str): About 10 minutes including server updates.
    """

    id = "ssh_key_strength"
    name = "SSH Key Strength"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking SSH key types — DSA keys are broken, and old RSA keys may be "
        "too weak. Ed25519 or ECDSA are the modern standard."
    )
    finding_explanation = (
        "DSA keys are cryptographically broken and should never be used. "
        "RSA keys need to be at least 2048 bits (4096 recommended). "
        "Ed25519 is the modern default and far more secure."
    )
    recommendation = (
        "Generate a new Ed25519 key: ssh-keygen -t ed25519 -C 'your@email'. "
        "Then update authorized_keys on any remote servers."
    )
    fix_level = "instructions"
    fix_description = "Generate a new strong SSH key"
    fix_steps = [
        "Run: ssh-keygen -t ed25519 -C 'your@email.com'",
        "Copy new public key to servers: ssh-copy-id user@host",
        "Remove old weak keys from ~/.ssh/ once new ones are working",
    ]
    fix_reversible = True
    fix_time_estimate = "~10 minutes"

    def run(self) -> CheckResult:
        """Scan ``~/.ssh/*.pub`` and ``authorized_keys`` for DSA and RSA key types.

        Reads each ``*.pub`` file and ``authorized_keys`` line by line.
        Categorises keys by their leading token into: broken (DSA), weak-but-
        acceptable (RSA), or modern (Ed25519/ECDSA). Returns the most severe
        category found.

        Returns:
            CheckResult: One of:

            - ``skip`` — ``~/.ssh`` directory does not exist.
            - ``warning`` — At least one DSA key found. ``result.data["weak_keys"]``
              contains descriptive strings for each broken key.
            - ``info`` — RSA key(s) found, no DSA. ``result.data["rsa_keys"]``
              contains filenames.
            - ``pass`` — Modern (Ed25519/ECDSA) keys present and no weak keys.
            - ``info`` — Other key types present but no clearly weak ones.
            - ``pass`` — No ``*.pub`` files found in ``~/.ssh``.

        Example::

            check = SSHKeyStrengthCheck()
            result = check.run()
            # warning: "Weak SSH keys found: id_dsa.pub (DSA — broken)"
            # info:    "RSA key(s) found: id_rsa.pub — consider upgrading to Ed25519"
        """
        if not _SSH_DIR.exists():
            return self._skip("No ~/.ssh directory found")

        weak_keys: list[str] = []
        rsa_keys: list[str] = []

        # Scan all public key files in the .ssh directory.
        for pub in _SSH_DIR.glob("*.pub"):
            try:
                text = pub.read_text(errors="replace").strip()
                if text.startswith("ssh-dss"):
                    # DSA is cryptographically broken; flag immediately.
                    weak_keys.append(f"{pub.name} (DSA — broken)")
                elif text.startswith("ssh-rsa"):
                    # RSA may be safe (>=2048 bit) but flag for awareness;
                    # Ed25519 is preferred for new keys.
                    rsa_keys.append(pub.name)
            except OSError:
                continue

        # Also scan authorized_keys for weak key types — a DSA key in
        # authorized_keys represents an active security weakness regardless
        # of whether the corresponding private key still exists locally.
        if _AUTHORIZED_KEYS.exists():
            try:
                for ln in _AUTHORIZED_KEYS.read_text(errors="replace").splitlines():
                    ln = ln.strip()
                    if ln.startswith("ssh-dss"):
                        weak_keys.append("authorized_keys entry (DSA — broken)")
            except OSError:
                pass

        if weak_keys:
            return self._warning(
                f"Weak SSH keys found: {', '.join(weak_keys[:3])}",
                data={"weak_keys": weak_keys},
            )

        if rsa_keys:
            # RSA might be fine (≥2048) but flag for awareness and future planning.
            return self._info(
                f"RSA key(s) found: {', '.join(rsa_keys)} — consider upgrading to Ed25519",
                data={"rsa_keys": rsa_keys},
            )

        # Check specifically for modern key files as a pass condition.
        modern = list(_SSH_DIR.glob("id_ed25519.pub")) + list(_SSH_DIR.glob("id_ecdsa*.pub"))
        if modern:
            return self._pass(
                f"Strong key(s) found: {', '.join(p.name for p in modern[:3])}"
            )

        if list(_SSH_DIR.glob("*.pub")):
            return self._info("SSH keys present — types appear acceptable")

        return self._pass("No local SSH keys found")


class LaunchAgentsCheck(BaseCheck):
    """Scan launch agent and daemon directories for non-Apple and suspicious entries.

    LaunchAgents and LaunchDaemons are the primary persistence mechanism on
    macOS. They are used by every background service from cloud sync clients
    to printer drivers — and equally by adware, spyware, and malware. This
    check applies two heuristics:

    1. **Structural suspicion**: Any ``.plist`` file found in
       ``~/Library/LaunchDaemons/`` is flagged at ``critical`` severity.
       This directory should be empty for all normal users; its non-empty
       state indicates either a misconfigured installer or malicious activity.

    2. **Ownership awareness**: ``*.plist`` files that do not begin with
       ``com.apple.`` are counted and listed, because macOS ships with only
       Apple-prefixed agents. Any third-party agent is worth knowing about,
       even if most are legitimate.

    Detection mechanism:
        Globs ``*.plist`` in each directory listed in ``_LAUNCH_AGENT_DIRS``.
        Applies filename prefix checks (``com.apple.`` / ``com.Apple.``) to
        classify entries. Does not read plist content or validate signatures.

    Severity scale:
        - ``pass``: No third-party or suspicious agents found.
        - ``info``: 1–10 third-party agents (common on developer machines).
        - ``warning``: > 10 third-party agents (elevated count warrants review).
        - ``critical``: Any entry found in ``~/Library/LaunchDaemons/``.

    Attributes:
        id (str): ``"launch_agents"``
        name (str): ``"Launch Agents & Daemons"``
        fix_level (str): ``"instructions"`` — disabling a launch agent requires
            ``launchctl unload`` followed by manual file deletion.
        fix_steps (list[str]): Terminal commands for listing, disabling, and
            removing launch agent plists.
        fix_reversible (bool): ``True`` — removed agents can be reinstalled
            by the originating application.
        fix_time_estimate (str): 10–30 minutes for thorough review.
    """

    id = "launch_agents"
    name = "Launch Agents & Daemons"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Scanning launch agent directories — malware and adware use launch "
        "agents to persist across reboots without your knowledge."
    )
    finding_explanation = (
        "Launch agents are programs that run automatically when you log in. "
        "Legitimate software uses them, but so does adware and malware — "
        "it's a primary persistence mechanism. ~/Library/LaunchDaemons/ "
        "should be empty for normal users; its presence is a red flag."
    )
    recommendation = (
        "Review any non-Apple launch agents. If you don't recognize who made "
        "it or why it's running, research it before removing."
    )
    fix_level = "instructions"
    fix_description = "Review and remove suspicious launch agents"
    fix_steps = [
        "Open Terminal and run: ls ~/Library/LaunchAgents/",
        "Research any plists you don't recognize",
        "To disable: launchctl unload ~/Library/LaunchAgents/<name>.plist",
        "To remove: rm ~/Library/LaunchAgents/<name>.plist",
    ]
    fix_reversible = True
    fix_time_estimate = "10–30 minutes"

    def run(self) -> CheckResult:
        """Glob ``*.plist`` in user and system launch directories; apply heuristic classification.

        Iterates each directory in ``_LAUNCH_AGENT_DIRS``. For each ``.plist``
        file found:

        - If the containing directory is ``~/Library/LaunchDaemons/``, it is
          added to the ``suspicious`` list (structural anomaly).
        - Otherwise, files whose names do not start with ``com.apple.`` or
          ``com.Apple.`` are added to ``non_apple`` for awareness.

        Returns:
            CheckResult: One of:

            - ``pass`` — No third-party or structurally suspicious entries.
            - ``info`` — 1–10 third-party entries.
            - ``warning`` — > 10 third-party entries.
            - ``critical`` — Any entry in ``~/Library/LaunchDaemons/``.

            All non-pass results include ``result.data["non_apple"]`` and/or
            ``result.data["suspicious"]``.

        Example::

            check = LaunchAgentsCheck()
            result = check.run()
            # info: "4 third-party launch agent(s) — verify all are intentional"
        """
        non_apple: list[str] = []
        suspicious: list[str] = []  # entries in structurally abnormal locations

        for directory in _LAUNCH_AGENT_DIRS:
            if not directory.exists():
                continue

            # ~/Library/LaunchDaemons/ should never contain plists for a normal
            # user; its presence indicates a potential compromise or malicious installer.
            in_user_daemons = "LaunchDaemons" in str(directory) and str(directory).startswith(str(HOME))

            for plist in directory.glob("*.plist"):
                name = plist.name

                if in_user_daemons:
                    suspicious.append(f"{name} (in ~/Library/LaunchDaemons/ — abnormal)")
                    continue

                # Any plist not prefixed with com.apple. is a third-party agent.
                # Both capitalisation variants are checked for robustness.
                if not name.startswith("com.apple.") and not name.startswith("com.Apple."):
                    non_apple.append(f"{name} ({directory.name})")

        if suspicious:
            return self._critical(
                f"Suspicious entries in ~/Library/LaunchDaemons/: "
                f"{', '.join(suspicious[:3])}",
                data={"suspicious": suspicious, "non_apple": non_apple},
            )

        if len(non_apple) > 10:
            return self._warning(
                f"{len(non_apple)} third-party launch agents — review for unwanted entries",
                data={"non_apple": non_apple},
            )

        if non_apple:
            return self._info(
                f"{len(non_apple)} third-party launch agent(s) — verify all are intentional",
                data={"non_apple": non_apple},
            )

        return self._pass("No unexpected launch agents or daemons found")


class EtcHostsCheck(BaseCheck):
    """Check ``/etc/hosts`` for non-standard entries that could redirect traffic.

    The ``/etc/hosts`` file maps hostnames to IP addresses and is consulted
    before DNS. An entry that redirects ``apple.com``, ``paypal.com``, or a
    bank's hostname to a malicious IP address means the user's browser silently
    connects to the attacker's server instead — the URL bar still shows the
    legitimate domain name, making phishing essentially undetectable.

    Some legitimate tools also modify ``/etc/hosts`` (e.g. ad-blockers point
    ad domains to 0.0.0.0). This check flags *non-loopback* entries so the
    user can distinguish intentional ad-blocker entries from malicious ones.

    Detection mechanism:
        Reads and parses ``/etc/hosts``. Skips comment lines, blank lines, and
        lines where the IP starts with a loopback or reserved prefix (from
        ``_LOOPBACK_PREFIXES``). Flags remaining entries pointing non-loopback
        IPs to non-standard hostnames.

    Severity scale:
        - ``pass``: No non-standard entries (all entries use loopback IPs or
          standard hostnames).
        - ``warning``: At least one non-loopback IP entry is found.

    Attributes:
        id (str): ``"etc_hosts"``
        name (str): ``"/etc/hosts Entries"``
        fix_level (str): ``"instructions"`` — requires reading the file,
          understanding each entry, and using ``sudo nano`` to edit.
        fix_steps (list[str]): Commands to view and edit ``/etc/hosts`` safely.
        fix_reversible (bool): ``True`` — removed entries can be re-added.
        fix_time_estimate (str): About 5 minutes.
    """

    id = "etc_hosts"
    name = "/etc/hosts Entries"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking /etc/hosts for unusual entries — malware sometimes adds "
        "entries here to redirect legitimate sites to malicious servers."
    )
    finding_explanation = (
        "/etc/hosts maps hostnames to IP addresses before DNS is consulted. "
        "An entry redirecting 'apple.com' to a malicious IP means visiting "
        "apple.com in a browser goes to the attacker's server instead."
    )
    recommendation = (
        "Review /etc/hosts and remove any entries you didn't add yourself. "
        "Run: sudo nano /etc/hosts"
    )
    fix_level = "instructions"
    fix_description = "Review /etc/hosts for rogue entries"
    fix_steps = [
        "Run: cat /etc/hosts",
        "Standard entries only: 127.0.0.1 localhost, ::1 localhost",
        "Remove any entries for well-known domains (google.com, apple.com, etc.)",
        "Edit with: sudo nano /etc/hosts",
    ]
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Parse ``/etc/hosts`` and flag entries with non-loopback IPs.

        Iterates every non-comment, non-blank line. Splits each line into an
        IP address and one or more hostnames. Skips any line whose IP begins
        with a prefix in ``_LOOPBACK_PREFIXES``. Remaining entries are
        collected as ``"<ip> → <hostname>"`` strings for display.

        Returns:
            CheckResult: One of:

            - ``pass`` — No unusual entries detected.
            - ``warning`` — One or more non-loopback entries found.
              ``result.data["unusual_entries"]`` contains the full list.
            - ``info`` — ``/etc/hosts`` not found.
            - ``error`` — File exists but could not be read.

        Example::

            check = EtcHostsCheck()
            result = check.run()
            # warning: "2 non-standard /etc/hosts entries: 1.2.3.4 → paypal.com, ..."
        """
        hosts_path = Path("/etc/hosts")
        if not hosts_path.exists():
            return self._info("/etc/hosts not found")

        try:
            content = hosts_path.read_text(errors="replace")
        except OSError as e:
            return self._error(f"Could not read /etc/hosts: {e}")

        unusual: list[str] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            ip, *hostnames = parts

            # Skip loopback, unspecified (0.0.0.0), and broadcast (255.) addresses —
            # these are all benign regardless of what hostname they point to.
            if any(ip.startswith(p) for p in _LOOPBACK_PREFIXES):
                continue

            # Any non-loopback entry that points to a non-standard hostname
            # is worth flagging. This catches ad-blocker entries pointing to
            # non-loopback IPs and genuine DNS-redirect attacks alike.
            for host in hostnames:
                if host not in _STANDARD_HOSTS:
                    unusual.append(f"{ip} → {host}")

        if not unusual:
            return self._pass("No unusual entries in /etc/hosts")

        n = len(unusual)
        examples = unusual[:3]
        return self._warning(
            f"{n} non-standard /etc/hosts entr{'ies' if n != 1 else 'y'}: "
            f"{', '.join(examples)}{'…' if n > 3 else ''}",
            data={"unusual_entries": unusual},
        )


class SharingServicesCheck(BaseCheck):
    """Detect active sharing services that expose network-listening ports.

    Each enabled sharing service opens a listening TCP/UDP port that is
    immediately visible to other devices on the same network. On public Wi-Fi
    (cafés, airports, hotels), these ports are accessible to all other network
    users. Disabling unused services eliminates the corresponding attack surface.

    Services checked:
        - **Remote Login (SSH)** — Port 22. Checked via
          ``systemsetup -getremotelogin``.
        - **Screen Sharing / VNC** — Port 5900. Checked via
          ``launchctl list com.apple.screensharing``.
        - **File Sharing (SMB)** — Port 445. Checked via
          ``launchctl list com.apple.smbd``.

    Detection mechanism:
        Uses ``systemsetup -getremotelogin`` for SSH state and
        ``launchctl list <service>`` for Screen Sharing and SMB. A service is
        considered active if ``launchctl list`` exits 0, returns non-empty
        output, and does not contain "Could not find".

    Severity scale:
        Always ``pass`` (no services) or ``info`` (some services active). This
        is ``info`` rather than ``warning`` because sharing services are
        *potentially* legitimate depending on the user's use case — e.g. a
        home server needs File Sharing enabled. The user is informed so they
        can make a conscious decision.

    Attributes:
        id (str): ``"sharing_services"``
        name (str): ``"Sharing Services"``
        fix_level (str): ``"guided"`` — opens System Settings → General → Sharing.
        fix_url (str): Deep-link URL to the Sharing settings pane.
        fix_reversible (bool): ``True`` — services can be re-enabled.
        fix_time_estimate (str): About 30 seconds.
    """

    id = "sharing_services"
    name = "Sharing Services"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking active sharing services — each enabled service (Screen Sharing, "
        "Remote Login, File Sharing) is an open port that attackers can probe."
    )
    finding_explanation = (
        "Services like Screen Sharing, Remote Login (SSH), and File Sharing "
        "open network ports on your Mac. On public Wi-Fi, these are immediately "
        "visible to other users on the network. Only enable what you actively use."
    )
    recommendation = (
        "Disable unused services in System Settings → General → Sharing."
    )
    fix_level = "guided"
    fix_description = "Opens Sharing settings"
    fix_url = "x-apple.systempreferences:com.apple.preferences.sharing"
    fix_reversible = True
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Query systemsetup and launchctl to detect active listening services.

        Checks Remote Login (SSH), Screen Sharing (VNC), and File Sharing (SMB)
        independently using the most appropriate detection method for each.

        Returns:
            CheckResult: One of:

            - ``pass`` — None of the three services are active.
            - ``info`` — One or more services are active. The message names each
              active service. ``result.data["active_services"]`` is a list of
              human-readable service names.

        Example::

            check = SharingServicesCheck()
            result = check.run()
            # info: "2 sharing services active: Remote Login (SSH), File Sharing (SMB)"
        """
        active: list[str] = []

        # Remote Login uses systemsetup rather than launchctl because
        # systemsetup -getremotelogin gives a definitive on/off state.
        rc, stdout, _ = self.shell(["systemsetup", "-getremotelogin"], timeout=5)
        if rc == 0 and "on" in stdout.lower():
            active.append("Remote Login (SSH)")

        # Screen Sharing / VNC — check whether the launchd service is registered.
        rc2, stdout2, _ = self.shell(
            ["launchctl", "list", "com.apple.screensharing"]
        )
        if rc2 == 0 and stdout2.strip() and "Could not find" not in stdout2:
            active.append("Screen Sharing")

        # File Sharing (AFP/SMB) — same launchctl list approach.
        rc3, stdout3, _ = self.shell(
            ["launchctl", "list", "com.apple.smbd"]
        )
        if rc3 == 0 and stdout3.strip() and "Could not find" not in stdout3:
            active.append("File Sharing (SMB)")

        if not active:
            return self._pass("No sharing services are active")

        n = len(active)
        return self._info(
            f"{n} sharing service{'s' if n != 1 else ''} active: {', '.join(active)}",
            data={"active_services": active},
        )


class ActivationLockCheck(BaseCheck):
    """Check whether Find My / Activation Lock is configured via NVRAM.

    Activation Lock ties a Mac to the owner's Apple ID via Find My. On a
    secondhand Mac, if the previous owner did not sign out of iCloud before
    selling the device, their Activation Lock may still be active — meaning
    they can remotely lock or erase the machine, and the new owner cannot
    remove the lock without the original Apple ID credentials.

    Detection mechanism:
        Reads the ``fmm-mobileme-token-FMM`` NVRAM variable using
        ``nvram fmm-mobileme-token-FMM``. A long (> 40 character) token
        value indicates Find My is configured. Note: this is a proxy
        indicator; on MDM-enrolled devices the NVRAM token may not
        accurately reflect the actual Activation Lock state.

    Severity scale:
        - ``pass``: Long token present — Find My is likely configured,
          Activation Lock is likely active (good).
        - ``info``: Token absent, short, or unreadable.

    Note:
        The NVRAM token check cannot definitively confirm Activation Lock
        status for MDM-enrolled devices. IT-managed Macs should have their
        Activation Lock status verified through the MDM console.

    Attributes:
        id (str): ``"activation_lock"``
        name (str): ``"Activation Lock"``
        fix_level (str): ``"instructions"`` — resolving a previous owner's lock
            requires their Apple ID credentials or Apple Support.
        fix_steps (list[str]): Steps for the previous owner to remove the lock
            via appleid.apple.com.
        fix_reversible (bool): ``False`` — removing Activation Lock from an
            account requires the account owner's credentials.
        fix_time_estimate (str): Varies depending on whether the previous owner
            is reachable.
    """

    id = "activation_lock"
    name = "Activation Lock"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking if Find My / Activation Lock is configured — on a secondhand Mac, "
        "a previous owner's lock still active means they can remotely wipe or lock it."
    )
    finding_explanation = (
        "Activation Lock ties a Mac to an Apple ID via Find My. If a previous owner's "
        "lock is still active and you don't have their credentials, you could lose access "
        "to the machine remotely. Note: on MDM-enrolled devices this NVRAM token may not "
        "accurately reflect Activation Lock status — check with your IT administrator."
    )
    recommendation = (
        "If this is a secondhand Mac, confirm the previous owner signed out of "
        "iCloud (System Settings → Apple ID → Sign Out) before handing it over."
    )
    fix_level = "instructions"
    fix_description = "Contact previous owner to remove their Activation Lock"
    fix_steps = [
        "Ask the previous owner to visit appleid.apple.com",
        "Sign in and go to Devices",
        "Select this Mac and choose 'Remove from Account'",
        "Or: erase and restore the Mac with original owner present",
    ]
    fix_reversible = False
    fix_time_estimate = "Varies"

    def run(self) -> CheckResult:
        """Read the Find My NVRAM token; a long value indicates Activation Lock is likely active.

        Invokes ``nvram fmm-mobileme-token-FMM`` and checks the length of the
        returned token. A token longer than 40 characters is treated as a
        valid Find My token indicating that Activation Lock is configured.
        Shorter tokens or absent values indicate Find My may not be set up.

        Returns:
            CheckResult: One of:

            - ``pass`` — Token length > 40 characters (Find My likely configured).
              ``result.data["find_my_configured"]`` is ``True``.
            - ``info`` — Token present but short; recommend verifying in
              System Settings → Apple ID.
            - ``info`` — No token found in NVRAM (Find My not configured or
              token not readable).

        Note:
            The 40-character threshold is empirically derived: a real
            Find My token is an OAuth-style credential that is always
            substantially longer than 40 characters.

        Example::

            check = ActivationLockCheck()
            result = check.run()
            # pass: "Find My is configured — Activation Lock is likely active"
        """
        # nvram fmm-mobileme-token-FMM — non-empty = Find My is configured.
        rc, stdout, _ = self.shell(
            ["nvram", "fmm-mobileme-token-FMM"], timeout=5
        )

        if rc != 0 or not stdout.strip():
            return self._info(
                "Activation Lock: Find My token not found in NVRAM — "
                "may not be configured or may not be readable"
            )

        token = stdout.strip()
        # A real Find My token is a long credential string; short values
        # may indicate the key exists but is not a valid token.
        if len(token) > 40:
            return self._pass(
                "Find My is configured — Activation Lock is likely active",
                data={"find_my_configured": True},
            )

        return self._info(
            "Find My token present but minimal — verify in System Settings → Apple ID",
            data={"token_length": len(token)},
        )


class MDMProfilesCheck(BaseCheck):
    """Detect installed MDM and configuration profiles that may alter security settings.

    Configuration profiles can make sweeping, silent changes to a macOS system:
    redirecting all DNS queries (enabling traffic interception), installing root
    certificates (enabling HTTPS decryption), modifying Gatekeeper policy,
    disabling system security features, and granting MDM full management control.
    A corporate device may legitimately have these, but any profile installed
    without the user's knowledge or consent is a serious security concern.

    Detection mechanism:
        Runs ``profiles list`` (the macOS profile management CLI). Parses output
        for lines containing ``_computerlevel`` or ``profileIdentifier`` to count
        installed profiles. A non-zero exit with a permissions-related error
        indicates the command needs administrator privileges.

    Severity scale:
        - ``pass``: No profiles installed.
        - ``warning``: One or more profiles found; always warrants review.
        - ``info``: Could not check (permission error or command failure).

    Attributes:
        id (str): ``"mdm_profiles"``
        name (str): ``"MDM / Configuration Profiles"``
        fix_level (str): ``"guided"`` — opens System Settings → Privacy &
            Security → Profiles via a deep-link URL.
        fix_url (str): Deep-link URL to the Security pane in System Settings.
        fix_reversible (bool): ``True`` — profiles can be removed from System
            Settings (requires administrator password).
        fix_time_estimate (str): About 5 minutes.
    """

    id = "mdm_profiles"
    name = "MDM / Configuration Profiles"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking for MDM and configuration profiles — a rogue profile can "
        "reroute DNS, inject certificates, and bypass security settings without "
        "your knowledge."
    )
    finding_explanation = (
        "Configuration profiles can change DNS servers (redirecting all traffic), "
        "install root certificates (decrypting all HTTPS), and alter security "
        "policies. Corporate devices legitimately have them, but a profile you "
        "didn't intentionally install is a serious red flag."
    )
    recommendation = (
        "Review profiles in System Settings → Privacy & Security → Profiles. "
        "Remove any you don't recognize or didn't intentionally install."
    )
    fix_level = "guided"
    fix_description = "Opens Privacy & Security → Profiles"
    fix_url = "x-apple.systempreferences:com.apple.preference.security"
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Run ``profiles list`` and count configuration profile entries.

        Runs ``profiles list`` (no ``-all`` flag — shows profiles for the
        current user context). Counts lines matching known profile output
        patterns to estimate the number of installed profiles.

        Returns:
            CheckResult: One of:

            - ``pass`` — "There are no" in output, or output is empty.
            - ``warning`` — At least one profile detected. ``result.data["profile_count"]``
              contains the estimated count; ``result.data["output_preview"]`` contains
              the first 200 characters of raw output.
            - ``info`` — Permission denied (needs admin) or command failed.

        Example::

            check = MDMProfilesCheck()
            result = check.run()
            # warning: "2 configuration profiles installed — verify they're intentional"
        """
        rc, stdout, stderr = self.shell(["profiles", "list"], timeout=8)

        if rc != 0:
            if "permission" in stderr.lower() or "not permitted" in stderr.lower():
                return self._info(
                    "Could not read profiles — run as admin to see all profiles"
                )
            if "There are no" in stdout or "There are no" in stderr:
                return self._pass("No configuration profiles installed")
            return self._info(f"Could not check profiles: {stderr[:80]}")

        if not stdout.strip() or "There are no" in stdout:
            return self._pass("No configuration profiles installed")

        # Count profile entries by looking for known output markers.
        # "_computerlevel" appears in computer-level profile entries;
        # "profileIdentifier" appears in the detailed profile output format.
        profile_lines = [
            ln for ln in stdout.splitlines()
            if "_computerlevel" in ln or "profileIdentifier" in ln.lower()
        ]
        n = max(len(profile_lines), 1)  # at least 1 if there's any output at all

        return self._warning(
            f"{n} configuration profile{'s' if n != 1 else ''} installed — verify they're intentional",
            data={"profile_count": n, "output_preview": stdout[:200]},
        )


class SystemRootCACheck(BaseCheck):
    """Audit the System keychain for unexpected or traffic-inspection root certificates.

    Root certificates installed in the System keychain are trusted to sign
    any TLS certificate. Enterprise traffic-inspection tools (Zscaler,
    Cisco Umbrella, Palo Alto, etc.) and malware both install root CAs here
    to perform Man-in-the-Middle attacks on HTTPS connections — the browser
    shows the padlock, but all traffic is being decrypted and re-encrypted
    by the interposing tool.

    On a personal Mac, any root CA beyond Apple's ~170 built-in certificates
    should be explainable. On a corporate Mac, enterprise CAs are expected.

    Detection mechanism:
        Runs ``security find-certificate -a /Library/Keychains/System.keychain``
        and parses ``"alis"<blob>="Name"`` lines to extract certificate common
        names. Checks each name against ``_MITM_INDICATORS``, a list of known
        traffic-inspection tool name fragments.

    Severity scale:
        - ``pass``: Certificate count is <= 200 and no known MITM tool names found.
        - ``info``: Certificate count is > 200 (slightly elevated, worth noting)
          or certificate names could not be parsed.
        - ``warning``: At least one certificate name matches a known
          traffic-inspection tool indicator.

    Attributes:
        id (str): ``"system_root_cas"``
        name (str): ``"System Root Certificates"``
        _MITM_INDICATORS (list[str]): Lowercase name fragments used to identify
            certificates from known traffic-inspection and MITM proxy tools.
            Matched case-insensitively against certificate common names.
        fix_level (str): ``"instructions"`` — certificate removal requires Keychain
            Access or the ``security`` CLI with administrator authorization.
        fix_steps (list[str]): Steps to identify and remove unexpected certificates
            via Keychain Access.
        fix_reversible (bool): ``True`` — removed certificates can be re-added if
            needed (e.g. enterprise CA can be reinstalled by IT).
        fix_time_estimate (str): About 10 minutes.
    """

    id = "system_root_cas"
    name = "System Root Certificates"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking the System keychain for unexpected root certificates — "
        "a rogue root CA lets an attacker silently decrypt all HTTPS traffic."
    )
    finding_explanation = (
        "Root certificates in the System keychain are trusted to verify any website's "
        "HTTPS certificate. Enterprise tools (Zscaler, Cisco Umbrella, Palo Alto) and "
        "some malware install root CAs here to inspect or forge encrypted traffic. "
        "On a personal Mac, any unexpected root CA is a serious concern."
    )
    recommendation = (
        "Review certificates in Keychain Access → System keychain → Certificates. "
        "Remove any you don't recognize or didn't intentionally install. "
        "Or run: security find-certificate -a /Library/Keychains/System.keychain"
    )
    fix_level = "instructions"
    fix_description = "Audit system root certificates via Keychain Access"
    fix_steps = [
        "Open Keychain Access (search Spotlight)",
        "Select 'System' in the left sidebar, then click 'Certificates'",
        "Look for certificates with unknown issuers or blue trust overrides",
        "Delete certificates you don't recognize (requires admin password)",
    ]
    fix_reversible = True
    fix_time_estimate = "~10 minutes"

    # Lowercase name fragments identifying known MITM and traffic-inspection tools.
    # Matched case-insensitively against certificate common names extracted from
    # the System keychain.
    _MITM_INDICATORS = [
        "zscaler", "cisco umbrella", "palo alto", "forcepoint",
        "charles proxy", "burp suite", "fiddler", "mitmproxy",
        "netskope", "iboss", "lightspeed", "smoothwall", "squid",
    ]

    def run(self) -> CheckResult:
        """Run ``security find-certificate`` on System.keychain and check for MITM tool certs.

        Parses ``"alis"<blob>="<name>"`` lines from the ``security`` command
        output to extract certificate common names. Checks each name for any
        of the fragments in ``_MITM_INDICATORS``. Also flags cert counts notably
        above the ~170 Apple defaults as potentially worth reviewing.

        Returns:
            CheckResult: One of:

            - ``pass`` — Count <= 200 and no MITM indicators found.
            - ``info`` — Count > 200 (above typical Apple defaults) or names
              could not be parsed.
            - ``info`` — Command failed (may require Full Disk Access).
            - ``warning`` — At least one certificate name matches a known
              traffic-inspection tool. ``result.data["mitm_certs"]`` lists
              matching names.

        Example::

            check = SystemRootCACheck()
            result = check.run()
            # warning: "Traffic inspection certificate detected: Zscaler Root CA"
        """
        rc, out, _ = self.shell(
            ["security", "find-certificate", "-a", "/Library/Keychains/System.keychain"]
        )

        if rc != 0 or not out.strip():
            return self._info(
                "Could not read System keychain certificates "
                "(may require Full Disk Access)"
            )

        # Extract certificate common names from "alis" attribute lines.
        # Format: "alis"<blob>="Certificate Name"
        names: list[str] = []
        for line in out.splitlines():
            line = line.strip()
            if '"alis"<blob>=' in line:
                try:
                    name = line.split('="', 1)[1].rstrip('"')
                    names.append(name)
                except IndexError:
                    continue

        if not names:
            return self._info("System keychain present (could not parse certificate names)")

        # Check for known traffic inspection / MITM tool certificates by
        # matching against the indicator list case-insensitively.
        mitm_found: list[str] = []
        for name in names:
            name_lower = name.lower()
            for indicator in self._MITM_INDICATORS:
                if indicator in name_lower:
                    mitm_found.append(name)
                    break

        count = len(names)

        if mitm_found:
            return self._warning(
                f"Traffic inspection certificate detected: "
                f"{', '.join(mitm_found[:2])} — HTTPS traffic may be monitored",
                data={"cert_count": count, "mitm_certs": mitm_found},
            )

        # macOS ships with ~170 root CAs; a count notably above 200 suggests
        # additional certificates were installed and is worth flagging for awareness.
        if count > 200:
            return self._info(
                f"{count} root certificates in System keychain "
                f"(~{count - 170} beyond typical Apple defaults — review if unexpected)",
                data={"cert_count": count},
            )

        return self._pass(
            f"{count} root certificate{'s' if count != 1 else ''} in System keychain (appears normal)",
            data={"cert_count": count},
        )


class GuestAccountCheck(BaseCheck):
    """Detect if the macOS Guest account is enabled.

    The macOS Guest account allows anyone to log in without a password.
    While Guest sessions are sandboxed (data is wiped on logout), Guest users
    can still browse the web, use apps, access any public iCloud-shared
    resources, and — on some configurations — trigger local privilege
    escalation vectors. The Guest account is also a first step in several
    documented jailbreak / local privilege escalation research chains.

    Detection mechanism:
        Reads ``GuestEnabled`` from
        ``/Library/Preferences/com.apple.loginwindow`` using ``defaults read``.
        A value of ``"1"`` means the Guest account is enabled.

    Severity scale:
        - ``pass``: Key absent or value is not ``"1"``.
        - ``warning``: Value is ``"1"`` (Guest account enabled).

    Attributes:
        id (str): ``"guest_account"``
        name (str): ``"Guest Account"``
        fix_level (str): ``"guided"`` — opens System Settings → Users & Groups
            via a deep-link URL.
        fix_url (str): Deep-link URL to the Users & Groups settings pane.
        fix_reversible (bool): ``True`` — the Guest account can be re-enabled.
        fix_time_estimate (str): About 30 seconds.
    """

    id = "guest_account"
    name = "Guest Account"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking if the Guest account is enabled — an enabled Guest account "
        "gives anyone who picks up your Mac a login with filesystem access."
    )
    finding_explanation = (
        "The macOS Guest account lets anyone log in without a password. "
        "While Guest sessions are sandboxed, Guest users can browse the web, "
        "use apps, and access iCloud-enabled services. "
        "It is also a common first step in local privilege-escalation research."
    )
    recommendation = (
        "Disable the Guest account in System Settings → General → Users & Groups → Guest User."
    )
    fix_level = "guided"
    fix_description = "Opens Users & Groups to disable the Guest account"
    fix_url = "x-apple.systempreferences:com.apple.preferences.users"
    fix_reversible = True
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Read ``GuestEnabled`` from com.apple.loginwindow via ``defaults read``.

        Returns:
            CheckResult: One of:

            - ``pass`` — Key absent or value is not ``"1"``.
            - ``warning`` — Value is ``"1"`` (Guest account is enabled).
              ``result.data["guest_enabled"]`` is ``True``.

        Example::

            check = GuestAccountCheck()
            result = check.run()
            # warning: "Guest account is enabled — anyone can log in without a password"
        """
        rc, out, _ = self.shell(
            ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"]
        )
        if rc == 0 and out.strip() == "1":
            return self._warning(
                "Guest account is enabled — anyone can log in without a password",
                data={"guest_enabled": True},
            )
        return self._pass("Guest account is disabled")


class LoginHooksCheck(BaseCheck):
    """Detect legacy login/logout hooks that run arbitrary scripts at session events.

    Login hooks (``LoginHook``) and logout hooks (``LogoutHook``) are a legacy
    macOS feature that runs a specified script as root every time any user logs
    in or out. They predate LaunchAgents as a persistence mechanism. On a
    personal Mac in 2024, there is almost no legitimate reason for these to
    be configured. Their presence is strongly associated with malware, enterprise
    management abuse, and persistence by sophisticated attackers who prefer
    mechanisms that bypass LaunchAgent scanning tools.

    Detection mechanism:
        Reads ``LoginHook`` and ``LogoutHook`` keys from
        ``com.apple.loginwindow`` using ``defaults read`` (no plist path
        specified — reads the current user domain). A non-zero exit from
        ``defaults read`` means the key is absent.

    Severity scale:
        - ``pass``: Both keys are absent.
        - ``warning``: Either key is present with a non-empty value.

    Attributes:
        id (str): ``"login_hooks"``
        name (str): ``"Login/Logout Hooks"``
        fix_level (str): ``"instructions"`` — removing hooks requires running
            ``sudo defaults delete`` for each key.
        fix_steps (list[str]): Commands to check and remove login/logout hooks,
            with a recommendation to investigate the script path before deleting.
        fix_reversible (bool): ``True`` — hooks can be re-added with
            ``sudo defaults write com.apple.loginwindow LoginHook /path``.
        fix_time_estimate (str): About 5 minutes.
    """

    id = "login_hooks"
    name = "Login/Logout Hooks"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking for login and logout hooks — these run arbitrary scripts as root "
        "at every login and logout event, a technique used by malware to persist."
    )
    finding_explanation = (
        "Login hooks run a script as root every time any user logs in. "
        "Logout hooks run at logout. They are a legacy persistence mechanism "
        "rarely needed by legitimate software today — their presence on a "
        "personal Mac is highly suspicious."
    )
    recommendation = (
        "If you did not set these hooks intentionally, remove them: "
        "sudo defaults delete com.apple.loginwindow LoginHook"
    )
    fix_level = "instructions"
    fix_description = "Remove unrecognised login/logout hooks"
    fix_steps = [
        "Check current hooks: defaults read com.apple.loginwindow LoginHook",
        "To remove login hook:  sudo defaults delete com.apple.loginwindow LoginHook",
        "To remove logout hook: sudo defaults delete com.apple.loginwindow LogoutHook",
        "Investigate the script path before removing to understand what it was doing",
    ]
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Read ``LoginHook`` and ``LogoutHook`` from com.apple.loginwindow.

        Iterates both key names and calls ``defaults read com.apple.loginwindow
        <key>`` for each. A non-zero exit code from ``defaults read`` means the
        key is absent. Non-empty values are collected and reported.

        Returns:
            CheckResult: One of:

            - ``pass`` — Both keys are absent (no hooks configured).
            - ``warning`` — One or both keys are present. ``result.data["hooks"]``
              contains ``"<key>: <truncated_value>"`` strings for each.

        Example::

            check = LoginHooksCheck()
            result = check.run()
            # warning: "Login hook detected: LoginHook: /Library/Scripts/evil.sh"
        """
        found: list[str] = []
        for key in ("LoginHook", "LogoutHook"):
            rc, out, _ = self.shell(
                ["defaults", "read", "com.apple.loginwindow", key]
            )
            if rc == 0 and out.strip():
                # Truncate long paths to 60 chars for readable display.
                found.append(f"{key}: {out.strip()[:60]}")

        if found:
            return self._warning(
                f"Login/logout hook{'s' if len(found) > 1 else ''} detected: "
                f"{'; '.join(found)}",
                data={"hooks": found},
            )
        return self._pass("No login or logout hooks configured")


class SSHConfigCheck(BaseCheck):
    """Check ``sshd_config`` for risky settings: password authentication and root login.

    When Remote Login (SSH) is enabled, macOS's ``sshd`` configuration
    determines what types of authentication are accepted. Two settings are
    especially dangerous:

    - **PasswordAuthentication yes** — Allows SSH login using a username and
      password. SSH servers with password auth enabled are constantly brute-
      forced by automated scanners; even with a strong password, this is an
      unnecessary risk when key-based auth is available.
    - **PermitRootLogin** (anything other than ``no`` or
      ``prohibit-password``) — Allows direct SSH login as root, granting an
      attacker instant full system access if they can authenticate.

    Detection mechanism:
        Reads ``/etc/ssh/sshd_config``, skips comment lines, and checks for
        explicit ``PasswordAuthentication yes`` and ``PermitRootLogin``
        (without ``no`` or ``prohibit``). The check is skipped if Remote Login
        is off, since ``sshd_config`` is not applicable in that state.

    Severity scale:
        - ``pass``: SSH is off, or no risky settings found.
        - ``warning``: At least one risky setting found.
        - ``skip``: ``sshd_config`` does not exist.
        - ``info``: File exists but could not be read (needs admin/sudo).

    Attributes:
        id (str): ``"ssh_config"``
        name (str): ``"SSH Server Config"``
        fix_level (str): ``"instructions"`` — hardening requires editing
            ``/etc/ssh/sshd_config`` with ``sudo`` and restarting the SSH daemon.
        fix_steps (list[str]): Commands to open, edit, and apply hardened
            SSH config settings.
        fix_reversible (bool): ``True`` — settings can be reverted by re-editing
            the config file.
        fix_time_estimate (str): About 5 minutes.
    """

    id = "ssh_config"
    name = "SSH Server Config"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking sshd_config for risky settings — password authentication and "
        "root login over SSH are among the most exploited server misconfigurations."
    )
    finding_explanation = (
        "SSH with password authentication enabled is constantly brute-forced on the "
        "internet. PermitRootLogin exposes the most privileged account. "
        "If Remote Login is enabled, these settings directly affect your Mac's "
        "exposure — key-only auth is the strong default."
    )
    recommendation = (
        "In /etc/ssh/sshd_config: set 'PasswordAuthentication no' and "
        "'PermitRootLogin no'. Restart SSH: sudo launchctl kickstart -k system/com.openssh.sshd"
    )
    fix_level = "instructions"
    fix_description = "Harden sshd_config to disable password auth and root login"
    fix_steps = [
        "Open: sudo nano /etc/ssh/sshd_config",
        "Set: PasswordAuthentication no",
        "Set: PermitRootLogin no",
        "Save and restart SSH: sudo launchctl kickstart -k system/com.openssh.sshd",
    ]
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Parse ``/etc/ssh/sshd_config`` for dangerous authentication settings.

        Skips the check entirely if Remote Login (SSH) is currently off, since
        ``sshd_config`` only matters when the SSH daemon is listening. Reads
        and parses the config file, skipping comment lines. Looks specifically
        for ``PasswordAuthentication yes`` and ``PermitRootLogin`` without a
        ``no`` or ``prohibit-password`` value.

        Returns:
            CheckResult: One of:

            - ``skip`` — ``sshd_config`` file does not exist.
            - ``pass`` — Remote Login is off, or no risky settings found.
            - ``warning`` — One or more risky settings detected.
              ``result.data["issues"]`` lists each finding.
            - ``info`` — File exists but was not readable (needs sudo).

        Example::

            check = SSHConfigCheck()
            result = check.run()
            # warning: "Risky SSH config: PasswordAuthentication yes (enables password brute-force)"
        """
        config_path = Path("/etc/ssh/sshd_config")
        if not config_path.exists():
            return self._skip("sshd_config not found")

        # Skip if SSH server is not running — sshd_config is irrelevant when
        # the daemon is not listening.
        rc_ssh, ssh_out, _ = self.shell(["systemsetup", "-getremotelogin"], timeout=5)
        if rc_ssh == 0 and "off" in ssh_out.lower():
            return self._pass("Remote Login (SSH) is off — sshd_config not applicable")

        try:
            content = config_path.read_text(errors="replace")
        except PermissionError:
            return self._info(
                "Could not read /etc/ssh/sshd_config — run macaudit with sudo to check"
            )

        issues: list[str] = []
        for line in content.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("#"):
                continue
            if stripped.startswith("passwordauthentication") and "yes" in stripped:
                issues.append("PasswordAuthentication yes (enables password brute-force)")
            if stripped.startswith("permitrootlogin") and "no" not in stripped and "prohibit" not in stripped:
                issues.append("PermitRootLogin is not 'no' (root login permitted)")

        if issues:
            return self._warning(
                f"Risky SSH config: {'; '.join(issues)}",
                data={"issues": issues},
            )
        return self._pass("SSH server config looks secure")


class SystemExtensionsCheck(BaseCheck):
    """List active system extensions and flag for user awareness.

    System extensions run at the highest privilege level below the macOS
    kernel, in userspace but with kernel entitlements. They are used by
    legitimate tools (antivirus endpoint security extensions, VPN network
    extensions, virtualization DriverKit drivers) and are approved during
    installation via a System Settings prompt. However, extensions that were
    installed by apps that have since been uninstalled can remain active
    indefinitely, running code the user may no longer intend to have on
    their system.

    Extension types:
        - **DriverKit** — Hardware driver extensions.
        - **Network Extensions** — VPN, DNS proxy, content filter, packet
          tunnel providers.
        - **Endpoint Security** — Security monitoring agents with access to
          system events (file operations, process launches, network events).

    Detection mechanism:
        Runs ``systemextensionsctl list`` and parses lines containing ``"["``
        and the words ``"enabled"`` or ``"activated"``. Each such line is
        treated as an active extension entry.

    Severity scale:
        Always ``pass`` (none found) or ``info`` (some found). Extensions are
        not flagged as ``warning`` because the presence of legitimate tools
        (e.g. Endpoint Security extensions from antivirus software) should not
        generate a warning. The user is informed to verify each extension
        corresponds to an intentionally installed app.

    Attributes:
        id (str): ``"system_extensions"``
        name (str): ``"System Extensions"``
        fix_level (str): ``"guided"`` — opens System Settings → Privacy &
            Security → Security.
        fix_url (str): Deep-link URL to the Security pane.
        fix_reversible (bool): ``True`` — extensions can be re-enabled via
            System Settings after being removed.
        fix_time_estimate (str): About 5 minutes.
    """

    id = "system_extensions"
    name = "System Extensions"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking installed system extensions — these run as kernel-adjacent "
        "privileged code. Unexpected extensions can be left by uninstalled apps "
        "or indicate compromise."
    )
    finding_explanation = (
        "System extensions (DriverKit, Network Extensions, Endpoint Security) "
        "run at the highest privilege level below the kernel. "
        "Legitimate apps like antivirus, VPNs, and virtualization tools use them. "
        "Extensions that remain after app uninstall continue running indefinitely."
    )
    recommendation = (
        "Review in System Settings → Privacy & Security → Security → System Extensions. "
        "Or run: systemextensionsctl list"
    )
    fix_level = "guided"
    fix_description = "Review system extensions in System Settings → Privacy & Security"
    fix_url = "x-apple.systempreferences:com.apple.preference.security"
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Run ``systemextensionsctl list`` and count active/enabled extensions.

        Parses each output line for the presence of ``[`` (extension state
        brackets) and the word ``"enabled"`` or ``"activated"``. Truncates
        each matching line to 80 characters for readable display.

        Returns:
            CheckResult: One of:

            - ``info`` — Command failed or produced no output.
            - ``pass`` — No active extensions found.
            - ``info`` — One or more active extensions found. The count is
              reported and the user is prompted to verify each entry.
              ``result.data["extensions"]`` lists truncated extension lines;
              ``result.data["count"]`` is the total.

        Example::

            check = SystemExtensionsCheck()
            result = check.run()
            # info: "3 system extensions active — verify all are from apps you installed"
        """
        rc, out, _ = self.shell(["systemextensionsctl", "list"], timeout=10)
        if rc != 0 or not out.strip():
            return self._info("Could not list system extensions")

        extensions: list[str] = []
        for line in out.splitlines():
            # Active extension lines have state brackets and "enabled" or "activated".
            if "[" in line and ("enabled" in line.lower() or "activated" in line.lower()):
                parts = line.strip().split()
                if len(parts) >= 2:
                    extensions.append(line.strip()[:80])

        n = len(extensions)
        if n == 0:
            return self._pass("No active system extensions found")
        return self._info(
            f"{n} system extension{'s' if n != 1 else ''} active — verify all are from apps you installed",
            data={"extensions": extensions, "count": n},
        )


class CronJobsCheck(BaseCheck):
    """Detect user cron jobs that could indicate unwanted scheduled persistence.

    Cron is a Unix job scheduler that executes commands on a time-based
    schedule. On modern macOS, legitimate software almost universally uses
    LaunchAgents/LaunchDaemons instead of cron. Cron jobs are, however, a
    classic malware persistence technique: a cron job can re-download a
    payload, phone home, or re-install a removed agent on a schedule, surviving
    manual removal attempts that don't also check crontab.

    Detection mechanism:
        Runs ``crontab -l`` for the current user. Non-zero exit or empty output
        means no cron jobs are configured. Non-comment, non-blank lines are
        counted as active jobs.

    Severity scale:
        - ``pass``: No cron jobs configured (``crontab -l`` fails or is empty).
        - ``warning``: At least one non-comment cron job found.

    Note:
        Only the current user's crontab is checked. System-level cron entries
        (``/etc/cron.d/``, ``/var/at/tabs/``) require elevated privileges to
        read and are not checked here.

    Attributes:
        id (str): ``"cron_jobs"``
        name (str): ``"Cron Jobs"``
        fix_level (str): ``"instructions"`` — removing cron jobs requires
            ``crontab -e`` (interactive editor), which cannot be automated.
        fix_steps (list[str]): Commands to list and edit crontab entries.
        fix_reversible (bool): ``True`` — removed cron jobs can be re-added.
        fix_time_estimate (str): About 5 minutes.
    """

    id = "cron_jobs"
    name = "Cron Jobs"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking for cron jobs — scheduled tasks are a classic persistence "
        "mechanism used by malware to survive reboots and re-infect after cleanup."
    )
    finding_explanation = (
        "Cron jobs execute commands on a schedule. Legitimate developers sometimes "
        "use them, but on a typical Mac user's system they're rare. "
        "Malware uses cron to periodically re-download payloads or exfiltrate data. "
        "Any unexpected cron entry warrants close inspection."
    )
    recommendation = (
        "Review your crontab with: crontab -l\n"
        "Remove unexpected entries with: crontab -e\n"
        "Also check /etc/cron.d/ and /var/at/tabs/ for system-level crons."
    )
    fix_level = "instructions"
    fix_description = "Review and remove unexpected cron entries"
    fix_steps = [
        "List current crons: crontab -l",
        "Edit crontab: crontab -e  (remove suspicious lines and save)",
        "Check system crons: ls /etc/cron.d/ (if it exists)",
    ]
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Run ``crontab -l`` and count non-comment job lines.

        ``crontab -l`` exits non-zero when no crontab exists for the current
        user. Empty output after filtering comments and blank lines also
        indicates no active jobs.

        Returns:
            CheckResult: One of:

            - ``pass`` — No crontab exists or no active (non-comment) entries.
            - ``warning`` — At least one active cron job found.
              ``result.data["jobs"]`` lists each job line;
              ``result.data["count"]`` is the total.

        Example::

            check = CronJobsCheck()
            result = check.run()
            # warning: "2 cron jobs found — verify each is intentional"
        """
        rc, out, _ = self.shell(["crontab", "-l"])
        if rc != 0 or not out.strip():
            return self._pass("No cron jobs configured for this user")

        # Filter out blank lines and comment lines (starting with #).
        jobs = [
            ln.strip()
            for ln in out.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if not jobs:
            return self._pass("No active cron jobs configured")

        n = len(jobs)
        return self._warning(
            f"{n} cron job{'s' if n != 1 else ''} found — verify each is intentional",
            data={"jobs": jobs, "count": n},
        )


class XProtectCheck(BaseCheck):
    """Check that XProtect malware signatures are recent (updated within 30 days).

    XProtect is macOS's built-in malware scanner. It relies on a signature
    database (``XProtectPlistConfigData``) that Apple delivers silently via
    background software updates. If Automatic Updates are disabled, if a
    proxy blocks Apple's update servers, or if ``softwareupdate`` is broken,
    signatures can go stale — leaving the Mac unprotected against malware
    families that Apple has already detected and catalogued.

    Detection mechanism:
        Runs ``pkgutil --pkg-info com.apple.pkg.XProtectPlistConfigData`` to
        retrieve the package version and install timestamp. Converts the
        ``install-time`` field (Unix timestamp) to an age in days. Falls back
        to checking for the XProtect bundle path directly if pkgutil fails.

    Severity scale:
        - ``pass``: Signatures updated within the last 30 days.
        - ``warning``: Signatures are older than 30 days.
        - ``info``: Version or date not determinable, but bundle is present.

    Attributes:
        id (str): ``"xprotect_freshness"``
        name (str): ``"XProtect Signatures"``
        fix_level (str): ``"guided"`` — opens Software Update settings where the
            user can enable "Install System Data Files and Security Updates".
        fix_url (str): Deep-link URL to Software Update preferences.
        fix_reversible (bool): ``True`` — re-enabling automatic updates is
            non-destructive.
        fix_time_estimate (str): About 30 seconds to change the setting.
    """

    id = "xprotect_freshness"
    name = "XProtect Signatures"
    category = "security"
    category_icon = "🛡️ "

    scan_description = (
        "Checking XProtect signature freshness — stale signatures leave your Mac "
        "unprotected against malware families Apple has already detected and catalogued."
    )
    finding_explanation = (
        "XProtect is macOS's built-in malware scanner. It relies on a signature "
        "database that Apple updates silently in the background. If auto-updates "
        "are disabled or a proxy blocks downloads, signatures become stale and "
        "won't detect newer malware variants."
    )
    recommendation = (
        "Ensure 'Install System Data Files and Security Updates' is enabled in "
        "System Settings → General → Software Update → Automatic Updates."
    )
    fix_level = "guided"
    fix_description = "Enable automatic XProtect updates via Software Update settings"
    fix_url = "x-apple.systempreferences:com.apple.preferences.softwareupdate"
    fix_reversible = True
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Query ``pkgutil`` for XProtect install date and warn if older than 30 days.

        Parses the ``version:`` and ``install-time:`` fields from
        ``pkgutil --pkg-info`` output. Converts the Unix epoch ``install-time``
        value to an age in days. Falls back to bundle existence check if
        ``pkgutil`` cannot find the package (e.g. on Apple Silicon with
        cryptex-based XProtect delivery).

        Returns:
            CheckResult: One of:

            - ``pass`` — Signatures updated within 30 days.
            - ``warning`` — Signatures are > 30 days old.
            - ``info`` — Package version present but install date unavailable.
            - ``info`` — pkgutil failed but XProtect bundle is present.
            - ``info`` — XProtect bundle not found (unusual; may be in system
              cryptex).

        Note:
            The ``import time as _time`` inside this method is intentional:
            ``time`` is only needed here, and the alias avoids shadowing the
            module-level ``time`` name if it were ever imported at the top.

        Example::

            check = XProtectCheck()
            result = check.run()
            # pass: "XProtect signatures updated 3 days ago (v5273)"
        """
        import time as _time

        rc, out, _ = self.shell(
            ["pkgutil", "--pkg-info", "com.apple.pkg.XProtectPlistConfigData"],
            timeout=5,
        )

        if rc != 0 or not out.strip():
            # Fallback: verify the XProtect bundle is at least present on disk.
            bundle = Path(
                "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
            )
            if bundle.exists():
                return self._info("XProtect is present (version unreadable via pkgutil)")
            return self._info("XProtect bundle not found — may be part of System volume")

        version = ""
        install_time = 0
        for line in out.splitlines():
            if line.startswith("version:"):
                version = line.split(":", 1)[1].strip()
            elif line.startswith("install-time:"):
                try:
                    install_time = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass

        if install_time:
            # Convert from Unix epoch to whole days of age.
            age_days = int((_time.time() - install_time) / 86400)
            age_str = f"{age_days} day{'s' if age_days != 1 else ''} ago"
            ver_str = f" (v{version})" if version else ""

            if age_days > 30:
                return self._warning(
                    f"XProtect signatures are {age_days} days old{ver_str} — "
                    "signatures may be stale",
                    data={"version": version, "age_days": age_days},
                )
            return self._pass(
                f"XProtect signatures updated {age_str}{ver_str}",
                data={"version": version, "age_days": age_days},
            )

        if version:
            return self._info(
                f"XProtect present (v{version} — install date unavailable)",
                data={"version": version},
            )
        return self._info("XProtect present (details unavailable)")


# ── Public list for main.py ───────────────────────────────────────────────────
# Consumed by macaudit/main.py to discover and register all checks in this module.
# Order here determines the order checks appear within the "security" category.

ALL_CHECKS: list[type[BaseCheck]] = [
    AutoLoginCheck,
    GuestAccountCheck,
    SSHAuthorizedKeysCheck,
    SSHKeyStrengthCheck,
    SSHConfigCheck,
    LaunchAgentsCheck,
    LoginHooksCheck,
    CronJobsCheck,
    EtcHostsCheck,
    SharingServicesCheck,
    ActivationLockCheck,
    MDMProfilesCheck,
    SystemRootCACheck,
    SystemExtensionsCheck,
    XProtectCheck,
]
