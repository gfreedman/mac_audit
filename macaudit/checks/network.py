"""
Network exposure and sharing-service checks.

This module implements 10 checks that audit the network-facing attack surface
of the Mac, covering wireless discoverability, active sharing services, DNS
configuration, proxy settings, listening ports, and Bluetooth exposure.

Design decisions:
    - All service-detection checks (SSH, Screen Sharing, File Sharing, Internet
      Sharing) use ``launchctl list <service-name>`` as the primary probe.
      This is more reliable than reading plist files directly because launchctl
      reflects the *live* kernel service state, not just the stored preference.
      Plist files are read as a fallback when launchctl is unavailable (e.g.
      when macaudit runs in a non-standard user context).
    - The DNS check targets only **public IPv4** addresses not in the
      known-safe set.  Private RFC-1918 ranges (10.x, 192.168.x, 172.16–31.x)
      and IPv6 addresses are unconditionally excluded; DHCP-assigned local
      resolvers are nearly always benign.
    - The Proxy check detects the default network interface via ``route get
      default`` rather than hardcoding ``en0`` or ``en1``, which handles Macs
      using Ethernet (en2, en3) or Thunderbolt adapters as the primary interface.
    - The listening-ports check uses ``lsof`` rather than ``netstat`` because
      ``lsof -i`` reports the process name alongside each port, allowing the
      display to show "TCP:12345 (processname)" rather than a raw port number.
    - Loopback-only listeners (127.0.0.1, ::1) are excluded from the
      ListeningPortsCheck because they are not reachable from the network and
      never represent an external exposure.

Checks:
    - :class:`AirDropCheck`          — AirDrop discoverability setting.
    - :class:`RemoteLoginCheck`      — SSH remote login service state.
    - :class:`ScreenSharingCheck`    — Screen Sharing (VNC) service state.
    - :class:`FileSharingCheck`      — SMB / AFP file sharing service state.
    - :class:`InternetSharingCheck`  — NAT hotspot / Internet Sharing state.
    - :class:`DNSCheck`              — Custom or suspicious DNS nameservers.
    - :class:`ProxyCheck`            — Active HTTP / HTTPS proxy detection.
    - :class:`SavedWifiCheck`        — Count of saved Wi-Fi networks.
    - :class:`BluetoothCheck`        — Bluetooth power state and discoverability.
    - :class:`ListeningPortsCheck`   — TCP and UDP listening port enumeration.

Attributes:
    _KNOWN_GOOD_DNS (set[str]): IPv4 addresses of well-known, trustworthy
        public DNS resolvers.  Addresses in this set do not trigger the
        DNSCheck warning even if they are not in a private range.
    _PRIVATE_PREFIXES (tuple[str, ...]): Tuple of address prefixes that
        identify RFC-1918 private network ranges and loopback.  Used by
        DNSCheck to unconditionally skip private-range DNS addresses.
    ALL_CHECKS (list[type[BaseCheck]]): Ordered list of check classes
        exported to the scan orchestrator.

Note:
    All subprocess calls use ``self.shell()``, which enforces ``LANG=C``
    and ``LC_ALL=C`` to guarantee English-language output for string
    matching regardless of the user's system locale.
"""

from __future__ import annotations

import re
import shutil

from macaudit.checks.base import BaseCheck, CheckResult


# ── AirDrop ───────────────────────────────────────────────────────────────────

class AirDropCheck(BaseCheck):
    """Check AirDrop discoverability setting and warn if set to Everyone."""

    id = "airdrop_visibility"
    name = "AirDrop Visibility"
    category = "network"
    category_icon = "📡"

    scan_description = (
        "Checking AirDrop discoverability setting — "
        "being visible to Everyone on a public network lets strangers send you files."
    )
    finding_explanation = (
        "AirDrop set to 'Everyone' means any nearby Apple device can see your Mac and "
        "attempt to send files. On public Wi-Fi (cafés, airports) this is a privacy risk. "
        "'Contacts Only' limits this to people in your contacts."
    )
    recommendation = (
        "Change AirDrop to 'Contacts Only' or 'No One' in Control Center → AirDrop. "
        "You can always temporarily enable 'Everyone' when you need it."
    )

    fix_level = "guided"
    fix_description = "Change AirDrop to Contacts Only in Control Center."
    fix_url = "x-apple.systempreferences:com.apple.preference.sharing"
    fix_reversible = True
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Read ``com.apple.sharingd DiscoverableMode`` and classify the discoverability setting.

        Reads the ``DiscoverableMode`` key from the ``com.apple.sharingd``
        defaults domain.  If the key is absent (``defaults read`` returns
        non-zero), AirDrop is likely set to ``"Contacts Only"`` — the safe
        default.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — key absent; assumed ``"Contacts Only"`` (safe default).
            - ``"warning"`` — mode is ``"Everyone"``; any nearby device can see
              the Mac.
            - ``"pass"`` — mode is ``"Contacts Only"`` or ``"Off"``.
            - ``"info"`` — any other unrecognised mode value.
        """
        rc, out, _ = self.shell(
            ["defaults", "read", "com.apple.sharingd", "DiscoverableMode"]
        )
        if rc != 0:
            return self._info("AirDrop discoverability setting not found (may be Contacts Only)")

        mode = out.strip()
        if mode == "Everyone":
            return self._warning(
                "AirDrop visible to Everyone — change to Contacts Only"
            )
        if mode in ("Contacts Only",):
            return self._pass("AirDrop: Contacts Only")
        if mode == "Off":
            return self._pass("AirDrop: Off")
        return self._info(f"AirDrop mode: {mode}")


# ── Remote Login (SSH) ────────────────────────────────────────────────────────

class RemoteLoginCheck(BaseCheck):
    """Check whether SSH remote login is enabled via systemsetup or launchctl."""

    id = "remote_login"
    name = "Remote Login (SSH)"
    category = "network"
    category_icon = "🔑"

    scan_description = (
        "Checking if SSH remote login is enabled — "
        "an open SSH server on public Wi-Fi is a significant attack surface."
    )
    finding_explanation = (
        "Remote Login enables SSH access to your Mac from any device on the network. "
        "If enabled on a public or shared network, it exposes your Mac to login attempts "
        "from anyone on that network. Disable it when not actively in use."
    )
    recommendation = (
        "Disable Remote Login in System Settings → General → Sharing → Remote Login "
        "when not needed. Only enable it temporarily when you actually need SSH access."
    )

    fix_level = "guided"
    fix_description = "Disable Remote Login in System Settings → Sharing."
    fix_url = "x-apple.systempreferences:com.apple.preference.sharing"
    fix_reversible = True
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Detect SSH service state via ``systemsetup -getremotelogin`` with launchctl fallback.

        ``systemsetup -getremotelogin`` is the canonical query but requires the
        user to be in the ``admin`` group.  When it returns a non-zero exit code
        (permission denied or unavailable), the check falls back to querying
        ``launchctl list com.openssh.sshd``: a zero exit code means the SSH
        daemon is registered and running.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"warning"`` — remote login is on; SSH access is open.
            - ``"pass"`` — remote login is off (SSH daemon not running).
        """
        rc, out, _ = self.shell(["systemsetup", "-getremotelogin"])
        if rc != 0:
            # systemsetup may require sudo — try launchctl
            rc2, out2, _ = self.shell(
                ["launchctl", "list", "com.openssh.sshd"]
            )
            if rc2 == 0:
                return self._warning("Remote Login (SSH) appears to be enabled")
            return self._pass("Remote Login (SSH) is Off")

        out_lower = out.lower()
        if "on" in out_lower:
            return self._warning(
                "Remote Login is On — SSH access is open"
            )
        return self._pass("Remote Login (SSH) is Off")


# ── Screen Sharing ────────────────────────────────────────────────────────────

class ScreenSharingCheck(BaseCheck):
    """Check whether Screen Sharing (VNC) is enabled via launchctl."""

    id = "screen_sharing"
    name = "Screen Sharing"
    category = "network"
    category_icon = "🖥️ "

    scan_description = (
        "Checking if Screen Sharing is enabled — "
        "an open screen sharing session lets others see and control your display remotely."
    )
    finding_explanation = (
        "Screen Sharing (VNC) allows remote control of your Mac. If left on and accessible "
        "from a network, it's a serious privacy risk. Always disable when not actively in use."
    )
    recommendation = (
        "Disable Screen Sharing in System Settings → General → Sharing. "
        "Enable only when you need it, then disable immediately after."
    )

    fix_level = "guided"
    fix_description = "Disable Screen Sharing in System Settings → Sharing."
    fix_url = "x-apple.systempreferences:com.apple.preference.sharing"
    fix_reversible = True
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Detect Screen Sharing service via ``launchctl`` with ``sharing -l`` as fallback.

        Queries ``launchctl list com.apple.screensharing``: a zero exit code
        indicates the VNC daemon is registered and running.  If launchctl
        returns an error, the check falls back to ``sharing -l`` and scans
        output for the word ``"screen"``.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"warning"`` — Screen Sharing (VNC) is enabled.
            - ``"pass"`` — Screen Sharing is off.
        """
        rc, out, _ = self.shell(
            ["launchctl", "list", "com.apple.screensharing"]
        )
        if rc == 0:
            return self._warning("Screen Sharing is enabled")

        # Also check via sharing command
        rc2, out2, _ = self.shell(["sharing", "-l"])
        if rc2 == 0 and "screen" in out2.lower():
            return self._warning("Screen Sharing appears to be enabled")

        return self._pass("Screen Sharing is Off")


# ── File Sharing ──────────────────────────────────────────────────────────────

class FileSharingCheck(BaseCheck):
    """Check whether SMB or AFP file sharing daemons are running via launchctl."""

    id = "file_sharing"
    name = "File Sharing"
    category = "network"
    category_icon = "📂"

    scan_description = (
        "Checking if File Sharing (SMB/AFP) is enabled — "
        "active file sharing broadcasts your Mac's presence on the network."
    )
    finding_explanation = (
        "File Sharing makes shared folders accessible to other devices on the network. "
        "On public Wi-Fi, this broadcasts that your Mac has shared folders and anyone "
        "on the network can attempt to access them."
    )
    recommendation = (
        "Disable File Sharing in System Settings → General → Sharing when not in use. "
        "Enable only temporarily when transferring files."
    )

    fix_level = "guided"
    fix_description = "Disable File Sharing in System Settings → Sharing."
    fix_url = "x-apple.systempreferences:com.apple.preference.sharing"
    fix_reversible = True
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Detect active file sharing daemons via ``launchctl`` for both SMB and AFP.

        Probes two launchd service labels in order:
        1. ``com.apple.smbd`` — the SMB (Server Message Block) file sharing daemon
           used by modern macOS.
        2. ``com.apple.AppleFileServer`` — the legacy AFP (Apple Filing Protocol)
           daemon, still present in some configurations.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"warning"`` — SMB or AFP file sharing is enabled.
            - ``"pass"`` — both SMB and AFP are off.
        """
        # Check if smbd is running
        rc, out, _ = self.shell(["launchctl", "list", "com.apple.smbd"])
        if rc == 0:
            return self._warning("File Sharing (SMB) is enabled")

        rc2, out2, _ = self.shell(["launchctl", "list", "com.apple.AppleFileServer"])
        if rc2 == 0:
            return self._warning("File Sharing (AFP) is enabled")

        return self._pass("File Sharing is Off")


# ── DNS check ─────────────────────────────────────────────────────────────────

_KNOWN_GOOD_DNS = {
    # Apple
    "17.0.0.0/8",
    # Google
    "8.8.8.8", "8.8.4.4",
    # Cloudflare
    "1.1.1.1", "1.0.0.1",
    # OpenDNS
    "208.67.222.222", "208.67.220.220",
    # Quad9
    "9.9.9.9", "149.112.112.112",
    # Common ISP / DHCP ranges (192.168.x.x, 10.x.x.x, 172.16–31.x.x)
}

_PRIVATE_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.2", "172.30.", "172.31.", "127.")


class DNSCheck(BaseCheck):
    """Parse scutil --dns for configured nameservers and flag unfamiliar public IPv4 addresses."""

    id = "dns_settings"
    name = "DNS Configuration"
    category = "network"
    category_icon = "🌐"

    scan_description = (
        "Checking DNS server configuration — "
        "modified DNS settings can silently redirect you to fake websites even "
        "when you type the right address."
    )
    finding_explanation = (
        "DNS translates website names (google.com) to IP addresses. If DNS is set to "
        "an unexpected server, every website lookup could be intercepted and redirected. "
        "This is a common attack from malicious software and rogue Wi-Fi hotspots."
    )
    recommendation = (
        "If you see unfamiliar DNS servers, check System Settings → Network → your "
        "connection → DNS. Reset to automatic or set known-safe servers (1.1.1.1, 8.8.8.8). "
        "Run 'scutil --dns' to see full configuration."
    )

    fix_level = "guided"
    fix_description = "Review DNS servers in System Settings → Network."
    fix_url = "x-apple.systempreferences:com.apple.Network-Settings.extension"
    fix_reversible = True
    fix_time_estimate = "~2 minutes"

    def run(self) -> CheckResult:
        """Parse ``scutil --dns`` for nameservers and flag unrecognised public IPv4 addresses.

        Runs ``scutil --dns`` and extracts all ``nameserver[N]: <addr>`` entries
        using a regular expression.  Each unique IPv4 address is checked against
        the ``_PRIVATE_PREFIXES`` tuple (RFC-1918 / loopback) and the
        ``_KNOWN_GOOD_DNS`` set.  Any address that passes neither filter is
        classified as ``"suspicious"`` and triggers a warning.

        IPv6 addresses are always skipped — DHCP assigns IPv6 DNS resolvers
        from ISP or router infrastructure, which are benign in every normal
        configuration.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — ``scutil`` failed, or no nameservers were found.
            - ``"warning"`` — one or more IPv4 addresses are not in the
              known-good or private-range lists; user should verify them.
            - ``"info"`` — all nameservers are either private-range or known-safe.
        """
        rc, out, _ = self.shell(["scutil", "--dns"])
        if rc != 0 or not out:
            return self._info("Could not read DNS configuration")

        servers = re.findall(r"nameserver\[[\d]+\]\s*:\s*([\d.a-f:]+)", out)
        if not servers:
            return self._info("No DNS servers found in scutil output")

        # De-duplicate
        unique = list(dict.fromkeys(servers))

        # IPv6 addresses are commonly assigned by ISP routers — only flag IPv4 as suspicious
        def _is_suspicious_ipv4(addr: str) -> bool:
            if ":" in addr:  # IPv6 — skip; ISP router DNS is normal
                return False
            return (
                not any(addr.startswith(p) for p in _PRIVATE_PREFIXES)
                and addr not in _KNOWN_GOOD_DNS
            )

        suspicious = [s for s in unique if _is_suspicious_ipv4(s)]

        if suspicious:
            return self._warning(
                f"Custom IPv4 DNS: {', '.join(suspicious[:3])} — verify these are intentional",
                data={"dns_servers": unique, "suspicious": suspicious},
            )
        return self._info(
            f"DNS: {', '.join(unique[:3])}",
            data={"dns_servers": unique},
        )


# ── Proxy check ───────────────────────────────────────────────────────────────

class ProxyCheck(BaseCheck):
    """Detect active HTTP/HTTPS proxies on the default network interface."""

    id = "proxy_settings"
    name = "HTTP/HTTPS Proxy"
    category = "network"
    category_icon = "🔀"

    scan_description = (
        "Checking for HTTP/HTTPS proxy configuration — "
        "an unexpected proxy routes all your web traffic through another server."
    )
    finding_explanation = (
        "A proxy server intercepts all your web traffic before it reaches its destination. "
        "If a proxy is configured that you didn't set, it could be logging or modifying "
        "your traffic. This can be set by malware or a misconfigured MDM profile."
    )
    recommendation = (
        "If you see an unexpected proxy: check System Settings → Network → your connection "
        "→ Proxies. Remove any proxies you did not configure. Also check for MDM profiles "
        "in System Settings → Privacy & Security → Profiles."
    )

    fix_level = "guided"
    fix_description = "Review proxy settings in System Settings → Network."
    fix_url = "x-apple.systempreferences:com.apple.Network-Settings.extension"
    fix_reversible = True
    fix_time_estimate = "~2 minutes"

    def run(self) -> CheckResult:
        """Detect the default interface then query ``networksetup`` for active web proxy settings.

        The check first runs ``route get default`` to identify the BSD interface
        name (e.g. ``en0``) of the active default route, then maps it to the
        ``networksetup`` display name (``"Wi-Fi"`` or ``"Ethernet"``).  This
        avoids hardcoding ``en0`` which would fail on Macs using Ethernet or
        Thunderbolt adapters as their primary connection.

        ``networksetup -getwebproxy`` and ``-getsecurewebproxy`` are then called
        for the detected interface.  Each output is scanned for ``Enabled: Yes``
        and a non-empty ``Server:`` value.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"warning"`` — one or more HTTP or HTTPS proxies are active;
              the proxy server address is included in the message.
            - ``"pass"`` — no HTTP or HTTPS proxy is configured.
        """
        # Detect active network interface
        rc, route_out, _ = self.shell(["route", "get", "default"])
        iface = "Wi-Fi"  # Default fallback
        if rc == 0:
            for line in route_out.splitlines():
                if "interface:" in line:
                    raw = line.split(":")[-1].strip()
                    # Map bsd interface name to networksetup name
                    if raw.startswith("en0"):
                        iface = "Wi-Fi"
                    elif raw.startswith("en"):
                        iface = "Ethernet"
                    break

        rc, out, _ = self.shell(
            ["networksetup", "-getwebproxy", iface]
        )
        https_rc, https_out, _ = self.shell(
            ["networksetup", "-getsecurewebproxy", iface]
        )

        proxies_found = []
        for label, text in [("HTTP", out), ("HTTPS", https_out)]:
            if not text:
                continue
            enabled = False
            server = ""
            port = ""
            for line in text.splitlines():
                if line.startswith("Enabled:") and "Yes" in line:
                    enabled = True
                if line.startswith("Server:"):
                    server = line.split(":", 1)[-1].strip()
                if line.startswith("Port:"):
                    port = line.split(":", 1)[-1].strip()
            if enabled and server:
                proxies_found.append(f"{label}: {server}:{port}")

        if proxies_found:
            return self._warning(
                f"Proxy active — {'; '.join(proxies_found)}",
                data={"proxies": proxies_found},
            )
        return self._pass("No HTTP/HTTPS proxy configured")


# ── Saved Wi-Fi networks ──────────────────────────────────────────────────────

class SavedWifiCheck(BaseCheck):
    """Count saved Wi-Fi networks and warn if the list is large enough to risk auto-join attacks."""

    id = "saved_wifi"
    name = "Saved Wi-Fi Networks"
    category = "network"
    category_icon = "📶"

    scan_description = (
        "Counting saved Wi-Fi networks — "
        "too many saved networks causes auto-join to rogue hotspots with common names."
    )
    finding_explanation = (
        "macOS auto-joins the first known network it finds. Attackers create hotspots named "
        "'Starbucks', 'Airport Wi-Fi', or 'xfinitywifi' knowing many devices will "
        "auto-connect. Pruning old networks reduces this exposure."
    )
    recommendation = (
        "Remove old Wi-Fi networks you no longer use in System Settings → Wi-Fi → "
        "click the info (ⓘ) button next to a network → Forget. Keep only current locations."
    )

    fix_level = "guided"
    fix_description = "Review and remove old Wi-Fi networks in System Settings → Wi-Fi."
    fix_url = "x-apple.systempreferences:com.apple.wifi-settings-extension"
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Enumerate saved Wi-Fi networks via ``networksetup`` and warn above the threshold.

        The Wi-Fi interface name (e.g. ``en0``) is discovered dynamically via
        ``networksetup -listallhardwareports`` rather than hardcoded, because on
        Macs with multiple adapters the Wi-Fi interface may not always be ``en0``.
        If discovery fails, ``en0`` and ``en1`` are tried as fallbacks.

        ``networksetup -listpreferredwirelessnetworks <iface>`` is then called;
        each non-header, non-blank line corresponds to one saved SSID.

        Severity thresholds:
            - ``info``    — 0–20 networks (normal).
            - ``warning`` — 21–30 networks (somewhat high; worth reviewing).
            - ``warning`` — 31+ networks (high; meaningful auto-join risk).

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — could not enumerate Wi-Fi networks.
            - ``"info"`` — 0 networks saved.
            - ``"info"`` — 1–20 networks (normal range).
            - ``"warning"`` — 21–30 networks.
            - ``"warning"`` — 31+ networks; auto-join attack risk highlighted.
        """
        # Find the actual Wi-Fi interface name rather than assuming en0/en1.
        # 'networksetup -listallhardwareports' reliably maps human names to BSDs.
        wifi_iface: str | None = None
        rc_list, list_out, _ = self.shell(["networksetup", "-listallhardwareports"])
        if rc_list == 0 and list_out:
            lines = list_out.splitlines()
            for i, line in enumerate(lines):
                if "wi-fi" in line.lower() or "airport" in line.lower():
                    for j in range(i + 1, min(i + 4, len(lines))):
                        if "Device:" in lines[j]:
                            wifi_iface = lines[j].split(":", 1)[-1].strip()
                            break
                    if wifi_iface:
                        break

        # Fall back to en0/en1 if discovery fails
        candidates = [wifi_iface] if wifi_iface else ["en0", "en1"]
        for iface in candidates:
            rc, out, _ = self.shell(
                ["networksetup", "-listpreferredwirelessnetworks", iface]
            )
            if rc == 0 and out and "Error" not in out:
                break
        else:
            return self._info("Could not list saved Wi-Fi networks")

        lines = [
            l.strip() for l in out.splitlines()
            if l.strip() and "Preferred networks" not in l
        ]
        count = len(lines)

        if count == 0:
            return self._info("No saved Wi-Fi networks found")
        if count > 30:
            return self._warning(
                f"{count} saved Wi-Fi networks — prune old ones to reduce auto-join risk",
                data={"count": count},
            )
        if count > 20:
            return self._warning(
                f"{count} saved networks — consider removing old ones",
                data={"count": count},
            )
        return self._info(
            f"{count} saved Wi-Fi network{'s' if count != 1 else ''}",
            data={"count": count},
        )


# ── Bluetooth ─────────────────────────────────────────────────────────────────

class BluetoothCheck(BaseCheck):
    """Check Bluetooth power state and whether Always Discoverable mode is enabled."""

    id = "bluetooth"
    name = "Bluetooth"
    category = "network"
    category_icon = "📡"

    scan_description = (
        "Checking Bluetooth status — Bluetooth left on in public spaces "
        "can expose your device to proximity-based attacks and passive tracking."
    )
    finding_explanation = (
        "Bluetooth on its own is low risk, but 'Always Discoverable' mode lets "
        "any nearby device see your Mac by name, enabling tracking across locations "
        "and exposure to Bluetooth-based exploits. Turn it off when not in use."
    )
    recommendation = (
        "Disable 'Always Discoverable' in System Settings → Bluetooth → Advanced. "
        "Turn Bluetooth off entirely when in public spaces where it isn't needed."
    )
    fix_level = "guided"
    fix_description = "Review Bluetooth settings"
    fix_url = "x-apple.systempreferences:com.apple.BluetoothSettings"
    fix_reversible = True
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Check Bluetooth power state and, if on, whether Always Discoverable mode is set.

        First reads ``ControllerPowerState`` from the
        ``/Library/Preferences/com.apple.Bluetooth`` plist via ``defaults read``.
        A value of ``0`` means Bluetooth is off.  If Bluetooth is on, the check
        calls ``system_profiler SPBluetoothDataType`` to locate the
        ``Discoverable:`` line and checks whether its value is ``"On"``.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"pass"`` — Bluetooth is off.
            - ``"warning"`` — Bluetooth is on **and** Always Discoverable is set;
              any nearby device can see the Mac's Bluetooth identity.
            - ``"info"`` — Bluetooth is on but not in Always Discoverable mode.
        """
        # ControllerPowerState: 1 = on, 0 = off
        rc, out, _ = self.shell(
            ["defaults", "read", "/Library/Preferences/com.apple.Bluetooth",
             "ControllerPowerState"]
        )
        if rc == 0 and out.strip() == "0":
            return self._pass("Bluetooth is off")

        # Bluetooth is on — check if 'Always Discoverable' is set
        rc2, out2, _ = self.shell(["system_profiler", "SPBluetoothDataType"], timeout=8)
        if rc2 == 0 and out2:
            for line in out2.splitlines():
                if "discoverable:" in line.lower():
                    if "on" in line.lower().split("discoverable:")[-1]:
                        return self._warning(
                            "Bluetooth is on and set to Always Discoverable",
                            data={"discoverable": True},
                        )
                    break  # found the line, not 'on'

        return self._info(
            "Bluetooth is on — turn off when not needed in public spaces",
            data={"bluetooth_on": True},
        )


# ── Listening ports ───────────────────────────────────────────────────────────

class ListeningPortsCheck(BaseCheck):
    """Enumerate TCP and UDP listening ports via lsof and flag unexpected non-system listeners."""

    id = "listening_ports"
    name = "Listening Network Ports"
    category = "network"
    category_icon = "🔌"

    scan_description = (
        "Checking for services listening on network ports (TCP and UDP) — "
        "each open port is a potential entry point for network-based attacks."
    )
    finding_explanation = (
        "Services that bind to network ports accept incoming connections. "
        "Beyond expected system services, unexpected listeners could indicate "
        "software you forgot about, development servers left running, or malicious processes. "
        "UDP listeners are checked too — they're commonly used for tunnels and C2 channels."
    )
    recommendation = (
        "Run 'lsof -i TCP -sTCP:LISTEN -n -P' and 'lsof -i UDP -n -P' to see all listeners. "
        "Identify each process and disable or uninstall anything unexpected."
    )
    fix_level = "instructions"
    fix_description = "Identify and disable unexpected listening services"
    fix_steps = [
        "Run: lsof -i TCP -sTCP:LISTEN -n -P",
        "Run: lsof -i UDP -n -P",
        "Identify each process by name and port number",
        "Disable unexpected services in System Settings → General → Sharing",
        "Quit or uninstall software you don't recognize",
    ]
    fix_reversible = True
    fix_time_estimate = "10–30 minutes"

    # Well-known system ports that don't warrant a flag
    _EXPECTED_TCP_PORTS = {
        22,    # SSH (Remote Login)
        88,    # Kerberos
        443,   # HTTPS system services
        445,   # SMB (File Sharing)
        548,   # AFP (File Sharing)
        631,   # CUPS printing
        3283,  # Apple Remote Desktop
        5900,  # VNC (Screen Sharing)
        7000,  # AirPlay receiver
        7100,  # Font server
        8009,  # AirPlay
    }

    _EXPECTED_UDP_PORTS = {
        53,    # DNS
        67,    # DHCP server
        68,    # DHCP client
        123,   # NTP
        137,   # NetBIOS name service
        138,   # NetBIOS datagram service
        5353,  # mDNS / Bonjour
        5354,  # mDNSResponder
        1900,  # SSDP / UPnP
        4500,  # IKE NAT traversal
        500,   # IKE (VPN)
    }

    def _parse_lsof_output(self, out: str) -> dict[int, list[str]]:
        """Parse ``lsof -i`` output into a mapping of port number to process names.

        Skips loopback-only listeners (127.0.0.1 and ::1) because they are not
        reachable from the network and therefore represent no external exposure.
        Also skips ephemeral ports (≥ 49152) which are dynamically allocated for
        outbound connections and are not persistent listeners.

        Args:
            out (str): Raw standard output from an ``lsof -i TCP/UDP`` command.
                The first line is the column header and is always skipped.

        Returns:
            dict[int, list[str]]: Mapping of port number (int) to list of unique
            process names (str) that are bound to that port.  A port may have
            multiple processes if multiple services share a well-known port via
            SO_REUSEPORT.
        """
        listeners: dict[int, list[str]] = {}
        for line in out.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 9:
                continue
            command = parts[0]
            name_field = parts[-1]  # e.g. "*:5900" or "127.0.0.1:631" or "[::1]:631"
            if ":" not in name_field:
                continue

            # Skip loopback-only listeners — not exposed to the network
            host_part = name_field.rsplit(":", 1)[0].lstrip("[").rstrip("]")
            if host_part in ("127.0.0.1", "::1", "localhost"):
                continue

            port_str = name_field.rsplit(":", 1)[-1]
            try:
                port = int(port_str)
            except ValueError:
                continue
            # Ignore ephemeral/high ports (≥49152)
            if port >= 49152:
                continue
            if port not in listeners:
                listeners[port] = []
            if command not in listeners[port]:
                listeners[port].append(command)
        return listeners

    def run(self) -> CheckResult:
        """Enumerate TCP/UDP listeners via ``lsof`` and flag ports outside the expected system set.

        Runs two ``lsof`` invocations concurrently (sequentially due to
        Python's subprocess model):

        1. ``lsof -i TCP -sTCP:LISTEN -n -P`` — TCP sockets in LISTEN state.
           The ``-n`` flag suppresses DNS lookups; ``-P`` suppresses port-name
           resolution, so ports appear as numbers.
        2. ``lsof -i UDP -n -P`` — UDP sockets (UDP has no LISTEN state concept;
           any bound UDP socket can receive data).

        Both outputs are parsed by ``_parse_lsof_output()``.  Loopback-only
        listeners and ephemeral ports (≥ 49152) are excluded.  The remaining
        ports are compared against ``_EXPECTED_TCP_PORTS`` and
        ``_EXPECTED_UDP_PORTS``; any port outside those sets is reported.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — both ``lsof`` calls failed (unusual; e.g. no lsof).
            - ``"pass"`` — all listening ports are in the expected system sets.
            - ``"warning"`` — more than 5 unexpected ports are open.
            - ``"info"`` — 1–5 unexpected ports are open (informational).
        """
        # TCP listeners
        rc_tcp, out_tcp, _ = self.shell(
            ["lsof", "-i", "TCP", "-sTCP:LISTEN", "-n", "-P"], timeout=12
        )
        # UDP listeners
        rc_udp, out_udp, _ = self.shell(
            ["lsof", "-i", "UDP", "-n", "-P"], timeout=12
        )

        if (rc_tcp != 0 or not out_tcp) and (rc_udp != 0 or not out_udp):
            return self._info("Could not enumerate listening ports")

        tcp_listeners = self._parse_lsof_output(out_tcp) if rc_tcp == 0 else {}
        udp_listeners = self._parse_lsof_output(out_udp) if rc_udp == 0 else {}

        unexpected_tcp = {p: c for p, c in tcp_listeners.items() if p not in self._EXPECTED_TCP_PORTS}
        unexpected_udp = {p: c for p, c in udp_listeners.items() if p not in self._EXPECTED_UDP_PORTS}
        total = len(tcp_listeners) + len(udp_listeners)

        if not unexpected_tcp and not unexpected_udp:
            return self._pass(
                f"{total} port{'s' if total != 1 else ''} listening (TCP+UDP — all expected)",
                data={"port_count": total},
            )

        all_unexpected: list[str] = []
        for port, procs in sorted(unexpected_tcp.items()):
            all_unexpected.append(f"TCP:{port} ({', '.join(procs[:2])})")
        for port, procs in sorted(unexpected_udp.items()):
            all_unexpected.append(f"UDP:{port} ({', '.join(procs[:2])})")

        examples = all_unexpected[:5]
        n = len(unexpected_tcp) + len(unexpected_udp)

        if n > 5:
            return self._warning(
                f"{n} unexpected listening port{'s' if n != 1 else ''}: "
                f"{', '.join(examples)}{'…' if n > 5 else ''}",
                data={"unexpected_tcp": {str(k): v for k, v in unexpected_tcp.items()},
                      "unexpected_udp": {str(k): v for k, v in unexpected_udp.items()},
                      "total": total},
            )
        return self._info(
            f"{n} non-system port{'s' if n != 1 else ''} listening: {', '.join(examples)}",
            data={"unexpected_tcp": {str(k): v for k, v in unexpected_tcp.items()},
                  "unexpected_udp": {str(k): v for k, v in unexpected_udp.items()},
                  "total": total},
        )


# ── Internet Sharing ──────────────────────────────────────────────────────────

class InternetSharingCheck(BaseCheck):
    """Check whether Internet Sharing (NAT hotspot) is enabled via the com.apple.nat plist."""

    id = "internet_sharing"
    name = "Internet Sharing"
    category = "network"
    category_icon = "📡"

    scan_description = (
        "Checking if Internet Sharing is enabled — sharing your connection "
        "creates a new network hotspot that other devices can join without authentication."
    )
    finding_explanation = (
        "Internet Sharing turns your Mac into a Wi-Fi hotspot and broadcasts "
        "your internet connection to nearby devices. Unless you deliberately set "
        "this up, it is a significant exposure — other devices on your network or "
        "in range could silently route traffic through your Mac."
    )
    recommendation = (
        "Disable Internet Sharing in System Settings → General → Sharing → Internet Sharing."
    )
    fix_level = "guided"
    fix_description = "Disable Internet Sharing in System Settings → Sharing"
    fix_url = "x-apple.systempreferences:com.apple.preference.sharing"
    fix_reversible = True
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Check the ``com.apple.nat`` plist for ``Enabled = 1`` with a ``kextstat`` fallback.

        The primary signal is the ``NAT`` dictionary in the system configuration
        plist at
        ``/Library/Preferences/SystemConfiguration/com.apple.nat``.
        An ``Enabled = 1`` entry in that dictionary confirms Internet Sharing is
        on.  As a secondary, weaker signal, ``kextstat`` is queried for
        ``com.apple.nke.ppp``; its presence suggests the NAT kernel module is
        loaded, though it can persist transiently after Internet Sharing is
        disabled.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"warning"`` — Internet Sharing is enabled (``Enabled = 1`` in plist).
            - ``"info"`` — the NAT kernel module is loaded but the plist does
              not confirm it is actively enabled (intermediate / partial state).
            - ``"pass"`` — Internet Sharing is off.
        """
        # Internet Sharing is controlled via the NAT plist
        rc, out, _ = self.shell(
            [
                "defaults", "read",
                "/Library/Preferences/SystemConfiguration/com.apple.nat",
                "NAT",
            ]
        )

        if rc == 0 and "Enabled = 1" in out:
            return self._warning(
                "Internet Sharing is enabled — your Mac is acting as a network hotspot",
                data={"internet_sharing_enabled": True},
            )

        # Also check if the NAT kernel module is loaded as a secondary signal
        rc2, out2, _ = self.shell(["kextstat"])
        if rc2 == 0 and "com.apple.nke.ppp" in out2:
            return self._info(
                "Internet Sharing may be partially active — verify in System Settings → Sharing"
            )

        return self._pass("Internet Sharing is off")


# ── Export ────────────────────────────────────────────────────────────────────

ALL_CHECKS = [
    AirDropCheck,
    RemoteLoginCheck,
    ScreenSharingCheck,
    FileSharingCheck,
    InternetSharingCheck,
    DNSCheck,
    ProxyCheck,
    SavedWifiCheck,
    BluetoothCheck,
    ListeningPortsCheck,
]
