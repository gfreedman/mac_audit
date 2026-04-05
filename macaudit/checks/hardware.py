"""
Hardware health checks for Mac Audit.

This module implements four hardware-level diagnostic checks that evaluate the
physical health and operating state of the Mac. Each check is implemented as a
subclass of :class:`~macaudit.checks.base.BaseCheck` and exposes its findings
as a :class:`~macaudit.checks.base.CheckResult`.

Design decisions:
    - ``_get_power_data()`` is decorated with ``@lru_cache(maxsize=1)`` so that
      ``system_profiler SPPowerDataType`` (which takes ~1–3 s to run) is invoked
      exactly once per process even though both ``BatteryCheck`` and future
      power-related checks may call it.
    - SMART status is queried via ``diskutil info /`` rather than ``diskutil info
      disk0`` to correctly handle external boot drives, Fusion Drives, and APFS
      volume configurations where the boot volume might not be on disk0.
    - Kernel panic files are located in ``/Library/Logs/DiagnosticReports`` (the
      system-wide panic log directory). Panics in the user's own
      ``~/Library/Logs/DiagnosticReports`` are *not* counted because they
      represent application crashes, not kernel-level failures.
    - Thermal throttling is detected through two complementary mechanisms:
      ``pmset -g thermlog`` (universal) and ``sysctl machdep.xcpm.cpu_thermal_level``
      (Intel/XCPM-only). The sysctl key does not exist on Apple Silicon.

Checks:
    - :class:`BatteryCheck`      — cycle count, condition, maximum capacity.
    - :class:`SMARTStatusCheck`  — disk SMART (Self-Monitoring, Analysis and
                                   Reporting Technology) health status.
    - :class:`KernelPanicCheck`  — count of kernel panic reports in the past 7 days.
    - :class:`ThermalCheck`      — CPU thermal throttling state.

Attributes:
    ALL_CHECKS (list[type[BaseCheck]]): Ordered list of check classes exported
        to the scan orchestrator. The orchestrator instantiates each class and
        calls ``execute()`` to obtain a :class:`CheckResult`.

Note:
    All subprocess calls use ``self.shell()``, which forces ``LANG=C`` and
    ``LC_ALL=C`` so that tool output is always in English regardless of the
    system locale. This is essential for reliable string matching.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta
from functools import lru_cache

from macaudit.checks.base import BaseCheck, CheckResult
from macaudit.system_info import IS_APPLE_SILICON


# ── Shared data fetcher ────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _get_power_data() -> str:
    """Invoke ``system_profiler SPPowerDataType`` once and cache the result.

    ``system_profiler SPPowerDataType`` outputs detailed power and battery
    information in a human-readable property-list style text format. The call
    typically takes 1–3 seconds because the tool enumerates hardware via IOKit.
    The ``@lru_cache`` decorator ensures this cost is paid only once per
    process lifetime even when multiple checks request the same data.

    CLI command::

        system_profiler SPPowerDataType

    Returns:
        str: The raw standard-output text from ``system_profiler``, or an
        empty string if the command fails, times out, or is unavailable (e.g.
        on headless or sandboxed environments).

    Note:
        ``LANG=C`` and ``LC_ALL=C`` are injected into the subprocess environment
        to guarantee English-language output regardless of the user's locale.
        Without this, field labels such as ``"Condition:"`` may appear translated
        on non-English macOS installations, breaking downstream regex parsing.

    Example::

        raw = _get_power_data()
        if "Battery Information" in raw:
            print("Battery present")
    """
    import subprocess
    try:
        # Force the C locale so all system_profiler output is in English.
        # macOS system tools respect LANG/LC_ALL even when the GUI is set
        # to another language.
        _env = {**os.environ, "LANG": "C", "LC_ALL": "C"}
        r = subprocess.run(
            ["system_profiler", "SPPowerDataType"],
            capture_output=True, text=True, timeout=15, check=False,
            env=_env,
        )
        return r.stdout
    except Exception:
        return ""


# ── Battery ───────────────────────────────────────────────────────────────────

class BatteryCheck(BaseCheck):
    """Check battery cycle count, maximum capacity, and Apple's condition rating.

    This check parses the output of ``system_profiler SPPowerDataType`` to
    extract three key battery health metrics:

    1. **Cycle count**: The number of complete charge cycles the battery has
       completed. Apple rates Mac batteries for approximately 1,000 cycles.
       Beyond that, maximum capacity degrades noticeably.
    2. **Maximum capacity**: The percentage of the battery's original design
       capacity still available. A new battery is typically 100%; anything
       below 80% indicates meaningful degradation.
    3. **Condition**: Apple's own assessment of battery health. The possible
       values are ``"Normal"``, ``"Service Recommended"``, ``"Replace Soon"``,
       and ``"Replace Now"``. Anything other than ``"Normal"`` warrants action.

    Detection mechanism:
        Calls ``_get_power_data()`` to obtain cached ``system_profiler
        SPPowerDataType`` output, then parses it line-by-line using string
        containment checks and ``re.search()`` for numeric extraction.

    Severity thresholds:
        - ``critical`` — condition is ``"Service Recommended"``, ``"Replace Now"``,
          or ``"Replace Soon"``. These indicate Apple's hardware diagnostics have
          flagged the battery as degraded.
        - ``warning`` — ``max_capacity < 80%`` even if condition is ``"Normal"``.
          This threshold (80%) is the same value Apple uses in System Settings to
          display the "Battery health: XX%" bar and trigger the "Service Recommended"
          state in newer macOS versions.
        - ``info`` — battery present and healthy, or this is a desktop Mac.

    Attributes:
        id (str): ``"battery_health"`` — stable machine-readable identifier.
        name (str): ``"Battery Health"`` — display name in the report.
        category (str): ``"hardware"`` — report section.
        category_icon (str): ``"🔋"`` — emoji for the section header.
        scan_description (str): Shown during the scan narration.
        finding_explanation (str): Educational copy shown in the report for
            non-passing results.
        recommendation (str): Concrete remediation advice for the user.
        fix_level (str): ``"instructions"`` — no automated fix is possible
            for battery replacement; only guidance is provided.
        fix_description (str): One-line summary of the manual guidance.
        fix_steps (list[str]): Step-by-step instructions for the user.
        fix_reversible (bool): ``True`` — battery replacement is a physical
            repair, not a software change; this flag marks the check as
            fixable in principle.
        fix_time_estimate (str): ``"N/A"`` — depends on service availability.
    """

    id = "battery_health"
    name = "Battery Health"
    category = "hardware"
    category_icon = "🔋"

    scan_description = (
        "Checking battery cycle count and condition — "
        "a degraded battery causes unexpected shutdowns, throttling, and poor performance."
    )
    finding_explanation = (
        "Mac batteries are rated for ~1000 charge cycles. Beyond that, maximum capacity "
        "degrades significantly. A battery in 'Service Recommended' state may cause random "
        "shutdowns and CPU throttling to protect the system."
    )
    recommendation = (
        "If condition is 'Service Recommended', consider battery replacement through "
        "Apple or an authorised service provider. Check battery stats in "
        "System Settings → Battery."
    )

    fix_level = "instructions"
    fix_description = "Open System Settings → Battery to see detailed health info."
    fix_steps = [
        "Open System Settings → Battery",
        "Click 'Battery Health…' for full details",
        "If 'Service Recommended', schedule a Genius Bar appointment",
    ]
    fix_reversible = True
    fix_time_estimate = "N/A"

    def run(self) -> CheckResult:
        """Parse cached SPPowerDataType output for Condition, Cycle Count, and Maximum Capacity.

        Calls the module-level cached ``_get_power_data()`` function to avoid
        re-running the slow ``system_profiler`` command. The raw text is
        iterated line-by-line; three specific fields are extracted by checking
        for the label string and then applying ``re.search()`` to pull numeric
        or string values from each matching line.

        The check detects desktop Macs by checking whether ``system_profiler``
        output contains neither ``"Battery Information"`` nor ``"Charge
        Information"`` — these section headers are only emitted on portable Macs
        that have a battery.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — power data unavailable, or desktop Mac (no battery).
            - ``"critical"`` — condition is ``"Service Recommended"``,
              ``"Replace Now"``, or ``"Replace Soon"``.
            - ``"warning"`` — ``max_capacity < 80%``.
            - ``"info"`` — battery present and within acceptable parameters.

        Note:
            The condition string comparison is case-insensitive to guard against
            minor variations in ``system_profiler`` output across macOS releases.

        Example::

            check = BatteryCheck()
            result = check.run()
            print(result.status, result.message)
        """
        raw = _get_power_data()
        if not raw:
            return self._info("Could not read power data")

        # Check if this is a desktop Mac (no battery section)
        if "Battery Information" not in raw and "Charge Information" not in raw:
            return self._info("No battery detected (desktop Mac)")

        condition = ""
        cycle_count = None
        max_capacity = None

        for line in raw.splitlines():
            line = line.strip()
            if "Condition:" in line:
                condition = line.split(":", 1)[-1].strip()
            elif "Cycle Count:" in line:
                m = re.search(r"\d+", line)
                if m:
                    cycle_count = int(m.group())
            elif "Maximum Capacity:" in line:
                # The value may be expressed as "83%" or plain "83"; the "?"
                # in the pattern makes the percent sign optional.
                m = re.search(r"(\d+)%?", line)
                if m:
                    max_capacity = int(m.group(1))

        # Build a compact summary string from whichever fields were found.
        parts = []
        if cycle_count is not None:
            parts.append(f"{cycle_count} cycles")
        if max_capacity is not None:
            parts.append(f"{max_capacity}% capacity")
        if condition:
            parts.append(condition)

        msg = "  ·  ".join(parts) if parts else "Battery info available"

        # Apple's own condition labels that require user action.
        if condition.lower() in ("service recommended", "replace now", "replace soon"):
            return self._critical(msg)
        # 80% is Apple's documented threshold for "battery health is degraded"
        # in newer macOS Battery Health settings.
        if max_capacity is not None and max_capacity < 80:
            return self._warning(msg)
        return self._info(msg)


# ── SMART status ──────────────────────────────────────────────────────────────

class SMARTStatusCheck(BaseCheck):
    """Check SMART disk health status on the boot volume.

    Self-Monitoring, Analysis and Reporting Technology (SMART) is a standard
    built into most modern hard drives and SSDs. The drive firmware continuously
    monitors internal health metrics — reallocated sectors, read error rates,
    uncorrectable errors, spin retries, etc. — and aggregates them into a single
    pass/fail status that the OS can query.

    This check queries the SMART status of the boot volume (the volume mounted at
    ``/``) via ``diskutil info /``. Using ``/`` rather than a device path such as
    ``disk0`` makes the check portable across single-drive setups, external boot
    drives, Fusion Drive configurations, and APFS volume groups.

    Detection mechanism:
        Runs ``diskutil info /`` and scans its output for the ``SMART Status:``
        line. The value after the colon is then classified into one of three
        outcomes: passing (``"Verified"``), failing (any value containing
        ``"fail"``), or informational (``"Not Supported"``, unknown values).

    Apple Silicon note:
        On Apple Silicon Macs (M1 and later), the NVMe controller is proprietary
        and does not expose the standard SMART protocol. ``diskutil`` will report
        ``"Not Supported"`` for such drives. This is expected and should not be
        treated as a warning. The check uses the ``IS_APPLE_SILICON`` flag from
        :mod:`macaudit.system_info` to suppress the warning on these platforms.

    Attributes:
        id (str): ``"smart_status"`` — stable machine-readable identifier.
        name (str): ``"Disk SMART Status"`` — display name in the report.
        category (str): ``"hardware"`` — report section.
        category_icon (str): ``"💾"`` — emoji for the section header.
        scan_description (str): Shown during the scan narration.
        finding_explanation (str): Educational copy shown in the report for
            non-passing results, including the Apple Silicon exception.
        recommendation (str): Concrete action when SMART reports a failure.
        fix_level (str): ``"instructions"`` — a failing SMART status requires
            immediate backup and hardware replacement; no automation is possible.
        fix_description (str): Brief description of the recommended manual steps.
        fix_steps (list[str]): Step-by-step recovery instructions.
        fix_reversible (bool): ``False`` — drive failure is not reversible.
        fix_time_estimate (str): ``"N/A"`` — depends on hardware availability.
    """

    id = "smart_status"
    name = "Disk SMART Status"
    category = "hardware"
    category_icon = "💾"

    scan_description = (
        "Checking disk SMART (Self-Monitoring, Analysis and Reporting Technology) status — "
        "early warning system for drive failure before you lose data."
    )
    finding_explanation = (
        "SMART monitors disk health indicators like reallocated sectors and read errors. "
        "A 'Failing' status on a primary drive is a serious early-warning sign that the disk "
        "may be about to fail. Note: 'Not Supported' is normal on Apple Silicon Macs — "
        "Apple's proprietary NVMe controllers do not expose the SMART protocol."
    )
    recommendation = (
        "Back up immediately if status is Failing. Replace the drive soon. "
        "Consider running Apple Diagnostics (hold D at startup) for additional hardware tests."
    )

    fix_level = "instructions"
    fix_description = "Immediate backup recommended if status is Failing."
    fix_steps = [
        "Back up with Time Machine or another backup solution immediately",
        "Run Apple Diagnostics: restart and hold D key",
        "Schedule a Genius Bar appointment for drive replacement",
    ]
    fix_reversible = False
    fix_time_estimate = "N/A"

    def run(self) -> CheckResult:
        """Run ``diskutil info /`` and extract the SMART Status field.

        The check uses ``"/"`` as the target path rather than ``"disk0"`` to
        correctly resolve the boot volume in all configurations: APFS volume
        groups, Fusion Drives (where the logical disk may be ``disk2``), and
        external boot drives. macOS resolves ``"/"`` to the correct underlying
        physical device automatically.

        The ``"SMART Status"`` line produced by ``diskutil info`` is extracted
        by iterating output lines and checking for the label string.  The
        extracted value is then matched against known states using
        case-insensitive substring matching.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — could not read disk info, or SMART not reported.
            - ``"pass"`` — SMART is ``"Verified"`` or ``"Not Applicable"``, or
              ``"Not Supported"`` on Apple Silicon (where it is expected).
            - ``"critical"`` — SMART value contains ``"fail"`` (e.g.
              ``"Failing"``); immediate data backup is recommended.
            - ``"info"`` — any other unrecognised SMART status value.

        Note:
            ``"Not Applicable"`` is returned by ``diskutil`` for APFS synthesised
            volumes and virtual disks (e.g. RAM disks, disk images). It should be
            treated as a passing state because there is no physical drive to assess.

        Example::

            check = SMARTStatusCheck()
            result = check.run()
            if result.status == "critical":
                print("DISK FAILURE IMMINENT — back up now!")
        """
        # Use "/" to resolve the boot volume dynamically — avoids hardcoding
        # disk0 which breaks on external boot drives and Fusion Drive setups.
        rc, out, _ = self.shell(["diskutil", "info", "/"])
        if rc != 0 or not out:
            return self._info("Could not read disk SMART status")

        smart_status = ""
        for line in out.splitlines():
            if "SMART Status" in line:
                smart_status = line.split(":", 1)[-1].strip()
                break

        if not smart_status:
            return self._info("SMART status not reported for this disk")

        if smart_status.lower() in ("verified", "not applicable"):
            return self._pass(f"SMART: {smart_status}")
        if "fail" in smart_status.lower():
            return self._critical(f"SMART: {smart_status} — back up immediately")
        # "Not Supported" is expected on Apple Silicon — proprietary NVMe controller
        # never exposes SMART. On Intel, it may indicate an external or unsupported drive.
        if smart_status.lower() == "not supported" and IS_APPLE_SILICON:
            return self._pass("SMART: Not Supported (expected on Apple Silicon)")
        return self._info(f"SMART: {smart_status}")


# ── Kernel panics ─────────────────────────────────────────────────────────────

class KernelPanicCheck(BaseCheck):
    """Count kernel panic reports from the last 7 days.

    A kernel panic is the macOS equivalent of a Windows BSOD: the operating
    system kernel detects an unrecoverable error — typically bad memory, a
    faulty kernel extension (kext), a GPU driver bug, or a hardware I/O error
    — and immediately halts to prevent data corruption.

    macOS writes a diagnostic report for each panic to
    ``/Library/Logs/DiagnosticReports``. These report files contain the panic
    backtrace, loaded kernel extensions, and hardware identifiers, and their
    filenames contain the word ``"Panic"``.

    Detection mechanism:
        This check scans the ``/Library/Logs/DiagnosticReports`` directory for
        files whose names contain ``"Panic"`` or ``"panic"`` and whose
        modification time (``mtime``) falls within the last 7 days. It does
        *not* parse file contents — the filename and recency are sufficient to
        establish the count.

    Why 7 days:
        A single isolated kernel panic over several months is not unusual and
        may be caused by a transient hardware condition (e.g. a brief power
        fluctuation). The 7-day window focuses attention on *recent* patterns
        that suggest an active, unresolved problem.

    Severity thresholds:
        - ``pass`` — zero panics in the last 7 days.
        - ``warning`` — 1 or 2 panics. Possibly transient; worth noting.
        - ``critical`` — 3 or more panics. A pattern that requires investigation.

    Full Disk Access note:
        Reading ``/Library/Logs/DiagnosticReports`` requires Full Disk Access
        (FDA) permission in macOS Ventura and later when running in a sandboxed
        context. If FDA is not granted, the check catches the resulting
        ``PermissionError`` and returns an ``info`` result rather than
        incorrectly reporting zero panics.

    Attributes:
        id (str): ``"kernel_panics"`` — stable machine-readable identifier.
        name (str): ``"Kernel Panics (7 days)"`` — display name in the report.
        category (str): ``"hardware"`` — report section.
        category_icon (str): ``"💥"`` — emoji for the section header.
        scan_description (str): Shown during the scan narration.
        finding_explanation (str): Educational copy explaining what kernel
            panics are and why repeated ones require investigation.
        recommendation (str): Actionable steps to diagnose the panic cause.
        fix_level (str): ``"instructions"`` — diagnosis requires manual steps;
            no automated resolution is possible.
        fix_description (str): Brief description of manual investigation steps.
        fix_steps (list[str]): Step-by-step diagnostic instructions.
        fix_reversible (bool): ``True`` — investigating panics does not modify
            the system.
        fix_time_estimate (str): ``"~20 minutes"`` for Apple Diagnostics run.
        _PANIC_DIR (str): Filesystem path of the system diagnostic reports
            directory. Class-level constant to ease testing via subclassing.
    """

    id = "kernel_panics"
    name = "Kernel Panics (7 days)"
    category = "hardware"
    category_icon = "💥"

    scan_description = (
        "Checking for kernel panics in the last 7 days — "
        "repeated panics indicate hardware or driver problems that need investigation."
    )
    finding_explanation = (
        "A kernel panic is a macOS crash where the OS detects an unrecoverable error. "
        "One occasional panic may be normal. Multiple panics in a week indicate a pattern "
        "that could be defective RAM, a bad GPU, a problematic kernel extension, or a "
        "failing drive."
    )
    recommendation = (
        "For repeated panics: run Apple Diagnostics (restart + hold D), check for third-party "
        "kernel extensions with 'kextstat', and consider a RAM test. Report to Apple Support "
        "if the problem persists."
    )

    fix_level = "instructions"
    fix_description = "Run Apple Diagnostics and check logs for panic cause."
    fix_steps = [
        "Restart Mac, hold D to boot into Apple Diagnostics",
        "Check panic report: Console.app → Crash Reports → Kernel",
        "If third-party kexts listed, update or remove them",
    ]
    fix_reversible = True
    fix_time_estimate = "~20 minutes"

    # System-wide diagnostic reports directory. Kernel panic files are written
    # here by the OS, not to the user's ~/Library/Logs/DiagnosticReports which
    # contains only application-level crash reports.
    _PANIC_DIR = "/Library/Logs/DiagnosticReports"

    def run(self) -> CheckResult:
        """Scan ``/Library/Logs/DiagnosticReports`` for panic files modified in the last 7 days.

        The check uses the filesystem ``mtime`` of each diagnostic report file as
        a proxy for when the panic occurred. This avoids parsing the (large,
        complex) panic report format and is sufficiently accurate for a 7-day
        recency filter.

        Files are filtered by name (must contain ``"Panic"`` or ``"panic"``) and
        then by ``mtime >= now - 7 days``. Individual ``OSError`` exceptions when
        stat-ing a specific file are silently skipped to handle race conditions
        (e.g. a file deleted between ``listdir`` and ``getmtime``).

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — directory not found (unusual system configuration)
              or Full Disk Access not granted.
            - ``"pass"`` — zero panic files in the last 7 days.
            - ``"warning"`` — 1 or 2 panic files in the last 7 days.
            - ``"critical"`` — 3 or more panic files in the last 7 days.
            - ``"error"`` — unexpected exception during directory enumeration.

        Raises:
            Exception: Caught by ``execute()`` if an unexpected error occurs
                outside the explicitly handled ``PermissionError`` and ``OSError``
                cases.

        Example::

            check = KernelPanicCheck()
            result = check.run()
            print(f"Panics found: {result.message}")
        """
        try:
            cutoff = datetime.now() - timedelta(days=7)
            panic_files = []

            if not os.path.isdir(self._PANIC_DIR):
                return self._info("Diagnostic reports directory not found")

            for fname in os.listdir(self._PANIC_DIR):
                if "Panic" not in fname and "panic" not in fname:
                    continue
                fpath = os.path.join(self._PANIC_DIR, fname)
                try:
                    mtime = datetime.fromtimestamp(os.path.getmtime(fpath))
                    if mtime >= cutoff:
                        panic_files.append(fname)
                except OSError:
                    # File may have been deleted between listdir() and getmtime();
                    # skip it rather than aborting the entire scan.
                    continue

            count = len(panic_files)
            if count == 0:
                return self._pass("No kernel panics in the last 7 days")
            if count == 1:
                return self._warning(f"1 kernel panic in the last 7 days")
            if count >= 3:
                return self._critical(f"{count} kernel panics in the last 7 days")
            return self._warning(f"{count} kernel panics in the last 7 days")

        except PermissionError:
            # Full Disk Access is required to read /Library/Logs/DiagnosticReports
            # on macOS Ventura+ in restricted execution contexts.
            return self._info(
                "Cannot read diagnostic reports — Full Disk Access needed"
            )
        except Exception as e:
            return self._error(f"Could not check kernel panics: {e}")


# ── Thermal throttling ────────────────────────────────────────────────────────

class ThermalCheck(BaseCheck):
    """Detect active CPU thermal throttling via pmset and sysctl.

    When a Mac's CPU or GPU generates more heat than the cooling system can
    dissipate, macOS's power management subsystem (``pmset``) automatically
    reduces CPU and GPU clock speeds to lower heat output. This is called
    thermal throttling. While it prevents hardware damage, it can reduce
    effective CPU performance by 30–50% and makes the Mac feel sluggish under
    load.

    Common causes of thermal throttling:
        - Blocked ventilation ports (laptop placed on a soft surface or lap).
        - Demanding workloads run continuously (ML training, video encoding).
        - Dust accumulation in vents or on heatsink fins.
        - A failing or disconnected fan.
        - Ambient temperature above the operating specification (10–35°C).

    Detection mechanism:
        Two complementary sources are queried:

        1. ``pmset -g thermlog`` — available on all Macs. The output includes
           a ``CPU_Speed_Limit`` field (0–100%) and a ``Thermal_Pressure`` field.
           ``CPU_Speed_Limit < 100`` or any thermal pressure event other than
           ``"No Thermal Pressure"`` indicates active throttling.

        2. ``sysctl -n machdep.xcpm.cpu_thermal_level`` — Intel/XCPM-only.
           The ``machdep.xcpm.*`` namespace belongs to the Intel eXtended CPU
           Power Management subsystem (XCPM) and does not exist on Apple Silicon.
           A non-zero value indicates the XCPM kernel driver is applying thermal
           limits.

    Apple Silicon note:
        On M-series Macs the sysctl key ``machdep.xcpm.cpu_thermal_level`` does
        not exist. The check guards against this with ``IS_APPLE_SILICON`` and
        only queries the sysctl on Intel hosts.

    Attributes:
        id (str): ``"thermal_state"`` — stable machine-readable identifier.
        name (str): ``"CPU Thermal State"`` — display name in the report.
        category (str): ``"hardware"`` — report section.
        category_icon (str): ``"🌡️ "`` — emoji for the section header.
        scan_description (str): Shown during the scan narration.
        finding_explanation (str): Explains thermal throttling mechanics and
            its performance impact.
        recommendation (str): Steps to reduce system temperature.
        fix_level (str): ``"instructions"`` — remediation requires physical
            actions (unblock vents, quit apps) that cannot be automated.
        fix_description (str): Brief summary of suggested manual steps.
        fix_steps (list[str]): Ordered remediation instructions.
        fix_reversible (bool): ``True`` — all steps are reversible.
        fix_time_estimate (str): ``"~5 minutes"`` for basic remediation.
    """

    id = "thermal_state"
    name = "CPU Thermal State"
    category = "hardware"
    category_icon = "🌡️ "

    scan_description = (
        "Checking CPU thermal state — excessive heat causes macOS to throttle CPU speed, "
        "making everything feel sluggish even when performance should be good."
    )
    finding_explanation = (
        "When a Mac runs too hot, macOS reduces CPU and GPU clock speeds to prevent damage. "
        "This 'thermal throttling' can reduce performance by 30–50%. Common causes: "
        "blocked vents, demanding workloads, or a failing fan."
    )
    recommendation = (
        "If throttling: ensure Mac vents are unobstructed, clean fans if accessible, "
        "quit demanding background apps. Apple Silicon Macs: check Activity Monitor → "
        "Energy for highest consumers."
    )

    fix_level = "instructions"
    fix_description = "Check Activity Monitor for CPU-intensive processes causing heat."
    fix_steps = [
        "Open Activity Monitor → Energy tab",
        "Identify high-impact processes and quit unnecessary ones",
        "Ensure Mac is on a hard flat surface with vents unobstructed",
        "For Intel Macs: consider SMC reset if problem persists",
    ]
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Detect thermal throttling via ``pmset -g thermlog`` and, on Intel, sysctl XCPM.

        The method first parses ``pmset -g thermlog`` output, looking for two
        distinct signal patterns:

        - ``CPU_Speed_Limit = N``: A value below 100 means the CPU is running at
          reduced speed. The ``pmset`` tool normalises this as a percentage of
          the maximum rated clock speed.
        - Thermal pressure keywords: The presence of ``"Thermal Pressure"``
          without the preceding ``"No"`` indicates an active throttle event.

        If no throttling is detected from ``pmset`` and the host is Intel, the
        check additionally queries ``sysctl -n machdep.xcpm.cpu_thermal_level``.
        A non-zero integer from this sysctl means XCPM has applied hardware-
        level thermal limits.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — pmset output unavailable.
            - ``"pass"`` — no thermal throttling detected by either source.
            - ``"warning"`` — active thermal throttling detected; performance
              is being reduced to manage heat.

        Note:
            The ``sysctl machdep.xcpm.cpu_thermal_level`` key is only available
            on Intel Macs running the XCPM power management stack. It is absent
            on Apple Silicon (M-series) Macs. This check guards against running
            the sysctl query on unsupported hardware using the module-level
            ``IS_APPLE_SILICON`` flag.

        Example::

            check = ThermalCheck()
            result = check.run()
            if result.status == "warning":
                print("Throttling active — check your vents and background apps.")
        """
        # pmset -g thermlog shows current thermal state
        rc, out, _ = self.shell(["pmset", "-g", "thermlog"])
        if rc != 0 or not out:
            return self._info("Could not read thermal state")

        # Look for CPU_Speed_Limit or Thermal_Level
        throttled = False
        for line in out.splitlines():
            line_lower = line.lower()
            if "cpu_speed_limit" in line_lower:
                m = re.search(r"=\s*(\d+)", line)
                # A CPU speed limit below 100% means the OS is deliberately
                # reducing clock frequency to manage thermal output.
                if m and int(m.group(1)) < 100:
                    throttled = True
                    break
            # "No Thermal Pressure" is the good state
            if "no thermal pressure" in line_lower:
                return self._pass("No thermal throttling detected")
            if "thermal pressure" in line_lower and "no" not in line_lower:
                throttled = True

        # machdep.xcpm.cpu_thermal_level is Intel/XCPM-only — does not exist on Apple Silicon
        if not throttled and not IS_APPLE_SILICON:
            rc2, out2, _ = self.shell(
                ["sysctl", "-n", "machdep.xcpm.cpu_thermal_level"]
            )
            if rc2 == 0 and out2.strip():
                try:
                    level = int(out2.strip())
                    # Any non-zero value means XCPM has applied throttling at the
                    # hardware/firmware level (CPU Pstate management).
                    if level > 0:
                        throttled = True
                except ValueError:
                    pass

        if throttled:
            return self._warning(
                "CPU is being thermally throttled — performance is reduced"
            )
        return self._pass("No thermal throttling detected")


# ── Export ────────────────────────────────────────────────────────────────────

#: Ordered list of hardware check classes exported to the scan orchestrator.
#: The orchestrator instantiates each class and calls ``execute()`` to run the
#: check with prerequisite gates and exception safety. Order here determines
#: display order in the report's hardware section.
ALL_CHECKS = [
    BatteryCheck,
    SMARTStatusCheck,
    KernelPanicCheck,
    ThermalCheck,
]
