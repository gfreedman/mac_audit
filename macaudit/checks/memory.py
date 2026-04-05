"""
Memory and performance checks for Mac Audit.

This module implements four checks that examine RAM utilisation, virtual memory
swap usage, and process-level CPU and memory consumption. Together they help the
user understand why their Mac may feel slow and identify the processes responsible.

Design decisions:
    - Process data is collected once via a single ``ps -eo pid,pcpu,pmem,comm``
      call and parsed by the shared ``_parse_ps()`` helper. Both ``TopCPUCheck``
      and ``TopMemoryCheck`` call ``ps`` independently rather than sharing a
      cache, because each check runs in isolation and the data changes rapidly
      enough that a stale cache would not be useful.
    - Memory pressure is queried via the ``memory_pressure`` CLI tool rather than
      a raw sysctl because the tool encodes Apple's own multi-factor assessment
      (not merely the percentage of RAM in use). The output format is undocumented
      and varies between macOS releases, so the parser uses a two-pass strategy:
      first a structured-line pass, then a colour-word fallback.
    - Swap usage is quantified via ``sysctl vm.swapusage`` rather than inspecting
      the ``/private/var/vm/swapfile*`` files directly. The sysctl gives an
      authoritative summary without requiring elevated privileges.
    - ``_short_name()`` truncates process command paths to 24 characters to keep
      report lines readable. The command value from ``ps`` may be a full absolute
      path (e.g. ``/Applications/Safari.app/Contents/MacOS/Safari``), so only
      the basename is needed.

Checks:
    - :class:`MemoryPressureCheck` — system memory pressure level (green/yellow/red).
    - :class:`SwapUsageCheck`      — virtual memory swap file usage in GB.
    - :class:`TopCPUCheck`         — top 5 CPU-consuming processes; warn if any ≥90%.
    - :class:`TopMemoryCheck`      — top 5 memory-consuming processes for visibility.

Attributes:
    ALL_CHECKS (list[type[BaseCheck]]): Ordered list of check classes exported
        to the scan orchestrator.

Note:
    All subprocess calls use ``self.shell()``, which forces ``LANG=C`` and
    ``LC_ALL=C`` to ensure consistent English-language output regardless of
    the user's system locale setting.
"""

from __future__ import annotations

import re

from macaudit.checks.base import BaseCheck, CheckResult


# ── Memory pressure ───────────────────────────────────────────────────────────

class MemoryPressureCheck(BaseCheck):
    """Report macOS memory pressure level (green/yellow/red) via the ``memory_pressure`` CLI.

    macOS computes memory pressure using a multi-factor algorithm that considers
    not just raw RAM utilisation but also the rate of pageouts, compressed memory
    size, swap activity, and wired memory. The result is expressed as one of three
    levels that correspond to traffic-light colours:

    - **Green (Normal)**: RAM is ample; no paging pressure.
    - **Yellow (Warning)**: Memory is being actively managed; performance may
      degrade under additional load. The Compressed Memory system is working hard.
    - **Red (Critical)**: The system is swapping heavily to disk. App launch times
      increase dramatically; the system may feel unresponsive.

    Detection mechanism:
        Runs the ``memory_pressure`` command-line tool, which is provided by macOS
        and reports the same level shown in Activity Monitor's Memory Pressure graph.
        The output format has changed across macOS versions, so the parser uses a
        two-pass approach: a structured ``"System memory pressure level: …"`` line
        is checked first, then a fallback scans for raw colour words
        (``"red"``, ``"yellow"``, ``"green"``).

    Attributes:
        id (str): ``"memory_pressure"`` — stable machine-readable identifier.
        name (str): ``"Memory Pressure"`` — display name in the report.
        category (str): ``"memory"`` — report section.
        category_icon (str): ``"🧠"`` — emoji for the section header.
        scan_description (str): Shown during the scan narration.
        finding_explanation (str): Explains the green/yellow/red scale and its
            real-world implications.
        recommendation (str): Concrete steps to reduce memory pressure.
        fix_level (str): ``"instructions"`` — remediation requires quitting
            apps; no automation is possible without user decision-making.
        fix_description (str): Brief summary of manual remediation steps.
        fix_steps (list[str]): Ordered Activity Monitor instructions.
        fix_reversible (bool): ``True`` — quitting apps is reversible.
        fix_time_estimate (str): ``"~2 minutes"`` to review and quit apps.
    """

    id = "memory_pressure"
    name = "Memory Pressure"
    category = "memory"
    category_icon = "🧠"

    scan_description = (
        "Checking system memory pressure — macOS grades RAM usage as Green, Yellow, or Red. "
        "Red pressure means the system is actively struggling for RAM."
    )
    finding_explanation = (
        "macOS reports memory pressure as green (healthy), yellow (managed but limited), "
        "or red (critical — swapping heavily to disk). Red pressure causes freezes, "
        "long app launch times, and system instability."
    )
    recommendation = (
        "If pressure is red or yellow: quit unused apps, especially browsers with many tabs "
        "and Electron-based apps (Slack, Discord, VS Code). Consider upgrading RAM if this "
        "is a recurring pattern."
    )

    fix_level = "instructions"
    fix_description = "Quit RAM-heavy apps and check Activity Monitor → Memory tab."
    fix_steps = [
        "Open Activity Monitor → Memory tab",
        "Sort by 'Memory' column to find top consumers",
        "Quit apps you don't need right now",
        "Check the Memory Pressure graph at the bottom for trend",
    ]
    fix_reversible = True
    fix_time_estimate = "~2 minutes"

    def run(self) -> CheckResult:
        """Run ``memory_pressure`` and parse output for Normal/Warning/Critical level.

        The ``memory_pressure`` tool is an Apple-provided command that surfaces the
        same underlying memory health metric used by Activity Monitor. It is located
        at ``/usr/bin/memory_pressure`` on all supported macOS versions.

        Parsing strategy:
            1. First pass — structured line detection: scans each line for the
               prefix ``"system memory pressure"`` and then classifies the trailing
               word as ``"critical"``, ``"warn"``, or ``"normal"``. This matches
               the documented format on macOS Ventura and Sonoma.
            2. Second pass (fallback) — colour word detection: if no structured line
               is found, searches the full output for the raw colour words
               ``"red"``, ``"yellow"``, or ``"green"``. This catches the simplified
               output format seen on macOS Sequoia (15+) and any future format
               changes.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — command failed or returned no output.
            - ``"critical"`` — pressure is Red (system actively swapping to disk).
            - ``"warning"`` — pressure is Yellow (RAM is running low).
            - ``"pass"`` — pressure is Green (Normal).
            - ``"info"`` — level could not be determined from the output.

        Note:
            The ``memory_pressure`` tool's output format is undocumented by Apple
            and has varied across macOS major versions. The two-pass fallback
            strategy here is intentionally defensive to handle future changes
            without requiring a code update.

        Example::

            check = MemoryPressureCheck()
            result = check.run()
            print(result.status, result.message)
        """
        rc, out, _ = self.shell(["memory_pressure"])
        if rc != 0 or not out:
            return self._info("Could not read memory pressure")

        out_lower = out.lower()

        # memory_pressure output format is undocumented and varies by macOS release.
        # macOS 13–14: includes a line like "System memory pressure level: Normal"
        # macOS 15+:   may output colour words like "green"/"yellow"/"red" directly.
        # We check for the structured line first, then fall back to colour words.
        level = "unknown"
        for line in out.splitlines():
            line_l = line.lower()
            if "system memory pressure" in line_l:
                if "critical" in line_l:
                    level = "critical"
                elif "warn" in line_l:
                    level = "warn"
                elif "normal" in line_l or "ok" in line_l:
                    level = "normal"
                break

        # Fallback: look for colour words when the structured line is absent.
        if level == "unknown":
            if "red" in out_lower:
                level = "critical"
            elif "yellow" in out_lower:
                level = "warn"
            elif "green" in out_lower or "normal" in out_lower:
                level = "normal"

        if level == "critical":
            return self._critical("Memory pressure is RED — system is actively swapping")
        if level == "warn":
            return self._warning("Memory pressure is YELLOW — RAM is running low")
        if level == "normal":
            return self._pass("Memory pressure is normal (Green)")
        return self._info(f"Memory pressure: {out.strip()[:80]}")


# ── Swap usage ────────────────────────────────────────────────────────────────

class SwapUsageCheck(BaseCheck):
    """Check virtual memory swap usage via ``sysctl vm.swapusage``.

    Virtual memory swap allows the OS to move portions of RAM contents to disk
    when physical RAM is exhausted. On macOS, swap files are stored in
    ``/private/var/vm/`` and are encrypted at rest. While swap enables the
    system to continue running under memory pressure, it is significantly slower
    than physical RAM — even on fast NVMe SSDs — and heavy swap usage adds wear
    cycles to the SSD.

    Apple Silicon vs Intel:
        Apple Silicon's unified memory architecture (SoC-integrated DRAM) handles
        swap somewhat more gracefully than Intel Macs because the memory bandwidth
        is higher and the swap target is always the internal NVMe. However, the
        fundamental performance penalty still applies, and the SSD wear concern is
        the same.

    Detection mechanism:
        Runs ``sysctl -n vm.swapusage`` and parses the ``used = N.NN M/G`` field
        using a regular expression. The unit (M for MiB, G for GiB) is captured
        and used to convert the value to GiB for threshold comparison.

    Severity thresholds (chosen empirically):
        - ``pass`` — less than 1 GB swap used. Minimal, incidental usage.
        - ``info`` — 1–3.9 GB used. Moderate; typical for power users with many
          large apps open.
        - ``warning`` — 4–7.9 GB used. Heavy swap; performance is meaningfully
          degraded.
        - ``critical`` — 8+ GB used. The system is severely swap-bound; closing
          applications or restarting is strongly recommended.

    Attributes:
        id (str): ``"swap_usage"`` — stable machine-readable identifier.
        name (str): ``"Swap Usage"`` — display name in the report.
        category (str): ``"memory"`` — report section.
        category_icon (str): ``"💽"`` — emoji for the section header.
        scan_description (str): Shown during the scan narration.
        finding_explanation (str): Explains why swap degrades performance and
            wears SSDs.
        recommendation (str): Steps to reduce swap usage.
        fix_level (str): ``"instructions"`` — remediation is quitting apps or
            restarting; cannot be automated.
        fix_description (str): Brief summary of manual steps.
        fix_reversible (bool): ``True`` — quitting apps and restarting are
            both reversible.
        fix_time_estimate (str): ``"~1 minute"`` to quit heavy apps.
    """

    id = "swap_usage"
    name = "Swap Usage"
    category = "memory"
    category_icon = "💽"

    scan_description = (
        "Checking swap file usage — heavy swap means macOS is using your SSD as slow RAM, "
        "which both slows performance and adds unnecessary wear to the drive."
    )
    finding_explanation = (
        "Swap (virtual memory) is disk space used as overflow RAM. While Apple Silicon "
        "Macs handle swap better than Intel, heavy swap still degrades responsiveness. "
        "Swap > 4 GB is a sign that RAM is insufficient for your typical workload."
    )
    recommendation = (
        "If swap is high: quit memory-heavy apps and restart if comfortable. "
        "If this is consistently high, your workload may need more RAM. "
        "Check Activity Monitor → Memory for the swap number."
    )

    fix_level = "instructions"
    fix_description = "Quit heavy apps, restart if needed."
    fix_reversible = True
    fix_time_estimate = "~1 minute"

    def run(self) -> CheckResult:
        """Parse ``sysctl -n vm.swapusage`` for the ``used`` value; threshold at 1/4/8 GB.

        The ``sysctl vm.swapusage`` key returns a summary line in the format::

            total = 3072.00M  used = 1536.00M  free = 1536.00M  (encrypted)

        The unit suffix is either ``M`` (mebibytes) or ``G`` (gibibytes). The
        regex captures both the numeric value and the unit character so the check
        can normalise to GiB for threshold comparison regardless of which unit
        macOS uses (determined by the magnitude of the swap file).

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — sysctl call failed, or output does not match the
              expected format.
            - ``"pass"`` — less than 1 GiB swap in use (minimal/negligible).
            - ``"info"`` — 1–3.9 GiB used (moderate; informational).
            - ``"warning"`` — 4–7.9 GiB used (heavy; performance degraded).
            - ``"critical"`` — 8+ GiB used (severe; system is swap-bound).

        Note:
            The thresholds (1 GiB / 4 GiB / 8 GiB) were chosen based on typical
            Mac configurations (8–16 GB RAM) and observed behavioural degradation
            at each level. On Macs with 32+ GB of RAM, these thresholds remain the
            same because swap usage at those levels still represents abnormal
            behaviour worth flagging.

        Example::

            check = SwapUsageCheck()
            result = check.run()
            print(result.status, result.message)
        """
        rc, out, _ = self.shell(["sysctl", "-n", "vm.swapusage"])
        if rc != 0 or not out:
            return self._info("Could not read swap usage")

        # Output: "total = 3072.00M  used = 1536.00M  free = 1536.00M  (encrypted)"
        # Capture the numeric value and the M/G unit suffix.
        m = re.search(r"used\s*=\s*([\d.]+)([MG])", out)
        if not m:
            return self._info(f"Swap: {out.strip()[:60]}")

        value = float(m.group(1))
        unit  = m.group(2)
        # Normalise to GiB: sysctl may report in M (mebibytes) or G (gibibytes).
        gb = value / 1024 if unit == "M" else value
        msg = f"{value:.1f} {unit}B used"

        if gb >= 8:
            return self._critical(msg)
        if gb >= 4:
            return self._warning(msg)
        if gb >= 1:
            return self._info(msg)
        return self._pass(f"Minimal swap ({msg})")


# ── Top CPU consumers ─────────────────────────────────────────────────────────

class TopCPUCheck(BaseCheck):
    """List the top 5 CPU-consuming processes and flag any above 90%.

    A process that consumes 90% or more of CPU continuously is almost certainly
    misbehaving — typical user-facing apps do not sustain near-maximum CPU usage
    for more than a few seconds. Sustained high CPU causes thermal throttling,
    battery drain, and stolen resources from the apps the user is actually using.

    Detection mechanism:
        Runs ``ps -eo pid,pcpu,pmem,comm`` to snapshot all running processes with
        their CPU percentage, memory percentage, and command name. The output is
        parsed by the shared ``_parse_ps()`` helper, sorted by CPU percentage
        descending, and the top 5 are selected. The top process's CPU usage
        determines the result status.

    ps field glossary:
        - ``pid``:  Process ID.
        - ``pcpu``: Instantaneous CPU usage percentage (0–100 per core).
        - ``pmem``: Resident set size as a percentage of total physical RAM.
        - ``comm``: Executable path (may be a full path or just the binary name).

    Severity threshold:
        - ``warning`` — the highest-CPU process is at 90% or more.
        - ``pass``    — all processes are below 90% CPU.

    Why 90%:
        On modern multi-core Macs, a single process consuming exactly 100% of one
        core is normal (e.g. a compilation job). However, when ``pcpu`` approaches
        or exceeds 90% it often means the process is spinning in a tight loop due
        to a bug or runaway state. 90% was chosen over 100% because macOS reports
        ``pcpu`` as a rolling average that rarely reaches the theoretical maximum.

    Attributes:
        id (str): ``"top_cpu"`` — stable machine-readable identifier.
        name (str): ``"Top CPU Consumers"`` — display name in the report.
        category (str): ``"memory"`` — report section (grouped with perf checks).
        category_icon (str): ``"⚡"`` — emoji for the section header.
        scan_description (str): Shown during the scan narration.
        finding_explanation (str): Explains why runaway CPU usage matters.
        recommendation (str): Activity Monitor instructions for the user.
        fix_level (str): ``"instructions"`` — the user must decide which
            processes to quit; this cannot be automated safely.
        fix_description (str): Brief Activity Monitor guidance.
        fix_steps (list[str]): Step-by-step Activity Monitor instructions.
        fix_reversible (bool): ``True`` — quitting processes is reversible.
        fix_time_estimate (str): ``"~2 minutes"`` to review and act.
    """

    id = "top_cpu"
    name = "Top CPU Consumers"
    category = "memory"
    category_icon = "⚡"

    scan_description = (
        "Checking which processes are consuming the most CPU — "
        "runaway processes can make your Mac hot, drain battery, and slow everything down."
    )
    finding_explanation = (
        "A process consuming >80% CPU for an extended time is usually a bug, infinite loop, "
        "or a poorly written app. This drains battery, generates heat, and steals resources "
        "from the apps you're actually using."
    )
    recommendation = (
        "If a process is unexpectedly consuming high CPU: check Activity Monitor → CPU tab. "
        "Consider quitting or force-quitting it. Check for updates for the offending app."
    )

    fix_level = "instructions"
    fix_description = "Use Activity Monitor to identify and quit runaway processes."
    fix_steps = [
        "Open Activity Monitor → CPU tab",
        "Sort by '%CPU' column",
        "Identify unexpected high-CPU processes",
        "Double-click → Quit or Force Quit if needed",
    ]
    fix_reversible = True
    fix_time_estimate = "~2 minutes"

    def run(self) -> CheckResult:
        """Run ``ps -eo pid,pcpu,pmem,comm``, sort by CPU%, and warn if top process ≥90%.

        Calls ``ps`` with a 10-second timeout (``ps`` should complete in
        milliseconds; the timeout is a safety net to prevent a hung system from
        blocking the scan indefinitely). The output is parsed by the shared
        ``_parse_ps()`` helper, which discards malformed lines and converts
        numeric fields to Python types.

        The result message includes the top 3 processes by CPU for at-a-glance
        visibility, formatted as ``"processname XX%  processname XX%  …"``.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — ``ps`` failed or returned no parseable data.
            - ``"warning"`` — the highest-CPU process is at ≥90%.
            - ``"pass"`` — all processes are below 90% CPU.

            Both the ``warning`` and ``pass`` results attach a ``data`` dict with
            the key ``"top_processes"`` containing the top 5 process dicts
            (``pid``, ``cpu``, ``mem``, ``comm``) for downstream consumers such
            as the JSON report.

        Example::

            check = TopCPUCheck()
            result = check.run()
            if result.status == "warning":
                print("Runaway process detected:", result.message)
        """
        rc, out, _ = self.shell(
            ["ps", "-eo", "pid,pcpu,pmem,comm"],
            timeout=10,
        )
        if rc != 0 or not out:
            return self._info("Could not read process list")

        procs = _parse_ps(out)
        procs.sort(key=lambda p: p["cpu"], reverse=True)
        top = procs[:5]

        if not top:
            return self._info("No process data available")

        top_cpu = top[0]["cpu"]
        top_name = _short_name(top[0]["comm"])

        # Build a compact summary of the top 3 processes for the result message.
        summary = "  ".join(
            f"{_short_name(p['comm'])} {p['cpu']:.0f}%" for p in top[:3]
        )

        if top_cpu >= 90:
            return self._warning(
                f"High CPU: {top_name} at {top_cpu:.0f}%  —  {summary}",
                data={"top_processes": top},
            )
        return self._pass(
            f"Top process: {top_name} at {top_cpu:.0f}%  —  {summary}",
            data={"top_processes": top},
        )


# ── Top memory consumers ──────────────────────────────────────────────────────

class TopMemoryCheck(BaseCheck):
    """List the top 5 memory-consuming processes for visibility into RAM usage.

    Unlike :class:`TopCPUCheck`, this check is purely informational — it does not
    produce a ``warning`` or ``critical`` result regardless of the values it
    finds. Its purpose is to give the user context for explaining high memory
    pressure or swap usage, not to flag a specific threshold.

    Detection mechanism:
        Runs ``ps -eo pid,pcpu,pmem,comm``, parses output via ``_parse_ps()``,
        sorts by ``pmem`` (memory percentage) descending, and reports the top 3
        in the result message.

    Why informational only:
        Memory usage percentages from ``ps`` (``pmem``) represent the Resident Set
        Size (RSS) as a fraction of total physical RAM and do not account for
        compressed memory, shared pages, or the GPU allocation pool. Setting hard
        thresholds on ``pmem`` would produce noisy false positives (e.g. a Chrome
        renderer at 8% on a 16 GB Mac is completely normal). The meaningful
        threshold for action is already surfaced by :class:`MemoryPressureCheck`.

    Attributes:
        id (str): ``"top_memory"`` — stable machine-readable identifier.
        name (str): ``"Top Memory Consumers"`` — display name in the report.
        category (str): ``"memory"`` — report section.
        category_icon (str): ``"📊"`` — emoji for the section header.
        scan_description (str): Shown during the scan narration.
        finding_explanation (str): Names the typical large memory consumers
            (Electron apps, browsers) to help the user self-diagnose.
        recommendation (str): Concrete guidance on which apps to quit.
        fix_level (str): ``"instructions"`` — quitting apps requires user
            decision; cannot be automated.
        fix_description (str): Brief Activity Monitor guidance.
        fix_steps (list[str]): Step-by-step Activity Monitor instructions.
        fix_reversible (bool): ``True`` — quitting apps is reversible.
        fix_time_estimate (str): ``"~2 minutes"`` to review and act.
    """

    id = "top_memory"
    name = "Top Memory Consumers"
    category = "memory"
    category_icon = "📊"

    scan_description = (
        "Checking which processes are using the most RAM — "
        "identifying memory hogs helps explain slow performance and high swap usage."
    )
    finding_explanation = (
        "Electron-based apps (Slack, Discord, VS Code, Zoom), browsers with many tabs, "
        "and some media apps routinely consume 1–3 GB each. Knowing the top consumers "
        "lets you make informed decisions about what to quit."
    )
    recommendation = (
        "Consider quitting apps you're not actively using. Browsers: close unused tabs "
        "or use tab suspension extensions. Slack/Discord: quit rather than hide when "
        "not in use."
    )

    fix_level = "instructions"
    fix_description = "Quit memory-heavy apps you don't need right now."
    fix_steps = [
        "Open Activity Monitor → Memory tab",
        "Sort by 'Memory' column",
        "Quit apps consuming large memory that you don't need",
    ]
    fix_reversible = True
    fix_time_estimate = "~2 minutes"

    def run(self) -> CheckResult:
        """Run ``ps -eo pid,pcpu,pmem,comm``, sort by memory%, and report the top 3.

        Calls ``ps`` with a 10-second timeout as a safety net. The output is
        parsed by the shared ``_parse_ps()`` helper. Processes are sorted by
        ``mem`` (pmem percentage) descending, and a compact summary string of
        the top 3 is included in the result message.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — ``ps`` failed or returned no parseable data.
            - ``"info"`` — always; this check is informational by design
              (no ``warning`` or ``critical`` conditions are defined).

            The result attaches a ``data`` dict with key ``"top_processes"``
            containing the top 5 process dicts (``pid``, ``cpu``, ``mem``,
            ``comm``) for downstream consumers such as the JSON report.

        Example::

            check = TopMemoryCheck()
            result = check.run()
            print(result.message)  # e.g. "Top memory consumers: Safari 8.1%  Slack 5.3%  ..."
        """
        rc, out, _ = self.shell(
            ["ps", "-eo", "pid,pcpu,pmem,comm"],
            timeout=10,
        )
        if rc != 0 or not out:
            return self._info("Could not read process list")

        procs = _parse_ps(out)
        procs.sort(key=lambda p: p["mem"], reverse=True)
        top = procs[:5]

        if not top:
            return self._info("No process data available")

        # Report the top 3 by memory % for a concise but informative message.
        summary = "  ".join(
            f"{_short_name(p['comm'])} {p['mem']:.1f}%" for p in top[:3]
        )

        return self._info(
            f"Top memory consumers: {summary}",
            data={"top_processes": top},
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_ps(output: str) -> list[dict]:
    """Parse ``ps -eo pid,pcpu,pmem,comm`` output into a list of process dicts.

    The ``ps`` output begins with a header line (``PID %CPU %MEM COMM``) that
    is unconditionally skipped by slicing ``output.splitlines()[1:]``. Each
    remaining line is split on whitespace with a maximum of 3 splits
    (``split(None, 3)``) to correctly handle command names that contain spaces
    (e.g. ``"Google Chrome Helper (Renderer)"``). Lines with fewer than 4 fields
    are silently skipped.

    Args:
        output (str): Raw standard output from the command
            ``ps -eo pid,pcpu,pmem,comm``.

    Returns:
        list[dict]: A list of process dictionaries. Each dict has the following
        keys:

        - ``"pid"`` (int): Process ID.
        - ``"cpu"`` (float): CPU usage as a percentage (0.0–100.0 per core).
        - ``"mem"`` (float): Resident set size as a percentage of total RAM.
        - ``"comm"`` (str): Full command path as reported by ``ps``
          (may be absolute path or relative name depending on the process).

        Lines that fail integer/float conversion (malformed ps output) are
        silently skipped.

    Note:
        ``pcpu`` in ``ps`` is not a real-time reading; it is a rolling exponential
        moving average of CPU utilisation since the process started. For long-lived
        processes (hours or days), this may understate a *recent* spike in CPU
        usage.

    Example::

        raw = "  PID  %CPU %MEM COMMAND\\n  123  45.2  3.1 /usr/bin/python3\\n"
        procs = _parse_ps(raw)
        # procs == [{"pid": 123, "cpu": 45.2, "mem": 3.1, "comm": "/usr/bin/python3"}]
    """
    procs = []
    for line in output.splitlines()[1:]:  # skip header
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        try:
            procs.append({
                "pid":  int(parts[0]),
                "cpu":  float(parts[1]),
                "mem":  float(parts[2]),
                "comm": parts[3].strip(),
            })
        except ValueError:
            # Malformed line (e.g. non-numeric PID in process table race condition);
            # skip it to keep the parse result clean.
            continue
    return procs


def _short_name(comm: str) -> str:
    """Shorten a process command path to just the basename, truncated to 24 characters.

    ``ps``'s ``comm`` field may contain an absolute path such as
    ``/Applications/Foo.app/Contents/MacOS/Foo`` or just the binary name.
    For display in the compact result message, only the final path component
    is needed. The result is truncated to 24 characters to keep lines
    a fixed width and avoid wrapping in the terminal report.

    Args:
        comm (str): The raw command value from ``ps -eo comm``. May be an
            absolute path, a relative path, or a bare binary name.

    Returns:
        str: The basename of the command path, truncated to 24 characters.
        If the input contains no ``"/"`` character, the input itself is
        returned (truncated to 24 characters).

    Example::

        _short_name("/Applications/Safari.app/Contents/MacOS/Safari")
        # Returns: "Safari"

        _short_name("com.apple.WebKit.WebContent")
        # Returns: "com.apple.WebKit.WebCon"  (24 chars)
    """
    return comm.rsplit("/", 1)[-1][:24]


# ── Export ────────────────────────────────────────────────────────────────────

#: Ordered list of memory and performance check classes exported to the scan
#: orchestrator. Order determines display order in the report's memory section.
ALL_CHECKS = [
    MemoryPressureCheck,
    SwapUsageCheck,
    TopCPUCheck,
    TopMemoryCheck,
]
