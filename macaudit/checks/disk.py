"""Disk and storage checks for macOS.

This module audits disk space and storage hygiene across eight dimensions:

1. **Free disk space** (``DiskSpaceCheck``) — Queries the boot volume's
   available bytes and grades the result across four severity tiers.

2. **APFS local snapshots** (``APFSSnapshotsCheck``) — Counts Time Machine
   local snapshots stored on the boot disk; reported as informational only,
   because macOS manages snapshot lifecycle automatically.

3. **Xcode DerivedData** (``XcodeDerivedDataCheck``) — Measures the Xcode
   build artifact cache, which can silently grow to 20–50 GB for active
   developers and is always safe to delete.

4. **Container runtime disk usage** (``DockerDiskCheck``) — Measures data
   directories for Docker Desktop, Colima, OrbStack, and Podman.

5. **Trash** (``TrashCheck``) — Reports how much space is consumed by files
   deleted from Finder but not yet permanently removed.

6. **Application caches** (``AppCachesCheck``) — Measures ``~/Library/Caches``,
   which apps grow without bound but which is always safe to clear.

7. **Log files** (``LogFilesCheck``) — Measures ``~/Library/Logs``, where
   app-level diagnostic logs accumulate indefinitely.

8. **iOS device backups** (``iOSBackupsCheck``) — Counts and measures iTunes/
   Finder device backups, which average 5–30 GB each and are never auto-cleaned.

Design decisions:
    - All size measurements use the ``du -sk`` command rather than Python's
      ``os.walk`` + ``os.stat`` approach. ``du`` is faster on APFS (avoids
      redundant ``stat`` calls on millions of inodes), handles sparse files
      correctly, and gracefully reports partial results when it encounters
      permission-denied subdirectories (exit code 1 with partial output).
    - The ``_du`` helper accepts exit code 1 from ``du`` so that measurements
      of user directories (e.g. ``~/Library/Caches``) work even when some
      app-specific subdirectories are protected by SIP or TCC.
    - The ``_df_free_bytes`` helper uses ``df -k`` (1-KB blocks) rather than
      ``df -b`` (bytes) because ``df -b`` is not available on all macOS
      versions.
    - APFS snapshot sizes are approximated via ``/.MobileBackups`` directory
      size, which is the user-visible proxy. The canonical ``tmutil`` approach
      would require iterating snapshots and is much slower.
    - The ``DockerDiskCheck`` also attempts ``docker system df`` (if the
      ``docker`` CLI is on ``$PATH``) for a richer "reclaimable" breakdown,
      but this is supplementary — the primary measurement is always the raw
      data directory size.

Attributes:
    HOME (Path): Resolved home directory of the running process. Used to
        construct all user-scoped paths (``~/Library/...``, ``~/.Trash``, etc.).
    ALL_CHECKS (list[type[BaseCheck]]): Ordered list of check classes exported
        to the main runner. Consumed by ``macaudit/main.py`` at startup.
"""

import re
import subprocess
from pathlib import Path

from macaudit.checks.base import BaseCheck, CheckResult

HOME = Path.home()


def _du(path: Path, timeout: int = 10) -> int:
    """Return the disk usage of a path in bytes, or -1 on unrecoverable error.

    Shells out to ``du -sk <path>`` (summarise, 1-KB blocks) and multiplies
    the reported value by 1024 to convert to bytes. Accepts ``du`` exit code 1
    because macOS ``du`` exits 1 when it encounters permission-denied
    subdirectories, yet still writes a valid total to stdout for the portions
    it could read.

    Args:
        path (Path): Filesystem path to measure. Must be an absolute path.
            If the path does not exist, 0 is returned immediately without
            invoking ``du``.
        timeout (int): Maximum seconds to wait for ``du`` to complete.
            Defaults to 10. Should be increased for large directories
            (e.g. Docker data dirs may need 15–20 s).

    Returns:
        int: Disk usage in bytes. Special values:

        - ``0`` — Path does not exist.
        - ``>0`` — Measured size in bytes (rounded to 1 KB by ``du``).
        - ``-1`` — ``du`` failed to produce parseable output (e.g. timeout,
          path disappeared between existence check and ``du`` invocation, or
          ``du`` output could not be parsed).

    Note:
        The return value is derived from the first whitespace-delimited token
        on stdout (the block count). If that token is not a pure digit string,
        -1 is returned rather than raising.

    Example::

        size = _du(Path.home() / "Library" / "Caches")
        if size > 0:
            print(f"Caches: {size / 1e9:.1f} GB")
    """
    if not path.exists():
        return 0
    try:
        r = subprocess.run(
            ["du", "-sk", str(path)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        # du exits 1 when it hits permission-denied subdirs but still outputs
        # a total — accept that result so partial measurements are still useful.
        if r.stdout and r.stdout.strip():
            parts = r.stdout.strip().split()
            if parts and parts[0].isdigit():
                return int(parts[0]) * 1024
    except Exception:
        pass
    return -1


def _fmt(size_bytes: int) -> str:
    """Format a byte count as a human-readable string with the largest applicable unit.

    Iterates GB → MB → KB, returning the first unit for which the value is
    >= 1. Values below 1 KB are returned as a plain byte count.

    Args:
        size_bytes (int): Size in bytes to format. May be negative (from
            ``_du`` error sentinel); ``-1`` is returned as ``"unknown"``.

    Returns:
        str: Human-readable size string with one decimal place and a unit
        suffix, e.g. ``"4.2 GB"``, ``"512.0 MB"``, ``"1.3 KB"``, ``"800 B"``.
        Returns ``"unknown"`` for any negative input.

    Example::

        print(_fmt(4_294_967_296))  # "4.3 GB"
        print(_fmt(524_288))        # "512.0 KB"
        print(_fmt(-1))             # "unknown"
    """
    if size_bytes < 0:
        return "unknown"
    for unit, threshold in [("GB", 1e9), ("MB", 1e6), ("KB", 1e3)]:
        if size_bytes >= threshold:
            return f"{size_bytes / threshold:.1f} {unit}"
    return f"{size_bytes} B"


def _df_free_bytes(path: str = "/") -> int:
    """Return the number of free bytes on the filesystem containing ``path``.

    Shells out to ``df -k <path>`` (POSIX 1-KB blocks) and extracts the
    "Available" column from the second output line. Multiplies by 1024 to
    convert from 1-KB blocks to bytes.

    Args:
        path (str): Mountpoint or any path on the filesystem to query.
            Defaults to ``"/"`` (the boot volume). Must be a string, not a
            ``Path`` object, because ``df`` is invoked via ``subprocess.run``.

    Returns:
        int: Free space in bytes, or ``-1`` if ``df`` failed, timed out,
        or produced output that could not be parsed (fewer than 4 columns
        on the data line, or a non-integer "Available" field).

    Note:
        ``df -k`` output format on macOS::

            Filesystem  1K-blocks  Used  Available  Capacity  iused  ifree ...
            /dev/disk3s5  976761856  ...  123456789  ...

        The "Available" column is index 3 (0-based) on the data line.

    Example::

        free = _df_free_bytes("/")
        if free > 0:
            print(f"Boot volume has {free / 1e9:.1f} GB free")
    """
    try:
        r = subprocess.run(
            ["df", "-k", path],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if r.returncode == 0:
            lines = r.stdout.strip().splitlines()
            if len(lines) >= 2:
                parts = lines[1].split()
                # df -k column layout: Filesystem | 1K-blocks | Used | Available | ...
                if len(parts) >= 4:
                    return int(parts[3]) * 1024
    except Exception:
        pass
    return -1


# ── Checks ────────────────────────────────────────────────────────────────────

class DiskSpaceCheck(BaseCheck):
    """Check free disk space on the boot volume and grade by severity tier.

    macOS requires free disk space for several critical functions: virtual
    memory swap files (``/private/var/vm``), software update staging, APFS
    snapshot allocation, and app temporary files. When available space drops
    below approximately 10 GB, the system begins to exhibit performance
    degradation and failed operations.

    Detection mechanism:
        Calls ``_df_free_bytes("/")`` which shells to ``df -k /`` and extracts
        the "Available" column. Result is compared against three thresholds.

    Severity scale:
        - ``pass``: >= 20 GB free.
        - ``info``: 10–20 GB free (adequate but worth monitoring).
        - ``warning``: 5–10 GB free (macOS performance begins to degrade).
        - ``critical``: < 5 GB free (macOS may become unstable; swap exhaustion
          likely).

    Attributes:
        id (str): ``"disk_space"``
        name (str): ``"Free Disk Space"``
        category (str): ``"disk"``
        category_icon (str): Emoji prefix for the TUI report.
        fix_level (str): ``"guided"`` — opens macOS Storage Management via a
            deep-link URL, which shows the largest space consumers.
        fix_url (str): Deep-link URL to Storage Management in System Settings.
        fix_reversible (bool): ``True`` — opening Storage Management makes no
            changes by itself.
        fix_time_estimate (str): Varies widely depending on what needs to be
            deleted.
    """

    id = "disk_space"
    name = "Free Disk Space"
    category = "disk"
    category_icon = "💽"

    scan_description = (
        "Checking available disk space — macOS needs free space for virtual "
        "memory, software updates, temporary files, and app caches."
    )
    finding_explanation = (
        "When free space drops below ~10 GB, macOS struggles: swap gets "
        "compressed aggressively (slowing everything), software updates fail "
        "to download, and apps crash trying to write temporary files."
    )
    recommendation = (
        "Free up space by emptying the Trash, removing unused apps, "
        "clearing ~/Library/Caches, and deleting large files you no longer need. "
        "macOS's Storage Management (Apple menu → About This Mac → More Info → Storage) "
        "can help identify space hogs."
    )
    fix_level = "guided"
    fix_description = "Opens Storage Management"
    fix_url = "x-apple.systempreferences:com.apple.settings.Storage"
    fix_reversible = True
    fix_time_estimate = "Varies"

    def run(self) -> CheckResult:
        """Query free bytes on the boot volume and return a severity-graded result.

        Calls ``_df_free_bytes("/")`` and converts the result to GB for
        threshold comparison. The four severity tiers map to distinct user
        situations: ample space, monitoring advisable, performance impact
        likely, and critical risk of instability.

        Returns:
            CheckResult: One of:

            - ``error`` — ``_df_free_bytes`` returned -1 (df failed).
            - ``critical`` — < 5 GB free.
            - ``warning`` — 5–10 GB free.
            - ``info`` — 10–20 GB free.
            - ``pass`` — >= 20 GB free.

            All non-error results include ``result.data["free_bytes"]``.

        Example::

            check = DiskSpaceCheck()
            result = check.run()
            # pass: "45.2 GB free"
            # warning: "8.1 GB free — getting low; macOS needs ~10 GB headroom"
        """
        free = _df_free_bytes("/")

        if free < 0:
            return self._error("Could not determine free disk space")

        free_str = _fmt(free)
        free_gb = free / 1e9

        if free_gb < 5:
            return self._critical(
                f"Only {free_str} free — macOS may become unstable",
                data={"free_bytes": free},
            )
        if free_gb < 10:
            return self._warning(
                f"{free_str} free — getting low; macOS needs ~10 GB headroom",
                data={"free_bytes": free},
            )
        if free_gb < 20:
            return self._info(
                f"{free_str} free — adequate but worth monitoring",
                data={"free_bytes": free},
            )

        return self._pass(
            f"{free_str} free",
            data={"free_bytes": free},
        )


class APFSSnapshotsCheck(BaseCheck):
    """Count local APFS snapshots stored on the boot volume by Time Machine.

    APFS local snapshots are point-in-time filesystem copies that Time Machine
    creates on the local disk while waiting to sync to an external backup
    drive. macOS manages their lifecycle automatically — reclaiming space when
    needed — but users are often unaware that 10–40 GB of their "available"
    space may be reserved for snapshots.

    Detection mechanism:
        Runs ``tmutil listlocalsnapshots /`` and counts the output lines.
        Attempts to approximate total size by running ``_du`` on
        ``/.MobileBackups``, the user-visible proxy directory for snapshot
        storage. This size measurement is a rough approximation only.

    Severity scale:
        Always ``info`` — macOS reclaims snapshot space automatically, so
        snapshot presence is never inherently a problem. The count and
        approximate size are surfaced for user awareness.

    Note:
        The recommended thinning command (``tmutil thinlocalsnapshots``) is
        documented in ``fix_steps`` with an explicit warning NOT to use
        ``tmutil deletelocalsnapshots``, which forcibly deletes all snapshots
        and can result in data loss if the external backup is not current.

    Attributes:
        id (str): ``"apfs_snapshots"``
        name (str): ``"APFS Local Snapshots"``
        fix_level (str): ``"instructions"`` — thinning requires a specific
            ``tmutil`` invocation that should only be run in low-space
            situations.
        fix_reversible (bool): ``False`` — thinned snapshots cannot be
            restored.
        fix_time_estimate (str): Approximately 1 minute for Time Machine to
            reclaim space from eligible snapshots.
    """

    id = "apfs_snapshots"
    name = "APFS Local Snapshots"
    category = "disk"
    category_icon = "💽"

    scan_description = (
        "Checking APFS local snapshots — Time Machine stores invisible snapshots "
        "on your disk that can consume 10–40 GB without showing up in Finder."
    )
    finding_explanation = (
        "APFS snapshots are point-in-time copies of your filesystem stored "
        "locally while waiting to sync to a Time Machine backup drive. "
        "macOS manages these automatically and reclaims space when needed, "
        "but if you're low on space they can be manually thinned."
    )
    recommendation = (
        "If you're very low on disk space, run: "
        "tmutil thinlocalsnapshots / 50000000000 4\n"
        "This asks Time Machine to reclaim 50 GB where safe. "
        "Do NOT manually delete snapshots — let Time Machine manage them."
    )
    fix_level = "instructions"
    fix_description = "Thin local snapshots (let Time Machine decide what's safe)"
    fix_steps = [
        "Only do this if you're very low on space",
        "Run: tmutil thinlocalsnapshots / 50000000000 4",
        "Time Machine will reclaim space from old snapshots safely",
        "Do NOT run tmutil deletelocalsnapshots — it's destructive",
    ]
    fix_reversible = False
    fix_time_estimate = "~1 minute"

    def run(self) -> CheckResult:
        """Run ``tmutil listlocalsnapshots /`` to count snapshots; measure ``/.MobileBackups``.

        If ``tmutil`` returns no output or exits non-zero (e.g. Time Machine
        has never been configured), ``info`` is returned without trying to
        measure size. Otherwise, the snapshot count and approximate size from
        ``/.MobileBackups`` are included in the result.

        Returns:
            CheckResult: Always ``info`` level:

            - ``info`` (no snapshots) — "No local APFS snapshots found".
            - ``info`` (snapshots found) — Count, approximate size, and note
              that macOS manages them automatically.
              ``result.data["snapshot_count"]`` and
              ``result.data["approx_size"]`` are populated.

        Example::

            check = APFSSnapshotsCheck()
            result = check.run()
            # info: "3 local APFS snapshots (12.4 GB) — managed automatically by Time Machine"
        """
        rc, stdout, _ = self.shell(
            ["tmutil", "listlocalsnapshots", "/"], timeout=8
        )

        if rc != 0 or not stdout.strip():
            return self._info("No local APFS snapshots found")

        snapshots = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
        n = len(snapshots)

        # /.MobileBackups is the user-visible proxy directory for APFS snapshot
        # storage. Its du output is a rough approximation — APFS deduplicated
        # data means actual consumption may differ.
        mb_path = Path("/.MobileBackups")
        size_bytes = _du(mb_path, timeout=5)
        size_str = _fmt(size_bytes) if size_bytes > 0 else "size unknown"

        return self._info(
            f"{n} local APFS snapshot{'s' if n != 1 else ''} "
            f"({size_str}) — managed automatically by Time Machine",
            data={"snapshot_count": n, "approx_size": size_str},
        )


class XcodeDerivedDataCheck(BaseCheck):
    """Measure the Xcode DerivedData folder size and flag when it is excessively large.

    Xcode stores compiled build products, module index data, and intermediate
    compiler outputs in ``~/Library/Developer/Xcode/DerivedData``. This
    directory is completely safe to delete at any time — Xcode regenerates it
    on the next build, though that build will be slower than usual.

    On active developer machines, DerivedData commonly grows to 20–50 GB as
    multiple projects accumulate build artifacts. Developers are often unaware
    of its size because it is hidden inside ``~/Library``.

    Detection mechanism:
        Calls ``_du(path, timeout=15)`` on
        ``~/Library/Developer/Xcode/DerivedData``. The 15-second timeout
        accommodates large directories with many small files.

    Severity scale:
        - ``pass``: Folder does not exist, or size < 2 GB.
        - ``info``: 2–10 GB.
        - ``warning``: >= 10 GB (worth the effort to delete).

    Attributes:
        id (str): ``"xcode_derived_data"``
        name (str): ``"Xcode DerivedData"``
        profile_tags (list[str]): ``["developer"]`` — only shown in developer
            profile runs.
        fix_level (str): ``"auto"`` — a single ``rm -rf`` command clears the
            folder; Xcode recreates it automatically.
        fix_command (list[str]): ``["rm", "-rf", "<path>"]`` where ``<path>``
            is the absolute DerivedData path.
        fix_reversible (bool): ``False`` — deleted build artifacts cannot be
            recovered; however, Xcode regenerates them automatically on next
            build.
        fix_time_estimate (str): The deletion itself takes ~10 seconds;
            warns that the next build will be slower.
    """

    id = "xcode_derived_data"
    name = "Xcode DerivedData"
    category = "disk"
    category_icon = "💽"
    profile_tags = ["developer"]

    scan_description = (
        "Checking Xcode's DerivedData folder — build artifacts accumulate here "
        "silently and can reach 20–50 GB for active developers."
    )
    finding_explanation = (
        "Xcode stores compiled build products, index data, and intermediate "
        "files in ~/Library/Developer/Xcode/DerivedData. It's completely safe "
        "to delete — Xcode recreates it on next build, though the first build "
        "will be slower."
    )
    recommendation = (
        "Delete DerivedData to reclaim space: "
        "rm -rf ~/Library/Developer/Xcode/DerivedData\n"
        "Or in Xcode: Product → Clean Build Folder"
    )
    fix_level = "auto"
    fix_description = "Deletes Xcode DerivedData (Xcode will rebuild it automatically)"
    fix_command = ["rm", "-rf", str(HOME / "Library/Developer/Xcode/DerivedData")]
    fix_reversible = False
    fix_time_estimate = "~10 seconds (next Xcode build will be slower)"

    def run(self) -> CheckResult:
        """Measure ``~/Library/Developer/Xcode/DerivedData`` via ``du -sk``.

        Returns early with ``pass`` if the directory does not exist (Xcode
        never installed or DerivedData was recently cleaned). The 15-second
        ``du`` timeout handles large developer directories with many small
        intermediate files.

        Returns:
            CheckResult: One of:

            - ``pass`` — Directory absent, or size < 2 GB.
            - ``info`` — 2–10 GB (notable but not urgent).
            - ``info`` — Directory exists but size could not be measured
              (``_du`` returned -1).
            - ``warning`` — >= 10 GB (recommend deletion).

            All results include ``result.data["size_bytes"]`` where measured.

        Example::

            check = XcodeDerivedDataCheck()
            result = check.run()
            # warning: "Xcode DerivedData is 23.4 GB — safe to delete"
        """
        path = HOME / "Library" / "Developer" / "Xcode" / "DerivedData"

        if not path.exists():
            return self._pass("No Xcode DerivedData folder found")

        size = _du(path, timeout=15)
        size_str = _fmt(size)

        if size < 0:
            return self._info("Xcode DerivedData exists (could not measure size)")

        size_gb = size / 1e9

        if size_gb >= 10:
            return self._warning(
                f"Xcode DerivedData is {size_str} — safe to delete",
                data={"path": str(path), "size_bytes": size},
            )
        if size_gb >= 2:
            return self._info(
                f"Xcode DerivedData is {size_str}",
                data={"path": str(path), "size_bytes": size},
            )

        return self._pass(
            f"Xcode DerivedData is {size_str} (manageable)",
            data={"size_bytes": size},
        )


class DockerDiskCheck(BaseCheck):
    """Measure disk usage across all detected container runtimes.

    Checks data directories for four container runtimes: Docker Desktop,
    Colima, OrbStack, and Podman. Container images, stopped containers,
    build cache, and volumes accumulate silently. Docker Desktop alone can
    consume 50–100 GB on an active machine.

    Detection mechanism:
        Tests for the existence of each runtime's data directory and calls
        ``_du`` on it. If the ``docker`` CLI is on ``$PATH``, additionally
        runs ``docker system df`` to surface a reclaimable breakdown (this
        is supplementary and does not affect severity).

    Data directory locations:
        - **Docker Desktop**: ``~/Library/Containers/com.docker.docker/Data``
        - **Colima**: ``~/.colima``
        - **OrbStack**: ``~/.orbstack``
        - **Podman**: ``~/.local/share/containers``

    Severity scale:
        - ``pass``: No container runtime detected.
        - ``info``: Runtime(s) found, total usage < 20 GB.
        - ``warning``: Total usage >= 20 GB (recommend ``docker system prune``).

    Attributes:
        id (str): ``"docker_disk"``
        name (str): ``"Docker / Container Runtime"``
        fix_level (str): ``"auto"`` — ``docker system prune -f`` is the
            canonical cleanup command.
        fix_command (list[str]): ``["docker", "system", "prune", "-f"]``
        fix_reversible (bool): ``False`` — pruned images and containers must
            be re-pulled or rebuilt.
        fix_time_estimate (str): Typically under 30 seconds.
    """

    id = "docker_disk"
    name = "Docker / Container Runtime"
    category = "disk"
    category_icon = "💽"

    scan_description = (
        "Checking Docker and container runtime disk usage — images, containers, "
        "and volumes can silently consume 20–100 GB."
    )
    finding_explanation = (
        "Container images, stopped containers, and unused volumes accumulate "
        "over time. Docker Desktop alone can use 50–100 GB. OrbStack and "
        "Colima are more disk-efficient alternatives, but all need occasional cleanup."
    )
    recommendation = (
        "Run 'docker system prune -a' to remove unused images, containers, "
        "and networks (add --volumes to also remove unused volumes)."
    )
    fix_level = "auto"
    fix_description = "Runs 'docker system prune' to remove unused Docker data"
    fix_command = ["docker", "system", "prune", "-f"]
    fix_reversible = False
    fix_time_estimate = "~30 seconds"

    def run(self) -> CheckResult:
        """Measure data directories for Docker Desktop, Colima, OrbStack, and Podman.

        Tests each runtime's data directory for existence and calls ``_du``
        with a 15-second timeout (Docker's data directory can be large). If
        the ``docker`` CLI is available, also runs ``docker system df`` to
        extract a reclaimable breakdown line; this information is supplementary
        and does not affect the severity classification.

        Returns:
            CheckResult: One of:

            - ``pass`` — No container runtime data directory found.
            - ``info`` — Runtime(s) detected, total usage < 20 GB.
            - ``warning`` — Total usage >= 20 GB.

            ``result.data["runtimes"]`` maps runtime names to sizes in bytes.
            ``result.data["total"]`` is the aggregate byte count (warning only).

        Example::

            check = DockerDiskCheck()
            result = check.run()
            # warning: "Container runtime using 42.1 GB: Docker Desktop: 40.3 GB, Colima: 1.8 GB"
        """
        runtimes: dict[str, int] = {}

        # Docker Desktop stores all container state under this path.
        docker_data = HOME / "Library" / "Containers" / "com.docker.docker" / "Data"
        if docker_data.exists():
            size = _du(docker_data, timeout=15)
            runtimes["Docker Desktop"] = size

        # Colima is a lightweight VM-based Docker runtime; state lives in ~/.colima.
        colima = HOME / ".colima"
        if colima.exists():
            size = _du(colima, timeout=15)
            runtimes["Colima"] = size

        # OrbStack is a Docker Desktop alternative; data lives in ~/.orbstack.
        orbstack = HOME / ".orbstack"
        if orbstack.exists():
            size = _du(orbstack, timeout=15)
            runtimes["OrbStack"] = size

        # Podman uses the XDG data home convention; its containers dir is here.
        podman = HOME / ".local" / "share" / "containers"
        if podman.exists():
            size = _du(podman, timeout=15)
            runtimes["Podman"] = size

        if not runtimes:
            return self._pass("No container runtime detected")

        # Supplement with docker system df if the CLI is available.
        # This provides a "reclaimable" breakdown but does not affect severity.
        df_summary = ""
        if self.has_tool("docker"):
            rc, stdout, _ = self.shell(["docker", "system", "df"], timeout=10)
            if rc == 0 and stdout:
                # Pull out the total or build cache line for additional context.
                for line in stdout.splitlines():
                    if "total" in line.lower() or "build cache" in line.lower():
                        df_summary = line.strip()
                        break

        # Sum all valid (positive) size measurements for the severity threshold.
        total_bytes = sum(s for s in runtimes.values() if s > 0)
        total_str = _fmt(total_bytes)

        lines = [f"{name}: {_fmt(size)}" for name, size in runtimes.items()]
        summary = ", ".join(lines)

        total_gb = total_bytes / 1e9

        if total_gb >= 20:
            return self._warning(
                f"Container runtime using {total_str}: {summary}",
                data={"runtimes": {k: v for k, v in runtimes.items()}, "total": total_bytes},
            )

        return self._info(
            f"Container runtime using {total_str}: {summary}",
            data={"runtimes": {k: v for k, v in runtimes.items()}},
        )


class TrashCheck(BaseCheck):
    """Measure the user's Trash folder size and flag when it is consuming significant space.

    Files deleted from Finder are moved to ``~/.Trash`` and remain there until
    the user explicitly empties the Trash. On a machine where the Trash has
    never been emptied (or has been overlooked), it can silently accumulate
    several gigabytes of deleted files.

    Detection mechanism:
        Calls ``_du(~/.Trash, timeout=10)``. If ``du`` reports 0 or an error,
        falls back to ``Path.iterdir()`` to determine whether the directory is
        actually empty (handles the case where ``du`` itself is confused by an
        empty directory).

    Severity scale:
        - ``pass``: Trash is absent or empty (no children).
        - ``info``: Trash is non-empty but < 500 MB.
        - ``warning``: >= 500 MB.

    Attributes:
        id (str): ``"trash"``
        name (str): ``"Trash"``
        fix_level (str): ``"auto"`` — the fix command uses ``find -delete``
            to remove all items under ``~/.Trash``.
        fix_command (list[str]): ``["find", "<path>", "-mindepth", "1", "-delete"]``
        fix_reversible (bool): ``False`` — emptying the Trash is permanent.
        fix_time_estimate (str): Typically a few seconds.
    """

    id = "trash"
    name = "Trash"
    category = "disk"
    category_icon = "💽"

    scan_description = (
        "Checking how much space is in the Trash — deleted files still consume "
        "disk space until the Trash is permanently emptied."
    )
    finding_explanation = (
        "Files in the Trash are deleted from Finder but still occupy disk space "
        "until you empty the Trash. This is a common source of 'mystery' disk usage."
    )
    recommendation = "Empty the Trash: right-click the Trash icon → Empty Trash."
    fix_level = "auto"
    fix_description = "Empties the Trash"
    fix_command = ["find", str(HOME / ".Trash"), "-mindepth", "1", "-delete"]
    fix_reversible = False
    fix_time_estimate = "~5 seconds"

    def run(self) -> CheckResult:
        """Measure ``~/.Trash`` via ``du -sk`` and return a severity-graded result.

        Falls back to ``Path.iterdir()`` when ``_du`` returns 0 or -1, to
        distinguish between "directory is empty" and "could not measure".
        This handles the edge case where ``du`` reports 0 bytes for an
        otherwise non-empty Trash containing only zero-byte files.

        Returns:
            CheckResult: One of:

            - ``pass`` — Trash does not exist, is empty, or appears empty.
            - ``info`` — Trash has content but < 500 MB.
            - ``info`` — Trash has items but size could not be measured.
            - ``warning`` — Trash contains >= 500 MB.

        Example::

            check = TrashCheck()
            result = check.run()
            # warning: "Trash contains 2.1 GB — empty it to reclaim space"
        """
        trash = HOME / ".Trash"

        if not trash.exists():
            return self._pass("Trash is empty")

        size = _du(trash, timeout=10)

        if size <= 0:
            # du reported 0 or error — fall back to directory listing to
            # distinguish "actually empty" from "could not measure".
            try:
                children = list(trash.iterdir())
                if not children:
                    return self._pass("Trash is empty")
                return self._info("Trash has items (could not measure size)")
            except OSError:
                return self._pass("Trash appears empty")

        size_str = _fmt(size)
        size_mb = size / 1e6

        if size_mb >= 500:
            return self._warning(
                f"Trash contains {size_str} — empty it to reclaim space",
                data={"size_bytes": size},
            )

        return self._info(
            f"Trash contains {size_str}",
            data={"size_bytes": size},
        )


class AppCachesCheck(BaseCheck):
    """Measure ``~/Library/Caches`` size and flag when it is excessively large.

    ``~/Library/Caches`` is the standard location where macOS apps store
    temporary data intended to speed up future operations (e.g. web content
    caches, compiled shader caches, search indexes). By design, caches are
    always safe to delete — every app recreates its cache on demand. However,
    apps do not reliably clean their own caches, and the directory can quietly
    grow to 5–20 GB over time.

    Detection mechanism:
        Calls ``_du(~/Library/Caches, timeout=15)``. The 15-second timeout
        accommodates large Caches directories with many small files.

    Severity scale:
        - ``pass``: Directory absent, or size < 3 GB.
        - ``info``: 3–10 GB.
        - ``warning``: >= 10 GB.

    Attributes:
        id (str): ``"app_caches"``
        name (str): ``"Application Caches"``
        fix_level (str): ``"instructions"`` — clearing caches requires
            manual review because some caches (e.g. Xcode, Safari) have
            in-app clearing workflows.
        fix_steps (list[str]): Guidance to navigate to the directory in
            Finder and delete large sub-folders, or run ``rm -rf`` after
            logging out.
        fix_reversible (bool): ``True`` — apps rebuild caches automatically.
        fix_time_estimate (str): About 5 minutes including review time.
    """

    id = "app_caches"
    name = "Application Caches"
    category = "disk"
    category_icon = "💽"

    scan_description = (
        "Checking ~/Library/Caches size — app caches grow without bound and "
        "can reach several gigabytes of data most apps will recreate on demand."
    )
    finding_explanation = (
        "Apps store temporary data in ~/Library/Caches to speed up future "
        "operations. Caches are designed to be safe to delete — apps rebuild "
        "them as needed. They can quietly grow to 5–20 GB over time."
    )
    recommendation = (
        "Clear caches carefully: some caches can be deleted directly from "
        "~/Library/Caches. Tools like CleanMyMac or OnyX can help. "
        "Alternatively, 'rm -rf ~/Library/Caches/*' is generally safe."
    )
    fix_level = "instructions"
    fix_description = "Clear app caches manually"
    fix_steps = [
        "Open Finder, press Cmd+Shift+G, enter ~/Library/Caches",
        "Review the largest folders",
        "Delete caches for apps you use regularly (they'll rebuild)",
        "Or run: rm -rf ~/Library/Caches/* (log out and back in first)",
    ]
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Measure ``~/Library/Caches`` via ``du -sk`` and return a graded result.

        Returns:
            CheckResult: One of:

            - ``pass`` — Directory absent or size < 3 GB.
            - ``info`` — 3–10 GB or size could not be measured.
            - ``warning`` — >= 10 GB.

            All measured results include ``result.data["size_bytes"]``.

        Example::

            check = AppCachesCheck()
            result = check.run()
            # warning: "App caches are 14.2 GB — consider clearing"
        """
        caches = HOME / "Library" / "Caches"

        if not caches.exists():
            return self._pass("~/Library/Caches not found")

        size = _du(caches, timeout=15)

        if size < 0:
            return self._info("Could not measure ~/Library/Caches size")

        size_str = _fmt(size)
        size_gb = size / 1e9

        if size_gb >= 10:
            return self._warning(
                f"App caches are {size_str} — consider clearing",
                data={"size_bytes": size},
            )
        if size_gb >= 3:
            return self._info(
                f"App caches are {size_str}",
                data={"size_bytes": size},
            )

        return self._pass(
            f"App caches are {size_str} (reasonable)",
            data={"size_bytes": size},
        )


class LogFilesCheck(BaseCheck):
    """Measure ``~/Library/Logs`` size and flag when it is consuming excessive space.

    Apps write diagnostic logs to ``~/Library/Logs`` for crash reporting and
    debugging. Unlike system logs in ``/var/log`` (which macOS rotates
    automatically via ``newsyslog``), user-space app logs are rarely rotated or
    cleaned up. On a machine with long-running apps or frequent crashes, this
    directory can grow to several gigabytes of log data that no one will ever
    read.

    Detection mechanism:
        Calls ``_du(~/Library/Logs, timeout=10)``.

    Severity scale:
        - ``pass``: Directory absent, or size < 200 MB.
        - ``info``: 200 MB – 1 GB.
        - ``warning``: >= 1 GB (1000 MB threshold for clean GB boundary).

    Note:
        Only ``~/Library/Logs`` is checked. System logs in ``/var/log`` are
        managed by macOS and should never be manually deleted.

    Attributes:
        id (str): ``"log_files"``
        name (str): ``"Log Files"``
        fix_level (str): ``"auto"`` — a single ``find -delete`` command removes
            all user log files; apps recreate them as needed.
        fix_command (list[str]): ``["find", "<path>", "-mindepth", "1", "-delete"]``
        fix_reversible (bool): ``False`` — deleted logs cannot be recovered, but
            apps generate new logs on their next run.
        fix_time_estimate (str): Typically a few seconds.
    """

    id = "log_files"
    name = "Log Files"
    category = "disk"
    category_icon = "💽"

    scan_description = (
        "Checking ~/Library/Logs size — app logs accumulate indefinitely and "
        "often reach gigabytes that nobody will ever read."
    )
    finding_explanation = (
        "Apps write diagnostic logs to ~/Library/Logs. Unlike system logs "
        "managed by macOS, user-space logs from apps rarely get cleaned up "
        "automatically and can quietly grow to several GB."
    )
    recommendation = (
        "Delete old logs: rm -rf ~/Library/Logs/*\n"
        "This is safe — apps create new log files as needed. "
        "System logs (/var/log) are managed by macOS and should not be deleted."
    )
    fix_level = "auto"
    fix_description = "Deletes user log files (apps recreate them as needed)"
    fix_command = ["find", str(HOME / "Library/Logs"), "-mindepth", "1", "-delete"]
    fix_reversible = False
    fix_time_estimate = "~5 seconds"

    def run(self) -> CheckResult:
        """Measure ``~/Library/Logs`` via ``du -sk`` and return a graded result.

        Returns:
            CheckResult: One of:

            - ``pass`` — Directory absent or size < 200 MB.
            - ``info`` — 200 MB – 1 GB, or size could not be measured.
            - ``warning`` — >= 1 GB (1000 MB threshold).

            All measured results include ``result.data["size_bytes"]``.

        Example::

            check = LogFilesCheck()
            result = check.run()
            # warning: "Log files are 3.2 GB — safe to delete"
        """
        logs = HOME / "Library" / "Logs"

        if not logs.exists():
            return self._pass("~/Library/Logs not found")

        size = _du(logs, timeout=10)

        if size < 0:
            return self._info("Could not measure ~/Library/Logs size")

        size_str = _fmt(size)
        size_mb = size / 1e6

        if size_mb >= 1000:
            return self._warning(
                f"Log files are {size_str} — safe to delete",
                data={"size_bytes": size},
            )
        if size_mb >= 200:
            return self._info(
                f"Log files are {size_str}",
                data={"size_bytes": size},
            )

        return self._pass(
            f"Log files are {size_str} (fine)",
            data={"size_bytes": size},
        )


class iOSBackupsCheck(BaseCheck):
    """Check for old iOS/iPadOS device backups consuming disk space.

    iTunes (macOS Catalina and earlier) and Finder (macOS Big Sur and later)
    store full device backups in
    ``~/Library/Application Support/MobileSync/Backup``. Each device gets its
    own uniquely named subdirectory. Backups from old phones, loaner devices,
    and factory-reset devices are never automatically deleted and can each
    consume 5–30 GB.

    Detection mechanism:
        Lists subdirectories of the Backup directory (one per device) using
        ``Path.iterdir()``. Measures total backup size with ``_du`` (20-second
        timeout because backup directories can be large and deeply nested).

    Severity scale:
        - ``pass``: Backup directory absent or contains no device subdirectories.
        - ``info``: 1–3 device backups AND total size < 20 GB.
        - ``warning``: > 3 device backups OR total size >= 20 GB.

    Note:
        Reading the Backup directory requires Full Disk Access on macOS
        Ventura and later. If FDA is not granted, a ``PermissionError`` is
        caught and an informational message guides the user to grant access
        via System Settings.

    Attributes:
        id (str): ``"ios_backups"``
        name (str): ``"iOS Device Backups"``
        fix_level (str): ``"instructions"`` — deletion is best done through
            Finder's "Manage Backups" UI to avoid accidentally removing a
            backup that is still needed.
        fix_steps (list[str]): Step-by-step guide using Finder's device
            management UI, plus the manual filesystem path as an alternative.
        fix_reversible (bool): ``False`` — deleted backups cannot be recovered.
        fix_time_estimate (str): About 5 minutes to review and delete.
    """

    id = "ios_backups"
    name = "iOS Device Backups"
    category = "disk"
    category_icon = "💽"

    scan_description = (
        "Checking for old iOS/iPadOS device backups — each backup is 5–30 GB "
        "and backups from devices you no longer own accumulate unnoticed."
    )
    finding_explanation = (
        "iTunes/Finder stores full device backups in ~/Library/Application Support/"
        "MobileSync/Backup. Each device gets its own folder. Old phones, "
        "loaner devices, and replaced iPads leave behind backups nobody needs."
    )
    recommendation = (
        "In Finder, connect your device → Manage Backups to see and delete old ones. "
        "Or browse ~/Library/Application Support/MobileSync/Backup directly."
    )
    fix_level = "instructions"
    fix_description = "Delete old device backups through Finder"
    fix_steps = [
        "Connect any iOS device to your Mac",
        "In Finder's sidebar, select the device",
        "Click 'Manage Backups' to see all stored backups",
        "Right-click old/unknown device backups and delete them",
        "Or navigate to ~/Library/Application Support/MobileSync/Backup",
    ]
    fix_reversible = False
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Count and measure device backup subdirectories in the MobileSync Backup folder.

        Lists subdirectories of
        ``~/Library/Application Support/MobileSync/Backup`` (each directory
        represents one device backup). Measures total size with a 20-second
        timeout. Handles ``PermissionError`` gracefully by returning an
        ``info`` result with guidance to grant Full Disk Access.

        Returns:
            CheckResult: One of:

            - ``pass`` — Backup directory absent or contains no subdirectories.
            - ``info`` — 1–3 device backups, total size < 20 GB.
            - ``info`` — Backup directory exists but requires Full Disk Access
              to read (returns guidance to grant FDA).
            - ``info`` — OS-level error reading the directory.
            - ``warning`` — > 3 device backups OR total size >= 20 GB.

            ``result.data["backup_count"]`` and ``result.data["size_bytes"]``
            are populated when backups are found.

        Example::

            check = iOSBackupsCheck()
            result = check.run()
            # warning: "5 iOS backups (48.2 GB) — consider removing old device backups"
        """
        backup_dir = (
            HOME / "Library" / "Application Support" / "MobileSync" / "Backup"
        )

        if not backup_dir.exists():
            return self._pass("No iOS device backups found")

        try:
            devices = [d for d in backup_dir.iterdir() if d.is_dir()]
        except PermissionError:
            # On macOS Ventura+, reading MobileSync/Backup requires Full Disk Access.
            return self._info(
                "iOS backup directory exists but requires Full Disk Access to read "
                "(grant in System Settings → Privacy & Security → Full Disk Access)"
            )
        except OSError:
            return self._info("Could not read iOS backup directory")

        n = len(devices)
        if n == 0:
            return self._pass("No iOS device backups found")

        # Measure total backup size; 20 s timeout for potentially large nested directories.
        size = _du(backup_dir, timeout=20)
        size_str = _fmt(size) if size > 0 else "unknown size"

        size_gb = size / 1e9 if size > 0 else 0

        # Trigger warning if there are many backups OR the total size is large.
        if n > 3 or size_gb >= 20:
            return self._warning(
                f"{n} iOS backup{'s' if n != 1 else ''} ({size_str}) — "
                f"consider removing old device backups",
                data={"backup_count": n, "size_bytes": size},
            )

        return self._info(
            f"{n} iOS backup{'s' if n != 1 else ''} ({size_str})",
            data={"backup_count": n, "size_bytes": size},
        )


# ── Public list for main.py ───────────────────────────────────────────────────
# Consumed by macaudit/main.py to discover and register all checks in this module.
# Order here determines the order checks appear within the "disk" category.

ALL_CHECKS: list[type[BaseCheck]] = [
    DiskSpaceCheck,
    APFSSnapshotsCheck,
    XcodeDerivedDataCheck,
    DockerDiskCheck,
    TrashCheck,
    AppCachesCheck,
    LogFilesCheck,
    iOSBackupsCheck,
]
