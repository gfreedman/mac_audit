"""
macOS system detection — version, architecture, and hardware model.

This module is the single authoritative source for host-system facts used
across every check module.  It is imported at module load time by all
checks, so correctness and performance are critical:

  - All expensive calls (``system_profiler``, ``sysctl``) are cached with
    ``@lru_cache`` so they execute at most once per process lifetime.
  - The module-level constants are populated eagerly at import time using
    the cheap ``platform`` stdlib module; no subprocess is needed.
  - The ``_run()`` helper never raises — all errors return ``""``.

Typical import pattern in check modules::

    from macaudit.system_info import IS_APPLE_SILICON, MACOS_VERSION

Attributes:
    MACOS_VERSION (tuple[int, int]): Two-element tuple of the running
        macOS major and minor version numbers, e.g. ``(15, 3)`` for
        macOS Sequoia 15.3.  Populated at import time via
        ``platform.mac_ver()``.
    IS_APPLE_SILICON (bool): ``True`` when the process is running
        natively on an Apple Silicon chip (arm64 architecture).
        ``False`` on Intel Macs or Rosetta 2 translation.
    MACOS_VERSION_STRING (str): Full version string as reported by
        ``platform.mac_ver()``, e.g. ``"15.3.1"``.

Note:
    All public constants are computed at import time and are read-only.
    Modifying them at runtime has no effect on already-resolved checks.
"""

import platform
import subprocess
import shutil
from functools import lru_cache
from typing import Any


# ── Module-level constants — imported by every check ─────────────────────────
# These are resolved once at import time using the lightweight ``platform``
# module to avoid spawning subprocesses on every check execution.

MACOS_VERSION: tuple[int, int] = tuple(
    map(int, platform.mac_ver()[0].split(".")[:2])
)
"""Two-element tuple ``(major, minor)`` of the running macOS version.

Examples: ``(13, 0)`` for Ventura, ``(14, 5)`` for Sonoma 14.5,
``(15, 3)`` for Sequoia 15.3.  Used by ``BaseCheck.execute()`` to gate
checks that require a minimum macOS version.
"""

IS_APPLE_SILICON: bool = platform.machine() == "arm64"
"""``True`` when running natively on Apple Silicon (arm64).

Note: This is ``False`` when a native arm64 Python is running inside a
Rosetta 2 x86_64 process, but that scenario is uncommon in practice.
"""

MACOS_VERSION_STRING: str = platform.mac_ver()[0]
"""Full dotted macOS version string, e.g. ``"15.3.1"``.

Used in human-readable messages.  Prefer ``MACOS_VERSION`` tuple for
programmatic version comparisons.
"""


def _run(cmd: list[str], timeout: int = 5) -> str:
    """Run a shell command and return its stdout as a stripped string.

    This is a lightweight helper used **only** within this module for the
    initial hardware queries.  Check modules should use
    ``BaseCheck.shell()`` instead, which provides richer error reporting
    and the C-locale override.

    Args:
        cmd (list[str]): The command and its arguments, e.g.
            ``["sysctl", "-n", "hw.model"]``.
        timeout (int): Maximum time in seconds before aborting.
            Defaults to 5.

    Returns:
        str: Stripped stdout of the command on success, or ``""`` on any
        error (timeout, file-not-found, permission denied, etc.).

    Note:
        Exceptions are intentionally swallowed.  The callers all have
        graceful fallbacks for an empty string return value.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout.strip()
    except Exception:
        # Any error (TimeoutExpired, FileNotFoundError, OSError) returns
        # an empty string.  The callers handle this gracefully.
        return ""


@lru_cache(maxsize=1)
def get_system_info() -> dict[str, Any]:
    """Return a dictionary describing the current Mac's hardware and software.

    Results are memoized with ``lru_cache`` so the potentially slow
    ``system_profiler`` call only runs once per process lifetime.

    Returns:
        dict[str, Any]: A dictionary with the following keys:

            ``macos_version`` (str)
                Full dotted version string, e.g. ``"15.3.1"``.
            ``macos_version_tuple`` (tuple[int, int])
                ``(major, minor)`` tuple, e.g. ``(15, 3)``.
            ``macos_name`` (str)
                Marketing name, e.g. ``"Sequoia"``, or the major-version
                number as a string for unknown future releases.
            ``architecture`` (str)
                ``"Apple Silicon"`` or ``"Intel"``.
            ``machine`` (str)
                Raw ``platform.machine()`` value: ``"arm64"`` or
                ``"x86_64"``.
            ``hostname`` (str)
                Network hostname, e.g. ``"Geoffs-MacBook-Pro.local"``.
            ``model_name`` (str)
                Human-readable model string, e.g.
                ``"MacBook Pro (M3 Max)"`` or the raw sysctl identifier
                as fallback.
            ``cpu_brand`` (str)
                CPU description, e.g. ``"Apple M3 Max"`` or
                ``"Intel Core i9"``.
            ``ram_gb`` (int)
                Physical RAM in gigabytes (integer division of bytes).
                Returns ``0`` if detection fails.
            ``has_brew`` (bool)
                ``True`` if ``brew`` is present in ``PATH``.
            ``has_macports`` (bool)
                ``True`` if ``port`` (MacPorts) is present in ``PATH``.

    Example::

        >>> info = get_system_info()
        >>> print(info["model_name"])
        MacBook Pro (M3 Max)
    """
    macos_name = _macos_name(MACOS_VERSION[0])
    model_name = _model_name()
    cpu_brand = _cpu_brand()
    ram_gb = _ram_gb()

    return {
        "macos_version": MACOS_VERSION_STRING,
        "macos_version_tuple": MACOS_VERSION,
        "macos_name": macos_name,
        "architecture": "Apple Silicon" if IS_APPLE_SILICON else "Intel",
        "machine": platform.machine(),
        "hostname": platform.node(),
        "model_name": model_name,
        "cpu_brand": cpu_brand,
        "ram_gb": ram_gb,
        "has_brew": shutil.which("brew") is not None,
        "has_macports": shutil.which("port") is not None,
    }


# ── Internal helpers ───────────────────────────────────────────────────────────

# Mapping of macOS major version integers to Apple marketing names.
# New entries should be added here when Apple releases a new major version.
_MACOS_NAMES: dict[int, str] = {
    13: "Ventura",
    14: "Sonoma",
    15: "Sequoia",
    16: "Tahoe",
}


def _macos_name(major: int) -> str:
    """Map a macOS major version integer to its Apple marketing name.

    Args:
        major (int): The major component of the macOS version, e.g. ``15``.

    Returns:
        str: The marketing name (e.g. ``"Sequoia"``), the major version
        as a string for unknown future versions (e.g. ``"16"``), or
        ``"Unknown"`` for versions below the known range.

    Note:
        Rather than raising for unknown future versions, the function
        returns the version number itself (e.g. ``"16"``), since the
        header already prepends ``"macOS"`` in the UI.
    """
    # Check the known-names table first for an O(1) lookup.
    name = _MACOS_NAMES.get(major)
    if name:
        return name

    # For future major versions not yet in the table, use the number itself
    # as a graceful fallback rather than "Unknown".
    if major >= 16:
        return str(major)

    # Anything older than Ventura (13) is truly unknown/historical.
    return "Unknown"


def _model_name() -> str:
    """Return a human-readable Mac model identifier.

    Attempts two strategies in order of speed:
      1. ``sysctl hw.model`` — fast (< 1 ms), returns machine-readable
         identifiers like ``"MacBookPro18,3"``.
      2. ``system_profiler SPHardwareDataType`` — slow (~500 ms), but
         returns the marketing name like ``"MacBook Pro"``.

    Returns:
        str: The marketing model name if ``system_profiler`` is available,
        the raw sysctl identifier string as a fallback, or ``"Mac"`` if
        both fail.

    Note:
        The result is not cached here because ``get_system_info()`` is
        decorated with ``@lru_cache`` and calls this exactly once.
    """
    # sysctl is always available and fast; used as a fallback identifier.
    brand = _run(["sysctl", "-n", "hw.model"])  # e.g. "MacBookPro18,3"
    if not brand:
        return "Mac"

    # system_profiler provides the friendly marketing name but is slower.
    # Parse only the "Model Name" line to avoid iterating the full output.
    sp = _run(
        ["system_profiler", "SPHardwareDataType"],
        timeout=5,
    )
    for line in sp.splitlines():
        if "Model Name" in line:
            # Line format: "      Model Name: MacBook Pro"
            return line.split(":", 1)[-1].strip()

    # system_profiler unavailable or "Model Name" line absent — fall back
    # to the raw sysctl identifier (e.g. "MacBookPro18,3").
    return brand


def _cpu_brand() -> str:
    """Return a human-readable CPU description string.

    Intel Macs expose the brand string via sysctl ``machdep.cpu.brand_string``
    (e.g. ``"Intel Core i9-9900K CPU @ 3.60GHz"``).  Apple Silicon Macs
    do not populate this key, so a composite fallback is built from
    ``hw.model`` instead.

    Returns:
        str: CPU description, e.g. ``"Apple M3 Max"``,
        ``"Intel Core i9"``, or ``"Apple Silicon (MacBookPro18,3)"``
        as a last-resort fallback.
    """
    brand = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
    if brand:
        return brand

    # Apple Silicon: machdep.cpu.brand_string is not available.
    # Build a reasonable description from the model identifier.
    chip = _run(["sysctl", "-n", "hw.model"])
    return f"Apple Silicon ({chip})" if chip else "Unknown CPU"


def _ram_gb() -> int:
    """Return total physical RAM in whole gigabytes.

    Reads ``hw.memsize`` via sysctl, which returns the raw byte count as
    a decimal string (e.g. ``"34359738368"`` for 32 GiB).

    Returns:
        int: RAM size rounded down to the nearest gigabyte, e.g. ``32``.
        Returns ``0`` if sysctl output cannot be parsed as an integer.
    """
    mem_bytes_str = _run(["sysctl", "-n", "hw.memsize"])
    try:
        # Integer-divide by 1 GiB (1024^3 bytes) for the whole-GB value.
        return int(mem_bytes_str) // (1024 ** 3)
    except (ValueError, TypeError):
        # Malformed or absent output — return 0 as a safe sentinel.
        return 0
