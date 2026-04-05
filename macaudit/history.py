"""
Scan history — persist full scan snapshots for inter-scan diffing.

Each completed scan is serialised to a JSON file under
``~/.config/macaudit/history/`` using a UTC ISO-8601 timestamp as the
filename.  The directory is created on first write and is capped at
``_MAX_SCANS`` files; older files are pruned automatically after each save.

JSON schema (``schema_version: 1``)::

    {
        "schema_version": 1,
        "macaudit_version": "1.12.0",
        "scan_time": "2025-04-04T12:00:00+00:00",
        "system": {
            "macos_version": "15.3.1",
            "architecture": "Apple Silicon",
            "model": "MacBook Pro (M3 Max)"
        },
        "score": 87,
        "summary": {"pass": 52, "warning": 4, "critical": 1, ...},
        "results": [ ... ]   // serialised CheckResult dataclasses
    }

Design decisions:
    - The payload shape intentionally mirrors the ``--json`` CLI output so
      that external tools consuming ``--json`` can also parse history files.
    - All I/O operations are wrapped in ``try/except OSError`` so a history
      write failure never crashes a scan.
    - ``_build_payload()`` is module-private but also imported directly by
      ``main.py`` for diff computation (to avoid building the payload twice).

Attributes:
    _HISTORY_DIR (pathlib.Path): Filesystem path to the history directory.
    _MAX_SCANS (int): Maximum number of scan snapshots to retain.
        Older files beyond this cap are deleted by ``prune_history()``.
"""

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from macaudit import __version__
from macaudit.checks.base import CheckResult, calculate_health_score


# ── Constants ─────────────────────────────────────────────────────────────────

# The history directory lives alongside other macaudit runtime state.
_HISTORY_DIR = Path.home() / ".config" / "macaudit" / "history"

# Retain only the most recent _MAX_SCANS snapshots; older ones are pruned.
# 10 scans provides roughly 10 days of history for daily users.
_MAX_SCANS = 10


# ── Public API ────────────────────────────────────────────────────────────────

def save_scan(results: list[CheckResult]) -> Optional[Path]:
    """Persist a completed scan to the history directory as a JSON file.

    The file is named using a UTC timestamp (``YYYY-MM-DDTHH-MM-SS.json``)
    to guarantee lexicographic sort order equals chronological order.
    After writing, ``prune_history()`` is called to enforce the cap.

    Args:
        results (list[CheckResult]): The complete list of check results
            returned by a scan run.  All results, including ``skip`` and
            ``error`` statuses, are included so that diffs accurately
            reflect suppressed checks.

    Returns:
        Optional[pathlib.Path]: The ``Path`` of the written file on
        success, or ``None`` if the write fails (e.g. disk full,
        permission denied).

    Note:
        Failure to save history is non-fatal.  The scan output has already
        been displayed to the user; this is only persistence for future
        diff computation.

    Example::

        path = save_scan(results)
        if path:
            print(f"History saved to {path}")
    """
    payload = _build_payload(results)

    # Format timestamp with hyphens instead of colons so the filename is
    # valid on all filesystems (colons are illegal in NTFS/FAT paths).
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    path = _HISTORY_DIR / f"{ts}.json"

    try:
        # Create intermediate directories if this is the first scan.
        _HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2))
    except OSError:
        return None

    # Enforce the maximum-scans cap after writing the new file.
    prune_history()
    return path


def load_previous_scan() -> Optional[dict]:
    """Return the most recent historical scan payload, or ``None``.

    Scans the ``_HISTORY_DIR`` for ``*.json`` files, sorts them
    lexicographically (which equals chronological order because filenames
    are ISO-8601 timestamps), and loads the last (newest) file.

    Returns:
        Optional[dict]: The parsed JSON dict of the most recent scan, or
        ``None`` if the history directory is absent, empty, or the newest
        file contains invalid JSON.

    Note:
        Only ``JSONDecodeError`` and ``OSError`` are caught.  A corrupt
        history file returns ``None`` to the caller; no exception
        propagates to the scan orchestrator.

    Example::

        previous = load_previous_scan()
        if previous:
            diff = compute_diff(current_payload, previous)
    """
    try:
        # Sorted glob gives chronological order (filename = timestamp).
        files = sorted(_HISTORY_DIR.glob("*.json"))
    except OSError:
        # History directory absent or not accessible.
        return None

    if not files:
        return None

    try:
        # Load only the newest file — we never need older history directly.
        return json.loads(files[-1].read_text())
    except (json.JSONDecodeError, OSError):
        return None


def prune_history() -> None:
    """Delete the oldest history files to stay within the ``_MAX_SCANS`` cap.

    Files are sorted lexicographically; those beyond the *last*
    ``_MAX_SCANS`` entries are deleted.  Individual deletion failures
    are silently ignored so a locked file never blocks future writes.

    Note:
        This is called automatically by ``save_scan()`` after every write.
        Manual invocation is not normally needed.
    """
    try:
        files = sorted(_HISTORY_DIR.glob("*.json"))
    except OSError:
        return

    # ``files[:-_MAX_SCANS]`` is empty when len(files) <= _MAX_SCANS,
    # so no deletions occur in the normal case.
    for old in files[:-_MAX_SCANS]:
        try:
            old.unlink()
        except OSError:
            # Silently skip locked or already-deleted files.
            pass


# ── Internal ──────────────────────────────────────────────────────────────────

def _build_payload(results: list[CheckResult]) -> dict:
    """Serialise a list of ``CheckResult`` objects into the canonical JSON payload.

    This function produces a dict in the same schema as ``_output_json`` in
    ``main.py`` so that history files and ``--json`` output are identical in
    structure.  It is intentionally a module-level function (not a method)
    because ``main.py`` imports it directly to compute the diff without
    re-serialising the results a second time.

    Args:
        results (list[CheckResult]): All results from a completed scan,
            including any with ``skip`` or ``error`` status.

    Returns:
        dict: A fully-populated payload dict with keys::

            schema_version, macaudit_version, scan_time, system,
            score, summary, results

        ``results`` is a list of ``dataclasses.asdict()``-serialised
        ``CheckResult`` dicts, with the ``min_macos`` tuple converted to
        a list for JSON compatibility.

    Note:
        ``from macaudit.system_info import get_system_info`` is imported
        lazily inside this function to avoid a circular import when
        ``history`` and ``system_info`` are both loaded at startup.
    """
    # Lazy import avoids circular dependency at module load time.
    from macaudit.system_info import get_system_info

    info = get_system_info()

    # Compute per-status counts for the "summary" section.
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    # Convert each CheckResult dataclass to a plain dict for JSON serialisation.
    serialised = []
    for r in results:
        d = dataclasses.asdict(r)
        # tuples are not valid JSON; convert min_macos tuple → list.
        d["min_macos"] = list(d["min_macos"])
        serialised.append(d)

    return {
        "schema_version":    1,
        "macaudit_version":  __version__,
        "scan_time":         datetime.now(timezone.utc).isoformat(),
        "system": {
            "macos_version": info["macos_version"],
            "architecture":  info["architecture"],
            "model":         info["model_name"],
        },
        "score":   calculate_health_score(results),
        "summary": counts,
        "results": serialised,
    }
