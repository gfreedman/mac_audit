"""
Scan diffing — compare two scan payloads and return structured changes.

This module implements **pure diffing logic** with no I/O or side-effects.
It consumes two JSON-shaped dicts (in the same schema as ``--json`` output)
and produces a diff dict describing what changed between them.

Diff categories:
    ``improved``
        Checks whose severity *decreased* (e.g. ``critical`` → ``pass``).
    ``regressed``
        Checks whose severity *increased* (e.g. ``pass`` → ``critical``).
    ``new_checks``
        Checks present in *current* but absent in *previous*
        (e.g. a new macaudit version added a check).
    ``removed_checks``
        Checks present in *previous* but absent in *current*
        (e.g. a check was removed or excluded via ``--skip``).

Filter-mismatch suppression:
    When the user runs two scans with different ``--only`` / ``--skip``
    flags, many checks will appear as added or removed even though no
    real change occurred.  If more than 50% of checks are in the
    ``new_checks`` or ``removed_checks`` buckets, those buckets are
    cleared to avoid misleading noise in the diff panel.

Attributes:
    _STATUS_SEVERITY (dict[str, int]): Maps each status string to an
        integer severity rank used to determine improvement vs regression.
        Higher values are more severe.

Note:
    All functions in this module are stateless and side-effect-free.
    They may be called freely from tests without any setup.
"""

from typing import Optional


# ── Status severity ranking ──────────────────────────────────────────────────
# Maps each check status to an integer rank.  A decrease in rank
# (curr_sev < prev_sev) means the check improved; an increase means
# it regressed.  ``pass`` is the best state (0); ``critical`` is worst (5).

_STATUS_SEVERITY: dict[str, int] = {
    "pass":     0,
    "info":     1,
    "skip":     2,
    "warning":  3,
    "error":    4,
    "critical": 5,
}


# ── Public API ────────────────────────────────────────────────────────────────

def compute_diff(current: dict, previous: dict) -> Optional[dict]:
    """Compare two scan payloads and return a structured diff dict.

    The two payloads must share the same ``schema_version``; diffing
    across incompatible schemas would produce meaningless results.  Both
    dicts must follow the JSON output schema (see ``_output_json`` in
    ``main.py`` for the canonical shape).

    The function returns ``None`` rather than an empty diff dict when there
    are no meaningful changes, allowing callers to skip the diff panel
    entirely.

    Args:
        current (dict): The payload produced by the just-completed scan.
            Must contain ``schema_version``, ``score``, and ``results``
            keys in the standard JSON output format.
        previous (dict): The most recent historical payload loaded from
            ``~/.config/macaudit/history/``.  Must share the same
            ``schema_version`` as *current*.

    Returns:
        Optional[dict]: A diff dict with the following keys on success::

            {
                "previous_scan_time": str,   # ISO-8601 timestamp
                "score_before":       int,   # health score of previous scan
                "score_after":        int,   # health score of current scan
                "score_delta":        int,   # score_after - score_before
                "improved":           list,  # checks that got better
                "regressed":          list,  # checks that got worse
                "new_checks":         list,  # checks only in current
                "removed_checks":     list,  # checks only in previous
            }

        Returns ``None`` if:
          - ``schema_version`` differs between the two payloads, OR
          - The diff contains no meaningful changes (score unchanged,
            no improved/regressed/new/removed checks).

    Note:
        Each entry in ``improved``, ``regressed``, ``new_checks``, and
        ``removed_checks`` is a dict with keys ``id``, ``name``,
        ``category``, ``status``, and ``message``.

    Example::

        diff = compute_diff(current_payload, previous_payload)
        if diff:
            print(f"Score changed by {diff['score_delta']} points")
    """
    # Refuse to diff across schema versions; the field shapes may differ.
    if current.get("schema_version") != previous.get("schema_version"):
        return None

    score_before = previous.get("score", 0)
    score_after  = current.get("score", 0)
    score_delta  = score_after - score_before

    # Index both scan result lists by check ID for O(1) cross-reference.
    prev_by_id: dict[str, dict] = {
        r["id"]: r for r in previous.get("results", [])
    }
    curr_by_id: dict[str, dict] = {
        r["id"]: r for r in current.get("results", [])
    }

    improved:       list[dict] = []
    regressed:      list[dict] = []
    new_checks:     list[dict] = []
    removed_checks: list[dict] = []

    # ── Compare checks present in both scans ──────────────────────────────────
    # For each check that appeared in both scans, compare severity ranks.
    # A lower rank in the current scan means improvement; higher means regression.
    common_ids = set(prev_by_id) & set(curr_by_id)
    for check_id in common_ids:
        prev_r = prev_by_id[check_id]
        curr_r = curr_by_id[check_id]

        prev_sev = _STATUS_SEVERITY.get(prev_r.get("status", ""), 0)
        curr_sev = _STATUS_SEVERITY.get(curr_r.get("status", ""), 0)

        if curr_sev < prev_sev:
            # The check status improved (e.g. critical → pass).
            improved.append({
                "id":            check_id,
                "name":          curr_r.get("name", ""),
                "category":      curr_r.get("category", ""),
                "before_status": prev_r.get("status", ""),
                "after_status":  curr_r.get("status", ""),
                "message":       curr_r.get("message", ""),
            })
        elif curr_sev > prev_sev:
            # The check status regressed (e.g. pass → warning).
            regressed.append({
                "id":            check_id,
                "name":          curr_r.get("name", ""),
                "category":      curr_r.get("category", ""),
                "before_status": prev_r.get("status", ""),
                "after_status":  curr_r.get("status", ""),
                "message":       curr_r.get("message", ""),
            })

    # ── Checks added in the current scan ──────────────────────────────────────
    # These are checks that exist now but did not exist in the previous scan.
    for check_id in set(curr_by_id) - set(prev_by_id):
        r = curr_by_id[check_id]
        new_checks.append({
            "id":       check_id,
            "name":     r.get("name", ""),
            "category": r.get("category", ""),
            "status":   r.get("status", ""),
            "message":  r.get("message", ""),
        })

    # ── Checks removed from the current scan ─────────────────────────────────
    # These were present previously but are absent now (e.g. check removed
    # from the suite, or excluded via --skip).
    for check_id in set(prev_by_id) - set(curr_by_id):
        r = prev_by_id[check_id]
        removed_checks.append({
            "id":       check_id,
            "name":     r.get("name", ""),
            "category": r.get("category", ""),
            "status":   r.get("status", ""),
            "message":  r.get("message", ""),
        })

    # Sort all lists by check ID for deterministic, reproducible output.
    improved.sort(key=lambda d: d["id"])
    regressed.sort(key=lambda d: d["id"])
    new_checks.sort(key=lambda d: d["id"])
    removed_checks.sort(key=lambda d: d["id"])

    diff = {
        "previous_scan_time": previous.get("scan_time", ""),
        "score_before":       score_before,
        "score_after":        score_after,
        "score_delta":        score_delta,
        "improved":           improved,
        "regressed":          regressed,
        "new_checks":         new_checks,
        "removed_checks":     removed_checks,
    }

    # ── Filter-mismatch suppression ───────────────────────────────────────────
    # When the user runs with different --only / --skip flags across scans,
    # many checks appear as "new" or "removed" even though nothing real changed.
    # Heuristic: if more than half of all checks are in the new/removed
    # buckets, it's almost certainly a filter mismatch — clear those buckets.
    total_checks = max(len(prev_by_id), len(curr_by_id), 1)
    filter_ratio = (len(new_checks) + len(removed_checks)) / total_checks
    if filter_ratio > 0.5:
        diff["new_checks"]     = []
        diff["removed_checks"] = []

    # If the diff is empty after suppression, signal "nothing to show".
    if is_empty_diff(diff):
        return None

    return diff


def is_empty_diff(diff: dict) -> bool:
    """Return ``True`` if the diff contains no meaningful changes.

    A diff is considered empty when the health score did not change AND
    none of the four change lists contain any entries.

    Args:
        diff (dict): A diff dict as returned by ``compute_diff()``.

    Returns:
        bool: ``True`` when all change indicators are zero / empty.

    Example::

        if is_empty_diff(diff):
            print("No changes since last scan")
    """
    return (
        diff.get("score_delta", 0) == 0
        and not diff.get("improved")
        and not diff.get("regressed")
        and not diff.get("new_checks")
        and not diff.get("removed_checks")
    )
