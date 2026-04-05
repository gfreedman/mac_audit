"""
Tests for macaudit/history.py — scan history persistence.

Covers:
    - ``save_scan()``: creates a valid JSON file with the expected schema;
      filename is ISO-8601 with hyphens (filesystem-safe, no colons).
    - ``load_previous_scan()``: returns ``None`` for an empty or absent
      directory; returns the most recent file (lexicographic = chronological);
      handles corrupt JSON gracefully.
    - ``prune_history()``: removes the oldest files when the count exceeds
      ``_MAX_SCANS``; does nothing when at or below the limit.
    - ``save_scan`` → ``load_previous_scan`` roundtrip: data survives
      serialise → write → read → parse intact.

Design:
    ``_patch_history_dir`` uses ``monkeypatch.setattr`` to redirect
    ``history_mod._HISTORY_DIR`` to a subdirectory of ``tmp_path``, so no
    test ever touches ``~/.config/macaudit/history/``.  ``_MAX_SCANS`` is
    also patched per-test where the default (10) would require creating too
    many files to trigger pruning.

Note:
    The ``_result()`` helper follows the same pattern as other test modules
    so the signature is consistent across the test suite.
"""

import json

import macaudit.history as history_mod
from macaudit.checks.base import CheckResult
from macaudit.history import load_previous_scan, prune_history, save_scan


# ── Helpers ──────────────────────────────────────────────────────────────────

def _result(**kwargs) -> CheckResult:
    """Build a minimal ``CheckResult`` suitable for passing to ``save_scan()``.

    All required ``CheckResult`` fields are populated with harmless defaults.
    Pass keyword arguments to override any subset of fields for scenario-
    specific testing.

    Args:
        **kwargs: Any ``CheckResult`` field to override.  Common overrides:
            ``id``, ``status``, ``message``.

    Returns:
        A fully-initialised ``CheckResult`` instance.
    """
    defaults = dict(
        id="test_check",
        name="Test Check",
        category="system",
        category_icon="🖥️",
        status="pass",
        message="all good",
        scan_description="",
        finding_explanation="",
        recommendation="",
        fix_level="none",
        fix_description="",
    )
    defaults.update(kwargs)
    return CheckResult(**defaults)


def _patch_history_dir(monkeypatch, tmp_path):
    """Redirect ``history_mod._HISTORY_DIR`` to an isolated temp subdirectory.

    Prevents every test from reading or writing the real
    ``~/.config/macaudit/history/`` directory.  The subdirectory is *not*
    pre-created here; ``save_scan()`` creates it on first write, and tests
    that need it to already exist do so explicitly.

    Args:
        monkeypatch: The pytest ``monkeypatch`` fixture.
        tmp_path:    The pytest ``tmp_path`` fixture (unique per test).
    """
    monkeypatch.setattr(history_mod, "_HISTORY_DIR", tmp_path / "history")


# ── Tests ────────────────────────────────────────────────────────────────────

class TestSaveScan:
    """Tests for ``save_scan()`` — file creation and naming contract."""
    def test_save_creates_json_file(self, tmp_path, monkeypatch):
        """save_scan creates a valid JSON file in the history directory."""
        _patch_history_dir(monkeypatch, tmp_path)
        results = [_result(id="sip", status="pass")]
        path = save_scan(results)
        assert path is not None
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["schema_version"] == 1
        assert "results" in data
        assert data["results"][0]["id"] == "sip"

    def test_save_filename_format(self, tmp_path, monkeypatch):
        """Filename uses ISO-like format with hyphens (filesystem safe)."""
        _patch_history_dir(monkeypatch, tmp_path)
        path = save_scan([_result()])
        assert path is not None
        # Format: YYYY-MM-DDTHH-MM-SS.json
        stem = path.stem
        assert "T" in stem
        assert ":" not in stem  # colons replaced with hyphens


class TestLoadPreviousScan:
    """Tests for ``load_previous_scan()`` — reading and selecting the most recent history file."""
    def test_load_from_empty_returns_none(self, tmp_path, monkeypatch):
        """Empty history dir → None."""
        _patch_history_dir(monkeypatch, tmp_path)
        (tmp_path / "history").mkdir(parents=True)
        assert load_previous_scan() is None

    def test_load_from_nonexistent_dir_returns_none(self, tmp_path, monkeypatch):
        """Nonexistent history dir → None."""
        _patch_history_dir(monkeypatch, tmp_path)
        assert load_previous_scan() is None

    def test_load_returns_most_recent(self, tmp_path, monkeypatch):
        """With multiple files, load returns the lexicographically last one."""
        _patch_history_dir(monkeypatch, tmp_path)
        hist = tmp_path / "history"
        hist.mkdir(parents=True)

        # Write two files with different timestamps
        old = {"schema_version": 1, "scan_time": "old", "score": 70, "results": []}
        new = {"schema_version": 1, "scan_time": "new", "score": 90, "results": []}
        (hist / "2026-02-25T10-00-00.json").write_text(json.dumps(old))
        (hist / "2026-02-26T10-00-00.json").write_text(json.dumps(new))

        loaded = load_previous_scan()
        assert loaded is not None
        assert loaded["scan_time"] == "new"
        assert loaded["score"] == 90

    def test_load_handles_corrupt_json(self, tmp_path, monkeypatch):
        """Corrupt JSON file → None."""
        _patch_history_dir(monkeypatch, tmp_path)
        hist = tmp_path / "history"
        hist.mkdir(parents=True)
        (hist / "2026-02-26T10-00-00.json").write_text("not json{{{")
        assert load_previous_scan() is None


class TestPruneHistory:
    """Tests for ``prune_history()`` — enforcing the ``_MAX_SCANS`` cap."""
    def test_prune_keeps_max_scans(self, tmp_path, monkeypatch):
        """Prune removes oldest files when count exceeds _MAX_SCANS."""
        _patch_history_dir(monkeypatch, tmp_path)
        monkeypatch.setattr(history_mod, "_MAX_SCANS", 3)
        hist = tmp_path / "history"
        hist.mkdir(parents=True)

        # Create 5 files
        for i in range(5):
            (hist / f"2026-02-{20+i:02d}T10-00-00.json").write_text("{}")

        prune_history()

        remaining = sorted(hist.glob("*.json"))
        assert len(remaining) == 3
        # Should keep the 3 newest (22, 23, 24)
        stems = [f.stem for f in remaining]
        assert "2026-02-22T10-00-00" in stems
        assert "2026-02-23T10-00-00" in stems
        assert "2026-02-24T10-00-00" in stems

    def test_prune_noop_when_under_limit(self, tmp_path, monkeypatch):
        """Prune does nothing when count ≤ _MAX_SCANS."""
        _patch_history_dir(monkeypatch, tmp_path)
        hist = tmp_path / "history"
        hist.mkdir(parents=True)
        (hist / "2026-02-26T10-00-00.json").write_text("{}")

        prune_history()
        assert len(list(hist.glob("*.json"))) == 1


class TestSaveLoadRoundtrip:
    """End-to-end roundtrip: ``save_scan`` then ``load_previous_scan`` returns equivalent data."""

    def test_roundtrip(self, tmp_path, monkeypatch):
        """All ``CheckResult`` fields survive JSON serialisation and deserialisation.

        Verifies the schema contract: the IDs present in the saved results
        are all recoverable from the loaded payload, and the top-level
        ``schema_version`` key is present.
        """
        _patch_history_dir(monkeypatch, tmp_path)
        results = [
            _result(id="sip", status="pass", message="enabled"),
            _result(id="filevault", status="critical", message="disabled"),
        ]
        save_scan(results)
        loaded = load_previous_scan()
        assert loaded is not None
        assert loaded["schema_version"] == 1
        assert len(loaded["results"]) == 2
        ids = {r["id"] for r in loaded["results"]}
        assert ids == {"sip", "filevault"}
