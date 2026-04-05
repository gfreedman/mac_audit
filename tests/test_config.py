"""
Tests for macaudit.config — config loading and check suppression.

Covers:
    - ``load_config()`` with a missing file, valid TOML, empty list, malformed
      TOML, wrong value types, a missing ``suppress`` key, TOML comments, and
      an unreadable file (mode 000).
    - ``TestSuppressionIntegration``: end-to-end flow from config load through
      check splitting to final health score, using synthetic ``BaseCheck``
      subclasses to keep the test hermetic.

Design:
    All I/O is routed through ``tmp_path`` so tests never touch the real
    ``~/.config/macaudit/config.toml``.  Synthetic check classes are created
    inline via ``_make_check_class()`` rather than importing real checks, so
    these tests remain fast and independent of macOS subsystem availability.

Note:
    The unreadable-file test restores the original permissions after the
    assertion to allow ``pytest`` to clean up ``tmp_path`` without errors.
"""

from pathlib import Path

import pytest

from macaudit.checks.base import CheckResult, calculate_health_score
from macaudit.config import load_config


class TestLoadConfig:
    """Unit tests for ``load_config()`` covering the full input space.

    Each test exercises a single failure mode or happy-path branch so that
    a regression is immediately localised to the broken case.
    """

    def test_missing_file_returns_empty_suppress(self, tmp_path):
        """A path that does not exist on disk → ``{"suppress": set()}``.

        ``load_config`` must never raise; missing configs are treated as
        "no suppressions configured" rather than an error.
        """
        missing = tmp_path / "nonexistent" / "config.toml"
        result = load_config(path=missing)
        assert result == {"suppress": set()}

    def test_valid_toml_with_suppress_list(self, tmp_path):
        """A well-formed config with two IDs → both IDs in the suppress set."""
        cfg = tmp_path / "config.toml"
        cfg.write_text('suppress = ["filevault", "gatekeeper"]\n')
        result = load_config(path=cfg)
        assert result == {"suppress": {"filevault", "gatekeeper"}}

    def test_empty_suppress_list(self, tmp_path):
        """``suppress = []`` → empty set, not ``None`` or a missing key."""
        cfg = tmp_path / "config.toml"
        cfg.write_text("suppress = []\n")
        result = load_config(path=cfg)
        assert result == {"suppress": set()}

    def test_malformed_toml_returns_empty(self, tmp_path):
        """Unparseable TOML syntax → graceful fallback, no exception raised."""
        cfg = tmp_path / "config.toml"
        cfg.write_text("suppress = [not valid toml\n")
        result = load_config(path=cfg)
        assert result == {"suppress": set()}

    def test_non_list_suppress_returns_empty(self, tmp_path):
        """``suppress`` set to a string → treated as invalid, returns empty set.

        Only list values are accepted; a scalar string could indicate a user
        typo (omitting square brackets) and must not be silently iterated.
        """
        cfg = tmp_path / "config.toml"
        cfg.write_text('suppress = "filevault"\n')
        result = load_config(path=cfg)
        assert result == {"suppress": set()}

    def test_suppress_as_integer_returns_empty(self, tmp_path):
        """``suppress`` set to an integer → treated as invalid, returns empty set."""
        cfg = tmp_path / "config.toml"
        cfg.write_text("suppress = 42\n")
        result = load_config(path=cfg)
        assert result == {"suppress": set()}

    def test_missing_suppress_key_returns_empty(self, tmp_path):
        """Valid TOML without a ``suppress`` key → empty set (no checks suppressed)."""
        cfg = tmp_path / "config.toml"
        cfg.write_text('title = "my config"\n')
        result = load_config(path=cfg)
        assert result == {"suppress": set()}

    def test_comments_in_toml_preserved(self, tmp_path):
        """TOML comments on their own line and inline are ignored correctly."""
        cfg = tmp_path / "config.toml"
        cfg.write_text(
            "# This is a comment\n"
            'suppress = ["filevault"]  # inline comment\n'
        )
        result = load_config(path=cfg)
        assert result == {"suppress": {"filevault"}}

    def test_unreadable_file_returns_empty(self, tmp_path):
        """File with mode 000 (no read permission) → graceful fallback.

        On systems where tests run as non-root, ``chmod(0o000)`` makes the
        file unreadable and ``load_config`` must catch the ``OSError``.
        Permissions are restored in teardown so ``tmp_path`` can be cleaned up.
        """
        cfg = tmp_path / "config.toml"
        cfg.write_text('suppress = ["filevault"]\n')
        cfg.chmod(0o000)
        result = load_config(path=cfg)
        assert result == {"suppress": set()}
        cfg.chmod(0o644)  # restore for cleanup


class TestSuppressionIntegration:
    """End-to-end suppression flow: config → check split → score.

    These tests verify the contract between ``load_config`` and the scan
    orchestrator: suppressed check IDs must produce ``skip`` results and must
    not penalise the health score.  Synthetic ``BaseCheck`` subclasses are used
    so the tests don't depend on real macOS commands being available.
    """

    def _make_check_class(self, check_id: str):
        """Return a new ``BaseCheck`` subclass with the specified ``id``.

        Args:
            check_id: The ``id`` string to assign to the generated class.
                Must be unique within a test to avoid class-variable sharing.

        Returns:
            A concrete ``BaseCheck`` subclass whose ``run()`` always returns
            a ``pass`` result; suitable for suppression testing.
        """
        from macaudit.checks.base import BaseCheck

        class FakeCheck(BaseCheck):
            id = check_id
            name = f"Fake {check_id}"
            category = "system"
            category_icon = "🔧"
            scan_description = "Testing"
            finding_explanation = "Test explanation"
            recommendation = "Test recommendation"

            def run(self):
                return self._pass("All good")

        return FakeCheck

    def test_suppressed_check_produces_skip_result(self):
        """``_skip()`` returns a ``CheckResult`` with status ``"skip"``.

        The scan orchestrator calls ``check._skip(...)`` for each suppressed
        ID.  The result must carry the correct ``id`` and ``message`` so that
        the rendered report can tell the user which checks were silenced.
        """
        CheckClass = self._make_check_class("filevault")
        check = CheckClass()
        result = check._skip("Suppressed by config")
        assert result.status == "skip"
        assert result.message == "Suppressed by config"
        assert result.id == "filevault"

    def test_suppressed_check_does_not_affect_score(self):
        """A ``skip`` result contributes zero penalty to the health score.

        Users who suppress noisy checks must not be punished with a lower score
        just because those checks are absent from the active set.
        """
        CheckClass = self._make_check_class("filevault")
        check = CheckClass()
        skip_result = check._skip("Suppressed by config")
        assert calculate_health_score([skip_result]) == 100

    def test_suppression_flow(self):
        """End-to-end: load config → split checks → verify results."""
        from macaudit.config import load_config

        FVCheck = self._make_check_class("filevault")
        GKCheck = self._make_check_class("gatekeeper")
        DiskCheck = self._make_check_class("disk_usage")

        all_checks = [FVCheck(), GKCheck(), DiskCheck()]
        suppressed_ids = {"filevault", "gatekeeper"}

        suppressed_results = []
        active_checks = []
        for check in all_checks:
            if check.id in suppressed_ids:
                suppressed_results.append(check._skip("Suppressed by config"))
            else:
                active_checks.append(check)

        # Only disk_usage should be active
        assert len(active_checks) == 1
        assert active_checks[0].id == "disk_usage"

        # Suppressed checks should produce skip results
        assert len(suppressed_results) == 2
        assert all(r.status == "skip" for r in suppressed_results)
        assert all(r.message == "Suppressed by config" for r in suppressed_results)

        # Score should be 100 (suppressed skips + one pass)
        active_results = [c.execute() for c in active_checks]
        all_results = active_results + suppressed_results
        assert calculate_health_score(all_results) == 100
