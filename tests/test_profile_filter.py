"""
Tests for the profile tag system.

Covers:
    - All ``dev_env`` checks carry exactly ``"developer"`` in ``profile_tags``
      and must NOT carry ``"standard"`` or ``"creative"``.
    - All ``system`` checks carry all three profiles
      (``"developer"``, ``"creative"``, ``"standard"``).
    - The ``profile_tags`` attribute on every check class is a ``tuple``
      (not a list), ensuring immutability.
    - The filtering predicate from ``main._collect_checks`` — replicated here
      as ``TestProfileFilter._filter()`` — correctly partitions checks across
      the three user profiles.

Design:
    Tests iterate over the ``ALL_CHECKS`` registry lists exported by each
    check module so that newly-added checks are automatically covered without
    updating this file.  Assertion messages name the offending class so
    failures are immediately actionable.

Note:
    ``TestProfileFilter._filter()`` is a static method that mirrors the
    filtering expression used in ``main._collect_checks``.  If the production
    expression ever changes, this helper must be updated in sync — it is the
    source of truth for the expected filter behaviour.
"""

import pytest

from macaudit.checks.dev_env import ALL_CHECKS as DEV_ENV_CHECKS
from macaudit.checks.system import ALL_CHECKS as SYSTEM_CHECKS


# ── dev_env profile tags ──────────────────────────────────────────────────────

class TestDevEnvProfileTags:
    """Verify that every ``dev_env`` check is scoped to the ``developer`` profile only."""

    def test_all_dev_env_checks_have_developer_tag(self):
        """Every check in ``DEV_ENV_CHECKS`` must include ``"developer"`` in its tags.

        A dev-env check missing this tag would be silently skipped for all
        developer-profile users — a bug that is hard to notice from the CLI.
        """
        for cls in DEV_ENV_CHECKS:
            tags = getattr(cls, "profile_tags", ())
            assert "developer" in tags, (
                f"{cls.__name__} is missing the 'developer' profile tag"
            )

    def test_no_dev_env_check_has_standard_tag(self):
        """No ``dev_env`` check may include ``"standard"`` — it would run for non-developers.

        Developer tooling checks (Git, Docker, SSH keys, etc.) are irrelevant
        and potentially confusing for standard or creative users.
        """
        for cls in DEV_ENV_CHECKS:
            tags = getattr(cls, "profile_tags", ())
            assert "standard" not in tags, (
                f"{cls.__name__} has 'standard' tag — "
                "dev checks should not run for non-developer users"
            )

    def test_no_dev_env_check_has_creative_tag(self):
        """No ``dev_env`` check may include ``"creative"`` — same exclusion as standard."""
        for cls in DEV_ENV_CHECKS:
            tags = getattr(cls, "profile_tags", ())
            assert "creative" not in tags, (
                f"{cls.__name__} has 'creative' tag — "
                "dev checks should not run for creative-profile users"
            )

    def test_profile_tags_is_tuple_on_all_dev_env_checks(self):
        """``profile_tags`` must be a ``tuple`` so it is immutable at the class level.

        A mutable list could be accidentally modified at runtime, silently
        altering which profiles see a check for the remainder of the process.
        """
        for cls in DEV_ENV_CHECKS:
            tags = getattr(cls, "profile_tags", ())
            assert isinstance(tags, tuple), (
                f"{cls.__name__}.profile_tags should be a tuple, got {type(tags).__name__}"
            )


# ── system profile tags ───────────────────────────────────────────────────────

class TestSystemProfileTags:
    """Verify that every ``system`` check covers all three user profiles."""

    def test_all_system_checks_have_all_three_profiles(self):
        """Core system checks (SIP, FileVault, Gatekeeper, etc.) are universal.

        A system check missing any profile tag would silently vanish for that
        user profile, leaving a security gap with no report entry.
        """
        for cls in SYSTEM_CHECKS:
            tags = getattr(cls, "profile_tags", ("developer", "creative", "standard"))
            for profile in ("developer", "creative", "standard"):
                assert profile in tags, (
                    f"{cls.__name__} is missing '{profile}' — "
                    "system checks should run for all profiles"
                )


# ── Profile filter simulation ─────────────────────────────────────────────────

class TestProfileFilter:
    """Simulate the ``profile`` filtering predicate from ``main._collect_checks``.

    ``_filter()`` below replicates the exact list-comprehension expression
    used in ``main._collect_checks`` to select active checks for a given
    profile.  If that expression changes, this helper must be updated in sync.

    The tests instantiate real check objects from the ``ALL_CHECKS`` registry
    so that any newly added check that violates the profile contract is caught
    automatically.
    """

    @staticmethod
    def _filter(checks, profile: str) -> list:
        """Return the subset of ``checks`` that should run for the given ``profile``.

        Mirrors the filtering logic in ``main._collect_checks``:
        a check without a ``profile_tags`` attribute defaults to matching
        all profiles (via the ``[profile]`` fallback).

        Args:
            checks:  List of instantiated ``BaseCheck`` objects.
            profile: Active user profile string
                (``"developer"``, ``"creative"``, or ``"standard"``).

        Returns:
            A list of check instances whose ``profile_tags`` include
            ``profile``.
        """
        return [
            c for c in checks
            if profile in getattr(c, "profile_tags", [profile])
        ]

    def test_dev_checks_excluded_for_standard_profile(self):
        """All ``dev_env`` checks are excluded when ``profile="standard"``."""
        checks = [cls() for cls in DEV_ENV_CHECKS]
        filtered = self._filter(checks, "standard")
        assert filtered == [], (
            "Dev env checks should be completely excluded for the 'standard' profile"
        )

    def test_dev_checks_excluded_for_creative_profile(self):
        """All ``dev_env`` checks are excluded when ``profile="creative"``."""
        checks = [cls() for cls in DEV_ENV_CHECKS]
        filtered = self._filter(checks, "creative")
        assert filtered == [], (
            "Dev env checks should be completely excluded for the 'creative' profile"
        )

    def test_dev_checks_all_included_for_developer_profile(self):
        """All ``dev_env`` checks are included when ``profile="developer"``."""
        checks = [cls() for cls in DEV_ENV_CHECKS]
        filtered = self._filter(checks, "developer")
        assert len(filtered) == len(DEV_ENV_CHECKS), (
            "All dev env checks should be included for the 'developer' profile"
        )

    def test_system_checks_included_for_standard_profile(self):
        """All ``system`` checks are included for ``profile="standard"``."""
        checks = [cls() for cls in SYSTEM_CHECKS]
        filtered = self._filter(checks, "standard")
        assert len(filtered) == len(SYSTEM_CHECKS), (
            "All system checks should be included for the 'standard' profile"
        )

    def test_system_checks_included_for_developer_profile(self):
        """All ``system`` checks are included for ``profile="developer"``."""
        checks = [cls() for cls in SYSTEM_CHECKS]
        filtered = self._filter(checks, "developer")
        assert len(filtered) == len(SYSTEM_CHECKS)
