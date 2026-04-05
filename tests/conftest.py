"""
Shared pytest fixtures for the macaudit test suite.

Design:
    Several macaudit subsystems cache expensive subprocess calls behind
    ``@lru_cache`` so they execute at most once per scan.  In the test
    environment these caches can retain results from a previous test,
    causing cross-test contamination — particularly on CI runners that
    execute all tests in a single process.

    The ``clear_lru_caches`` fixture is declared ``autouse=True`` so it
    applies automatically to every test in every module, with zero
    boilerplate at the call site.

Note:
    Add new ``cache_clear()`` calls here whenever a new ``@lru_cache``
    is introduced to a macaudit module.  The fixture teardown runs
    *after* each test (post-``yield``), ensuring a clean slate for the
    next test regardless of whether the current test passed or failed.
"""
import pytest

from macaudit.checks import hardware, system
from macaudit import system_info


@pytest.fixture(autouse=True)
def clear_lru_caches():
    """Clear all ``@lru_cache`` caches after each test to prevent state leakage.

    macaudit caches subprocess results (``system_profiler``, ``softwareupdate``,
    etc.) so that live scans pay the subprocess overhead only once.  In tests
    this optimisation becomes a liability: a cache populated by one test would
    return stale data to the next test that runs in the same process.

    Placement after ``yield`` (teardown phase) guarantees cleanup even if the
    test body raises an exception, keeping the test order independent.
    """
    yield
    hardware._get_power_data.cache_clear()
    system._fetch_software_updates.cache_clear()
    system_info.get_system_info.cache_clear()
