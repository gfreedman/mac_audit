"""
Mac Audit — macOS System Health Inspector & Auditor.

This package is the top-level namespace for the ``macaudit`` CLI tool.
It exposes the canonical version string resolved at runtime from the
installed package metadata (PEP 566 / importlib.metadata), with a
``"dev"`` sentinel used when the package is executed directly from
source without being installed.

Design contract:
    - ``__version__`` is the *only* version source of truth in the package.
    - All other modules that need the version string must import it from
      here (``from macaudit import __version__``) rather than re-reading
      ``pyproject.toml`` or hardcoding their own copy.
    - The ``PackageNotFoundError`` fallback ensures the package is usable
      in development without requiring a prior ``pip install -e .``.

Attributes:
    __version__ (str): Semantic version string (e.g. ``"1.12.0"``), or
        ``"dev"`` when the package is not formally installed.
    __author__ (str): Human-readable author / project name label.

Example::

    >>> import macaudit
    >>> macaudit.__version__
    '1.12.0'

Note:
    Importing this package has no side-effects beyond the
    ``importlib.metadata.version()`` call.  It is safe to import
    in any context, including test fixtures and subprocesses.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    # Resolve the installed version from package metadata at import time.
    # This matches the ``version`` field in pyproject.toml after installation.
    __version__ = version("macaudit")
except PackageNotFoundError:
    # Package is not installed (e.g. running directly from the repo root).
    # Use a sentinel string rather than raising, so the rest of the tool
    # can still function normally during development.
    __version__ = "dev"

__author__ = "Mac Audit"
