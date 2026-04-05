"""
Configuration file loading for macaudit.

Reads ``~/.config/macaudit/config.toml`` and returns a structured
configuration dictionary.  This module is intentionally defensive:
it **never raises**, always returning a dict with valid default values
regardless of whether the file exists, is malformed, or references
an unsupported TOML parser.

Supported TOML schema (all keys optional)::

    # Suppress specific checks by their string ID.
    # Suppressed checks appear in the report with status 'skip'
    # rather than being omitted entirely, preserving report completeness.
    suppress = ["homebrew_outdated", "disk_space"]

Design decisions:
    - ``tomllib`` (stdlib, Python ≥ 3.11) is preferred; ``tomli`` is
      accepted as a fallback for Python 3.10.
    - All parse errors are silently swallowed so a bad config file
      never prevents the user from running a scan.
    - The ``suppress`` list is coerced to a ``set[str]`` for O(1)
      membership tests in the main scan loop.

Attributes:
    _CONFIG_PATH (pathlib.Path): Default filesystem path for the
        user configuration file.

Note:
    The public API surface is intentionally minimal: a single
    ``load_config()`` function.  There is no write path — the user
    edits the TOML file directly.
"""

from pathlib import Path

# Default filesystem location for the user config file.
# Follows the XDG Base Directory convention (~/.config/<app>/).
_CONFIG_PATH = Path.home() / ".config" / "macaudit" / "config.toml"


def load_config(path: Path | None = None) -> dict:
    """Load and return the macaudit configuration from a TOML file.

    Reads the config file at *path* (or ``_CONFIG_PATH`` if *path* is
    ``None``) and returns a validated configuration dictionary.

    This function is **safe to call unconditionally** — it catches every
    expected failure mode (file absent, permission error, bad TOML, wrong
    value types) and returns an empty-defaults dict rather than raising.

    Args:
        path (pathlib.Path | None): Explicit path to a TOML config file,
            used primarily in tests to inject a fixture config.  Pass
            ``None`` (the default) to use the standard
            ``~/.config/macaudit/config.toml`` location.

    Returns:
        dict: A configuration dict guaranteed to contain:

            ``suppress`` (set[str])
                Set of check IDs that should be skipped during scans.
                Empty set when no suppression is configured.

    Note:
        The returned ``suppress`` set always exists (never ``None``),
        so callers can safely iterate or call ``in`` without a guard.

    Example::

        >>> cfg = load_config()
        >>> if "homebrew_outdated" in cfg["suppress"]:
        ...     print("homebrew_outdated suppressed")
    """
    config_path = path or _CONFIG_PATH

    # Canonical empty configuration — returned on any failure path.
    empty: dict = {"suppress": set()}

    # Guard: do nothing if the config file does not exist.
    # This is the normal case for first-time users.
    if not config_path.is_file():
        return empty

    # Read raw bytes; OSError covers permission denied and similar I/O errors.
    try:
        raw = config_path.read_bytes()
    except OSError:
        return empty

    # Resolve the TOML parser.  ``tomllib`` is in the stdlib as of Python 3.11;
    # ``tomli`` is the backport for Python 3.10 (listed as optional dep).
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            # Neither parser available — silently skip config loading.
            return empty

    # Parse the TOML document; any malformed file returns defaults.
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except Exception:
        return empty

    # Validate the ``suppress`` key: must be a list if present.
    # Wrong type (e.g. a bare string) is treated as misconfiguration → ignore.
    suppress = data.get("suppress")
    if not isinstance(suppress, list):
        return empty

    # Coerce each list element to str and store as a set for O(1) lookup.
    return {"suppress": {str(item) for item in suppress}}
