"""
Shell secrets scanner — opt-in check enabled via ``--check-shell-secrets``.

This module implements a single check that scans shell configuration files
(``~/.zshrc``, ``~/.bashrc``, etc.) for patterns matching hardcoded
credentials such as API keys, tokens, and passwords.

Opt-in design rationale:
    This check reads the full contents of shell config files, which may contain
    personal information beyond credentials (aliases, functions, private PATH
    entries).  Because users must explicitly pass ``--check-shell-secrets`` to
    run it, they provide informed consent before their config is scanned.  The
    scan results are not written to history (never persisted to disk) and the
    ``--json`` output warns on stderr when used together with
    ``--check-shell-secrets``.

Detection methodology:
    1. **Key-name matching** — the ``_CRED_RE`` regex matches lines containing
       an assignment (``KEY=value``, ``KEY: value``, ``export KEY=value``) where
       the left-hand side matches either a specific known credential name
       (``AWS_SECRET_ACCESS_KEY``, ``GITHUB_TOKEN``, etc.) or a generic
       pattern ending in ``_API_KEY``, ``_SECRET``, ``_TOKEN``, etc.
    2. **Value length filter** — the value must be at least 10 characters long.
       This eliminates placeholder strings like ``"none"`` or ``"changeme"``.
    3. **Safe-value allow-list** — ``_SAFE_VALUE_RE`` matches values that look
       like variable references (``$VAR``), file paths (``/``, ``~``), URLs
       (``https://``), short lowercase words, pure numbers, or booleans.
       Matches here are unconditionally skipped (false-positive suppression).

Secret redaction:
    Matching values are never displayed in full.  The displayed form is
    ``<first 4 chars>…<last 2 chars>``, e.g. ``ghp_…xy``.  This is enough
    to help the user identify which secret was found without exposing the
    full credential.

Attributes:
    _SHELL_CONFIGS (list[str]): Paths (relative to ``~``) of shell config
        files to scan.
    _CRED_RE (re.Pattern): Compiled regular expression that detects credential
        key-value assignment lines.  See inline comments for group semantics.
    _SAFE_VALUE_RE (re.Pattern): Compiled regular expression that matches
        known-safe value patterns used to suppress false positives.
    ALL_CHECKS (list[type[BaseCheck]]): The single check exported to the
        scan orchestrator.

Note:
    The ``ShellSecretsCheck`` category is ``"security"`` so that findings
    contribute to the security section of the health score.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from macaudit.checks.base import BaseCheck, CheckResult


# ── Files to scan ─────────────────────────────────────────────────────────────

_SHELL_CONFIGS = [
    "~/.zshrc",
    "~/.zprofile",
    "~/.zshenv",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.bash_aliases",
    "~/.profile",
]


# ── Key-name patterns that suggest credentials ─────────────────────────────────
#
# Match: export KEY=value  |  KEY=value  |  KEY: value  |  KEY="value"
# Group 1 = the key name, Group 2 = the raw value

_CRED_RE = re.compile(
    r"""
    (?ix)               # case-insensitive, verbose
    (?:export\s+)?      # optional 'export '
    (                   # GROUP 1: key name
        # Specific well-known keys
        AWS_ACCESS_KEY_ID
      | AWS_SECRET_ACCESS_KEY
      | AWS_SESSION_TOKEN
      | GITHUB_TOKEN | GH_TOKEN | GITHUB_PAT
      | OPENAI_API_KEY
      | STRIPE_SECRET_KEY | STRIPE_PUBLISHABLE_KEY
      | SENDGRID_API_KEY
      | TWILIO_AUTH_TOKEN
      | SLACK_TOKEN | SLACK_BOT_TOKEN
      | HEROKU_API_KEY
      | DIGITALOCEAN_ACCESS_TOKEN
      | NPM_TOKEN
      | PYPI_TOKEN
      # Generic patterns (must be a recognisable credential noun)
      | [A-Z][A-Z0-9_]*(?:_API_KEY | _SECRET_KEY | _SECRET | _TOKEN | _PASSWORD | _PASSWD | _PWD | _AUTH | _CREDENTIALS)
      | (?:API_KEY | SECRET_KEY | AUTH_TOKEN | ACCESS_TOKEN | PRIVATE_KEY | DATABASE_URL)[A-Z0-9_]*
    )
    \s*[=:]\s*          # separator
    ["']?               # optional quote
    ([^\s"'#\$\{]{10,}) # GROUP 2: value — at least 10 non-space chars,
                        #           must not start with $ or { (variable refs)
    """,
    re.VERBOSE | re.IGNORECASE,
)


# ── Value allow-list — things that look like values but are NOT secrets ────────

_SAFE_VALUE_RE = re.compile(
    r"""
    ^(
        \$[\w{]       |   # $VARIABLE or ${VAR}
        /             |   # file path
        ~             |   # home-relative path
        https?://     |   # URL (likely not a secret in assignment position)
        [a-z_-]{1,30}$|   # short lowercase word (e.g. "none", "default")
        \d+$          |   # pure number
        true|false|yes|no|on|off  # booleans
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


# ── Check ─────────────────────────────────────────────────────────────────────

class ShellSecretsCheck(BaseCheck):
    """Scan shell config files (~/.zshrc, ~/.bashrc, etc.) for hardcoded credentials."""

    id = "shell_secrets"
    name = "Shell Config Secrets"
    category = "security"
    category_icon = "🔑"

    scan_description = (
        "Scanning shell config files for hardcoded credentials — "
        "API keys and tokens in ~/.zshrc leak into every process you launch "
        "and may end up in committed dotfiles."
    )
    finding_explanation = (
        "Shell config files (like ~/.zshrc) are inherited by every process you start "
        "and are frequently committed to public dotfiles repositories. "
        "Hardcoded secrets in these files mean: (1) every child process inherits them "
        "via the environment, (2) they may be exposed if you ever share your config, "
        "and (3) they cannot be easily rotated without editing the file."
    )
    recommendation = (
        "Move secrets to a dedicated file that is never committed: "
        "create ~/.secrets with your export statements, "
        "add 'source ~/.secrets' to ~/.zshrc, "
        "and add ~/.secrets to ~/.gitignore. "
        "If any secrets were ever committed to a public repo, rotate them immediately."
    )

    fix_level = "instructions"
    fix_description = "Move hardcoded secrets to a gitignored ~/.secrets file."
    fix_steps = [
        "Create ~/.secrets (touch ~/.secrets && chmod 600 ~/.secrets)",
        "Move any 'export SECRET=...' lines from ~/.zshrc to ~/.secrets",
        "Add to ~/.zshrc:  [ -f ~/.secrets ] && source ~/.secrets",
        "Add ~/.secrets to ~/.gitignore (echo '~/.secrets' >> ~/.gitignore)",
        "If any secret was ever committed to a public repo: rotate it now",
    ]
    fix_reversible = True
    fix_time_estimate = "~10 minutes"

    def run(self) -> CheckResult:
        """Scan shell config files with ``_CRED_RE``; suppress false positives via ``_SAFE_VALUE_RE``; redact findings.

        The check iterates ``_SHELL_CONFIGS``, reads each existing file, and
        applies ``_CRED_RE`` to every non-comment, non-blank line.  When a match
        is found:

        1. The raw value (group 2 of the match) is tested against
           ``_SAFE_VALUE_RE``; matches are skipped (false positive).
        2. The value is redacted to ``<first 4>…<last 2>`` characters.
        3. A finding dict is appended with the filename, line number, key name,
           and redacted value.

        Only the **first** match per line is recorded (early break after one
        finding per line prevents duplicate entries for lines with multiple
        variable assignments on the same line — an unusual but valid shell syntax).

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"pass"`` — no potential credentials found in any scanned file.
            - ``"warning"`` — one or more lines contain what appear to be
              hardcoded credentials; redacted key names and values shown.

            The result ``data`` dict includes:
              - ``"findings"`` (list[dict]): Each dict has ``file``, ``line``,
                ``key``, and ``redacted_value``.
              - ``"files_scanned"`` (list[str]): Names of files that were read.

        Note:
            ``PermissionError`` and ``OSError`` when reading individual config
            files are caught and silently skipped so a restricted file never
            blocks the rest of the scan.
        """
        findings: list[dict] = []
        files_scanned: list[str] = []

        for config_str in _SHELL_CONFIGS:
            config_path = Path(os.path.expanduser(config_str))
            if not config_path.exists():
                continue

            files_scanned.append(config_path.name)

            try:
                lines = config_path.read_text(errors="replace").splitlines()
            except (PermissionError, OSError):
                continue

            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()

                # Skip blank lines and comments
                if not stripped or stripped.startswith("#"):
                    continue

                # Guard against pathological lines before running the regex.
                # _CRED_RE uses alternation and quantifiers that can cause
                # quadratic backtracking on extremely long inputs.
                if len(stripped) > 500:
                    continue

                m = _CRED_RE.search(stripped)
                if not m:
                    continue

                key   = m.group(1)
                value = m.group(2)

                # Skip values that are clearly not real secrets
                if _SAFE_VALUE_RE.search(value):
                    continue

                # Redact the value — show only a hint
                display_value = _redact(value)

                findings.append({
                    "file":    str(config_path),
                    "line":    lineno,
                    "key":     key,
                    "display": f"{config_path.name}:{lineno}  {key}={display_value}",
                })
                # Continue to next line — multiple credentials per file are possible

        if not findings:
            n = len(files_scanned)
            return self._pass(
                f"No credential patterns found "
                f"({n} file{'s' if n != 1 else ''} scanned: "
                f"{', '.join(files_scanned) or 'none found'})"
            )

        count = len(findings)
        preview = "  ·  ".join(f["display"] for f in findings[:2])
        suffix  = f"  (+{count - 2} more)" if count > 2 else ""

        return self._warning(
            f"{count} potential hardcoded credential{'s' if count != 1 else ''} "
            f"in shell config: {preview}{suffix}",
            data={"findings": findings, "files_scanned": files_scanned},
        )


def _redact(value: str) -> str:
    """Show first 3 chars + last 2 chars; mask everything in between."""
    if len(value) <= 6:
        return "****"
    return value[:3] + "…" + value[-2:]


# ── Export ────────────────────────────────────────────────────────────────────

ALL_CHECKS = [ShellSecretsCheck]
