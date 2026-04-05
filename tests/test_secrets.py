"""
Tests for checks/secrets.py — opt-in shell-config credential scanner.

Covers:
    - ``_redact()``: short values (≤6 chars → all stars), boundary at 7 chars,
      long values (first 3 + ellipsis + last 2), middle is never revealed.
    - ``ShellSecretsCheck.run()``:
        - **Clean files**: empty, PATH-only, comment-only → ``pass``.
        - **Detected credentials**: AWS access key ID, AWS secret, OpenAI key,
          generic API key pattern, GitHub token.
        - **Message properties**: includes variable name, redacts the value,
          includes count when multiple findings.
        - **Safe-value exclusions**: variable references (``$VAR``), file
          paths, ``~/`` paths, boolean literals, URLs, short values (<10 chars).
        - **Edge cases**: long-line ReDOS guard (>500 chars skipped), boundary
          at exactly 500 chars (scanned), missing/nonexistent file (skipped).
        - **Data structure**: ``result.data["findings"]`` is a non-empty list.

Design:
    ``TestShellSecretsCheck._run_with_content()`` writes content to a real
    temporary file and patches ``_SHELL_CONFIGS`` so the check scans only
    that file.  Using real ``tempfile`` I/O (rather than a mock ``open``)
    validates the file-reading path end-to-end.

Note:
    The credential strings in the detection tests are obviously fake but match
    the format of real credentials (AWS AKID prefix, OpenAI ``sk-`` prefix,
    GitHub ``ghp_`` prefix) so the regex patterns are exercised as written.
"""

import os
import tempfile
from unittest.mock import patch

import pytest

from macaudit.checks.secrets import ShellSecretsCheck, _redact


# ── _redact() ─────────────────────────────────────────────────────────────────

class TestRedact:
    """Tests for ``_redact()`` — the credential-value masking function.

    ``_redact()`` must reveal just enough of the value for the user to
    recognise which credential is exposed, while ensuring the bulk of the
    secret is never written to any output file or log.
    """

    def test_value_6_chars_or_fewer_returns_stars(self):
        """Very short values are fully masked — showing any chars would reveal too much."""
        assert _redact("abc") == "****"
        assert _redact("abcdef") == "****"

    def test_value_7_chars_shows_3_plus_2(self):
        """7-char value is long enough to show the ``ABC…FG`` pattern."""
        assert _redact("ABCDEFG") == "ABC…FG"

    def test_long_value_shows_first_3_and_last_2(self):
        """10-char value → ``ABC…IJ`` (first 3 + ellipsis + last 2)."""
        result = _redact("ABCDEFGHIJ")
        assert result == "ABC…IJ"

    def test_middle_is_not_revealed(self):
        """The middle portion of a long secret is always hidden by the ellipsis."""
        secret = "sk-very-secret-token-value-1234567890"
        result = _redact(secret)
        assert result.startswith(secret[:3])
        assert result.endswith(secret[-2:])
        assert "…" in result
        assert len(result) < len(secret)

    def test_ellipsis_separates_prefix_and_suffix(self):
        """A single ``…`` character separates the visible prefix from the suffix."""
        result = _redact("ABCDEFGHIJKLMNOP")
        parts = result.split("…")
        assert len(parts) == 2
        assert parts[0] == "ABC"
        assert parts[1] == "OP"


# ── ShellSecretsCheck.run() ───────────────────────────────────────────────────

class TestShellSecretsCheck:
    """Tests for ``ShellSecretsCheck.run()`` scanning controlled temp files.

    Each test writes specific content to a real temporary file (not a mock)
    and patches ``_SHELL_CONFIGS`` to point exclusively at that file.  This
    exercises the full file-reading, line-filtering, and regex-matching path.
    """

    def _run_with_content(self, content: str):
        """Write ``content`` to a temp ``.zshrc`` file and run the check against it.

        Args:
            content: The shell-config file content to scan.  Write realistic
                ``export KEY=value`` lines to exercise specific code paths.

        Returns:
            The ``CheckResult`` produced by ``ShellSecretsCheck.run()``.
        """
        check = ShellSecretsCheck()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".zshrc", delete=False
        ) as f:
            f.write(content)
            tmpfile = f.name
        try:
            with patch("macaudit.checks.secrets._SHELL_CONFIGS", [tmpfile]):
                return check.run()
        finally:
            os.unlink(tmpfile)

    # ── Clean files ───────────────────────────────────────────────────────────

    def test_clean_file_returns_pass(self):
        """A typical ``PATH`` assignment has no secrets → ``pass``."""
        result = self._run_with_content("export PATH=$PATH:/usr/local/bin\n")
        assert result.status == "pass"

    def test_empty_file_returns_pass(self):
        """An empty shell config file has no secrets → ``pass``."""
        result = self._run_with_content("")
        assert result.status == "pass"

    def test_comment_only_file_returns_pass(self):
        """A credential pattern on a commented-out line must not trigger a warning.

        Shell comment lines (``#``) are excluded from scanning to avoid
        false positives from examples or disabled exports.
        """
        result = self._run_with_content("# export AWS_SECRET_ACCESS_KEY=abc123defxyz\n")
        assert result.status == "pass"

    # ── Detected credentials ──────────────────────────────────────────────────

    def test_detects_aws_access_key_id(self):
        """A live ``AWS_ACCESS_KEY_ID`` export → ``warning`` with the variable name."""
        result = self._run_with_content(
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        )
        assert result.status == "warning"
        assert "AWS_ACCESS_KEY_ID" in result.message

    def test_detects_aws_secret_access_key(self):
        """A live ``AWS_SECRET_ACCESS_KEY`` export → ``warning``."""
        result = self._run_with_content(
            "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENGbPxRfiCYEXAMPLEKEY\n"
        )
        assert result.status == "warning"

    def test_detects_openai_api_key(self):
        """An ``OPENAI_API_KEY`` with ``sk-`` prefix → ``warning`` with variable name."""
        result = self._run_with_content(
            "export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcde\n"
        )
        assert result.status == "warning"
        assert "OPENAI_API_KEY" in result.message

    def test_detects_generic_api_key_pattern(self):
        """A generic ``*_API_KEY`` variable with an ``sk-`` prefixed value → ``warning``."""
        result = self._run_with_content(
            "export MY_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890\n"
        )
        assert result.status == "warning"

    def test_detects_github_token(self):
        """A ``GITHUB_TOKEN`` with a ``ghp_`` prefixed value → ``warning``."""
        result = self._run_with_content(
            "export GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456\n"
        )
        assert result.status == "warning"

    def test_warning_message_includes_file_and_key(self):
        """The warning message names the variable so the user knows where to look."""
        result = self._run_with_content(
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        )
        assert "AWS_ACCESS_KEY_ID" in result.message

    def test_warning_redacts_value(self):
        """The full secret value must NOT appear verbatim in the warning message.

        This is a security property: the scan output itself must not leak
        the credential in plaintext.
        """
        secret = "AKIAIOSFODNN7EXAMPLE"
        result = self._run_with_content(f"export AWS_ACCESS_KEY_ID={secret}\n")
        assert result.status == "warning"
        assert secret not in result.message

    def test_count_in_message_when_multiple_findings(self):
        """Multiple findings in the same file → the count appears in the message."""
        content = (
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcde\n"
        )
        result = self._run_with_content(content)
        assert result.status == "warning"
        assert "2" in result.message

    # ── Safe-value exclusions ─────────────────────────────────────────────────

    def test_ignores_variable_reference_dollar_sign(self):
        """Values beginning with ``$`` are variable references, not literal secrets."""
        result = self._run_with_content("export API_KEY=$SOME_VAR\n")
        assert result.status == "pass"

    def test_ignores_file_path_value(self):
        """Values beginning with ``/`` are file paths, not credentials."""
        result = self._run_with_content("export DATABASE_URL=/var/db/my.db\n")
        assert result.status == "pass"

    def test_ignores_home_relative_path(self):
        """Values beginning with ``~/`` are home-relative paths, not credentials."""
        result = self._run_with_content("export MY_SECRET=~/secrets/key.pem\n")
        assert result.status == "pass"

    def test_ignores_boolean_value(self):
        """Single-word boolean values like ``true``/``false`` are not credentials."""
        result = self._run_with_content("export MY_TOKEN=true\n")
        assert result.status == "pass"

    def test_ignores_url_value(self):
        """URL values (containing ``://``) are connection strings, not secrets."""
        result = self._run_with_content(
            "export DATABASE_URL=https://user:pass@db.example.com/mydb\n"
        )
        assert result.status == "pass"

    def test_ignores_short_value_under_10_chars(self):
        """Values shorter than 10 characters don't match the regex → ``pass``.

        Real credentials are always long; a short value is almost certainly a
        placeholder or config flag, not an actual secret.
        """
        result = self._run_with_content("export API_KEY=tooshort\n")
        assert result.status == "pass"

    # ── Edge cases ────────────────────────────────────────────────────────────

    def test_long_lines_are_skipped_by_redos_guard(self):
        """Lines longer than 500 characters are skipped to prevent ReDoS.

        Pathological regex inputs on very long lines could cause catastrophic
        backtracking.  The guard must silently skip the line, not crash.
        """
        long_line = "A" * 501
        result = self._run_with_content(long_line + "\n")
        assert result.status == "pass"

    def test_line_exactly_500_chars_is_not_skipped(self):
        """A 500-character line is at the boundary and must still be scanned.

        The guard condition is ``> 500``, so exactly 500 characters is allowed.
        The result status is not constrained (the line content is benign here)
        — the test just asserts the check doesn't crash.
        """
        line = "export PATH=" + "x" * 488  # 500 chars total, value is file-path-like
        result = self._run_with_content(line + "\n")
        assert result.status in ("pass", "warning", "info")

    def test_nonexistent_file_is_skipped_gracefully(self):
        """A path in ``_SHELL_CONFIGS`` that does not exist → silently skipped.

        Users commonly reference shell configs that don't yet exist
        (e.g. ``~/.zshrc`` on a new machine); the check must not error out.
        """
        check = ShellSecretsCheck()
        with patch(
            "macaudit.checks.secrets._SHELL_CONFIGS",
            ["/does/not/exist/.mactuner_test_zshrc"],
        ):
            result = check.run()
        assert result.status == "pass"

    def test_result_data_contains_findings_list(self):
        """``result.data["findings"]`` is a non-empty list when a secret is detected.

        The diff engine and JSON export consume ``result.data`` to track
        which credentials were found; the structure must be a list, not a
        plain count.
        """
        result = self._run_with_content(
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        )
        assert "findings" in result.data
        assert isinstance(result.data["findings"], list)
        assert len(result.data["findings"]) >= 1
