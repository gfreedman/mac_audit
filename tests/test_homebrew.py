"""
Tests for the ``brew doctor`` check in checks/homebrew.py.

Covers:
    - ``_parse_doctor_warnings()``: the pure parser that splits raw
      ``brew doctor`` output into ``DoctorWarning`` blocks (preamble dropped,
      one block per column-0 ``Warning:`` line, indentation preserved, ANSI
      escapes and control characters removed, CRLF tolerated).
    - ``_parse_untrusted_taps()``: extraction of tap names and installed
      formulae/casks from Homebrew's tap-trust warning, including several
      items on one line and rejection of names failing the allow-lists.
    - ``_untrusted_tap_steps()``: the copy-pasteable remediation steps.
    - ``HomebrewDoctorCheck``: fix metadata (must be ``instructions``, not
      ``auto`` — re-running ``brew doctor`` fixes nothing) and ``run()``
      end-to-end with ``shell()`` patched, including the ``rc == -1`` error
      path and the ``--json`` data contract.

Design:
    ``UNTRUSTED_TAP_OUTPUT`` is verbatim ``brew doctor`` stderr captured on a
    real machine, so the parser is tested against what Homebrew actually
    prints rather than a hand-simplified approximation. The multi-item and
    cask variants follow the exact format of Homebrew's
    ``check_for_untrusted_taps`` (``Library/Homebrew/diagnostic.rb``).
    ``run()`` tests patch ``HomebrewDoctorCheck.shell`` to return canned
    ``(rc, stdout, stderr)`` tuples; no subprocess is spawned and ``brew``
    need not be installed.
"""

from unittest.mock import patch

import pytest

from macaudit.checks.homebrew import (
    DoctorWarning,
    HomebrewDoctorCheck,
    _is_untrusted_taps_warning,
    _parse_doctor_warnings,
    _parse_untrusted_taps,
    _untrusted_tap_steps,
)
from macaudit.enums import CheckStatus, FixLevel


# Verbatim stderr from Homebrew with one untrusted tap that has one installed
# formula. Captured from `brew doctor` (exit status 1).
UNTRUSTED_TAP_OUTPUT = """\
Please note that these warnings are just used to help the Homebrew maintainers
with debugging if you file an issue. If everything you use Homebrew for is
working fine: please don't worry or file an issue; just ignore this. Thanks!

Warning: The following taps are not trusted:
  gfreedman/mactuner

Homebrew is currently ignoring formulae, casks and commands
from these taps because tap trust is required.
Prefer trusting only the specific formulae, casks or commands you need.
Trust installed formulae from these taps with:
  brew trust --formula gfreedman/mactuner/mactuner
Trust other specific casks and commands with:
  brew trust --cask <user>/<tap>/<cask>
  brew trust --command <user>/<tap>/<command>
Whole-tap trust is broader and includes all current and future formulae,
casks and commands from the listed taps. Trust whole taps with:
  brew trust gfreedman/mactuner
Untap them with:
  brew untap gfreedman/mactuner
For more information, see:
  https://docs.brew.sh/Tap-Trust
"""

# Two untrusted taps: one with two formulae and a cask installed, one empty.
# Homebrew puts every installed item of a kind on a single line.
MULTI_TAP_OUTPUT = """\
Warning: The following taps are not trusted:
  acme/tools
  acme/unused

Homebrew is currently ignoring formulae, casks and commands
from these taps because tap trust is required.
Prefer trusting only the specific formulae, casks or commands you need.
Trust installed formulae from these taps with:
  brew trust --formula acme/tools/alpha acme/tools/beta@2
Trust installed casks from these taps with:
  brew trust --cask acme/tools/gizmo
"""

# A generic, unrecognised warning in Homebrew's usual shape.
BROKEN_SYMLINKS_OUTPUT = """\
Warning: Broken symlinks were found. Remove them with `brew cleanup`:
  /opt/homebrew/bin/foo
"""


def _run_with(rc: int, stdout: str = "", stderr: str = ""):
    """Run ``HomebrewDoctorCheck.run()`` with ``shell()`` returning canned output.

    Args:
        rc (int): Exit status to report for ``brew doctor``.
        stdout (str): Simulated standard output.
        stderr (str): Simulated standard error.

    Returns:
        CheckResult: The result produced by ``run()``.
    """
    with patch.object(HomebrewDoctorCheck, "shell", return_value=(rc, stdout, stderr)):
        return HomebrewDoctorCheck().run()


# ── _parse_doctor_warnings() — pure parser ───────────────────────────────────

class TestParseDoctorWarnings:
    """Tests for splitting ``brew doctor`` output into warning blocks."""

    def test_empty_output_yields_no_warnings(self):
        """No ``Warning:`` lines means an empty list, not an error."""
        assert _parse_doctor_warnings("") == []

    def test_preamble_is_discarded(self):
        """The "Please note..." boilerplate before the first warning is not a block."""
        warnings = _parse_doctor_warnings(UNTRUSTED_TAP_OUTPUT)
        assert len(warnings) == 1
        assert warnings[0].title == "The following taps are not trusted:"

    def test_details_keep_leading_indentation(self):
        """Indentation marks list items, so it must survive parsing."""
        warnings = _parse_doctor_warnings(UNTRUSTED_TAP_OUTPUT)
        assert warnings[0].details[0] == "  gfreedman/mactuner"

    def test_multiple_blocks_split_on_warning_lines(self):
        """Each ``Warning:`` line opens a new block; details do not bleed across."""
        warnings = _parse_doctor_warnings(UNTRUSTED_TAP_OUTPUT + BROKEN_SYMLINKS_OUTPUT)
        assert [w.title.split()[0] for w in warnings] == ["The", "Broken"]
        assert not any("foo" in line for line in warnings[0].details)
        assert warnings[1].details == ("  /opt/homebrew/bin/foo",)

    def test_indented_warning_text_does_not_open_a_block(self):
        """Only column-0 ``Warning:`` starts a block; indented text is body."""
        warnings = _parse_doctor_warnings("Warning: A\n  Warning: quoted\n")
        assert len(warnings) == 1
        assert warnings[0].details == ("  Warning: quoted",)

    def test_ansi_colour_codes_are_stripped(self):
        """``HOMEBREW_COLOR`` output (``\\x1b[4;33mWarning\\x1b[0m:``) still parses."""
        coloured = "\x1b[4;33mWarning\x1b[0m: Something \x1b[1mbad\x1b[0m\n  detail\n"
        (warning,) = _parse_doctor_warnings(coloured)
        assert warning.title == "Something bad"
        assert warning.details == ("  detail",)

    def test_crlf_line_endings(self):
        """CRLF output parses identically to LF output."""
        crlf = UNTRUSTED_TAP_OUTPUT.replace("\n", "\r\n")
        assert _parse_doctor_warnings(crlf) == _parse_doctor_warnings(UNTRUSTED_TAP_OUTPUT)


# ── _parse_untrusted_taps() — tap and item extraction ────────────────────────

class TestParseUntrustedTaps:
    """Tests for extracting taps and installed items from the tap-trust warning."""

    def test_detects_untrusted_taps_warning(self):
        """The tap-trust block is recognised; an unrelated block is not."""
        tap_w, sym_w = _parse_doctor_warnings(UNTRUSTED_TAP_OUTPUT + BROKEN_SYMLINKS_OUTPUT)
        assert _is_untrusted_taps_warning(tap_w)
        assert not _is_untrusted_taps_warning(sym_w)

    def test_extracts_tap_and_installed_formula(self):
        """The real capture yields one tap with one installed formula."""
        (warning,) = _parse_doctor_warnings(UNTRUSTED_TAP_OUTPUT)
        taps, items = _parse_untrusted_taps(warning)
        assert taps == ["gfreedman/mactuner"]
        assert items == {"gfreedman/mactuner": ["--formula gfreedman/mactuner/mactuner"]}

    def test_placeholder_commands_are_ignored(self):
        """``brew trust --cask <user>/<tap>/<cask>`` is a template, not an item."""
        (warning,) = _parse_doctor_warnings(UNTRUSTED_TAP_OUTPUT)
        _, items = _parse_untrusted_taps(warning)
        assert all("<" not in i for its in items.values() for i in its)

    def test_several_items_on_one_line_and_casks(self):
        """Every name on a multi-item line is kept, and casks are recognised.

        Regression: a single-name regex mapped this tap to ``[]`` and wrongly
        advised a plain ``brew untap``, which Homebrew refuses.
        """
        (warning,) = _parse_doctor_warnings(MULTI_TAP_OUTPUT)
        taps, items = _parse_untrusted_taps(warning)
        assert taps == ["acme/tools", "acme/unused"]
        assert items == {
            "acme/tools": [
                "--formula acme/tools/alpha",
                "--formula acme/tools/beta@2",
                "--cask acme/tools/gizmo",
            ],
            "acme/unused": [],
        }

    @pytest.mark.parametrize(
        "bad", ["evil/tap; rm -rf ~", "no-slash", "a/b/c", "../..", "--force/x", ".hidden/tap"]
    )
    def test_malformed_tap_names_rejected(self, bad):
        """Names failing the allow-list never reach a suggested command."""
        warning = DoctorWarning("The following taps are not trusted:", (f"  {bad}",))
        taps, _ = _parse_untrusted_taps(warning)
        assert taps == []

    def test_malformed_item_names_rejected(self):
        """A bad name on a trust line is dropped; its valid neighbours are kept."""
        warning = DoctorWarning(
            "The following taps are not trusted:",
            ("  a/one", "", "  brew trust --formula a/one/ok a/one/$(bad) a/one/-x"),
        )
        _, items = _parse_untrusted_taps(warning)
        assert items == {"a/one": ["--formula a/one/ok"]}

    def test_item_for_unlisted_tap_ignored(self):
        """A trust line naming a tap that is not in the list is dropped."""
        warning = DoctorWarning(
            "The following taps are not trusted:",
            ("  a/one", "", "  brew trust --formula other/tap/thing"),
        )
        _, items = _parse_untrusted_taps(warning)
        assert items == {"a/one": []}


# ── _untrusted_tap_steps() — remediation text ────────────────────────────────

class TestUntrustedTapSteps:
    """Tests for the copy-pasteable remediation steps."""

    def test_installed_items_get_remove_then_trust(self):
        """Removal (``untap --force``) comes first; trust covers each item."""
        steps = _untrusted_tap_steps(
            ["acme/tools"], {"acme/tools": ["--formula acme/tools/alpha", "--cask acme/tools/gizmo"]}
        )
        assert len(steps) == 2
        # `--force` because plain `brew untap` refuses while items are installed.
        assert steps[0].endswith("brew untap --force acme/tools")
        assert "brew trust --formula acme/tools/alpha" in steps[1]
        assert "brew trust --cask acme/tools/gizmo" in steps[1]

    def test_commands_sit_on_their_own_lines(self):
        """Each command is on a separate line so it can be copied cleanly."""
        steps = _untrusted_tap_steps(["a/one"], {"a/one": ["--formula a/one/x"]})
        assert steps[0].splitlines()[1].strip() == "brew untap --force a/one"

    def test_empty_tap_gets_plain_untap_only(self):
        """With nothing installed, the single suggestion is a plain untap."""
        steps = _untrusted_tap_steps(["a/one"], {"a/one": []})
        assert len(steps) == 1
        assert steps[0].splitlines()[1].strip() == "brew untap a/one"


# ── HomebrewDoctorCheck — metadata and run() ─────────────────────────────────

class TestHomebrewDoctorCheck:
    """End-to-end tests for ``HomebrewDoctorCheck`` with ``shell()`` patched."""

    def test_fix_is_instructions_not_auto(self):
        """``brew doctor`` changes nothing, so it must never be offered as an auto fix."""
        check = HomebrewDoctorCheck()
        assert check.fix_level == FixLevel.INSTRUCTIONS
        assert check.fix_command is None
        assert check.fix_steps

    def test_colour_is_disabled_for_brew(self):
        """``brew doctor`` is invoked with ``HOMEBREW_NO_COLOR`` set."""
        with patch.object(HomebrewDoctorCheck, "shell", return_value=(0, "", "")) as shell:
            HomebrewDoctorCheck().run()
        assert shell.call_args.kwargs["env"] == {"HOMEBREW_NO_COLOR": "1"}

    def test_exit_zero_passes(self):
        """Exit status 0 is a pass."""
        result = _run_with(0, "Your system is ready to brew.\n")
        assert result.status == CheckStatus.PASS

    def test_ready_to_brew_text_does_not_mask_failure(self):
        """A non-zero exit is a warning even if "ready to brew" appears somewhere."""
        result = _run_with(1, stderr=BROKEN_SYMLINKS_OUTPUT.replace("foo", "ready to brew"))
        assert result.status == CheckStatus.WARNING

    def test_could_not_run_is_error_not_finding(self):
        """``rc == -1`` (timeout / exec failure) is an ``error``, not a Homebrew issue."""
        result = _run_with(-1, stderr="Command timed out after 30s: brew doctor")
        assert result.status == CheckStatus.ERROR
        assert "timed out" in result.message

    def test_untrusted_tap_names_tap_and_gives_commands(self):
        """The real capture produces a specific message and targeted steps."""
        result = _run_with(1, stderr=UNTRUSTED_TAP_OUTPUT)
        assert result.status == CheckStatus.WARNING
        assert result.message == "Homebrew: Untrusted tap gfreedman/mactuner"
        assert any("brew untap --force gfreedman/mactuner" in s for s in result.fix_steps)
        assert result.fix_steps[-1].startswith("Re-run 'brew doctor'")

    def test_json_data_contract(self):
        """``data`` always has the same three keys; ``warnings`` keeps its old format."""
        result = _run_with(1, stderr=UNTRUSTED_TAP_OUTPUT)
        assert result.data == {
            "warnings": ["Warning: The following taps are not trusted:"],
            "untrusted_taps": ["gfreedman/mactuner"],
            "output_preview": "",
        }
        fallback = _run_with(1, stderr="Error: something unexpected")
        assert set(fallback.data) == {"warnings", "untrusted_taps", "output_preview"}

    def test_support_tier_stdout_is_not_parsed_into_warnings(self):
        """stdout's trailer is not appended to the last warning block."""
        result = _run_with(1, stdout="Support tier notice\n", stderr=UNTRUSTED_TAP_OUTPUT)
        assert result.data["untrusted_taps"] == ["gfreedman/mactuner"]
        assert not any("Support tier" in s for s in result.fix_steps)

    def test_per_result_steps_do_not_mutate_class_defaults(self):
        """Targeted steps live on the result only; the class fallback is untouched."""
        before = list(HomebrewDoctorCheck.fix_steps)
        _run_with(1, stderr=UNTRUSTED_TAP_OUTPUT)
        assert HomebrewDoctorCheck.fix_steps == before

    def test_unrecognised_warning_points_at_its_title(self):
        """Unknown warnings get a step naming the warning to look for."""
        result = _run_with(1, stderr=BROKEN_SYMLINKS_OUTPUT)
        assert result.message.startswith("Homebrew: Broken symlinks were found")
        assert "Warning: Broken symlinks" in result.fix_steps[0]

    def test_long_titles_are_truncated_in_message(self):
        """A very long warning title cannot blow up the report row."""
        result = _run_with(1, stderr="Warning: " + "x" * 500 + "\n")
        assert len(result.message) < 100
        assert result.message.endswith("…")

    def test_multiple_warnings_counted_and_summarised(self):
        """Two blocks produce a count and both summaries."""
        result = _run_with(1, stderr=MULTI_TAP_OUTPUT + BROKEN_SYMLINKS_OUTPUT)
        assert result.message.startswith("2 Homebrew warnings — untrusted taps acme/tools, acme/unused; ")
        assert len(result.data["warnings"]) == 2

    def test_unparseable_failure_falls_back_to_generic_steps(self):
        """A non-zero exit without ``Warning:`` lines keeps the class-level steps."""
        result = _run_with(1, stderr="Error: something unexpected")
        assert result.message == "brew doctor reported issues"
        assert result.fix_steps == HomebrewDoctorCheck.fix_steps
        assert result.data["output_preview"] == "Error: something unexpected"
