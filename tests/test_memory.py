"""
Tests for ``MemoryPressureCheck`` in checks/memory.py.

Covers:
    - ``_classify_memory_pressure_output()``: the pure fallback parser for the
      ``memory_pressure`` tool, including the regression where "wired"
      (``Pages wired down``) was matched as the colour word "red".
    - ``MemoryPressureCheck.run()``: the kernel sysctl as primary source
      (libdispatch encoding 1/2/4), and fallback to ``memory_pressure`` when
      the sysctl fails or returns an unknown value.

Design:
    ``MACOS_27_OUTPUT`` is verbatim ``memory_pressure`` output captured on
    macOS 27.0 with normal pressure. It contains no level line and no colour
    word — only statistics — so it must classify as unknown, never critical.
    ``run()`` tests patch ``shell()`` with a side-effect function keyed on the
    command so each source can be controlled independently; no subprocess is
    spawned.
"""

from unittest.mock import patch

import pytest

from macaudit.checks.memory import MemoryPressureCheck, _classify_memory_pressure_output
from macaudit.enums import CheckStatus


# Verbatim `memory_pressure` output from macOS 27.0 (pressure: normal).
MACOS_27_OUTPUT = """\
The system has 17179869184 (1048576 pages with a page size of 16384).

Stats:
Pages free: 25838
Pages purgeable: 6172
Pages purged: 5077641

Swap I/O:
Swapins: 0
Swapouts: 0

Page Q counts:
Pages active: 273673
Pages inactive: 275900
Pages speculative: 3028
Pages throttled: 0
Pages wired down: 134086

Compressor Stats:
Pages used by compressor: 298548
Pages decompressed: 19376403
Pages compressed: 25336615

File I/O:
Pageins: 37640379
Pageouts: 43328

System-wide memory free percentage: 57%
"""


def _run_with(sysctl: tuple[int, str, str], tool: tuple[int, str, str] = (0, "", "")):
    """Run ``MemoryPressureCheck.run()`` with canned output for each command.

    Args:
        sysctl: ``(rc, stdout, stderr)`` returned for the sysctl call.
        tool: ``(rc, stdout, stderr)`` returned for ``memory_pressure``.

    Returns:
        CheckResult: The result produced by ``run()``.
    """
    def fake_shell(cmd, *args, **kwargs):
        return sysctl if cmd[0] == "sysctl" else tool

    with patch.object(MemoryPressureCheck, "shell", side_effect=fake_shell):
        return MemoryPressureCheck().run()


# ── _classify_memory_pressure_output() — fallback parser ─────────────────────

class TestClassifyMemoryPressureOutput:
    """Tests for the whole-word ``memory_pressure`` fallback parser."""

    def test_wired_is_not_red(self):
        """Regression: "Pages wired down" must not be read as the colour red."""
        assert _classify_memory_pressure_output(MACOS_27_OUTPUT) is None

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("System memory pressure level: Normal", "normal"),
            ("System memory pressure level: Warning", "warn"),
            ("System memory pressure level: Critical", "critical"),
        ],
    )
    def test_structured_line(self, line, expected):
        """The macOS 13–14 structured line is classified by its level word."""
        assert _classify_memory_pressure_output(f"Stats:\n{line}\n") == expected

    def test_substring_ok_does_not_count_as_normal(self):
        """"ok" inside another word (e.g. "broken") is not the word "ok"."""
        assert _classify_memory_pressure_output("System memory pressure: broken\n") is None

    @pytest.mark.parametrize(("word", "expected"), [("red", "critical"), ("Yellow", "warn"), ("GREEN", "normal")])
    def test_colour_words(self, word, expected):
        """Whole colour words are recognised case-insensitively."""
        assert _classify_memory_pressure_output(f"Pressure: {word}\n") == expected

    def test_most_severe_colour_wins(self):
        """If several colour words appear, red outranks yellow and green."""
        assert _classify_memory_pressure_output("green then red\n") == "critical"


# ── MemoryPressureCheck.run() ────────────────────────────────────────────────

class TestMemoryPressureCheck:
    """End-to-end tests for ``MemoryPressureCheck.run()`` with ``shell()`` patched."""

    @pytest.mark.parametrize(
        ("value", "status"),
        [("1", CheckStatus.PASS), ("2", CheckStatus.WARNING), ("4", CheckStatus.CRITICAL)],
    )
    def test_sysctl_levels(self, value, status):
        """The kernel's 1/2/4 encoding maps to pass/warning/critical."""
        result = _run_with(sysctl=(0, f"{value}\n", ""))
        assert result.status == status
        assert result.data["source"] == "sysctl"

    def test_sysctl_wins_over_tool_output(self):
        """With a valid sysctl value, ``memory_pressure`` text is never consulted."""
        result = _run_with(sysctl=(0, "1\n", ""), tool=(0, "Pressure: red\n", ""))
        assert result.status == CheckStatus.PASS

    def test_macos_27_normal_is_not_critical(self):
        """Regression: the real macOS 27 system this was found on reports pass."""
        result = _run_with(sysctl=(0, "1\n", ""), tool=(0, MACOS_27_OUTPUT, ""))
        assert result.status == CheckStatus.PASS

    def test_falls_back_when_sysctl_fails(self):
        """A failed sysctl falls back to parsing ``memory_pressure``."""
        result = _run_with(
            sysctl=(1, "", "unknown oid"),
            tool=(0, "System memory pressure level: Warning\n", ""),
        )
        assert result.status == CheckStatus.WARNING
        assert result.data["source"] == "memory_pressure"

    def test_falls_back_on_unknown_sysctl_value(self):
        """An undocumented sysctl value is not guessed at; the tool decides."""
        result = _run_with(sysctl=(0, "8\n", ""), tool=(0, "Pressure: green\n", ""))
        assert result.status == CheckStatus.PASS
        assert result.data["source"] == "memory_pressure"

    def test_unrecognised_fallback_is_info(self):
        """No sysctl and unclassifiable tool output → ``info``, never a false alarm."""
        result = _run_with(sysctl=(1, "", ""), tool=(0, MACOS_27_OUTPUT, ""))
        assert result.status == CheckStatus.INFO

    def test_both_sources_fail_is_info(self):
        """Neither source available → ``info`` "Could not read memory pressure"."""
        result = _run_with(sysctl=(-1, "", ""), tool=(-1, "", "not found"))
        assert result.status == CheckStatus.INFO
        assert result.message == "Could not read memory pressure"
