"""
Developer environment health checks.

This module implements six checks targeting common developer toolchain
configurations that lead to hard-to-debug environment issues on macOS.
The philosophy is **PATH-focused**: checks look at what is visible in ``PATH``
and well-known home-directory locations, rather than exhaustively scanning the
filesystem for every possible installation.

Rationale:
    A filesystem-wide search (e.g. ``find / -name python3``) would be slow,
    noisy, and produce false positives for virtual environments and Docker
    volumes.  Checking ``PATH`` and a small set of well-known directories
    matches what the shell actually resolves at runtime.

Checks:
    - :class:`XcodeToolsCheck`      — Xcode Command Line Tools installed and
                                      version visible.
    - :class:`PythonConflictsCheck` — Multiple ``python3`` binaries in PATH
                                      that can cause package installation
                                      confusion.
    - :class:`CondaCheck`           — Conda ``auto_activate_base`` setting that
                                      silently overrides the default Python.
    - :class:`NodeManagerCheck`     — Multiple Node.js version managers (nvm,
                                      volta, fnm, n) installed simultaneously.
    - :class:`RubyConflictsCheck`   — System Ruby (``/usr/bin/ruby``) first in
                                      PATH, breaking ``gem install`` workflows.
    - :class:`GitConfigCheck`       — Git global user identity and plaintext
                                      credential helper detection.

Attributes:
    ALL_CHECKS (list[type[BaseCheck]]): Ordered list of check classes exported
        to the scan orchestrator.  All checks use
        ``profile_tags = ("developer",)`` and therefore run only under the
        ``developer`` profile (auto-detected when Homebrew is installed).

Note:
    All subprocess calls use ``self.shell()``, which enforces ``LANG=C``
    and ``LC_ALL=C`` for consistent English output regardless of locale.
"""

from __future__ import annotations

import os

from macaudit.checks.base import BaseCheck, CheckResult


# ── Xcode Command Line Tools ──────────────────────────────────────────────────

class XcodeToolsCheck(BaseCheck):
    """Verify Xcode Command Line Tools are installed and current."""

    id = "xcode_cli_tools"
    name = "Xcode CLI Tools"
    category = "dev_env"
    category_icon = "🛠️ "
    profile_tags = ("developer",)

    scan_description = (
        "Checking Xcode Command Line Tools — "
        "outdated or missing tools break git, compilers, and most developer workflows."
    )
    finding_explanation = (
        "Xcode Command Line Tools provide essential compilers (clang), git, make, "
        "and build tools that Homebrew and most dev tools depend on. "
        "Outdated CLTools can cause 'invalid active developer path' errors, "
        "Homebrew build failures, and mysterious 'xcrun' errors after macOS upgrades."
    )
    recommendation = (
        "If missing, run: xcode-select --install  "
        "If outdated, run: softwareupdate --all --install --force  "
        "Or check Software Update in System Settings."
    )

    fix_level = "instructions"
    fix_description = "Install or update Xcode Command Line Tools."
    fix_steps = [
        "To install: xcode-select --install",
        "To update:  softwareupdate --all --install --force",
        "Or: System Settings → Software Update",
    ]
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Confirm CLTools installation via ``xcode-select -p`` and retrieve the version.

        Runs ``xcode-select -p`` to check whether the active developer directory
        is set.  A non-zero exit code means CLTools are not installed.  If
        installed, the check queries ``pkgutil`` for the
        ``com.apple.pkg.CLTools_Executables`` package to extract the version
        string shown in the result message.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"warning"`` — CLTools are not installed; many developer tools
              will be broken or absent.
            - ``"pass"`` — CLTools are installed; version is shown if detectable
              via ``pkgutil``.
        """
        rc, path_out, _ = self.shell(["xcode-select", "-p"])

        if rc != 0:
            return self._warning("Xcode Command Line Tools not installed")

        path = path_out.strip()

        # Try to get the CLTools version
        rc2, ver_out, _ = self.shell(
            ["pkgutil", "--pkg-info=com.apple.pkg.CLTools_Executables"]
        )
        if rc2 == 0:
            for line in ver_out.splitlines():
                if "version:" in line.lower():
                    version = line.split(":", 1)[-1].strip()
                    return self._pass(f"CLTools {version}  —  {path}")

        # Fallback: just confirm they're installed
        return self._pass(f"Installed at {path}")


# ── Python PATH conflicts ─────────────────────────────────────────────────────

class PythonConflictsCheck(BaseCheck):
    """Detect multiple python3 binaries in PATH that could cause version and pip conflicts."""

    id = "python_conflicts"
    name = "Python PATH Conflicts"
    category = "dev_env"
    category_icon = "🐍"
    profile_tags = ("developer",)

    scan_description = (
        "Checking for multiple Python 3 installations in PATH — "
        "conflicting Pythons cause packages to install to the wrong place "
        "and 'import' to fail unexpectedly."
    )
    finding_explanation = (
        "When 'python3' could resolve to the system Python, a Homebrew Python, "
        "a pyenv Python, or a conda Python, pip installs to different locations "
        "depending on which python3 is active. This causes packages to appear "
        "'missing' and version conflicts between projects."
    )
    recommendation = (
        "Use one canonical Python per project via virtual environments "
        "('python3 -m venv .venv'). "
        "Run 'which -a python3' to see all Pythons in PATH. "
        "Consider pyenv or conda for managing multiple versions intentionally."
    )

    fix_level = "instructions"
    fix_description = "Use virtual environments to isolate project dependencies."
    fix_steps = [
        "Run: which -a python3  (see all python3 in PATH)",
        "For each project: python3 -m venv .venv && source .venv/bin/activate",
        "To standardise: use pyenv to manage Python versions",
        "Homebrew users: avoid 'pip install' globally, prefer venvs",
    ]
    fix_reversible = True
    fix_time_estimate = "~10 minutes"

    def run(self) -> CheckResult:
        """Run ``which -a python3`` and warn if more than one unique binary path is returned.

        ``which -a`` lists **all** matching executables in ``PATH`` in order.
        Duplicate paths are de-duplicated via a dict (preserving order).
        If the de-duplicated list has more than one entry it means different
        directories in ``PATH`` each contain a different ``python3`` binary —
        the classic conflict scenario.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — no ``python3`` found in PATH at all.
            - ``"pass"`` — exactly one unique ``python3`` path in PATH;
              active version string is shown.
            - ``"warning"`` — two or more unique ``python3`` paths; the count
              and active version are shown.
        """
        rc, out, _ = self.shell(["which", "-a", "python3"])
        if rc != 0 or not out.strip():
            return self._info("python3 not found in PATH")

        paths = [p.strip() for p in out.splitlines() if p.strip()]
        unique = list(dict.fromkeys(paths))

        ver_rc, ver_out, _ = self.shell(["python3", "--version"])
        version = ver_out.strip() if ver_rc == 0 else ""

        if len(unique) <= 1:
            active = unique[0] if unique else "in PATH"
            return self._pass(f"{version}  —  {active}")

        return self._warning(
            f"{len(unique)} python3 binaries in PATH — version conflicts possible",
            data={"python_paths": unique, "active": version},
        )


# ── Conda ─────────────────────────────────────────────────────────────────────

class CondaCheck(BaseCheck):
    """Detect conda installations and warn if auto_activate_base is enabled."""

    id = "conda_detected"
    name = "Conda / Anaconda"
    category = "dev_env"
    category_icon = "🐍"
    profile_tags = ("developer",)

    scan_description = (
        "Checking for conda (Anaconda/Miniconda/Miniforge) — "
        "conda auto-activation overrides system Python and can conflict with Homebrew."
    )
    finding_explanation = (
        "Conda manages its own Python ecosystem. When 'auto_activate_base' is on, "
        "every new shell starts with conda's Python active, which can override "
        "Homebrew Python and make pip installs go to conda's environment silently."
    )
    recommendation = (
        "Run: conda config --set auto_activate_base false  "
        "This prevents conda from hijacking your default shell. "
        "Activate it explicitly with 'conda activate' when you need it."
    )

    fix_level = "instructions"
    fix_description = "Disable conda auto-activation to prevent PATH conflicts."
    fix_command = ["conda", "config", "--set", "auto_activate_base", "false"]
    fix_steps = [
        "Run: conda config --set auto_activate_base false",
        "Restart your terminal",
        "Use 'conda activate <env>' only when working in conda projects",
    ]
    fix_reversible = True
    fix_time_estimate = "~1 minute"

    _CONDA_DIRS = [
        "anaconda3", "miniconda3", "miniforge3",
        "opt/anaconda3", "opt/miniconda3", "opt/miniforge3",
    ]
    _CONDA_SYSTEM_DIRS = [
        "/opt/anaconda3", "/opt/miniconda3", "/opt/miniforge3",
        "/opt/homebrew/Caskroom/miniconda/base",
    ]

    def run(self) -> CheckResult:
        """Scan well-known conda directories and PATH; check ``auto_activate_base`` if conda is present.

        Detection proceeds in two phases:

        1. **Directory scan** — checks each path in ``_CONDA_DIRS`` (relative to
           ``~``) and ``_CONDA_SYSTEM_DIRS`` (absolute system paths) for a
           directory that exists.
        2. **Command probe** — checks whether ``conda`` is in ``PATH``.

        If conda is detected, ``conda config --show auto_activate_base`` is
        called to read the current setting.  A missing or inaccessible config
        is treated as "auto-activate is on" (the conda default).

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"pass"`` — no conda installation detected.
            - ``"warning"`` — conda detected and ``auto_activate_base`` is
              ``True``; every new shell will activate the base environment.
            - ``"info"`` — conda detected but ``auto_activate_base`` is
              ``False``; no PATH override on shell start.
        """
        home = os.path.expanduser("~")
        found_paths = []

        for d in self._CONDA_DIRS:
            p = os.path.join(home, d)
            if os.path.isdir(p):
                found_paths.append(p)

        for p in self._CONDA_SYSTEM_DIRS:
            if os.path.isdir(p):
                found_paths.append(p)

        has_conda_cmd = self.has_tool("conda")

        if not found_paths and not has_conda_cmd:
            return self._pass("No conda installation detected")

        location = found_paths[0] if found_paths else "in PATH"

        # Check auto_activate_base setting
        auto_activate = True
        if has_conda_cmd:
            rc, out, _ = self.shell(
                ["conda", "config", "--show", "auto_activate_base"], timeout=15
            )
            if rc == 0 and "false" in out.lower():
                auto_activate = False

        if auto_activate:
            return self._warning(
                f"Conda auto-activate is ON — overrides default Python ({location})",
                data={"conda_path": location, "auto_activate": True},
            )

        return self._info(
            f"Conda detected — auto-activate is off ({location})",
            data={"conda_path": location, "auto_activate": False},
        )


# ── Node version managers ─────────────────────────────────────────────────────

class NodeManagerCheck(BaseCheck):
    """Detect Node.js version managers (nvm, volta, fnm, n) and warn if multiple are installed."""

    id = "node_managers"
    name = "Node Version Manager"
    category = "dev_env"
    category_icon = "🟩"
    profile_tags = ("developer",)

    scan_description = (
        "Checking for Node.js version managers — "
        "multiple managers (nvm + fnm + volta) can conflict and run the wrong Node version."
    )
    finding_explanation = (
        "Node version managers (nvm, fnm, volta, n) each hook into your shell differently. "
        "Having multiple installed means one manager's Node may shadow another's, "
        "causing projects to run with an unexpected Node version silently."
    )
    recommendation = (
        "Stick with one Node version manager. "
        "If you have multiple, remove the ones you don't use from your shell config. "
        "Run 'which -a node' to see all node binaries in PATH."
    )

    fix_level = "instructions"
    fix_description = "Standardise on one Node version manager."
    fix_steps = [
        "Run: which -a node  (see all node binaries in PATH)",
        "Remove unused manager init lines from ~/.zshrc / ~/.bashrc",
        "volta and fnm are fastest; nvm is most widely used",
    ]
    fix_reversible = True
    fix_time_estimate = "~10 minutes"

    def run(self) -> CheckResult:
        """Detect Node version managers by directory and PATH probe; warn if multiple are found.

        Detection strategy per manager:
          - **nvm**: checks for the ``~/.nvm/`` directory (nvm is a shell
            function, not a standalone binary, so PATH alone is insufficient).
          - **volta**: checks for the ``~/.volta/`` directory.
          - **fnm**, **n**: checks for the binary name in ``PATH`` via
            ``shutil.which``.

        If exactly one manager is found, the current ``node --version`` output
        is retrieved for the result message.  If no manager is found but Node is
        in PATH, that is reported as ``info`` without a warning.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — no Node.js detected, or one manager installed cleanly.
            - ``"warning"`` — two or more managers are installed simultaneously.
        """
        home = os.path.expanduser("~")
        found = []

        # nvm: usually a shell function — detect via directory
        if os.path.isdir(os.path.join(home, ".nvm")):
            found.append("nvm")

        # volta: ~/.volta/
        if os.path.isdir(os.path.join(home, ".volta")):
            found.append("volta")

        # fnm, n: binary in PATH
        for mgr in ("fnm", "n"):
            if self.has_tool(mgr) and mgr not in found:
                found.append(mgr)

        if not found:
            if self.has_tool("node"):
                rc, ver, _ = self.shell(["node", "--version"])
                return self._info(
                    f"Node {ver.strip()} installed (no version manager detected)"
                )
            return self._info("Node.js not detected")

        if len(found) > 1:
            return self._warning(
                f"Multiple Node managers detected: {', '.join(found)}",
                data={"managers": found},
            )

        # Single manager — get current node version
        if self.has_tool("node"):
            rc, ver, _ = self.shell(["node", "--version"])
            node_ver = ver.strip() if rc == 0 else "unknown"
            return self._info(
                f"Node manager: {found[0]}  —  node {node_ver}",
                data={"managers": found},
            )

        return self._info(f"Node manager: {found[0]}", data={"managers": found})


# ── Ruby PATH conflicts ───────────────────────────────────────────────────────

class RubyConflictsCheck(BaseCheck):
    """Check whether system Ruby (/usr/bin/ruby) is first in PATH, causing gem install issues."""

    id = "ruby_conflicts"
    name = "Ruby PATH"
    category = "dev_env"
    category_icon = "💎"
    profile_tags = ("developer",)

    scan_description = (
        "Checking Ruby PATH — "
        "system Ruby (/usr/bin/ruby) being first in PATH causes CocoaPods "
        "and gem install to fail or write to wrong locations."
    )
    finding_explanation = (
        "macOS ships a system Ruby at /usr/bin/ruby that should never be used for "
        "gem installs — it requires sudo and gets wiped by OS updates. "
        "If system Ruby is first in PATH ahead of Homebrew or rbenv Ruby, "
        "'gem install' goes to the wrong place and 'pod install' breaks."
    )
    recommendation = (
        "Add Homebrew Ruby before system ruby in PATH: "
        "export PATH=\"$(brew --prefix)/opt/ruby/bin:$PATH\" in ~/.zshrc. "
        "Or use rbenv: eval \"$(rbenv init -)\" in ~/.zshrc."
    )

    fix_level = "instructions"
    fix_description = "Ensure Homebrew or rbenv ruby comes before system ruby in PATH."
    fix_steps = [
        "Run: which -a ruby  (see all ruby in PATH)",
        "If system ruby is first, add to ~/.zshrc:",
        "  export PATH=\"$(brew --prefix)/opt/ruby/bin:$PATH\"",
        "Or: eval \"$(rbenv init -)\"  (if using rbenv)",
        "Then: exec $SHELL  to reload",
    ]
    fix_reversible = True
    fix_time_estimate = "~5 minutes"

    def run(self) -> CheckResult:
        """Run ``which -a ruby`` and warn if ``/usr/bin/ruby`` is first in the resolved list.

        ``which -a ruby`` returns every ``ruby`` binary found in ``PATH`` in
        order.  If the first entry is ``/usr/bin/ruby`` **and** at least one
        other Ruby exists (meaning the user has a non-system Ruby installed but
        it is not first in PATH), a warning is issued.

        If ``/usr/bin/ruby`` is the *only* Ruby, an informational result is
        returned suggesting installation of Homebrew Ruby for gem work.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"info"`` — ``ruby`` not found in PATH.
            - ``"info"`` — only system Ruby found; no managed Ruby installed.
            - ``"warning"`` — system Ruby is first but a better Ruby exists
              later in PATH (not being used).
            - ``"pass"`` — a non-system Ruby is first in PATH; version shown.
        """
        rc, out, _ = self.shell(["which", "-a", "ruby"])
        if rc != 0 or not out.strip():
            return self._info("ruby not found in PATH")

        paths = [p.strip() for p in out.splitlines() if p.strip()]
        unique = list(dict.fromkeys(paths))

        if len(unique) == 0:
            return self._info("No ruby in PATH")

        first = unique[0]

        # System ruby first = problem
        if first == "/usr/bin/ruby":
            if len(unique) == 1:
                return self._info(
                    "Only system Ruby (/usr/bin/ruby) in PATH — install Homebrew Ruby for gem work"
                )
            return self._warning(
                "System Ruby is first in PATH — gem installs go to the wrong place",
                data={"ruby_paths": unique},
            )

        # Non-system ruby first = good
        ver_rc, ver_out, _ = self.shell(["ruby", "--version"])
        version = ""
        if ver_rc == 0:
            parts = ver_out.split()
            version = parts[1] if len(parts) > 1 else ""
        return self._pass(
            f"Ruby {version}  —  {first}",
            data={"ruby_paths": unique},
        )


# ── Git config ────────────────────────────────────────────────────────────────

class GitConfigCheck(BaseCheck):
    """Verify git global config has user identity set and credential.helper is not 'store' (plaintext)."""

    id = "git_config"
    name = "Git Global Config"
    category = "dev_env"
    category_icon = "🔀"
    profile_tags = ("developer",)

    scan_description = (
        "Checking git global configuration — "
        "missing identity makes commits authorless; "
        "a plaintext credential helper exposes tokens."
    )
    finding_explanation = (
        "Git needs user.name and user.email to attribute commits correctly. "
        "Without them, commits show as 'Unknown' in GitHub, GitLab, and code review tools. "
        "The credential.helper setting controls how passwords are stored: "
        "'store' saves them in plaintext; 'osxkeychain' uses the secure macOS Keychain."
    )
    recommendation = (
        "Set: git config --global user.name 'Your Name'  "
        "and: git config --global user.email 'you@example.com'  "
        "Use secure credentials: git config --global credential.helper osxkeychain"
    )

    fix_level = "instructions"
    fix_description = "Configure git identity and use osxkeychain for secure credentials."
    fix_steps = [
        "git config --global user.name 'Your Name'",
        "git config --global user.email 'your@email.com'",
        "git config --global credential.helper osxkeychain",
    ]
    fix_reversible = True
    fix_time_estimate = "~2 minutes"

    def run(self) -> CheckResult:
        """Parse ``git config --global -l`` for identity fields and credential helper security.

        Runs ``git config --global -l`` and builds a ``{key: value}`` dict from
        all lines.  Three fields are checked:

        1. ``user.name`` — must be present for commits to be correctly attributed.
        2. ``user.email`` — must be present for commits to be correctly attributed.
        3. ``credential.helper`` — ``"store"`` stores credentials in a plaintext
           file (``~/.git-credentials``), which is a security risk.
           ``"osxkeychain"`` uses the encrypted macOS Keychain and is safe.

        Returns:
            CheckResult: A result with one of the following statuses:

            - ``"skip"`` — git is not installed.
            - ``"warning"`` — global config absent, or one or more of the three
              checks failed; issues are listed in the message.
            - ``"pass"`` — name and email are set; credential helper is not
              ``"store"``; active configuration is shown.
        """
        if not self.has_tool("git"):
            return self._skip("git not installed")

        rc, out, _ = self.shell(["git", "config", "--global", "-l"])

        # rc != 0 when no global config exists at all
        if rc != 0 and not out.strip():
            return self._warning(
                "No git global config found — user.name and user.email not set"
            )

        config: dict[str, str] = {}
        for line in out.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                config[k.strip().lower()] = v.strip()

        issues = []
        if "user.name" not in config:
            issues.append("user.name not set")
        if "user.email" not in config:
            issues.append("user.email not set")

        cred = config.get("credential.helper", "")
        if cred == "store":
            issues.append("credential.helper=store saves tokens in plaintext")

        if issues:
            return self._warning(
                f"Git config: {'; '.join(issues)}",
                data={"issues": issues},
            )

        name  = config.get("user.name", "?")
        email = config.get("user.email", "?")
        cred_note = f"  ·  creds: {cred}" if cred else "  ·  no credential helper set"
        return self._pass(f"{name} <{email}>{cred_note}")


# ── Export ────────────────────────────────────────────────────────────────────

ALL_CHECKS = [
    XcodeToolsCheck,
    PythonConflictsCheck,
    CondaCheck,
    NodeManagerCheck,
    RubyConflictsCheck,
    GitConfigCheck,
]
