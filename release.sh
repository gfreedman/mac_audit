#!/usr/bin/env bash
#
# release.sh — single-command release for macaudit
#
# Runs every step of a release in order:
#   1. Preflight  — clean tree, correct branch, tools present, tests green
#   2. Version    — bump pyproject.toml, validate semver
#   3. Changelog  — abort if no human-written entry for this version
#   4. Git        — commit, tag, push (idempotent: skips if tag exists)
#   5. GitHub     — create release with changelog body (skips if exists)
#   6. Homebrew   — full formula regeneration from PyPI (not sed-patching)
#   7. Docs       — sync check count in docs/index.html
#   8. Summary    — print what happened
#
# Usage:
#   ./release.sh 1.7.0            # full release
#   ./release.sh --preflight-only  # just run checks, don't touch anything
#
set -euo pipefail

# ── Colours / helpers ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
BOLD='\033[1m'; RESET='\033[0m'

info()  { printf "${BLUE}▸${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}✓${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}⚠${RESET} %s\n" "$*"; }
die()   { printf "${RED}✗${RESET} %s\n" "$*" >&2; exit 1; }
phase() { printf "\n${BOLD}── Phase %s ──${RESET}\n" "$1"; }

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

# Prefer the project venv's python — it has pytest and project deps installed.
# Homebrew's bare `python3` may point at a different version without them.
if [ -x ".venv/bin/python" ]; then
  PYTHON=".venv/bin/python"
else
  PYTHON="python3"
fi

# ── Parse CLI args ───────────────────────────────────────────────────────────
PREFLIGHT_ONLY=false
VERSION=""

for arg in "$@"; do
  case "$arg" in
    --preflight-only) PREFLIGHT_ONLY=true ;;
    --help|-h)
      echo "Usage: ./release.sh [--preflight-only] [VERSION]"
      echo ""
      echo "  VERSION           Semver X.Y.Z (e.g. 1.7.0)"
      echo "  --preflight-only  Run preflight checks only, then exit"
      exit 0
      ;;
    *) VERSION="$arg" ;;
  esac
done

# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — Preflight
# ─────────────────────────────────────────────────────────────────────────────
phase "1 — Preflight"

# Bail on uncommitted or staged changes — we're about to modify pyproject.toml
if ! git diff --quiet || ! git diff --cached --quiet; then
  die "Working tree has uncommitted changes. Commit or stash first."
fi
if [ -n "$(git ls-files --others --exclude-standard)" ]; then
  die "Working tree has untracked files. Clean up first."
fi
ok "Clean working tree"

BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
  die "Must be on 'main' branch (currently on '$BRANCH')."
fi
ok "On main branch"

for cmd in git python3 gh curl shasum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    die "Required tool '$cmd' not found in PATH."
  fi
done
ok "All required tools available"

info "Running tests…"
if ! $PYTHON -m pytest --tb=short -q 2>&1; then
  die "Tests failed. Fix them before releasing."
fi
ok "Tests pass"

if $PREFLIGHT_ONLY; then
  ok "Preflight complete (--preflight-only mode)."
  exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — Version
# ─────────────────────────────────────────────────────────────────────────────
phase "2 — Version"

# Read current version from pyproject.toml
CURRENT_VERSION=$($PYTHON -c "
import re, pathlib
m = re.search(r'version\s*=\s*\"([^\"]+)\"', pathlib.Path('pyproject.toml').read_text())
print(m.group(1))
")
info "Current version: $CURRENT_VERSION"

# Prompt interactively if not passed as an argument
if [ -z "$VERSION" ]; then
  printf "Enter new version (X.Y.Z): "
  read -r VERSION
fi

if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  die "Invalid version '$VERSION'. Must be semver X.Y.Z."
fi

# If version already matches, this is a re-run — skip the bump.
# Otherwise ensure the new version is strictly higher.
if [ "$VERSION" = "$CURRENT_VERSION" ]; then
  ok "pyproject.toml already at $VERSION (re-run)"
else
  HIGHER=$($PYTHON -c "
from packaging.version import Version
import sys
try:
    result = Version('$VERSION') > Version('$CURRENT_VERSION')
except Exception:
    new = tuple(int(x) for x in '$VERSION'.split('.'))
    cur = tuple(int(x) for x in '$CURRENT_VERSION'.split('.'))
    result = new > cur
print('yes' if result else 'no')
")
  if [ "$HIGHER" != "yes" ]; then
    die "New version $VERSION must be greater than current $CURRENT_VERSION."
  fi

  sed -i '' "s/^version = \".*\"/version = \"$VERSION\"/" pyproject.toml
  ok "Updated pyproject.toml to $VERSION"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — Changelog gate
# Changelogs are human-written, never auto-generated. If there's no entry
# for the new version we abort so the author writes one first.
# ─────────────────────────────────────────────────────────────────────────────
phase "3 — Changelog gate"

if ! grep -qF "## [$VERSION]" CHANGELOG.md; then
  # Revert the version bump so the working tree stays clean for next run
  git checkout pyproject.toml 2>/dev/null || true
  die "CHANGELOG.md has no entry for [$VERSION]. Write one before releasing."
fi
ok "Changelog entry found for $VERSION"

# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 — Commit, tag, push
# Idempotent: if the tag already exists we skip everything.
# ─────────────────────────────────────────────────────────────────────────────
phase "4 — Commit, tag, push"

TAG="v$VERSION"

if git rev-parse "$TAG" >/dev/null 2>&1; then
  warn "Tag $TAG already exists — skipping commit/tag/push."
else
  git add pyproject.toml
  git commit -m "Bump version to $VERSION"
  git tag "$TAG"
  ok "Created commit and tag $TAG"

  info "Pushing to origin…"
  git push origin main
  git push origin "$TAG"
  ok "Pushed main and $TAG"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 — GitHub Release
# Uses the changelog section as the release body so GitHub shows the same
# human-written notes. Falls back to --generate-notes if extraction fails.
# ─────────────────────────────────────────────────────────────────────────────
phase "5 — GitHub Release"

if gh release view "$TAG" --repo gfreedman/mac_audit >/dev/null 2>&1; then
  warn "GitHub release $TAG already exists — skipping."
else
  # Extract everything between this version's ## heading and the next one
  NOTES=$(awk -v ver="$VERSION" '
    /^## \[/ { if (found) exit; if (index($0, "[" ver "]")) found=1; next }
    found { print }
  ' CHANGELOG.md)

  if [ -z "$NOTES" ]; then
    warn "Could not extract changelog notes — using --generate-notes."
    gh release create "$TAG" \
      --repo gfreedman/mac_audit \
      --title "Mac Audit $TAG" \
      --generate-notes
  else
    gh release create "$TAG" \
      --repo gfreedman/mac_audit \
      --title "Mac Audit $TAG" \
      --notes "$NOTES"
  fi
  ok "Created GitHub release $TAG"
fi

gh release upload "$TAG" install-macaudit.command \
  --repo gfreedman/mac_audit --clobber
ok "Uploaded install-macaudit.command to release $TAG"

RELEASE_URL="https://github.com/gfreedman/mac_audit/releases/tag/$TAG"

# ─────────────────────────────────────────────────────────────────────────────
# Phase 6 — Homebrew formula (full regeneration)
#
# Why regenerate instead of sed-patching?
# A sed patch can only update the tarball URL + sha256. When dependencies
# change (added, removed, or upgraded) the resource blocks go stale.
# Full regeneration fetches the current dependency tree from PyPI and
# writes every resource block from scratch — always correct.
# ─────────────────────────────────────────────────────────────────────────────
phase "6 — Homebrew formula"

TAP_DIR="/tmp/homebrew-macaudit"
FORMULA="$TAP_DIR/Formula/macaudit.rb"

# Use git rev-parse to verify the clone is intact (survives /tmp partial cleanup)
if git -C "$TAP_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  info "Updating existing tap clone…"
  git -C "$TAP_DIR" pull --ff-only origin main
else
  info "Cloning tap repo…"
  rm -rf "$TAP_DIR"
  gh repo clone gfreedman/homebrew-macaudit "$TAP_DIR"
fi

# Download the release tarball and compute its sha256.
# The tarball may not be available immediately after tag push, so we retry
# up to 10 times with a 5s delay. We detect an empty/missing tarball by
# comparing against the sha256 of zero bytes.
TARBALL_URL="https://github.com/gfreedman/mac_audit/archive/refs/tags/$TAG.tar.gz"
EMPTY_SHA="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
TARBALL_SHA=""
info "Waiting for tarball…"
for attempt in $(seq 1 10); do
  TARBALL_SHA=$(curl -sfL "$TARBALL_URL" | shasum -a 256 | awk '{print $1}')
  if [ -n "$TARBALL_SHA" ] && [ "$TARBALL_SHA" != "$EMPTY_SHA" ]; then
    break
  fi
  warn "Attempt $attempt: tarball not ready, retrying in 5s…"
  sleep 5
  TARBALL_SHA=""
done
if [ -z "$TARBALL_SHA" ]; then
  die "Failed to download tarball after 10 attempts."
fi
ok "Tarball SHA256: $TARBALL_SHA"

# Parse direct dependencies from pyproject.toml's dependencies array.
# We split on version-specifier characters (>=, <=, ~=, !=, etc.) to
# extract just the bare package name.
DIRECT_DEPS=$($PYTHON -c "
import re, pathlib
text = pathlib.Path('pyproject.toml').read_text()
m = re.search(r'dependencies\s*=\s*\[(.*?)\]', text, re.DOTALL)
for dep in re.findall(r'\"([^\"]+)\"', m.group(1)):
    # Strip version specifiers: >=, <=, ~=, !=, ==, etc.
    name = re.split(r'[><=!~;]', dep)[0].strip()
    print(name)
")
info "Direct deps: $(echo $DIRECT_DEPS | tr '\n' ' ')"

# BFS-resolve the full dependency tree via PyPI's JSON API.
#
# Starting from the direct deps above, we fetch each package's metadata,
# grab its sdist URL + sha256, then enqueue any transitive dependencies.
# We skip deps that only apply to extras (e.g. dev/test) or Windows.
#
# Output: Homebrew `resource` blocks, one per dependency, sorted by name.
info "Resolving dependency tree via PyPI…"
RESOURCE_BLOCKS=$($PYTHON << 'PYEOF'
import json, re, sys, urllib.request, urllib.error

def normalize(name):
    """PEP 503 normalize: rich_text -> rich-text, Rich -> rich."""
    return re.sub(r'[-_.]+', '-', name).lower()

def fetch_pypi(pkg):
    """Fetch package metadata from https://pypi.org/pypi/{name}/json."""
    url = f"https://pypi.org/pypi/{normalize(pkg)}/json"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  WARNING: PyPI lookup failed for {pkg}: {e}", file=sys.stderr)
        return None

def parse_requires(requires_dist):
    """Return unconditional, non-extras, non-Windows dependency names.

    PyPI's requires_dist entries look like:
      'mdurl ~=0.1'                       -> mdurl  (keep)
      'pygments >=2.13.0,<3.0.0'         -> pygments (keep)
      'foo ; extra == "jupyter"'          -> skip (extras-only)
      'bar ; sys_platform == "win32"'     -> skip (Windows-only)
    """
    deps = []
    if not requires_dist:
        return deps
    for req in requires_dist:
        if 'extra ==' in req or 'extra==' in req:
            continue
        if 'sys_platform == "win32"' in req or "sys_platform == 'win32'" in req:
            continue
        if 'platform_system == "Windows"' in req or "platform_system == 'Windows'" in req:
            continue
        # Split on whitespace or version operators to get the bare name.
        # The ~ handles PEP 440 compatible-release (~=) specifiers.
        name = re.split(r'[\s><=!~;\[]', req)[0].strip()
        if name:
            deps.append(name)
    return deps

def get_sdist(data):
    """Return (url, sha256) for the sdist archive, or (None, None)."""
    for url_info in data.get("urls", []):
        if url_info.get("packagetype") == "sdist":
            return url_info["url"], url_info["digests"]["sha256"]
    return None, None

# --- Main: BFS from direct deps ------------------------------------------

import pathlib
text = pathlib.Path("pyproject.toml").read_text()
m = re.search(r'dependencies\s*=\s*\[(.*?)\]', text, re.DOTALL)
direct = []
for dep in re.findall(r'"([^"]+)"', m.group(1)):
    # Strip version specifiers (>=, ~=, etc.) to get bare package name
    name = re.split(r'[><=!~;]', dep)[0].strip()
    direct.append(name)

# Human-written explanation printed above each resource block in the
# formula. Keyed by PEP 503-normalized name. A dependency missing from this
# table still gets a comment naming the package that pulled it in, plus a
# note on stderr so the author can add a proper description.
RESOURCE_DOCS = {
    "click": [
        "click — a library for building elegant command-line interfaces.",
        "macaudit uses Click to define its CLI commands, flags, and help text.",
    ],
    "markdown-it-py": [
        "markdown-it-py — a Markdown parser used by rich to render Markdown-formatted",
        "text (like bold, italics, bullet lists) directly in the terminal.",
    ],
    "mdurl": [
        "mdurl — a tiny URL-parsing utility required by markdown-it-py to correctly",
        "handle links inside Markdown content.",
    ],
    "pygments": [
        "pygments — a source-code syntax highlighter used internally by rich",
        "to colorize code snippets and structured data in terminal output.",
    ],
    "rich": [
        "rich — a library for beautiful, colorful terminal output.",
        "It powers macaudit's formatted tables, progress bars, and styled text.",
    ],
    "simple-term-menu": [
        "simple-term-menu — provides interactive arrow-key menus in the terminal.",
        "macaudit uses this so users can navigate audit options without typing commands.",
    ],
}

seen = set()                # normalized names we've already visited
queue = list(direct)        # BFS frontier
required_by = {}            # norm_name -> package that first required it
resources = {}              # norm_name -> (name, sdist_url, sdist_sha256)

while queue:
    pkg = queue.pop(0)
    norm = normalize(pkg)
    if norm in seen:
        continue
    seen.add(norm)

    data = fetch_pypi(pkg)
    if not data:
        continue

    sdist_url, sdist_sha = get_sdist(data)
    if not sdist_url:
        print(f"  WARNING: No sdist for {pkg}, skipping", file=sys.stderr)
        continue

    resources[norm] = (norm, sdist_url, sdist_sha)

    # Enqueue transitive dependencies for the next BFS iteration
    requires = data.get("info", {}).get("requires_dist") or []
    for child in parse_requires(requires):
        child_norm = normalize(child)
        if child_norm not in seen:
            queue.append(child)
            # First requirer wins; BFS order makes that the shallowest path.
            required_by.setdefault(child_norm, pkg)

# Print Homebrew resource blocks, sorted alphabetically
for norm in sorted(resources):
    name, url, sha = resources[norm]
    doc = RESOURCE_DOCS.get(norm)
    if doc is None:
        parent = required_by.get(norm)
        doc = [f"{name} — required by {parent}." if parent else f"{name} — direct dependency of macaudit."]
        print(f"  NOTE: no description for '{name}' — add one to RESOURCE_DOCS in release.sh",
              file=sys.stderr)
    for line in doc:
        print(f"  # {line}")
    print(f'  resource "{name}" do')
    print(f'    url "{url}"')
    print(f'    sha256 "{sha}"')
    print(f'  end')
    print()
PYEOF
)

if [ -z "$RESOURCE_BLOCKS" ]; then
  die "Failed to resolve any dependencies."
fi
ok "Resolved dependency tree"

# Write the complete formula from a template (not patching the old one).
info "Writing formula…"
# The comments below are the formula's teaching notes, kept here because the
# formula is regenerated on every release (anything edited in the tap repo is
# overwritten). This is an UNQUOTED heredoc so $TARBALL_URL etc. expand:
# every literal backtick and dollar sign must be escaped as \` and \$, or bash
# will run/expand it. Per-dependency comments come from RESOURCE_DOCS above.
cat > "$FORMULA" << FORMULA_EOF
# =============================================================================
# Homebrew Formula for macaudit
# =============================================================================
#
# What is a Homebrew Formula?
#   Homebrew is the most popular package manager for macOS. A "formula" is just
#   a Ruby script that tells Homebrew how to download, build, and install a
#   piece of software. When you run \`brew install macaudit\`, Homebrew reads
#   this file and follows its instructions.
#
# What is macaudit?
#   macaudit is a command-line tool that inspects and audits the health of a
#   Mac system — checking things like security settings, disk health, software
#   updates, and more.
#
# This file is generated by release.sh in gfreedman/mac_audit. Edit the
# template there — changes made directly here are overwritten on release.
# =============================================================================

# Every Homebrew formula is a Ruby class that inherits from \`Formula\`.
# This gives our class all the built-in Homebrew behavior for free
# (downloading files, verifying checksums, installing binaries, etc.).
class Macaudit < Formula
  # ----------------------------------------------------------------------------
  # Mixin: Python Virtualenv support
  # ----------------------------------------------------------------------------
  # \`include\` in Ruby is like importing a "mixin" (a bundle of reusable methods).
  # Language::Python::Virtualenv is a Homebrew helper that knows how to:
  #   1. Create an isolated Python virtual environment (venv) for this tool.
  #   2. Install this package and all its Python dependencies into that venv.
  #
  # Why a venv? Without isolation, installing Python packages globally can
  # break other tools. A venv keeps macaudit's dependencies sandboxed.
  include Language::Python::Virtualenv

  # ----------------------------------------------------------------------------
  # Metadata
  # ----------------------------------------------------------------------------
  desc "Mac System Health Inspector & Auditor" # Short one-line description shown by \`brew info\`
  homepage "https://github.com/gfreedman/mac_audit" # Project's website, shown by \`brew home macaudit\`

  # The URL where Homebrew downloads the source code for this specific release.
  # This points to a .tar.gz archive (a compressed folder) of the $TAG tag on GitHub.
  url "$TARBALL_URL"

  # A SHA-256 cryptographic checksum of the downloaded file.
  # After downloading, Homebrew hashes the file and compares it to this value.
  # If they don't match, the download is rejected — this protects against
  # corrupted downloads or tampered files (supply-chain security).
  sha256 "$TARBALL_SHA"

  license "MIT" # The open-source license under which macaudit is distributed

  # Optional: allows \`brew install macaudit --HEAD\` to install the latest
  # unreleased code straight from the main branch on GitHub (useful for testing
  # cutting-edge changes before an official release).
  head "https://github.com/gfreedman/mac_audit.git", branch: "main"

  # ----------------------------------------------------------------------------
  # System Dependencies
  # ----------------------------------------------------------------------------
  # macaudit is a Python application, so we need Python to run it.
  # \`depends_on\` tells Homebrew to install Python 3.12 first if it isn't
  # already present. Homebrew handles the dependency resolution automatically.
  depends_on "python@3.12"

  # ----------------------------------------------------------------------------
  # Python Package Dependencies (resources)
  # ----------------------------------------------------------------------------
  # macaudit is built on top of several third-party Python libraries.
  # Each \`resource\` block declares one of those libraries, where to download
  # it from (PyPI — the Python Package Index), and its SHA-256 checksum for
  # integrity verification (same idea as the main \`sha256\` above).
  #
  # Pinning exact URLs + checksums instead of just listing package names means
  # every install is 100% reproducible — the same bits, every time, for every user.

$RESOURCE_BLOCKS
  # ----------------------------------------------------------------------------
  # Install Method
  # ----------------------------------------------------------------------------
  # \`def install\` is the method Homebrew calls to actually install the software.
  # Because we included the Language::Python::Virtualenv mixin above, we get
  # access to \`virtualenv_install_with_resources\`, which does all the heavy
  # lifting in one line:
  #
  #   1. Creates a Python venv inside Homebrew's Cellar (its storage directory).
  #   2. Installs every \`resource\` block defined above into that venv.
  #   3. Installs macaudit itself into the venv.
  #   4. Symlinks the \`macaudit\` executable into Homebrew's bin directory
  #      (/opt/homebrew/bin on Apple Silicon, /usr/local/bin on Intel)
  #      so you can run it from anywhere in your terminal.
  def install
    virtualenv_install_with_resources
  end

  # ----------------------------------------------------------------------------
  # Caveats Method
  # ----------------------------------------------------------------------------
  # \`def caveats\` returns a string that Homebrew prints to the user after
  # installation completes. It's used for post-install instructions that the
  # user needs to act on manually — things Homebrew cannot do automatically
  # (like editing shell config files).
  #
  # <<~EOS ... EOS is a Ruby "heredoc": a convenient way to write a
  # multi-line string. The \`~\` strips leading whitespace so the text lines up
  # nicely in the source code without adding extra spaces to the output.
  def caveats
    <<~EOS
      To enable shell completion, add to your ~/.zshrc:
        eval "\$(_MACAUDIT_COMPLETE=zsh_source macaudit)"

      For bash, add to ~/.bash_profile:
        eval "\$(_MACAUDIT_COMPLETE=bash_source macaudit)"

      Then restart your terminal or run: source ~/.zshrc
    EOS
  end

  # ----------------------------------------------------------------------------
  # Test Block
  # ----------------------------------------------------------------------------
  # \`test do\` defines a simple sanity-check that Homebrew runs when you execute
  # \`brew test macaudit\`. It verifies the installation worked correctly.
  #
  # Here we run \`macaudit --version\` in a shell and check that its output
  # contains the expected version string (e.g. "$VERSION").
  #
  # \`version.to_s\` converts the Homebrew version object to a plain string like
  # "$VERSION". \`shell_output\` runs the command and returns its stdout as a string.
  # \`assert_match\` fails the test if the version string isn't found in the output.
  test do
    assert_match version.to_s, shell_output("\#{bin}/macaudit --version")
  end
end
FORMULA_EOF

ok "Formula written to $FORMULA"

# Commit and push — skip if the formula didn't actually change (idempotent)
cd "$TAP_DIR"
if git diff --quiet Formula/macaudit.rb; then
  warn "Formula unchanged — skipping commit."
else
  git add Formula/macaudit.rb
  git commit -m "macaudit $VERSION"
  git push origin main
  ok "Formula committed and pushed"
fi
cd "$REPO_ROOT"

# ─────────────────────────────────────────────────────────────────────────────
# Phase 7 — Docs check count
# Keep the "N checks" claim on the docs site in sync with reality.
# ─────────────────────────────────────────────────────────────────────────────
phase "7 — Docs check count"

CHECK_COUNT=$($PYTHON -c "
from macaudit.checks import system, security, privacy, homebrew, disk, hardware, memory, network, dev_env, apps, secrets
modules = [system, security, privacy, homebrew, disk, hardware, memory, network, dev_env, apps, secrets]
print(sum(len(m.ALL_CHECKS) for m in modules))
")
info "Total checks: $CHECK_COUNT"

if grep -q "[0-9]\+ checks" docs/index.html; then
  sed -i '' "s/[0-9]\{1,\} checks/$CHECK_COUNT checks/g" docs/index.html
  if ! git diff --quiet docs/index.html; then
    git add docs/index.html
    git commit -m "docs: update check count to $CHECK_COUNT"
    git push origin main
    ok "Updated docs check count to $CHECK_COUNT"
  else
    ok "Docs check count already $CHECK_COUNT"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Phase 8 — Summary
# ─────────────────────────────────────────────────────────────────────────────
phase "8 — Summary"

printf "\n"
printf "${GREEN}${BOLD}Release $VERSION complete!${RESET}\n"
printf "\n"
printf "  Version:  %s\n" "$VERSION"
printf "  Tag:      %s\n" "$TAG"
printf "  Release:  %s\n" "$RELEASE_URL"
printf "  Formula:  %s\n" "$FORMULA"
printf "\n"
printf "  brew install gfreedman/macaudit/macaudit\n"
printf "\n"
