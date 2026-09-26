# Changelog

All notable changes to Mac Audit are documented here.

## [1.12.2] — 2026-09-26

### Fixed
- **Memory Pressure** no longer reports a false RED/critical on macOS 27. The tool's output no longer includes a pressure level, and the fallback matched "red" inside "wired" (`Pages wired down`). The level is now read directly from the kernel (`kern.memorystatus_vm_pressure_level`), the same value Activity Monitor shows
- **Python PATH Conflicts** counts distinct interpreters: symlinks to the same Python (e.g. python.org's `/usr/local/bin/python3`) count once, and macOS's own `/usr/bin/python3`, which cannot be removed, is no longer flagged

### Changed
- The Homebrew formula is now generated with its explanatory comments, so they survive every release

---

## [1.12.1] — 2026-09-26

### Fixed
- **Homebrew health check** no longer offers `brew doctor` as an "automatic" fix — it only diagnoses, so `macaudit --fix --auto` reported success while every issue remained. The check is now step-by-step, and warnings are parsed: untrusted taps get the exact `brew untap --force` / `brew trust` commands, and other warnings are named individually
- **Homebrew health check** reports a `brew doctor` timeout as an error rather than a Homebrew issue, and no longer passes when a failing run happens to contain the text "ready to brew"
- **Fix steps** containing square brackets are now displayed literally instead of being interpreted as terminal formatting (which could abort the fix session)

---

## [1.12.0] — 2026-02-27

### Added
- **Virus Protection audit section** — new `malware` category with three read-only checks:
  - **ClamAV**: detects installation, checks signature freshness (warns if > 7 days old), and verifies freshclam is configured for automatic updates. Falls back to noting macOS XProtect as a baseline if ClamAV is absent
  - **Objective-See Tools**: reports which of LuLu, BlockBlock, KnockKnock, and RansomWhere are installed with educational context on what each tool does
  - **Persistence Directories**: enumerates `.plist` files across `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and `/Library/LaunchDaemons` as a hygiene awareness check (informational only, no false positives)

---

## [1.11.0] — 2026-02-26

### Added
- **One-click `.command` installer** — a double-clickable file that installs Homebrew (if needed) and macaudit in one step. Available as a release asset and linked from the docs site
- **Release asset upload** — `release.sh` now uploads the `.command` installer to each GitHub release automatically

---

## [1.10.0] — 2026-02-26

### Added
- **Check suppression via config file** — users can permanently dismiss specific findings by listing check IDs in `~/.config/macaudit/config.toml` (e.g. `suppress = ["filevault"]`). Suppressed checks are skipped (not run), appear dimmed in the report as "Suppressed by config", and do not penalize the health score

---

## [1.9.0] — 2026-02-26

### Added
- **Scan diffing** — after every scan, full results are persisted to `~/.config/macaudit/history/`. On subsequent runs a "Changes Since Last Scan" panel shows what improved, what regressed, new/removed checks, and the score delta
- **JSON diff output** — `--json` mode includes a `"diff"` key when changes are detected against the previous scan
- **History pruning** — oldest snapshots are automatically cleaned up, keeping the 10 most recent scans
- **Filter mismatch suppression** — when >50% of checks are new/removed (likely a `--only`/`--skip` difference), those sections are suppressed to avoid noisy diffs

---

## [1.8.0] — 2026-02-26

### Added
- **Inline MDM badges** — on MDM-enrolled Macs, findings for MDM-relevant checks (FileVault, Firewall, Gatekeeper, auto-updates, screen lock, sharing services, etc.) now show a persistent `🏢 may be managed by your org` badge alongside the result, not just a one-time advisory panel
- **Contextual verdicts** — when 1–2 critical issues exist, the summary verdict names them specifically (e.g. "FileVault Disk Encryption — disk encryption is disabled") instead of a generic count

### Improved
- **GitHub Pages copy** — hero tagline, quick start, fix mode intro, safety list, and score section rewritten to emphasize read-only-by-default, explain-then-act fix flow, and safety-first positioning

---

## [1.7.3] — 2026-02-25

### Improved
- **Theme consolidation** — centralised `score_color()` helper and fix-level emoji/label dicts in `theme.py`, eliminating duplicated if/elif chains and local dicts in `report.py`, `welcome.py`, and `fixer/runner.py`
- **Progress bar colors** — replaced hardcoded `"cyan"` and `"bright_green"` with theme constants (`PROGRESS_BAR_COLOR` / `PROGRESS_COMPLETE_COLOR`)
- **Recommendations panel** — added leading total-count line (e.g. "12 fixable items — top issues:") so users see scope at a glance
- **Category panel borders** — all-passing categories now use green borders instead of dim
- **Fix card title** — changed `[1/5]` to `Fix 1 of 5` for readability
- **Fix menu consistency** — unified both auto and guided menus to `["Skip", "Apply/Continue", "Quit"]` with Skip as the safe default
- **Narrator underline** — dynamic width `min(44, console_width - 6)` prevents overflow on narrow terminals
- **Result name column** — widened from 36 to 38 chars for better alignment with longer check names
- **Pre-scan prompt** — removed hardcoded "~10–15 seconds" time estimate

---

## [1.7.2] — 2026-02-25

### Added
- **Category headers in live scan** — bold icon + name header with thin underline and spacing between each category section, so checks are no longer one flat list

---

## [1.7.1] — 2026-02-24

### Fixed
- Summary panel emoji alignment — status counts line (`Critical / Warnings / Passed / Info`) now uses consistent 2-cell-wide icons from the theme instead of hardcoded `⚠️` and `ℹ️` which have variation selectors that render at inconsistent widths across terminals

### Added
- **CONTRIBUTING.md** — dev setup, project structure, check contract, testing patterns, profile system, release process, and style guide for new contributors

---

## [1.7.0] — 2026-02-24

### Added
- **`release.sh` — single-command release script:** `./release.sh X.Y.Z` handles version bump, changelog validation, commit/tag/push, GitHub release with human-written notes, and full Homebrew formula regeneration (BFS-resolved dependency tree from PyPI) in one idempotent command

---

## [1.6.0] — 2026-02-24

### Added
- **Arrow-key fix prompts:** replaced raw `input()` with interactive arrow-key menus powered by `simple-term-menu` — highlight follows cursor properly
- **Quit option:** every fix prompt now has a Quit choice to bail out of the session
- **`--dry-run` flag:** walk through the entire fix flow without executing any changes
- **Homebrew install docs:** README and docs site now include Homebrew install instructions for new users

### Fixed
- Menu title no longer duplicates when holding down arrow keys (moved title out of `TerminalMenu` redraw loop)
- Loop variable `idx` no longer shadowed by `menu.show()` return value, fixing card numbering on subsequent fixes
- Release workflow now skips gracefully if the GitHub Release already exists

### Changed
- Replaced `questionary` dependency with `simple-term-menu` (no `prompt_toolkit` conflict with Rich)

---

## [1.5.0] — 2026-02-20

### Changed
- **Parallel check execution:** checks now run concurrently via `ThreadPoolExecutor(max_workers=8)`, cutting scan time from ~35–45s to ~10–15s. Results print in deterministic category order. Serial path preserved for `--quiet`/`--json`.
- Scan narrator simplified: spinner + progress bar replaces per-check description panels

---

## [1.3.0] — 2026-02-19

### Added
- **Mode-aware header:** right column shows active mode (🔍 scan / 🔧 fix / 🎯 targeted) with contextual tips
- **Recommendations panel:** after every scan, surfaces the top fixable items and the exact command to run next
- **Pre-scan prompt:** count of checks + press ↵ to begin (skip with `-y`)
- **Sequential fix cards:** `--fix` now shows one rich card per fix (status, explanation, command, time, reversibility) and prompts inline — no more checkbox pre-selection menu
- **MDM warning suppression:** advisory banner only appears on first run; silenced on subsequent runs
- **Console width cap:** all panels capped at 120 columns regardless of terminal width
- **Light-mode palette:** all `white`/`dim white` style strings replaced with palette-aware constants — readable in both dark and light terminals
- **Hero copy button:** clipboard icon on the `brew install` command in the docs site

### Fixed
- Removed `questionary` dependency (no longer used since fix mode was rewritten)
- Docs site Quick Start code boxes now align vertically across all three step cards
- Docs site install/uninstall grid uses equal-width 3-column layout

---

## [1.2.0] — 2026-02-18

### Added
- **10 new security checks:** Guest Account, SSH Server Config (sshd_config), Login/Logout Hooks, Cron Jobs, System Extensions, XProtect signature freshness
- **2 new network checks:** Internet Sharing, improved Listening Ports (now covers UDP as well as TCP)
- **`--fail-on-critical` flag:** exits with code 2 when critical issues are found (enables scripting/CI use)
- **Scan duration** displayed in the Summary panel at the end of every scan
- **Localization fix:** all subprocess calls now force `LANG=C`/`LC_ALL=C`, preventing false results on non-English macOS

### Fixed
- SMART disk check now targets the boot volume (`diskutil info /`) instead of hardcoded `disk0`
- `BaseCheck.shell()` now forces C locale for consistent English output on all systems
- Secrets scanner now finds all credentials per file (was stopping after first match per file)
- LoginItemsCheck now uses `osascript System Events` for accurate login item counts (previously `launchctl list` over-counted dramatically)
- Executor `run_auto_fix` now passes `fix_command` as a string with `shell=True` so `~` and glob patterns expand correctly
- `auto_sudo` fix commands in system.py are now plain shell commands (previously double-wrapped in AppleScript)

### Changed
- Firewall check now discloses that macOS Application Firewall (ALF) is **inbound-only** and notes that outbound filtering requires a third-party tool
- ListeningPortsCheck now also scans UDP and skips loopback-only listeners (reducing false positives)

---

## [1.1.0] — 2026-02-17

### Added
- **3 new checks:** Bluetooth discoverability, Listening Ports (TCP), System Root Certificates (MITM detection)
- MDM-enrolled Mac detection: prints advisory banner if device is under MDM management
- `SavedWifiCheck` now dynamically discovers the Wi-Fi interface (was assuming `en0`)
- `SIPCheck` now detects partially-disabled SIP ("custom configuration") and reports it as a warning

### Fixed
- Critical bug: `auto_sudo` fix commands were double-wrapped in AppleScript, silently breaking all 4 privileged fixes
- Critical bug: `run_auto_fix` used `shlex.split()` + `shell=False`, preventing `~` and `*` expansion
- `LoginItemsCheck` replaced `launchctl list` (massively over-counts) with `osascript System Events` query
- `score_impact` field removed (was dead code — `calculate_health_score` never read it)
- Removed `_SYSTEM_LABEL_PREFIXES` from `LoginItemsCheck` (no longer needed)

### Changed
- `ActivationLockCheck` message now correctly says "Find My is configured — Activation Lock is likely active" (avoids overstating certainty)

---

## [1.0.0] — 2026-02-16

Initial release.

### Checks (62 total across 10 categories)
- **System:** macOS version, pending updates, SIP, FileVault, Firewall, Gatekeeper, Time Machine, auto-updates, screen lock, Rosetta 2, Secure Boot
- **Security:** auto-login, SSH keys (presence + strength), launch agents, /etc/hosts, sharing services, Activation Lock, MDM profiles, system root CAs
- **Privacy:** TCC guided review (Full Disk Access, Screen Recording, Accessibility)
- **Homebrew:** brew doctor, outdated formulae/casks, orphaned dependencies, cache size
- **Disk:** free space, APFS snapshots, DerivedData, Docker usage, Trash, caches
- **Hardware:** battery cycle count/condition, SMART status, kernel panics, thermal throttling
- **Memory:** pressure, swap, top CPU/memory consumers
- **Network:** AirDrop, Remote Login, Screen/File Sharing, DNS, proxy, saved Wi-Fi
- **Dev Env:** Xcode CLTools, Python/Ruby PATH, conda, Node managers, git config
- **Apps:** App Store updates (via mas), iCloud status, login items

### Features
- Narrated scan with live spinner and Rich progress
- Health score 0–100 with category-weighted deductions
- Fix mode (`--fix`): interactive menu + auto mode (`--auto`)
- Four fix levels: `auto`, `auto_sudo` (native macOS password dialog), `guided`, `instructions`
- Profiles: `developer`, `standard`, `creative` (auto-detected)
- Opt-in credential scanner: `--check-shell-secrets`
- JSON output: `--json`
- Category filtering: `--only`, `--skip`
- MDM-aware, graceful error handling, read-only by default
