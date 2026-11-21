# Changelog

## 2.1.1

Security containment patch:

- **Fail-closed Bubblewrap isolation for LNReader TypeScript execution (`scripts/nox_scaffold.py`, `scripts/nox_android.py`):**
  - Executed `_execute_lnreader_ts_in_node` strictly inside Bubblewrap (`--unshare-all`, `--unshare-net`, `--clearenv`, read-only staged `/work`, ephemeral `--tmpfs /tmp`, zero host `$HOME` or credential mounts) and routed `@libs/fetch` requests over an authenticated per-run stdin/stdout host bridge constrained to the target origin and SSRF policy.
  - Propagated `sandbox_available_override` through `execute_extension_behavior`, `auto_create_extension`, and `auto_fix_extension`, failing closed (`status='BLOCKED'`, `executed=False`, `executed_unprotected=False`) with a clear beginner explanation when `bwrap` isolation is unavailable (zero host fallback).
- **Root-cause SSRF & DNS-rebinding hardening (`scripts/nox_core.py`, `scripts/nox_scaffold.py`, `scripts/nox_issues.py`, `scripts/references.py`):**
  - Replaced unpinned `urllib.request.urlopen` calls with `safe_http_fetch_detailed` / `safe_http_fetch` across runtime probers, GitHub issue queries, and reference sync helpers.
  - Enforced strict canonical host/IP validation (blocking octal/hex/integer/shorthand IPv4 forms, zone IDs, trailing-dot IPs, backslashes in authority, embedded IPv4-in-IPv6 forms such as IPv4-mapped/NAT64/6to4/Teredo, CGNAT, and `0.0.0.0/8`), single DNS resolution validating all returned addresses, pinned-IP HTTP/HTTPS socket connections with preserved TLS certificate + SNI hostname verification, hop-by-hop redirect validation (blocking HTTPS->HTTP downgrades and public->loopback redirects), proxy-environment bypass, and loopback-only local fixture scope.

## 2.1.0

Security hardening, automated beginner workflows, and Issue #10 CLI fix:

- **Fix [Issue #10](https://github.com/ProjectNox-org/nox-extension-developer/issues/10) — Global CLI flags anywhere (`scripts/nox.py`):**
  - Propagated `--json`, `--beginner`, `--technical`, `--dry-run`, and non-conflicting `--lang` recursively across top-level parsers, subcommands, and nested subcommands (`doctor --json`, `--json doctor`, `lab image <file> --json`, `issues verify-historical --json`, `adb doctor --json`) while preserving `scaffold --lang` for extension source language.
- **Fail-closed Bubblewrap sandbox & Gradle execution chain verification (`scripts/nox_android.py`, `scripts/nox_enhancements.py`, `scripts/nox.py`):**
  - Added `verify_gradle_execution_chain` (checks `gradlew` regular-file confinement & suspicious shell commands, strict `urlsplit` host check on `distributionUrl`, mandatory valid `distributionSha256Sum` matched against `KNOWN_OFFICIAL_GRADLE_SHA256`, ZIP/manifest validation of `gradle-wrapper.jar` without native binaries, and rejection of repo `init.gradle*` or `-javaagent` flags in `gradle.properties`).
  - Added `probe_bwrap_sandbox` and `run_in_bwrap_sandbox` (`--unshare-all`, `--unshare-net` by default, `--die-with-parent`, `--new-session`, `--clearenv`, ephemeral staging copy excluding `.git`/symlinks/secrets, no `$HOME`/`~/.ssh`/`~/.agents` exposure).
  - Updated `build_debug_apk` and `nox.py bisect --test-cmd` to fail **closed** (`BLOCKED`, `executed_unprotected: false`) when Bubblewrap isolation is unavailable — zero host fallback.
  - Hardened `run_git_bisect_regression` with `-c core.hooksPath=/dev/null -c protocol.file.allow=never` and per-commit `audit_untrusted_pr_or_repo` gating.
- **Automated beginner-first orchestration, real code execution, post-build APK delivery & loop prevention (`scripts/nox_core.py`, `scripts/nox_scaffold.py`, `scripts/nox_android.py`, `scripts/nox.py`, `SKILL.md`):**
  - Added `build_agent_continuation`, updated `format_adaptive_response` (beginner mode stores technical details in `diagnostics_file` cleanly behind the scenes instead of dumping JSON/verifier payloads), auto-detected prompt UI language (`detect_user_ui_language`), and `detect_investigation_loop`.
  - Separated `metadata_lang` (`"pt-BR"`), `dir_lang` (`"pt"` / `"portuguese"`), and Kotlin `package_lang` (`"pt"` without `-`, preserving official `compute_source_id(name, "pt-BR", 1)`), plus static path/delimiter/package validation (`validate_generated_package_and_paths`).
  - Upgraded `auto_create_extension` and `auto_fix_extension` with real behavioral execution (`execute_extension_behavior`: Node.js `.ts` runner for LNReader and extracted-selector HTTP runner for Keiyoushi/Yuzono), 8 explicit `execution_stages`, Pass 2 structural/non-regex repair + rollback guard + `agent_solver` continuation, standalone Kotlin -> `d8` -> `aapt2` -> `apksigner` Debug APK compilation in fail-closed Bubblewrap (`compile_kotlin_extension_to_debug_apk` & `verify_apk_contains_compiled_extension`), and honest `BLOCKED`/`INCONCLUSIVE`/`PASS` gating.
  - Upgraded `verify_and_offer_apk_delivery`, `run_guided_adb_install_and_test`, and `handle_apk_delivery_choice` with DEX class/method verification, host-app + `uiautomator` screen checks (`INCONCLUSIVE` on install-only without UI verification, automatic post-install repair trigger on UI/Logcat errors), and standardized `.github/ISSUE_TEMPLATE/*.yml` titles + GitHub Private Security Advisory links.
  - Updated `SKILL.md` and bilingual guides so agents never stop at intermediate tools and beginners never face unnecessary technical questions or raw logs.

## 2.0.0

Major local engineering upgrade (`1,200` traced items: `1,000` original catalog requirements + `200` autonomous enhancements):

- **Modular local CLI (`scripts/nox.py`) & core evidence engine (`scripts/nox_core.py`):**
  - Added strict evidence statuses (`PASS`, `FAIL`, `INCONCLUSIVE`, `BLOCKED`, `NOT_RUN`), SHA-256 execution receipts, unsupported-claim gate, `nox.py report`, and `nox.py verify-report`.
- **Environment Doctor, Scaffolding & Structural API Compare (`scripts/nox_env.py`, `scripts/nox_scaffold.py`, `scripts/api_compare.py`):**
  - Added `doctor`, `inspect` (detecting Keiyoushi `KeiSource`, Yuzono `AniSource`, LNReader, KSP vs legacy, deterministic 64-bit MD5 `sourceId`), `search-existing`, dependency/reproducibility/compliance checks, `scaffold` + ephemeral HTTP functional scenarios (`scenarios`), and structural multiline API comparison with quality/Hermes checks.
- **Site DNA, Media & Image Lab (`scripts/nox_lab.py`):**
  - Added `site-inspect`, real image magic bytes/dimension inspection (rejecting deceptive HTTP 200 HTML/SVG), `unscramble_image_slices` (permutation bijection + DRM/EME block), `lab visual-diff` with PII redaction, fractional chapter continuity (`59.5`), Yuzono `getHosterList`/`getVideoList`/HLS/DASH/subtitles, LNReader readability, `search == popular` guard, HAR replay, disk-persisted budget-enforced canary monitor, and mutation self-testing.
- **Android Build, APK/DEX Inspection & ADB/Logcat (`scripts/nox_android.py`):**
  - Added security-gated `build` (`gradlew assembleDebug`), `apk-inspect` (`aapt2`/`apksigner`, SHA-256, Debug vs Release, conditional 16 KB `.so` check), `api-binary-compare` (`.dex`/`.class`/`.jar`), `deeplink-check`, `adb doctor`, `parse_uiautomator_hierarchy_and_plan_actions` + `adb ui-plan` (hardware runs stay honestly `BLOCKED`/`NOT_RUN` when `adb devices` is empty), package/PID-isolated `adb filter-logcat` with secret redaction, and `bisect`.
- **Multi-Ecosystem Nox Issue Intelligence (`scripts/nox_issues.py`):**
  - Added live GitHub API + pinned diff inspection across Keiyoushi (`keiyoushi/extensions-source`), Yuzono (`yuzono/anime-extensions`), and LNReader (`LNReader/lnreader-plugins`), strictly distinguishing `VERIFIED_FIX` from `MERGED_UNVERIFIED`, `REVERTED_FIX`, `OPEN_OR_UNMERGED`, `CLOSED_UNMERGED`, `SUPERSEDED`, and synthetic `merge_commit_sha` traps, plus cross-version copy guard, `autofix-diagnose`, and real-analyzer `review-council`.
- **Security & Supply-Chain Hardening (`scripts/nox_core.py`, `scripts/nox_android.py`, `scripts/nox_enhancements.py`):**
  - Added SSRF private/IPv4-mapped IPv6/numeric-IP/meta-refresh blocking, Gradle RCE/wrapper/workflow script-injection scanner, TLS/`DexClassLoader`/WebView/Zip-Bomb/Zip-Slip checks, Trojan Source (`scan_bidi_controls`), and secret redaction.
- **175 On-Demand Modular Enhancements (`scripts/nox_enhancements.py`) & 1,200-Item Matrix (`scripts/nox_matrix.py`):**
  - Registered `1026`–`1200` on-demand guards (`enhance --list`, `enhance --audit-source`) plus `1001`–`1025` core capabilities, frozen catalog `references/catalog-1000.json`, validated matrix `references/matrix-1000.json` + bilingual tables (`docs/pt-BR/matriz-1000.md`, `docs/en/matrix-1000.md`), dynamic `benchmark` comparing real `v1.0.3` baseline against current tooling, updated CI, and unit/integration test suites (`tests/`).

## 1.0.3

- Clarify Node.js version requirements and dependency setup for each ecosystem in both READMEs.
- Add concrete JDK, Android SDK, and project-local build guidance while preserving existing installations.

## 1.0.2

- Reorganize the Portuguese and English READMEs around a beginner-friendly setup and usage journey.
- Clarify ecosystem dependencies, agent compatibility, community resources, and licensing.

## 1.0.1

- Expand bilingual dependency and Android SDK guidance, add practical examples, and clarify Windows/WSL limitations.
- Document verified OpenCode discovery after installation from the public repository.

## 1.0.0

- Added an Agent Skills workflow for Keiyoushi, Yuzono, and LNReader, with on-demand official references pinned to upstream commits.
- Added integrity-checked snapshots, offline fallback, corruption quarantine, and serialized updates.
- Added scoped API comparison with conservative heuristics and documented uncertainty.
- Added local symlink installation and deterministic candidate packaging.
- Added regression tests and documented security, compatibility, licensing, and validation limits.
- Treat added API declarations as indeterminate; adding an interface method can break implementers.
- Read package inputs without following symlinks and publish complete ZIPs without replacing an existing file.
- Clarified natural-language examples, synthetic-test limits, and the owner’s licensing decision.
- Treat unknown or nonnumeric version identifiers as indeterminate in scoped API comparisons.
- Require a known-positive search check and clarify site inspection, dependency reuse, and resuming interrupted work.
- Include both language guides, prompts, and visual assets in the distribution ZIP.
- Install under the canonical skill name even when the source directory was renamed.

Released under AGPL-3.0-only. Third-party projects retain their own licenses; see `ATRIBUICOES.md`.
