[Português (Brasil)](README.md) | [English](README.en.md)

<p align="center">
  <img src="assets/nox-emblem.webp" alt="Official Project Nox emblem" width="96" />
</p>

<h1 align="center">Project Nox · Extension Developer</h1>

<p align="center">
  Open-source skill to help AI agents build, fix, and maintain extensions.
</p>

## What is Nox Extension Developer?

**Nox Extension Developer** is a free, open-source skill designed to guide compatible AI agents when creating, fixing, updating, and reviewing manga, anime, and novel extensions.

It is **not** a standalone AI: it is a structured set of local instructions, API contracts, and helper scripts loaded by your chosen agent. You describe your goal in plain language, and the agent uses the skill to sync official references, inspect code patterns, and guide implementation, testing, and builds.

> Project Nox is not affiliated with the reference projects listed below. Use only authorized sources and review generated code; the skill assists development without guaranteeing compatibility with every website.

## Supported ecosystems

| Content | Reference | Application | Output |
|---|---|---|---|
| Manga | Keiyoushi | Mihon and compatible apps | APK |
| Anime | Yuzono | Aniyomi and compatible apps | APK |
| Novel | LNReader | LNReader | Plugin or bundle |

Each ecosystem is independent: **Keiyoushi**, **Yuzono**, and **LNReader** conventions, APIs, and rules must stay separate and must not be mixed across ecosystems.

## Quick installation

### Recommended method: AI-assisted installation

Copy the prompt below into your compatible AI agent and approve only the steps you agree with:

```text
Install and configure the Nox Extension Developer skill from:
https://github.com/ProjectNox-org/nox-extension-developer

Identify my operating system and AI agent, check the official documentation,
and ask whether I want to work with manga, anime, novels, or all of them. Check
existing tools first and prefer:
npx skills add ProjectNox-org/nox-extension-developer

Configure only needed dependencies (including Java and Android SDK only when
applicable). Ask my permission before consequential changes, privileged
operations, or accepting licenses; do not overwrite settings or expose
credentials. Once done, verify skill discovery in a new session and explain how
to get started and what was not tested.
```

Ready-to-use prompt files: [`prompts/install-en.txt`](prompts/install-en.txt) · [`prompts/install-pt-BR.txt`](prompts/install-pt-BR.txt).

### Alternative method: manual installation via NPX

Run in a terminal:

```bash
npx skills add ProjectNox-org/nox-extension-developer
```

Choose your agent when prompted (or pass flags such as `--global --agent opencode`). A local symlink installer is also provided in [`scripts/install.py`](scripts/install.py).

- Requires compatible Node.js and npm (local tests with Skills CLI `1.8.1` required Node.js `22.20.0+`; check current CLI requirements).
- `npx skills add` installs **only** the skill — it does not install or configure a Java JDK, Android SDK, or LNReader project dependencies.
- After installation, **start a new agent session** and explicitly ask: `Use the nox-extension-developer skill`. See full details in the [installation guide](docs/en/guide.md).

## How to update the skill

### Method 1 — AI-assisted update (recommended)

Copy the prompt below into your compatible AI agent and approve only the steps you agree with:

```text
Update my existing installation of the Nox Extension Developer skill to the
latest stable version, following the official documentation and preserving my
settings.

Repository:
https://github.com/ProjectNox-org/nox-extension-developer

Identify my operating system, AI agent, installation method, and paths used.

Check the latest stable version published in GitHub Releases and compare it
with the installed version. Do not confuse the main branch with a stable
release.

Before updating, check for local changes and back up existing settings and
customizations.

Update only Nox Extension Developer, without modifying other skills,
unnecessary dependencies, or agent configurations.

Do not overwrite custom files, delete data, or run privileged commands without
my authorization.

If there are conflicts, present them before continuing.

After updating, confirm the actual installed version/tag/commit, verify that
the skill is still recognized by the agent, and report the result and any
limitations.
```

### Method 2 — Manual update

To check for available updates and update using the [Skills CLI](https://github.com/vercel-labs/skills/blob/main/docs/commands.md):

```bash
npx skills check
npx skills update nox-extension-developer
```

For a global installation:

```bash
npx skills update nox-extension-developer --global
```

- Use these commands only for installations managed by the Skills CLI (`npx skills`).
- Updates may track the recorded installation source, including the `main` branch, rather than necessarily targeting the latest stable GitHub Release.
- Manual installations via Git or symlinks (such as [`scripts/install.py`](scripts/install.py)) may require a different procedure, such as updating the local repository to the desired release tag.
- Identify and back up any local customizations before replacing files, as the CLI does not guarantee automatic preservation of local changes or settings.
- After updating, validate the installation in a **new agent session** by asking: `Use the nox-extension-developer skill`.

## Practical examples

Replace the bracketed placeholders with the target website or repository details.

### Manga — create (Keiyoushi / Mihon)

```text
Use the nox-extension-developer skill to create a manga extension following the
Keiyoushi standard for Mihon for this site: [SITE URL].
```

### Manga — fix (Keiyoushi / Mihon)

```text
Use the nox-extension-developer skill to fix a manga extension following the
Keiyoushi standard.
Repository: [KEIYOUSHI OR PROJECT NOX REPOSITORY]
Extension name: [EXTENSION NAME]
Issue: [e.g., chapters are missing or pages fail to load]
```

Repositories: [Keiyoushi](https://github.com/keiyoushi/extensions-source) · [Project Nox](https://github.com/ProjectNox-org/manga-fonte-extensoes).

### Anime — create (Yuzono / Aniyomi)

```text
Use the nox-extension-developer skill to create an anime extension following the
Yuzono standard for Aniyomi for this site: [SITE URL].
```

### Anime — fix (Yuzono / Aniyomi)

```text
Use the nox-extension-developer skill to fix an anime extension following the
Yuzono standard.
Repository: [YUZONO OR PROJECT NOX REPOSITORY]
Extension name: [EXTENSION NAME]
Issue: [e.g., episodes fail to list or video sources fail to play]
```

Repositories: [Yuzono](https://github.com/yuzono/anime-extensions) · [Project Nox](https://github.com/ProjectNox-org/anime-fonte-extensoes).

### Novel — create (LNReader)

```text
Use the nox-extension-developer skill to create a novel plugin following the
LNReader standard for this site: [SITE URL].
```

### Novel — fix (LNReader)

```text
Use the nox-extension-developer skill to fix a novel plugin following the
LNReader standard.
Repository: https://github.com/LNReader/lnreader-plugins
Plugin name: [PLUGIN NAME]
Issue: [e.g., search returns no results or chapters fail to load]
```

To update an existing extension, provide its source code and ask the agent to preserve local API compatibility. Always request the output APK/bundle path and verification steps.

## Dependencies

Separate tools needed to **run the skill** from tools required to **build extensions**:

- **Skill and local scripts:** **Git** and **Python 3** (POSIX environment on Linux, macOS, or **Windows via WSL** — `scripts/references.py` relies on `fcntl`); **Node.js and npm** when using `npx skills`.
- **Manga and Anime (APK):** **Java JDK** and **Android SDK** (`Command-line Tools`, Android platform, and `Build Tools`) matching the target repository (`compileSdk` and Gradle Wrapper `./gradlew`). Local project tests used JDK 21, Android SDK 37.0, and Build Tools 36.0.0/37.0.0 — treat those numbers as test observations, not universal fixed requirements.
- **Novels (LNReader):** compatible **Node.js** (LNReader projects typically expect Node 22+) and local project packages via `npm install` (TypeScript and repository dependencies). **If you only work on novels, you do not need to install the Android SDK.**

Full operating-system instructions (**Windows via WSL**, **Arch Linux**, **Ubuntu**, **Debian**, **Fedora**, and **macOS**):
[Operating system preparation](docs/en/guide.md#operating-system-preparation) · [Dependencies](docs/en/dependencies.md) · [Android SDK](docs/en/android-sdk.md).

## Agent compatibility

| Agent | Status |
|---|---|
| [OpenCode](https://opencode.ai/) | ✅ Tested (`v2.2.7` on Arch Linux) |
| [Codex](https://developers.openai.com/codex/) | 🟡 Documented (execution not tested) |
| [Claude Code](https://code.claude.com/) | 🟡 Documented (execution not tested) |
| [Google Antigravity](https://antigravity.google/) | 🟡 Documented (not verified) |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent) | ⚪ Not verified |

`Codex` (`~/.agents/skills/`), `Claude Code` (`~/.claude/skills/`), and `Google Antigravity` (`~/.gemini/antigravity/skills/`) have documented targets prepared in [`scripts/install.py`](scripts/install.py), without local symlink or execution tests; `Hermes Agent` has no dedicated installer target. Official tests ran on **Arch Linux** (other Linux distros, macOS, and Windows via WSL have not been verified). See [`COMPATIBILIDADE.md`](COMPATIBILIDADE.md).

## Documentation

- [Full installation, `nox.py` CLI, Debug APK/ADB, and troubleshooting guide](docs/en/guide.md) ([Português](docs/pt-BR/guia.md))
- [Tool-by-tool dependencies](docs/en/dependencies.md) ([Português](docs/pt-BR/dependencias.md))
- [Safe Android SDK setup](docs/en/android-sdk.md) ([Português](docs/pt-BR/android-sdk.md))
- [Traceability matrix & counters (`0001`–`1200`)](docs/en/matrix-1000.md) ([Português](docs/pt-BR/matriz-1000.md)) · [JSON Catalog (`0001`–`1000`)](references/catalog-1000.json) · [Validated JSON Matrix](references/matrix-1000.json)
- [Agent and OS compatibility](COMPATIBILIDADE.md)
- [Security and operational boundaries](SEGURANCA.md) · [Reporting policy (`SECURITY.md`)](SECURITY.md)
- [Scoped API contracts and comparison](references/api-contracts.md)

## Local tooling and evidence-based verification

Beginners only need a plain-language request (as shown above). For maintainers and agents, [`scripts/nox.py`](scripts/nox.py) provides modular local commands with no background daemon:

- `python3 scripts/nox.py doctor` — checks JDK, Android SDK, Node.js, Git, Python, and ADB (separating missing optional tools from broken installs).
- `python3 scripts/nox.py inspect <path>` — detects ecosystem (`keiyoushi`/`yuzono`/`lnreader`), modern (`KeiSource`/`AniSource`/KSP) vs legacy architecture, and deterministic `sourceId`.
- `python3 scripts/nox.py lab <image|manga|anime|novel|search>` — verifies real image magic bytes (rejecting deceptive HTTP 200 HTML), fractional chapters (`59.5`), `getHosterList`/`getVideoList` & HLS/DRM separation, LNReader readability, and positive search integrity.
- `python3 scripts/nox.py apk-inspect <file.apk>` & `python3 scripts/nox.py adb <doctor|filter-logcat>` — inspects SHA-256, package, Debug vs Release certificates, and package/PID-isolated Logcat with secret redaction.
- `python3 scripts/nox.py issues <classify|correlate|fetch>` & `python3 scripts/nox.py security-audit <repo>` — classifies PRs (`VERIFIED_FIX` vs `REVERTED_FIX`/`OPEN_OR_UNMERGED`), fetches real GitHub issues/PRs, and audits Gradle/TLS/DexClassLoader/Trojan Source threats before running builds (`nox.py build`).
- `python3 scripts/nox.py scaffold` & `python3 scripts/nox.py scenarios` — generates official-pattern Keiyoushi/Yuzono/LNReader sources and validates creation, repair (before→after), and identity update against a local HTTP server.
- `python3 scripts/nox.py benchmark` & `python3 scripts/nox.py matrix --validate` — runs the Level 1 dynamic benchmark vs real `v1.0.3` + Level 2 HTTP scenarios (`PASS`) and validates the two-dimension `0001`–`1200` matrix (`1,000` original + `200` autonomous).
- `python3 scripts/nox.py autofix-diagnose <target> --symptom "<error>"` & `python3 scripts/nox.py review-council <target> --enabled` — correlates bugs with Keiyoushi/Yuzono/LNReader PR precedents (excluding unmerged/reverted PRs) and runs real 4-role analyzer council.
- `python3 scripts/nox.py auto "<request>"` & `python3 scripts/nox.py build <repo> <task>` & `apk-deliver` — drives full creation (`auto-create`) and real code repair (`auto-fix`) instead of stopping at templates or recommendations, keeps internal diagnostics out of beginner replies, isolates Gradle builds inside fail-closed Bubblewrap (`bwrap`), and offers save/optional ADB install/keep choices only after a confirmed APK build. Global flags (`--json`, `--beginner`, `--technical`, `--dry-run`) work before and after subcommands.

Every report strictly distinguishes **`PASS` / `FAIL` / `INCONCLUSIVE` / `BLOCKED` / `NOT_RUN`**: compilation does not prove real-site behavior, and Android device tests are never claimed unless an authorized device was actually exercised.

## Frequently asked questions

- **Do I need to know how to code?** Not to start with an AI agent, though reviewing diffs, debugging edge cases, and maintaining extensions may require technical help.
- **Is the skill free?** Yes. Usage fees, limits, and quotas depend strictly on the AI agent and model you choose.
- **Do I need to install the Android SDK?** Only if you build manga (Keiyoushi) or anime (Yuzono) APKs. For LNReader novel plugins, **no**.
- **Which agents are supported?** Execution was verified on OpenCode (`v2.2.7` on Arch Linux); Codex, Claude Code, and Google Antigravity have documented paths without official verification, and Hermes Agent has not been verified.
- **What if my agent does not recognize the skill?** Start a new session, ask for `Use the nox-extension-developer skill` by exact name, and check the installed path/symlink in the [troubleshooting guide](docs/en/guide.md#troubleshooting).
- **Where are update or removal instructions?** For updates, see [How to update the skill](#how-to-update-the-skill). For removal, see `npx skills remove --help` and the manual symlink instructions in the [installation and removal guide](docs/en/guide.md#installation).

## Support and contributions

- [Issues](https://github.com/ProjectNox-org/nox-extension-developer/issues) — Report reproducible bugs or documentation mismatches.
- [Discussions](https://github.com/ProjectNox-org/nox-extension-developer/discussions) — Ask questions and share ideas.
- [Pull Requests](https://github.com/ProjectNox-org/nox-extension-developer/pulls) — Submit improvements following [`CONTRIBUTING.en.md`](CONTRIBUTING.en.md).
- [Releases](https://github.com/ProjectNox-org/nox-extension-developer/releases) — Follow published versions.

**Security notice:** never post passwords, tokens, API keys, or personal data in issues or PRs. Report vulnerabilities exclusively through [`SECURITY.md`](SECURITY.md).

**Project Nox ecosystem:** [Official Hub](https://projectnox-org.github.io/) · [Project Nox Manga](https://github.com/ProjectNox-org/project-nox-manga) · [Importer](https://github.com/ProjectNox-org/project-nox-importer) · [Manga Extensions](https://github.com/ProjectNox-org/manga-extensoes) ([source](https://github.com/ProjectNox-org/manga-fonte-extensoes)) · [Anime Extensions](https://github.com/ProjectNox-org/anime-extensoes) ([source](https://github.com/ProjectNox-org/anime-fonte-extensoes)) · [Requests](https://github.com/ProjectNox-org/project-nox-requests) · [Tracker](https://github.com/ProjectNox-org/project-nox-tracker).

## Credits and licensing

Created by [**Awerkori**](https://github.com/Awerkori) for [**Project Nox**](https://github.com/ProjectNox-org). [Keiyoushi](https://github.com/keiyoushi/extensions-source), [Yuzono](https://github.com/yuzono/anime-extensions), [LNReader](https://github.com/LNReader/lnreader-plugins), and the [Agent Skills](https://agentskills.io/) specification are independent technical references without affiliation; see [`ATRIBUICOES.md`](ATRIBUICOES.md).

This software is licensed under the **GNU Affero General Public License v3.0 (`AGPL-3.0-only`)** — see [`LICENSE`](LICENSE) for full terms (including Corresponding Source obligations for remote network interaction under Section 13 and protection of **Project Nox** and **Awerkori** marks under Section 7(e)). The license applies solely to the skill's code, without warranty and without granting rights over third-party sites or copyrighted works.
