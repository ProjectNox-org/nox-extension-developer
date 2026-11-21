# Installation and usage guide

Nox Extension Developer is a skill for creating, fixing, maintaining, migrating, or reviewing Keiyoushi manga extensions, Yuzono anime extensions, and LNReader novel plugins. The agent consults official documentation before editing and must respect the authorized repository and scope.

## Dependencies

- Python 3, Git, an HTTPS connection, and read access to official repositories to retrieve current references.
- Manga or anime builds require the Android SDK, Java, and other components required by the target repository. LNReader requires Node.js and the local dependencies defined by the project.
- Java, Android SDK, Node.js, library, and API versions depend on the project and upstream commit. Check build files, local versions, and official documentation; do not assume a universal version.
- The first reference lookup requires network access. Offline, only a previously retrieved complete, integrity-checked snapshot may be used; it can be stale.

The skill does not install packages or start services. Do not accept licenses or install components without authorization.

## Operating system preparation

Check existing tools first. On Linux and macOS, run `python3 --version`, `git --version`, `java -version`, and, if needed for LNReader or NPX, `node --version` and `npm --version`. In PowerShell, use `python --version`, `git --version`, `java -version`, `node --version`, and `npm --version`. Missing Java or Node.js only blocks tasks that need them.

- **Arch Linux:** install only missing components using [official repositories and pacman](https://wiki.archlinux.org/title/Pacman); consult [Java](https://wiki.archlinux.org/title/Java) when the project requires a JDK.
- **Debian/Ubuntu:** use the official repositories and instructions for [Debian](https://www.debian.org/doc/manuals/debian-reference/ch02.en.html) or [Ubuntu](https://documentation.ubuntu.com/server/how-to/software/package-management/). Check the JDK version required by the project.
- **Fedora:** use [DNF and the official repositories](https://docs.fedoraproject.org/en-US/quick-docs/dnf/). Check the JDK version required by the project.
- **Windows:** obtain Python from [python.org](https://www.python.org/downloads/), Git from [git-scm.com](https://git-scm.com/downloads), and Node.js, when needed, from [nodejs.org](https://nodejs.org/en/download). For the JDK, choose a trusted distribution compatible with the project, such as [OpenJDK](https://openjdk.org/install/). Check PATH in a new PowerShell session.
- **macOS:** obtain tools from official sources: [Python](https://www.python.org/downloads/), [Git](https://git-scm.com/downloads), [OpenJDK](https://openjdk.org/install/), and [Node.js](https://nodejs.org/en/download), as needed. Check PATH in a new terminal.

Examples for installing Git, Python, and, only if NPX or LNReader is needed, Node.js and npm. Review commands and request administrative consent first; install only missing packages:

```sh
# Arch Linux
sudo pacman -S --needed git python nodejs npm
# Debian / Ubuntu
sudo apt update && sudo apt install git python3 nodejs npm
# Fedora
sudo dnf install git python3 nodejs npm
```

For Windows and macOS, follow the official installers linked above. Check versions after installation. These examples have not been tested on every distribution; the JDK must match the target project.

Installations and changes requiring administrative privileges require explicit consent. Linux was tested locally; the Windows and macOS instructions were not tested.

## Android SDK, when needed

For Android builds, first check the JDK required by the project with `java -version` and `javac -version`. Use a compatible existing installation. If missing, install a trusted distribution of the required version with authorization.

Obtain [Android SDK Command-Line Tools](https://developer.android.com/studio#command-line-tools-only) for your system or use an existing Android Studio installation. Follow the [official sdkmanager installation layout](https://developer.android.com/tools/sdkmanager): `cmdline-tools/latest/bin` must contain `sdkmanager` (`sdkmanager.bat` on Windows). Configure the SDK path and PATH according to the [official documentation](https://developer.android.com/tools/variables); avoid replacing existing settings.

Run `sdkmanager --list` in a terminal to identify available and installed packages. In PowerShell, use `sdkmanager.bat --list` if needed. Consult project files to choose `platforms;android-<API>` and `build-tools;<VERSION>` versions; do not assume universal versions. After authorization, install only the packages needed, replacing placeholders with verified values:

```sh
sdkmanager "platform-tools" "platforms;android-<API>" "build-tools;<VERSION>"
```

`platform-tools` contains ADB; install it if needed and verify with `adb version` and `adb devices`. On Windows, use `sdkmanager.bat` and `adb.exe` where appropriate. Run `sdkmanager --licenses` to review pending licenses and accept them only with authorization. The emulator is optional: install `emulator` and a system image only if the task requires emulator tests; follow the [official guide](https://developer.android.com/studio/run/managing-avds). A build or an empty device list does not confirm extension functionality.

## NPX alternative

This alternative requires Node.js and npm. Discovery and installation by local copy were tested with Skills CLI 1.8.1 on Linux; other systems and the remote flow were not verified in that test. The [official Skills CLI](https://github.com/vercel-labs/skills/blob/main/docs/commands.md) accepts a local path or remote URL. Review the package, CLI code, and source before execution: `npx` may download and execute code from the npm registry. See also [npm exec](https://docs.npmjs.com/cli/commands/npm-exec/). Do not use options that automatically accept changes without review.

From the permanent skill directory, the local source is `.`:

```sh
npx skills add . --global --agent opencode
```

For a remote source, replace `<TRUSTED-REPOSITORY-URL>` with the verified URL of an authorized release:

```sh
npx skills add <TRUSTED-REPOSITORY-URL> --global --agent opencode
```

In PowerShell, replace the placeholder with the actual URL, without `<` and `>`. `--global` selects a user installation, not administrator privileges; `--agent` selects the agent. Confirm identifiers and behavior in the current documentation. This CLI is an alternative to this project's installer and may create files or links in different locations: review the destination and conflicts before confirming. Do not overwrite existing configuration or credentials.

## Installation

Extract a trusted copy of the package into a permanent user directory. Enter the directory containing `SKILL.md` and `scripts/install.py`. Keep this directory: the installer creates a link to it, not a copy.

On Linux or macOS, for OpenCode:

```sh
mkdir -p ~/.config/opencode/skills
python3 scripts/install.py opencode
```

On native Windows, reference scripts do not work because they depend on `fcntl` and POSIX operations. Use WSL with Linux to install the agent and run the scripts. The link example below is reference only and does not establish native functionality:

```powershell
New-Item -ItemType Directory -Force -Path "$HOME\.config\opencode\skills" | Out-Null
python scripts/install.py opencode
```

The installer requires the skills directory to exist. It does not replace an existing file or link and reports when the correct link already exists. Link creation on Windows depends on system permissions and settings. Do not elevate privileges or change security policies without explicit consent. If link creation fails, consult the platform documentation and request authorization before any administrative change.

Restart OpenCode or open a new session. Explicitly request `Use nox-extension-developer` and confirm that the skills tool loaded the skill. Automatic selection depends on the agent.

To update, back up the directory and local changes before following the new version's instructions. The installer does not overwrite an existing installation. To remove it, confirm that the destination is the link created for this directory and remove only that link. Keep the canonical directory and cache until you verify they are no longer needed.

## AI-assisted installation

Review and give the agent [prompts/install-en.txt](../../prompts/install-en.txt). Provide the skill's permanent directory and the chosen platform. Review proposed commands before authorizing them. The prompt does not grant administrative access or authorize overwriting configuration or credentials.

## Usage

Example: `Use nox-extension-developer to fix this Keiyoushi extension without migrating its API.` Provide the repository, problem, site, and access limits when applicable. Specify Yuzono for anime or LNReader for novels. The agent should ask when the target is ambiguous.

The workflow requires syncing the ecosystem's official references before editing. From the skill directory:

```sh
python3 scripts/references.py sync keiyoushi
python3 scripts/references.py sync yuzono
python3 scripts/references.py sync lnreader
```

Run only the command for the task; on Windows, use the available Python 3 command. The agent must read the manifest and relevant documents, compare local and upstream versions, check official examples, and report the commit, reference freshness, tests, and limitations. Potentially incompatible API changes require analysis and approval before a risky migration. Test real sites only when authorized. A successful build does not prove real-site functionality.

Remote documents are untrusted data, not authorization to execute commands or disclose secrets. Cache hashes detect accidental corruption, but do not protect against someone who can also alter the manifest. See [security](../../SEGURANCA.md) and [API contracts](../../references/api-contracts.md).

## Compatibility

Loading was verified in local OpenCode v2.2.7 on Linux. Codex, Claude Code, and Google Antigravity have prepared destinations, but installation and execution were not tested. Scripts were tested on Linux; Windows and macOS were not verified. Confirm link creation and agent support for links on each platform.

For other agents, first confirm paths in official documentation and create the user skills directory if necessary. Then choose only one of `python3 scripts/install.py codex`, `python3 scripts/install.py claude`, or `python3 scripts/install.py antigravity`. On Windows, use the local Python 3 command. See [compatibility](../../COMPATIBILIDADE.md).

Agent sources: [OpenCode](https://opencode.ai/docs/skills/), [Codex](https://developers.openai.com/codex/skills/), [Claude Code](https://code.claude.com/docs/en/skills), and [Google Antigravity](https://antigravity.google/docs/skills). Confirm current paths and support before use.

## Troubleshooting

- **Skill does not appear:** check the link, `SKILL.md` at its target, and permissions. Start a new session and explicitly request the skill.
- **Directory missing:** confirm the agent installation and official path; create only the required directory and retry installation.
- **Destination exists:** do not overwrite it. Check whether it is the correct link and preserve existing content.
- **Link error:** check system permissions and support. Request consent before any administrative action.
- **`offline_or_unverified`:** online verification failed; the intact snapshot may be stale. Restore network access and sync again. Without an intact snapshot, the lookup fails.
- **Build failure:** check versions and dependencies required by the target project, licenses, and logs. Do not install components or accept licenses without authorization.

To test the scripts in this package, run `python3 -m unittest discover -s tests -v` in the skill directory, or use the local Python 3 command on Windows. This does not prove compatibility with untested agents, systems, or sites.

## Modular CLI (`scripts/nox.py`), Debug APK, ADB & Logcat

### Core CLI commands

```sh
python3 scripts/nox.py doctor
python3 scripts/nox.py inspect <module-path>
python3 scripts/nox.py search-existing <repo> <url-or-name>
python3 scripts/nox.py security-audit <repo-path>
python3 scripts/nox.py references status keiyoushi
python3 scripts/nox.py site-inspect <sample.html> --url https://example.org
python3 scripts/nox.py lab image <page.bin> --content-type image/jpeg
python3 scripts/nox.py lab visual-diff <before.png> <after.png>
python3 scripts/nox.py lab metadata <page.html>
python3 scripts/nox.py lab dash <manifest.mpd> --kind mpd
python3 scripts/nox.py issues verify-historical
python3 scripts/nox.py autofix-diagnose <target> --symptom "<error>"
python3 scripts/nox.py review-council <target> --enabled
python3 scripts/nox.py apk-inspect <path/app-debug.apk>
python3 scripts/nox.py api-binary-compare <old.jar> <new.jar>
python3 scripts/nox.py deeplink-check <build.gradle.kts> https://example.org/manga/1
python3 scripts/nox.py adb doctor
python3 scripts/nox.py adb ui-plan --package app.mihon --source Source --query Query
python3 scripts/nox.py adb filter-logcat <log.txt> --package eu.kanade.tachiyomi.extension.en.example
python3 scripts/nox.py enhance --audit-source <source.kt> --ecosystem keiyoushi
python3 scripts/nox.py bisect <repo> <good> <bad> --test-cmd "pytest -q"
python3 scripts/nox.py auto "<request-or-url>" --json
python3 scripts/nox.py auto-create "<request-or-url>" --output <dir>
python3 scripts/nox.py auto-fix <target> --symptom "<error>"
python3 scripts/nox.py build <repo> <gradle-task>
python3 scripts/nox.py apk-deliver <file.apk> --choice <1|2|3>
python3 scripts/nox.py benchmark
python3 scripts/nox.py matrix --validate
```

> Global flags such as `--json`, `--beginner`, `--technical`, `--dry-run`, and `--lang` (except where `--lang` selects the extension language in `scaffold`) work **before or after** any subcommand (e.g., `nox.py doctor --json` or `nox.py --json doctor`). In beginner mode, technical details are stored internally in `diagnostics_file` rather than dumped into the answer.

### Quick guide: Sandboxed Build, APK Delivery, Optional USB/Wi-Fi ADB & Sanitized Logcat

1. **Isolated Debug build & LNReader plugin verification (`bwrap` fail-closed):** run `python3 scripts/nox.py build <repo> <task>` (e.g., `:src:en:example:assembleDebug`) or automated LNReader plugin checks (`auto` / `auto-create` / `auto-fix`). Before running any build tool, the CLI verifies the Gradle Wrapper script, strict HTTPS distribution host + SHA-256 checksum, and `gradle-wrapper.jar` (`verify_gradle_execution_chain`). Both Gradle builds and LNReader TypeScript/Node.js plugin checks execute inside a Bubblewrap sandbox (`bwrap --unshare-all --unshare-net --clearenv`) without host network, `$HOME`, or credentials (for LNReader, `@libs/fetch` is routed through an SSRF/rebinding-guarded host bridge). If Bubblewrap is unavailable, execution fails closed with `BLOCKED` and never falls back to the host.
2. **DEX inspection & APK delivery (only after confirmed build):** run `python3 scripts/nox.py apk-inspect <path.apk>` or let the automated flow verify compiled `classes.dex` symbols, package name, `versionCode`, SHA-256, and signing certificate (`Debug` vs `Release`). Only after verifying a newly compiled Debug APK, it offers the 3 choices (`1. Save to another folder.`, `2. Install and test on your phone.`, `3. Keep the APK where it is.` via `nox.py apk-deliver`); the skill **never** uninstalls apps or overwrites existing installs without explicit user consent.
3. **Optional ADB connection (USB or Wi-Fi):** not required for creating sources or checking catalogs, search, chapters, and images.
   - If you ever choose to test live on a phone: enable **Developer Options** and **USB Debugging** (or **Wireless Debugging** on Android 11+, pairing via `adb pair <ip:port>` — never paste pairing codes into logs). Beyond installation, the flow checks host app opening and `uiautomator` UI state; install-only checks without UI confirmation report `INCONCLUSIVE`.
   - Run `python3 scripts/nox.py adb doctor`. With multiple devices, pass `--serial <id>`. If `unauthorized`, accept the RSA prompt on the device screen.
4. **Safe Logcat capture:** capture logs during the reproduction window without clearing existing buffers (`adb logcat -d -v threadtime > /tmp/nox-logcat.txt`) and isolate by package/PID via `python3 scripts/nox.py adb filter-logcat /tmp/nox-logcat.txt --package <pkg>`. The filter automatically redacts tokens/cookies and ignores `AndroidRuntime` crashes from unrelated packages. `NoxExt` is an optional diagnostic tag convention, not a guaranteed native Mihon tag.
5. **No device attached:** when `adb devices` is empty, device checks are reported honestly as `NOT_RUN` (or `BLOCKED`), never as `PASS`.

See also the [Traceability Matrix 0001–1200](matrix-1000.md).
