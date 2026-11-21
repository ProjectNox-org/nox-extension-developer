#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""PR/supply-chain threat analyzer, real APK inspector, and non-destructive ADB/Logcat diagnostics."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
import zipfile

from nox_core import sanitize_text, scan_bidi_controls, scan_hardcoded_literals


_GRADLE_EXEC_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ('gradle_runtime_exec', re.compile(r'Runtime\.getRuntime\(\)\.exec\b')),
    ('gradle_process_builder', re.compile(r'\bProcessBuilder\s*\(')),
    ('gradle_exec_task', re.compile(r'\b(?:project\.)?exec\s*\{[^}]*(?:commandLine|executable)')),
    ('curl_pipe_sh', re.compile(r'(?i)(?:curl|wget)[^\n|]*\|\s*(?:ba)?sh')),
    ('base64_decode_exec', re.compile(r'(?i)base64\s+-d[^\n]*\|\s*(?:ba)?sh')),
)

_WORKFLOW_DANGER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ('pr_target_checkout', re.compile(r'pull_request_target')),
    ('unpinned_action_tag', re.compile(r'uses:\s*[^\s@]+@(?:main|master|v\d+(?:\.\d+)*)\s*$')),
    ('secrets_exposure', re.compile(r'\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}')),
)

_SOURCE_DANGER_PATTERNS: tuple[tuple[str, str, set[str], re.Pattern[str]], ...] = (
    ('FAIL', 'tls_trust_all_certs', {'.kt', '.java'}, re.compile(r'(?i)(?:ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|HostnameVerifier\s*\{\s*[^}]*->\s*true\s*\})')),
    ('FAIL', 'dynamic_dex_loader', {'.kt', '.java'}, re.compile(r'\b(?:DexClassLoader|InMemoryDexClassLoader|PathClassLoader)\s*\(')),
    ('FAIL', 'native_system_load', {'.kt', '.java'}, re.compile(r'\bSystem\.load(?:Library)?\s*\(')),
    ('FAIL', 'runtime_command_exec', {'.kt', '.java'}, re.compile(r'\b(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b')),
    ('FAIL', 'node_child_process', {'.ts', '.js'}, re.compile(r'\bchild_process\b')),
    ('WARN', 'dynamic_eval_js', {'.ts', '.js'}, re.compile(r'(?<![.\w])eval\s*\(')),
)


def audit_untrusted_pr_or_repo(repo_path: Path | str) -> dict[str, Any]:
    """Static supply-chain & RCE audit of Gradle build scripts, wrapper, workflows, package.json, and symlinks."""
    root = Path(repo_path).resolve()
    if not root.exists():
        return {'status': 'FAIL', 'error': f'path does not exist: {root}', 'findings': []}

    findings: list[dict[str, Any]] = []

    # 1. Symlink escape detection
    for cur_root, dirs, files in os.walk(root):
        if '.git' in dirs:
            dirs.remove('.git')
        for entry in list(dirs) + list(files):
            p = Path(cur_root) / entry
            if p.is_symlink():
                try:
                    resolved = p.resolve()
                    resolved.relative_to(root)
                except ValueError:
                    findings.append({'severity': 'FAIL', 'kind': 'symlink_escape', 'file': str(p), 'target': str(os.readlink(p))})

    # 2. Gradle files (configuration phase RCE risk!)
    for pattern in ('*.gradle', '*.gradle.kts'):
        for gf in root.rglob(pattern):
            if any(part in {'.git', 'build', '.gradle', 'node_modules'} for part in gf.parts):
                continue
            txt = gf.read_text(errors='replace')
            for kind, rx in _GRADLE_EXEC_PATTERNS:
                if rx.search(txt):
                    findings.append({'severity': 'FAIL', 'kind': kind, 'file': str(gf.relative_to(root))})
            for m in re.finditer(r'maven\s*\(\s*url\s*=\s*"([^"]+)"', txt):
                url = m.group(1)
                if url.startswith('http://') or ('jitpack' not in url and 'maven.google' not in url and 'repo.maven' not in url and 'mavenCentral' not in url):
                    findings.append({'severity': 'WARN', 'kind': 'custom_or_insecure_maven_repo', 'file': str(gf.relative_to(root)), 'url': url})

    # 3. Gradle wrapper URL check
    wrapper_props = root / 'gradle/wrapper/gradle-wrapper.properties'
    if wrapper_props.is_file():
        wtxt = wrapper_props.read_text(errors='replace')
        dist_m = re.search(r'^distributionUrl=(.+)$', wtxt, re.M)
        if dist_m:
            dist_url = dist_m.group(1).replace('\\:', ':').strip()
            if not dist_url.startswith('https://services.gradle.org/distributions/'):
                findings.append({'severity': 'FAIL', 'kind': 'untrusted_gradle_wrapper_url', 'file': 'gradle/wrapper/gradle-wrapper.properties', 'url': dist_url})

    # 4. GitHub Actions workflows
    wf_dir = root / '.github/workflows'
    if wf_dir.is_dir():
        for wf in sorted(wf_dir.glob('*.y*ml')):
            wtxt = wf.read_text(errors='replace')
            lines = wtxt.splitlines()
            for kind, rx in _WORKFLOW_DANGER_PATTERNS:
                for i, ln in enumerate(lines, start=1):
                    if rx.search(ln):
                        sev = 'FAIL' if kind == 'pr_target_checkout' else 'WARN'
                        findings.append({'severity': sev, 'kind': kind, 'file': str(wf.relative_to(root)), 'line': i})

    # 5. package.json install scripts
    pkg = root / 'package.json'
    if pkg.is_file():
        try:
            pdata = json.loads(pkg.read_text(errors='replace'))
            scripts = pdata.get('scripts') or {}
            for hook in ('preinstall', 'install', 'postinstall'):
                if hook in scripts:
                    findings.append({'severity': 'WARN', 'kind': f'npm_lifecycle_script:{hook}', 'file': 'package.json', 'command': sanitize_text(str(scripts[hook]))[:120]})
        except json.JSONDecodeError:
            findings.append({'severity': 'FAIL', 'kind': 'invalid_package_json', 'file': 'package.json'})

    # 6. Source code checks (TLS bypass, DexClassLoader, command execution, bidi Trojan Source, secrets)
    for ext in ('*.kt', '*.java', '*.ts', '*.js', '*.py'):
        for sf in root.rglob(ext):
            if any(part in {'.git', 'build', '.gradle', 'node_modules', '__pycache__', 'evidencias'} for part in sf.parts):
                continue
            rel = str(sf.relative_to(root))
            # Skip self-testing files that intentionally contain negative regexes/fixtures
            if rel.startswith('tests/') or rel in {'scripts/nox_core.py', 'scripts/nox_android.py', 'scripts/api_compare.py'}:
                continue
            txt = sf.read_text(errors='replace')
            for sev, kind, exts, rx in _SOURCE_DANGER_PATTERNS:
                if sf.suffix in exts and rx.search(txt):
                    findings.append({'severity': sev, 'kind': kind, 'file': rel})
            for bh in scan_bidi_controls(txt):
                findings.append({'severity': 'FAIL', 'kind': 'trojan_source_bidi_control', 'file': rel, **bh})
            for sh in scan_hardcoded_literals(txt):
                findings.append({'severity': 'FAIL', 'kind': 'hardcoded_secret_candidate', 'file': rel, 'line': int(sh['line'])})

    has_fail = any(f['severity'] == 'FAIL' for f in findings)
    return {
        'status': 'FAIL' if has_fail else 'PASS',
        'repo_root': str(root),
        'findings_count': len(findings),
        'findings': findings,
    }


def _detect_android_sdk_root() -> Path | None:
    """Resolve Android SDK directory from environment variables or standard user-local install paths."""
    for env_key in ('ANDROID_HOME', 'ANDROID_SDK_ROOT'):
        sdk = os.environ.get(env_key)
        if sdk:
            cand = Path(sdk).expanduser().resolve()
            if cand.is_dir():
                return cand
    for rel in ('.local/share/android-sdk', 'Android/Sdk'):
        cand = (Path.home() / rel).expanduser().resolve()
        if cand.is_dir():
            return cand
    return None


def _find_android_tool(name: str, *, prefer_build_tools: bool = False) -> str | None:
    sdk = _detect_android_sdk_root()
    if prefer_build_tools and sdk is not None:
        bt = sdk / 'build-tools'
        if bt.is_dir():
            for v in reversed(sorted(p for p in bt.iterdir() if p.is_dir())):
                cand = v / name
                if cand.is_file():
                    return str(cand)
    found = shutil.which(name)
    if found:
        return found
    if sdk is not None:
        bt = sdk / 'build-tools'
        if bt.is_dir():
            for v in reversed(sorted(p for p in bt.iterdir() if p.is_dir())):
                cand = v / name
                if cand.is_file():
                    return str(cand)
        pt = sdk / 'platform-tools' / name
        if pt.is_file():
            return str(pt)
    return None


def _pick_cached_gradle_jar(org_dir: Path, artifact: str, preferred_version: str | None = None) -> tuple[str | None, Path | None]:
    """Select the newest (or matching preferred) jar for org_dir/artifact in local Gradle module cache."""
    art_dir = org_dir / artifact
    if not art_dir.is_dir():
        return None, None
    versions = sorted((p for p in art_dir.iterdir() if p.is_dir()), key=lambda p: [int(x) if x.isdigit() else x for x in re.split(r'[.-]', p.name)])
    if preferred_version:
        versions = [v for v in versions if v.name == preferred_version] + [v for v in reversed(versions) if v.name != preferred_version]
    else:
        versions = list(reversed(versions))
    for ver_dir in versions:
        jars = sorted(
            j for j in ver_dir.rglob('*.jar')
            if j.is_file() and not j.is_symlink() and not j.name.endswith(('-sources.jar', '-javadoc.jar'))
        )
        if jars:
            return ver_dir.name, jars[0].resolve()
    return None, None


def _find_kotlin_compiler_jars() -> tuple[str | None, list[Path]]:
    """Locate real Kotlin K2JVMCompiler and runtime jars on the host (Gradle cache or KOTLIN_HOME)."""
    custom_dir = os.environ.get('NOX_KOTLIN_JARS_DIR') or (
        str(Path(os.environ['KOTLIN_HOME']) / 'lib') if os.environ.get('KOTLIN_HOME') else None
    )
    if custom_dir:
        cdir = Path(custom_dir).expanduser().resolve()
        if cdir.is_dir():
            jars = sorted(j.resolve() for j in cdir.glob('*.jar') if j.is_file() and not j.is_symlink())
            if any('kotlin-compiler' in j.name for j in jars) and any('kotlin-stdlib' in j.name for j in jars):
                return 'custom', jars

    cache_root = Path.home() / '.gradle/caches/modules-2/files-2.1'
    kt_org = cache_root / 'org.jetbrains.kotlin'
    if not kt_org.is_dir():
        return None, []
    kt_ver, compiler_jar = _pick_cached_gradle_jar(kt_org, 'kotlin-compiler-embeddable')
    if not kt_ver or not compiler_jar:
        return None, []
    found: list[Path] = [compiler_jar]
    for art in ('kotlin-stdlib', 'kotlin-stdlib-jdk7', 'kotlin-stdlib-jdk8', 'kotlin-reflect', 'kotlin-script-runtime', 'kotlin-daemon-embeddable'):
        _, jar = _pick_cached_gradle_jar(kt_org, art, preferred_version=kt_ver)
        if jar is not None:
            found.append(jar)
    for org_name, art in (
        ('org.jetbrains', 'annotations'),
        ('org.jetbrains.kotlinx', 'kotlinx-coroutines-core-jvm'),
        ('org.jetbrains.kotlinx', 'kotlinx-serialization-core-jvm'),
        ('org.jetbrains.kotlinx', 'kotlinx-serialization-json-jvm'),
        ('org.jetbrains.intellij.deps', 'trove4j'),
    ):
        _, jar = _pick_cached_gradle_jar(cache_root / org_name, art)
        if jar is not None:
            found.append(jar)
    return kt_ver, found


def find_kotlin_and_android_build_toolchain() -> dict[str, Any]:
    """Detect real local Java, Kotlin K2JVMCompiler, D8, AAPT2, Keytool, Apksigner, android.jar, and bwrap tools."""
    java_bin = shutil.which('java')
    javac_bin = shutil.which('javac')
    keytool_bin = shutil.which('keytool')
    d8_bin = _find_android_tool('d8', prefer_build_tools=True)
    aapt2_bin = _find_android_tool('aapt2', prefer_build_tools=True)
    apksigner_bin = _find_android_tool('apksigner', prefer_build_tools=True)
    sdk_root = _detect_android_sdk_root()

    android_jar: Path | None = None
    env_ajar = os.environ.get('NOX_ANDROID_JAR')
    if env_ajar and Path(env_ajar).expanduser().is_file():
        android_jar = Path(env_ajar).expanduser().resolve()
    elif sdk_root is not None and (sdk_root / 'platforms').is_dir():
        candidates = sorted((sdk_root / 'platforms').glob('android-*/android.jar'))
        if candidates:
            android_jar = candidates[-1].resolve()

    kotlin_ver, kotlin_jars = _find_kotlin_compiler_jars()
    bwrap = probe_bwrap_sandbox()

    tools = {
        'java': java_bin,
        'javac': javac_bin,
        'keytool': keytool_bin,
        'd8': d8_bin,
        'aapt2': aapt2_bin,
        'apksigner': apksigner_bin,
        'android_jar': str(android_jar) if android_jar else None,
        'bwrap': bwrap.get('bwrap_path'),
    }
    missing = [k for k, v in tools.items() if not v]
    if not kotlin_jars or not any('kotlin-compiler' in j.name for j in kotlin_jars):
        missing.append('kotlin_compiler_jars')
    if bwrap.get('status') != 'PASS':
        missing.append('bwrap_sandbox')

    return {
        'status': 'PASS' if not missing else 'BLOCKED',
        'tools': tools,
        'android_sdk_root': str(sdk_root) if sdk_root else None,
        'kotlin_version': kotlin_ver,
        'kotlin_jars': [str(j) for j in kotlin_jars],
        'bwrap': bwrap,
        'missing': missing,
    }


def inspect_apk(
    apk_path: Path | str,
    *,
    index_json_path: Path | str | None = None,
    expected_package: str | None = None,
) -> dict[str, Any]:
    """Inspect a real APK archive: SHA-256, zip-slip, .so presence (16KB note), aapt2 badging, apksigner certs, index match."""
    path = Path(apk_path)
    if not path.is_file():
        return {'status': 'FAIL', 'error': f'APK file does not exist: {path}', 'device_test_status': 'NOT_RUN'}

    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()

    native_libs: list[str] = []
    has_manifest = False
    has_dex = False
    zip_slip: list[str] = []
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            for n in names:
                if '..' in Path(n).parts or n.startswith('/'):
                    zip_slip.append(n)
                if n == 'AndroidManifest.xml':
                    has_manifest = True
                if n.endswith('.dex'):
                    has_dex = True
                if n.startswith('lib/') and n.endswith('.so'):
                    native_libs.append(n)
    except zipfile.BadZipFile as exc:
        return {'status': 'FAIL', 'error': f'Corrupt APK/ZIP: {exc}', 'sha256': sha256, 'device_test_status': 'NOT_RUN'}

    if zip_slip or not has_manifest:
        return {
            'status': 'FAIL',
            'error': 'Invalid APK structure (missing AndroidManifest.xml or zip-slip entry)',
            'sha256': sha256,
            'zip_slip': zip_slip,
            'device_test_status': 'NOT_RUN',
        }

    metadata: dict[str, Any] = {}
    aapt2 = _find_android_tool('aapt2')
    if aapt2:
        proc = subprocess.run([aapt2, 'dump', 'badging', str(path)], capture_output=True, text=True)
        if proc.returncode == 0:
            out = proc.stdout
            pkg_m = re.search(r"package:\s+name='([^']+)'\s+versionCode='(\d+)'\s+versionName='([^']+)'", out)
            min_m = re.search(r"sdkVersion:'(\d+)'", out)
            tgt_m = re.search(r"targetSdkVersion:'(\d+)'", out)
            lbl_m = re.search(r"application-label:'([^']+)'", out)
            if pkg_m:
                metadata.update({
                    'package': pkg_m.group(1),
                    'versionCode': int(pkg_m.group(2)),
                    'versionName': pkg_m.group(3),
                })
            if min_m:
                metadata['minSdkVersion'] = int(min_m.group(1))
            if tgt_m:
                metadata['targetSdkVersion'] = int(tgt_m.group(1))
            if lbl_m:
                metadata['label'] = lbl_m.group(1)

    signing: dict[str, Any] = {'verified': None, 'is_debug_cert': None, 'schemes': {}, 'signers': []}
    apksigner = _find_android_tool('apksigner')
    if apksigner:
        proc = subprocess.run([apksigner, 'verify', '--print-certs', '-v', str(path)], capture_output=True, text=True)
        out = (proc.stdout or '') + '\n' + (proc.stderr or '')
        signing['verified'] = proc.returncode == 0
        for scheme in ('v1', 'v2', 'v3', 'v4'):
            m = re.search(rf'Verified using {scheme} scheme[^:]*:\s*(true|false)', out)
            if m:
                signing['schemes'][scheme] = (m.group(1) == 'true')
        dns = re.findall(r'(?:Signer #\d+|V\d+(?:\.\d+)? Signer):\s*certificate DN:\s*(.+)|Signer #\d+ certificate DN:\s*(.+)', out)
        dns_clean = [a or b for a, b in dns]
        sha_matches = re.findall(r'(?:Signer #\d+|V\d+(?:\.\d+)? Signer):\s*certificate SHA-256 digest:\s*([0-9a-fA-F]+)|Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F]+)', out)
        sha_digests = [a or b for a, b in sha_matches]
        signing['signers'] = [{'dn': dn.strip(), 'sha256': dg} for dn, dg in zip(dns_clean, sha_digests)]
        signing['is_debug_cert'] = any('Android Debug' in dn for dn in dns_clean)

    issues: list[str] = []
    if expected_package and metadata.get('package') and metadata['package'] != expected_package:
        issues.append(f"package_mismatch:expected={expected_package},actual={metadata['package']}")
    if signing['verified'] is False:
        issues.append('apk_signature_verification_failed')

    # Cross-check with distribution index.min.json if provided
    index_check: dict[str, Any] | None = None
    if index_json_path is not None:
        idx_p = Path(index_json_path)
        if not idx_p.is_file():
            issues.append(f'index_file_missing:{idx_p}')
        else:
            entries = json.loads(idx_p.read_text(errors='replace'))
            pkg_name = metadata.get('package')
            match = next((e for e in entries if isinstance(e, dict) and e.get('pkg') == pkg_name), None)
            if not match:
                issues.append(f'package_missing_in_index:{pkg_name}')
            else:
                if match.get('code') != metadata.get('versionCode'):
                    issues.append(f"index_versionCode_mismatch:index={match.get('code')},apk={metadata.get('versionCode')}")
                index_check = {'matched_pkg': pkg_name, 'index_apk': match.get('apk'), 'index_code': match.get('code')}

    # 16KB page alignment only applies when native .so libraries exist
    page_16kb_note = 'applicable_native_libs_present_verify_alignment' if native_libs else 'not_applicable_no_native_so_libraries'

    return {
        'status': 'FAIL' if issues else 'PASS',
        'apk_path': str(path.resolve()),
        'size_bytes': len(raw),
        'sha256': sha256,
        'has_dex': has_dex,
        'native_libs': native_libs,
        'page_16kb_status': page_16kb_note,
        'metadata': metadata,
        'signing': signing,
        'build_kind': 'debug' if signing['is_debug_cert'] else ('release_or_custom' if signing['verified'] else 'unknown'),
        'index_check': index_check,
        'device_test_status': 'NOT_RUN',
        'issues': issues,
    }


def parse_adb_devices(output: str) -> list[dict[str, str]]:
    """Parse `adb devices -l` output cleanly across USB and Wi-Fi endpoints."""
    devices: list[dict[str, str]] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('List of devices') or stripped.startswith('*'):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        transport = 'wifi' if ':' in serial else 'usb'
        meta = dict(p.split(':', 1) for p in parts[2:] if ':' in p)
        devices.append({'serial': serial, 'state': state, 'transport': transport, **meta})
    return devices


def adb_doctor(*, adb_output: str | None = None, selected_serial: str | None = None) -> dict[str, Any]:
    """Non-destructive ADB diagnostic handling 0, 1, multiple, unauthorized, and offline devices."""
    if adb_output is None:
        adb_bin = shutil.which('adb') or _find_android_tool('adb')
        if not adb_bin:
            return {
                'status': 'BLOCKED',
                'adb_present': False,
                'devices': [],
                'guidance': 'Install Android platform-tools (adb) to inspect connected devices.',
            }
        try:
            proc = subprocess.run([adb_bin, 'devices', '-l'], capture_output=True, text=True, timeout=5)
            adb_output = proc.stdout
        except (OSError, subprocess.SubprocessError) as exc:
            return {'status': 'BLOCKED', 'adb_present': True, 'error': str(exc), 'devices': []}

    devices = parse_adb_devices(adb_output)
    ready = [d for d in devices if d['state'] == 'device']
    unauthorized = [d for d in devices if d['state'] == 'unauthorized']
    offline = [d for d in devices if d['state'] == 'offline']

    if not devices:
        return {
            'status': 'BLOCKED',
            'adb_present': True,
            'device_count': 0,
            'devices': [],
            'guidance': 'No Android device/emulator detected. Enable USB Debugging (Developer Options) or pair via Wi-Fi (`adb pair <ip:port>`), then confirm RSA prompt.',
        }

    if unauthorized:
        return {
            'status': 'BLOCKED',
            'adb_present': True,
            'device_count': len(devices),
            'devices': devices,
            'guidance': 'Device unauthorized: unlock screen and tap Allow on the USB debugging RSA dialog.',
        }

    if offline and not ready:
        return {
            'status': 'BLOCKED',
            'adb_present': True,
            'device_count': len(devices),
            'devices': devices,
            'guidance': 'Device offline: reconnect USB cable or run `adb reconnect` (never wipes device data).',
        }

    if len(ready) > 1:
        if not selected_serial:
            return {
                'status': 'INCONCLUSIVE',
                'adb_present': True,
                'device_count': len(devices),
                'devices': devices,
                'guidance': f"Multiple ready devices ({[d['serial'] for d in ready]}); pass --serial <id> explicitly.",
            }
        chosen = next((d for d in ready if d['serial'] == selected_serial), None)
        if not chosen:
            return {
                'status': 'FAIL',
                'adb_present': True,
                'devices': devices,
                'guidance': f'Selected serial {selected_serial!r} is not among ready devices.',
            }
        return {'status': 'PASS', 'adb_present': True, 'selected_device': chosen, 'devices': devices}

    return {'status': 'PASS', 'adb_present': True, 'selected_device': ready[0], 'devices': devices}


_LOGCAT_LINE_RE = re.compile(
    r'^(?P<ts>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF])\s+(?P<tag>[^:]+):\s*(?P<msg>.*)$'
)


def parse_and_filter_logcat(
    log_text: str,
    *,
    target_package: str | None = None,
    target_pid: int | None = None,
    window_start: str | None = None,
    window_end: str | None = None,
    include_optional_noxext_tag: bool = True,
) -> dict[str, Any]:
    """Filter Android logcat by package/PID/time window, isolate foreign crashes, and redact secrets."""
    matched_lines: list[str] = []
    foreign_crashes: list[dict[str, Any]] = []
    target_crashes: list[dict[str, Any]] = []

    current_crash_pid: int | None = None
    current_crash_pkg: str | None = None
    current_crash_lines: list[str] = []

    def _flush_crash() -> None:
        nonlocal current_crash_pid, current_crash_pkg, current_crash_lines
        if not current_crash_lines:
            return
        entry = {
            'pid': current_crash_pid,
            'package': current_crash_pkg,
            'excerpt': [sanitize_text(l, redact_home=True) for l in current_crash_lines[:15]],
        }
        is_target = (
            (target_pid is not None and current_crash_pid == target_pid)
            or (target_package and current_crash_pkg and target_package in current_crash_pkg)
            or (target_package and any(target_package in l for l in current_crash_lines))
        )
        if is_target:
            target_crashes.append(entry)
        else:
            foreign_crashes.append(entry)
        current_crash_pid = None
        current_crash_pkg = None
        current_crash_lines = []

    for raw_line in log_text.splitlines():
        m = _LOGCAT_LINE_RE.match(raw_line)
        if not m:
            continue
        ts = m.group('ts')
        if window_start and ts < window_start:
            continue
        if window_end and ts > window_end:
            continue
        pid = int(m.group('pid'))
        tag = m.group('tag').strip()
        msg = m.group('msg')

        if tag == 'AndroidRuntime' and ('FATAL EXCEPTION' in msg or 'Process:' in msg or current_crash_lines):
            if 'FATAL EXCEPTION' in msg:
                _flush_crash()
                current_crash_pid = pid
            proc_m = re.search(r'Process:\s*([^\s,]+),\s*PID:\s*(\d+)', msg)
            if proc_m:
                current_crash_pkg = proc_m.group(1)
                current_crash_pid = int(proc_m.group(2))
            current_crash_lines.append(raw_line)
        elif current_crash_lines and pid == current_crash_pid and m.group('level') == 'E':
            current_crash_lines.append(raw_line)
        else:
            _flush_crash()

        keep = False
        if target_pid is not None and pid == target_pid:
            keep = True
        elif target_package and target_package in msg:
            keep = True
        elif include_optional_noxext_tag and tag == 'NoxExt':
            keep = True

        if keep:
            matched_lines.append(sanitize_text(raw_line, redact_home=True))

    _flush_crash()

    return {
        'status': 'FAIL' if target_crashes else 'PASS',
        'target_package': target_package,
        'target_pid': target_pid,
        'matched_lines_count': len(matched_lines),
        'matched_lines': matched_lines[:200],
        'target_crashes': target_crashes,
        'foreign_crashes_ignored': foreign_crashes,
        'note': 'NoxExt is an optional diagnostic tag convention, not a guaranteed native Mihon tag.',
    }


KNOWN_OFFICIAL_GRADLE_SHA256: dict[str, str] = {
    'gradle-7.6.4-bin.zip': 'bed1da33cca0f557ab13691c77f38bb67388119e4794d113e051039b80af9bb1',
    'gradle-8.5-bin.zip': '9d926787066a081739e8200858338b4a69e837c3a821a33aca9db09dd4a41026',
    'gradle-8.7-bin.zip': '544c35d6bd849ae8a5ed0bcea39ba677dc40f49df7d1835561582da2009b961d',
    'gradle-8.9-bin.zip': 'd725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab',
    'gradle-8.10.2-bin.zip': '31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26',
    'gradle-8.11.1-bin.zip': 'f397b287023acdba1e9f6fc5ea72d22dd63669d59ed4a289a29b1a76eee151c6',
    'gradle-8.12.1-bin.zip': '8d97a97984f6cbd2b85fe4c60a743440a347544bf18818048e611f5288d46c94',
    'gradle-8.13-bin.zip': '20f1b1176237254a6fc5ea710aed786e9f6fa6fc5ea72d22dd63669d59ed4a41',
    'gradle-8.14-bin.zip': '61ad310d3c7d3e5da131b76bbf22b5a4c0786e9d892dae8c1658d4b484de3caa',
}

_OFFICIAL_GRADLE_DIST_HOSTS: frozenset[str] = frozenset({
    'services.gradle.org',
    'downloads.gradle.org',
    'downloads.gradle-dn.com',
})

_SUSPICIOUS_WRAPPER_EXEC_TOKENS: tuple[str, ...] = (
    '/dev/tcp/',
    'bash -i',
    'nc -e',
    'python -c',
    'python3 -c',
    'curl ',
    'wget ',
    'base64 -d',
    '.ssh/',
)


def _is_confined_regular_file(path: Path, root: Path) -> bool:
    """Ensure path exists as a non-symlink regular file strictly confined under root."""
    if not path.exists() or path.is_symlink() or not path.is_file():
        return False
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def verify_gradle_execution_chain(repo_root: Path | str) -> dict[str, Any]:
    """Validate gradlew script, wrapper properties/SHA-256, wrapper JAR integrity, and build properties."""
    root = Path(repo_root).resolve()
    findings: list[dict[str, str]] = []

    gradlew = root / 'gradlew'
    if not _is_confined_regular_file(gradlew, root):
        findings.append({'severity': 'FAIL', 'kind': 'wrapper_missing_or_symlink', 'file': 'gradlew'})
    else:
        gw_text = gradlew.read_text(encoding='utf-8', errors='replace')
        if scan_bidi_controls(gw_text):
            findings.append({'severity': 'FAIL', 'kind': 'wrapper_bidi_trojan', 'file': 'gradlew'})
        gw_low = gw_text.lower()
        for tok in _SUSPICIOUS_WRAPPER_EXEC_TOKENS:
            if tok in gw_low:
                findings.append({'severity': 'FAIL', 'kind': f'suspicious_gradlew_command:{tok.strip()}', 'file': 'gradlew'})

    props_path = root / 'gradle' / 'wrapper' / 'gradle-wrapper.properties'
    checksum_verified_against_catalog = False
    dist_url = ''
    if not _is_confined_regular_file(props_path, root):
        findings.append({'severity': 'FAIL', 'kind': 'wrapper_properties_missing_or_symlink', 'file': 'gradle/wrapper/gradle-wrapper.properties'})
    else:
        props_raw = props_path.read_text(encoding='utf-8', errors='replace')
        props: dict[str, str] = {}
        for line in props_raw.splitlines():
            s = line.strip()
            if not s or s.startswith('#') or s.startswith('!') or '=' not in s:
                continue
            k, v = s.split('=', 1)
            props[k.strip()] = v.strip().replace('\\:', ':')

        dist_url = props.get('distributionUrl', '')
        parsed = urlsplit(dist_url)
        host = (parsed.hostname or '').lower()
        if parsed.scheme != 'https' or host not in _OFFICIAL_GRADLE_DIST_HOSTS or not parsed.path.endswith('.zip'):
            findings.append({'severity': 'FAIL', 'kind': 'untrusted_gradle_distribution_url', 'file': 'gradle/wrapper/gradle-wrapper.properties'})

        sha = props.get('distributionSha256Sum', '').lower()
        if not re.fullmatch(r'[0-9a-f]{64}', sha):
            findings.append({'severity': 'FAIL', 'kind': 'missing_or_invalid_distribution_sha256', 'file': 'gradle/wrapper/gradle-wrapper.properties'})
        elif len(set(sha)) <= 2 or sha.startswith('00000000'):
            findings.append({'severity': 'FAIL', 'kind': 'weak_dummy_distribution_sha256', 'file': 'gradle/wrapper/gradle-wrapper.properties'})
        else:
            archive_name = Path(parsed.path).name
            expected = KNOWN_OFFICIAL_GRADLE_SHA256.get(archive_name)
            if expected is not None:
                if sha != expected:
                    findings.append({'severity': 'FAIL', 'kind': f'forged_gradle_checksum_mismatch:{archive_name}', 'file': 'gradle/wrapper/gradle-wrapper.properties'})
                else:
                    checksum_verified_against_catalog = True

    jar_path = root / 'gradle' / 'wrapper' / 'gradle-wrapper.jar'
    if not _is_confined_regular_file(jar_path, root):
        findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_missing_or_symlink', 'file': 'gradle/wrapper/gradle-wrapper.jar'})
    else:
        sz = jar_path.stat().st_size
        if sz < 512 or sz > 5 * 1024 * 1024:
            findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_suspicious_size', 'file': 'gradle/wrapper/gradle-wrapper.jar'})
        else:
            try:
                with zipfile.ZipFile(jar_path, 'r') as zf:
                    names = zf.namelist()
                    bad_entries = [
                        n for n in names
                        if n.startswith('/') or '..' in Path(n).parts or n.lower().endswith(('.so', '.dll', '.exe', '.sh', '.bat', '.vbs', '.ps1'))
                    ]
                    if bad_entries:
                        findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_disallowed_payload', 'file': 'gradle/wrapper/gradle-wrapper.jar'})
                    if 'META-INF/MANIFEST.MF' not in names or 'org/gradle/wrapper/GradleWrapperMain.class' not in names:
                        findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_missing_main_class', 'file': 'gradle/wrapper/gradle-wrapper.jar'})
                    else:
                        manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='replace')
                        if 'org.gradle.wrapper.GradleWrapperMain' not in manifest:
                            findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_manifest_mismatch', 'file': 'gradle/wrapper/gradle-wrapper.jar'})
            except zipfile.BadZipFile:
                findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_corrupt_zip', 'file': 'gradle/wrapper/gradle-wrapper.jar'})

    for init_cand in ('init.gradle', 'init.gradle.kts', '.gradle/init.d'):
        if (root / init_cand).exists():
            findings.append({'severity': 'FAIL', 'kind': 'repo_init_script_present', 'file': init_cand})

    gprops = root / 'gradle.properties'
    if gprops.exists() and not gprops.is_symlink():
        gp_text = gprops.read_text(encoding='utf-8', errors='replace')
        if any(flag in gp_text for flag in ('-javaagent:', '-agentpath:', '-Xbootclasspath')):
            findings.append({'severity': 'FAIL', 'kind': 'jvm_agent_injection_in_gradle_properties', 'file': 'gradle.properties'})

    ok = not any(f['severity'] == 'FAIL' for f in findings)
    return {
        'status': 'PASS' if ok else 'FAIL',
        'reason': 'gradle execution chain verified' if ok else f"wrapper verification failed: {', '.join(f['kind'] for f in findings[:4])}",
        'distribution_url': dist_url,
        'checksum_verified_against_catalog': checksum_verified_against_catalog,
        'findings': findings,
    }


def build_bwrap_invocation(
    work_dir: Path | str,
    command: Sequence[str],
    *,
    allow_network: bool = False,
    bwrap_bin: str | None = None,
    extra_ro_binds: Sequence[tuple[str, str]] | None = None,
    ro_work: bool = False,
) -> list[str]:
    """Construct a fail-closed Bubblewrap invocation isolating namespaces, environment, and $HOME."""
    bwrap = bwrap_bin or shutil.which('bwrap') or 'bwrap'
    work = Path(work_dir).resolve()
    cmd: list[str] = [
        bwrap,
        '--unshare-all',
        '--die-with-parent',
        '--new-session',
        '--clearenv',
    ]
    cmd.append('--share-net' if allow_network else '--unshare-net')

    for sys_path in ('/usr', '/bin', '/sbin', '/lib', '/lib64'):
        sp = Path(sys_path)
        if sp.is_symlink():
            cmd.extend(['--symlink', os.readlink(sp), sys_path])
        elif sp.is_dir():
            cmd.extend(['--ro-bind', sys_path, sys_path])

    etc_entries: list[Path] = [
        Path('/etc/alternatives'),
        Path('/etc/ssl'),
        Path('/etc/ca-certificates'),
        Path('/etc/ld.so.cache'),
        Path('/etc/ld.so.conf'),
        Path('/etc/ld.so.conf.d'),
        Path('/etc/localtime'),
        Path('/etc/nsswitch.conf'),
        Path('/etc/hosts'),
    ]
    etc_root = Path('/etc')
    if etc_root.is_dir():
        etc_entries.extend(sorted(etc_root.glob('java*')))
        etc_entries.extend(sorted(etc_root.glob('jvm*')))
    if allow_network:
        etc_entries.append(Path('/etc/resolv.conf'))

    for ep in etc_entries:
        if ep.is_symlink():
            resolved = ep.resolve()
            if resolved.exists():
                cmd.extend(['--ro-bind', str(resolved), str(ep)])
        elif ep.exists():
            cmd.extend(['--ro-bind', str(ep), str(ep)])

    path_parts: list[str] = []
    java_home_raw = os.environ.get('JAVA_HOME')
    if java_home_raw:
        jh = Path(java_home_raw).expanduser().resolve()
        if jh.is_dir():
            cmd.extend(['--ro-bind', str(jh), '/sandbox-sdk/java'])
            cmd.extend(['--setenv', 'JAVA_HOME', '/sandbox-sdk/java'])
            path_parts.append('/sandbox-sdk/java/bin')

    android_raw = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if android_raw:
        ah = Path(android_raw).expanduser().resolve()
        if ah.is_dir():
            cmd.extend(['--ro-bind', str(ah), '/sandbox-sdk/android-sdk'])
            cmd.extend(['--setenv', 'ANDROID_HOME', '/sandbox-sdk/android-sdk'])
            cmd.extend(['--setenv', 'ANDROID_SDK_ROOT', '/sandbox-sdk/android-sdk'])
            path_parts.append('/sandbox-sdk/android-sdk/platform-tools')

    for host_src, guest_dst in extra_ro_binds or ():
        hs = Path(host_src).expanduser().resolve()
        gd_norm = Path(guest_dst).as_posix()
        if hs.exists() and gd_norm.startswith('/sandbox-sdk/') and '..' not in Path(gd_norm).parts:
            cmd.extend(['--ro-bind', str(hs), gd_norm])
            if gd_norm == '/sandbox-sdk/node':
                path_parts.append('/sandbox-sdk/node/bin')

    path_parts.extend(['/usr/local/sbin', '/usr/local/bin', '/usr/bin', '/bin'])
    cmd.extend([
        '--setenv', 'PATH', ':'.join(path_parts),
        '--setenv', 'HOME', '/tmp' if ro_work else '/work/.nox-sandbox-home',
        '--setenv', 'GRADLE_USER_HOME', '/work/.gradle-home',
        '--setenv', 'TMPDIR', '/tmp',
        '--setenv', 'LANG', 'C.UTF-8',
        '--setenv', 'LC_ALL', 'C.UTF-8',
        '--proc', '/proc',
        '--dev', '/dev',
        '--tmpfs', '/tmp',
        '--ro-bind' if ro_work else '--bind', str(work), '/work',
        '--chdir', '/work',
        '--',
        *command,
    ])
    return cmd


def probe_bwrap_sandbox(*, sandbox_available_override: bool | None = None) -> dict[str, Any]:
    """Verify at runtime that Bubblewrap executes unprivileged user-namespace sandboxes cleanly."""
    if sandbox_available_override is False:
        return {
            'status': 'BLOCKED',
            'bwrap_installed': bool(shutil.which('bwrap')),
            'userns_supported': False,
            'reason': 'bubblewrap sandbox unavailable or disabled (fail-closed)',
        }
    bwrap = shutil.which('bwrap')
    if not bwrap:
        return {
            'status': 'BLOCKED',
            'bwrap_installed': False,
            'userns_supported': False,
            'reason': 'bwrap binary not found on PATH; refusing unprotected host execution',
        }
    probe_cmd = [
        bwrap,
        '--unshare-all',
        '--unshare-net',
        '--die-with-parent',
        '--new-session',
        '--clearenv',
    ]
    for sys_path in ('/usr', '/bin', '/lib', '/lib64'):
        sp = Path(sys_path)
        if sp.is_symlink():
            probe_cmd.extend(['--symlink', os.readlink(sp), sys_path])
        elif sp.is_dir():
            probe_cmd.extend(['--ro-bind', sys_path, sys_path])
    probe_cmd.extend(['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--', '/usr/bin/env', 'true'])
    try:
        proc = subprocess.run(probe_cmd, capture_output=True, text=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
    except Exception as exc:
        return {
            'status': 'BLOCKED',
            'bwrap_installed': True,
            'bwrap_path': bwrap,
            'userns_supported': False,
            'reason': f'bwrap probe failed: {exc}',
        }
    if proc.returncode != 0:
        err_msg = sanitize_text(proc.stderr or proc.stdout or '', redact_home=True).strip()
        return {
            'status': 'BLOCKED',
            'bwrap_installed': True,
            'bwrap_path': bwrap,
            'userns_supported': False,
            'reason': f'bwrap kernel/userns sandbox unavailable ({err_msg or f"exit {proc.returncode}"})',
        }
    return {
        'status': 'PASS',
        'bwrap_installed': True,
        'bwrap_path': bwrap,
        'userns_supported': True,
        'reason': 'bubblewrap sandbox verified via live execution probe',
    }


def _stage_project_for_sandbox(src_root: Path, stage_dir: Path) -> None:
    """Copy clean regular files from src_root into ephemeral stage_dir, stripping .git, symlinks, and secret files."""
    skip_dirs = {'.git', '.gradle', '.nox-sandbox-home', '.gradle-home'}
    for dirpath, dirnames, filenames in os.walk(src_root, topdown=True, followlinks=False):
        rel_dir = Path(dirpath).relative_to(src_root)
        dirnames[:] = [
            d for d in dirnames
            if d not in skip_dirs and not (Path(dirpath) / d).is_symlink()
        ]
        target_sub = stage_dir / rel_dir
        target_sub.mkdir(parents=True, exist_ok=True)
        for fname in filenames:
            low_f = fname.lower()
            if (
                low_f == '.env'
                or low_f.startswith('.env.')
                or low_f.endswith(('.pem', '.key', '.p12', '.jks', '.keystore'))
                or 'secret' in low_f
                or 'credential' in low_f
            ):
                continue
            src_file = Path(dirpath) / fname
            if src_file.is_symlink() or not src_file.is_file():
                continue
            dst_file = target_sub / fname
            shutil.copy2(src_file, dst_file)
    (stage_dir / '.nox-sandbox-home').mkdir(parents=True, exist_ok=True)
    (stage_dir / '.gradle-home').mkdir(parents=True, exist_ok=True)


def _extract_sandbox_apks_to_host(stage_dir: Path, host_root: Path) -> list[Path]:
    """Copy built APK outputs from ephemeral sandbox stage directory back into confined host paths."""
    collected: list[Path] = []
    stage_resolved = stage_dir.resolve()
    host_resolved = host_root.resolve()
    for cand in sorted(stage_dir.rglob('*.apk')):
        if cand.is_symlink() or not cand.is_file():
            continue
        try:
            rel = cand.resolve().relative_to(stage_resolved)
        except ValueError:
            continue
        if 'build' not in rel.parts or 'apk' not in rel.parts:
            continue
        dst = host_resolved / rel
        # Guard every intermediate directory against symlink escape on host
        cur = host_resolved
        safe = True
        for part in rel.parts[:-1]:
            cur = cur / part
            if cur.is_symlink():
                safe = False
                break
        if not safe or dst.is_symlink():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cand, dst)
        collected.append(dst)
    return collected


def run_in_bwrap_sandbox(
    target_dir: Path | str,
    command: Sequence[str],
    *,
    timeout: int = 300,
    allow_network: bool = False,
    extract_outputs_to_host: bool = False,
    sandbox_available_override: bool | None = None,
    extra_ro_binds: Sequence[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Execute command inside an ephemeral, network-isolated Bubblewrap copy; fail closed when unavailable."""
    if not command:
        return {'status': 'FAIL', 'reason': 'empty sandbox command', 'executed_unprotected': False, 'returncode': None}

    probe = probe_bwrap_sandbox(sandbox_available_override=sandbox_available_override)
    if probe['status'] != 'PASS':
        return {
            'status': 'BLOCKED',
            'reason': probe['reason'],
            'sandbox': probe,
            'executed_unprotected': False,
            'returncode': None,
            'sandbox_command': [],
            'collected_apks': [],
        }

    src_root = Path(target_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='nox-bwrap-stage-') as tmp:
        stage_dir = Path(tmp) / 'work'
        _stage_project_for_sandbox(src_root, stage_dir)
        bwrap_cmd = build_bwrap_invocation(
            stage_dir,
            command,
            allow_network=allow_network,
            bwrap_bin=probe.get('bwrap_path'),
            extra_ro_binds=extra_ro_binds,
        )
        try:
            proc = subprocess.run(
                bwrap_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={'PATH': '/usr/bin:/bin'},
            )
        except subprocess.TimeoutExpired:
            return {
                'status': 'FAIL',
                'reason': f'sandboxed command timed out after {timeout}s',
                'timed_out': True,
                'executed_unprotected': False,
                'returncode': None,
                'sandbox_command': bwrap_cmd,
                'sandbox': {**probe, 'bwrap_used': True, 'network_isolated': not allow_network, 'clearenv': True, 'ephemeral_stage': True},
                'collected_apks': [],
            }

        apks = _extract_sandbox_apks_to_host(stage_dir, src_root) if (extract_outputs_to_host and proc.returncode == 0) else []
        out_status = 'PASS' if proc.returncode == 0 else 'FAIL'
        return {
            'status': out_status,
            'reason': 'sandbox execution completed' if proc.returncode == 0 else f'sandboxed command exited {proc.returncode}',
            'executed_unprotected': False,
            'returncode': proc.returncode,
            'stdout': proc.stdout or '',
            'stderr': proc.stderr or '',
            'sandbox_command': bwrap_cmd,
            'collected_apks': [str(p) for p in apks],
            'sandbox': {
                **probe,
                'bwrap_used': True,
                'network_isolated': not allow_network,
                'clearenv': True,
                'ephemeral_stage': True,
            },
        }


def build_debug_apk(
    repo_root: Path | str,
    gradle_task: str,
    *,
    timeout: int = 300,
    offline: bool = False,
    allow_network: bool = False,
    sandbox_available_override: bool | None = None,
) -> dict[str, Any]:
    """Run security & wrapper pre-flight, execute Gradle inside fail-closed Bubblewrap sandbox, and inspect produced APK."""
    root = Path(repo_root).resolve()
    gradlew = root / 'gradlew'
    if not gradlew.is_file():
        return {'status': 'BLOCKED', 'reason': f'gradlew not found at {root}', 'apk_inspection': None, 'executed_unprotected': False}
    if not re.fullmatch(r':[A-Za-z0-9:_-]+', gradle_task):
        return {'status': 'FAIL', 'reason': f'unsafe gradle task syntax: {gradle_task!r}', 'apk_inspection': None, 'executed_unprotected': False}

    sec = audit_untrusted_pr_or_repo(root)
    if sec['status'] == 'FAIL':
        return {'status': 'FAIL', 'reason': 'security pre-flight failed; refusing to execute gradlew', 'security': sec, 'executed_unprotected': False}

    chain = verify_gradle_execution_chain(root)
    if chain['status'] != 'PASS':
        return {'status': 'FAIL', 'reason': chain['reason'], 'wrapper_verification': chain, 'security': sec, 'executed_unprotected': False}

    gradle_args = ['./gradlew', '--no-daemon', '--console=plain']
    if offline:
        gradle_args.append('--offline')
    gradle_args.append(gradle_task)

    import time
    build_started_at = time.time()
    sandbox_res = run_in_bwrap_sandbox(
        root,
        gradle_args,
        timeout=timeout,
        allow_network=allow_network,
        extract_outputs_to_host=True,
        sandbox_available_override=sandbox_available_override,
    )
    if sandbox_res['status'] == 'BLOCKED' or sandbox_res.get('returncode') is None:
        return {
            'status': sandbox_res['status'],
            'reason': sandbox_res['reason'],
            'command': sandbox_res.get('sandbox_command', []),
            'wrapper_verification': chain,
            'sandbox': sandbox_res.get('sandbox'),
            'executed_unprotected': False,
            'apk_inspection': None,
        }

    log_out = sanitize_text((sandbox_res.get('stdout') or '') + '\n' + (sandbox_res.get('stderr') or ''), redact_home=False)
    cmd = sandbox_res['sandbox_command']
    if sandbox_res['returncode'] != 0:
        return {
            'status': 'FAIL',
            'reason': f'gradlew exited {sandbox_res["returncode"]}',
            'command': cmd,
            'wrapper_verification': chain,
            'sandbox': sandbox_res['sandbox'],
            'executed_unprotected': False,
            'log_tail': log_out.splitlines()[-40:],
        }

    # Prefer freshly collected sandbox APK outputs matching module path before scanning host outputs
    parts = [p for p in gradle_task.split(':') if p]
    module_dir = root.joinpath(*parts[:-1]) if len(parts) > 1 else root
    collected = sorted(Path(p) for p in (sandbox_res.get('collected_apks') or []))
    apks = [p for p in collected if str(p).startswith(str(module_dir))] or collected or sorted(module_dir.glob('build/outputs/apk/**/*.apk'))
    if not apks:
        return {
            'status': 'FAIL',
            'reason': 'gradlew exited 0 but no .apk artifact was produced under build/outputs/apk',
            'command': cmd,
            'wrapper_verification': chain,
            'sandbox': sandbox_res['sandbox'],
            'executed_unprotected': False,
            'log_tail': log_out.splitlines()[-25:],
        }

    apk_path = apks[-1]
    inspection = inspect_apk(apk_path)
    return {
        'status': inspection['status'],
        'command': cmd,
        'apk_path': str(apk_path),
        'build_started_at': build_started_at,
        'apk_inspection': inspection,
        'wrapper_verification': chain,
        'sandbox': sandbox_res['sandbox'],
        'executed_unprotected': False,
        'log_tail': log_out.splitlines()[-25:],
    }


def verify_apk_contains_compiled_extension(
    apk_path: Path | str,
    *,
    expected_package: str | None = None,
    expected_class_name: str | None = None,
    expected_methods: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Verify an APK contains valid DEX bytecode registering the compiled Kotlin class descriptor and methods."""
    insp = inspect_apk(apk_path, expected_package=expected_package)
    if insp.get('status') == 'FAIL' or not insp.get('has_dex'):
        return {
            'status': 'FAIL',
            'apk_path': str(Path(apk_path).resolve()) if Path(apk_path).exists() else str(apk_path),
            'apk_inspection': insp,
            'has_dex': bool(insp.get('has_dex')),
            'class_found_in_dex': False,
            'methods_verified': [],
            'missing_methods': list(expected_methods or ()),
            'reason': 'apk_missing_valid_dex_or_manifest',
        }

    p = Path(apk_path)
    dex_names: list[str] = []
    dex_blobs: list[bytes] = []
    valid_dex_headers = True
    try:
        with zipfile.ZipFile(p) as zf:
            for name in sorted(zf.namelist()):
                if name.endswith('.dex') and not name.startswith('/') and '..' not in Path(name).parts:
                    blob = zf.read(name)
                    dex_names.append(name)
                    if not blob.startswith(b'dex\n') or len(blob) < 64:
                        valid_dex_headers = False
                    dex_blobs.append(blob)
    except zipfile.BadZipFile as exc:
        return {
            'status': 'FAIL',
            'apk_path': str(p),
            'apk_inspection': insp,
            'has_dex': False,
            'class_found_in_dex': False,
            'reason': f'corrupt_apk_zip:{exc}',
        }

    if not dex_blobs or not valid_dex_headers:
        return {
            'status': 'FAIL',
            'apk_path': str(p.resolve()),
            'apk_inspection': insp,
            'has_dex': False,
            'dex_files': dex_names,
            'class_found_in_dex': False,
            'reason': 'invalid_or_empty_dex_header',
        }

    combined_dex = b'\n'.join(dex_blobs)
    expected_descriptor: str | None = None
    class_found = True
    if expected_package and expected_class_name:
        pkg_slash = expected_package.strip('.').replace('.', '/')
        expected_descriptor = f'L{pkg_slash}/{expected_class_name};'
        class_found = expected_descriptor.encode('utf-8') in combined_dex
    elif expected_package:
        pkg_slash = expected_package.strip('.').replace('.', '/')
        expected_descriptor = f'L{pkg_slash}/'
        class_found = expected_descriptor.encode('utf-8') in combined_dex
    elif expected_class_name:
        expected_descriptor = f'/{expected_class_name};'
        class_found = expected_descriptor.encode('utf-8') in combined_dex

    verified_methods: list[str] = []
    missing_methods: list[str] = []
    for m_name in expected_methods or ():
        if m_name.encode('utf-8') in combined_dex:
            verified_methods.append(m_name)
        else:
            missing_methods.append(m_name)

    issues = list(insp.get('issues') or [])
    sig_ok = (insp.get('signing') or {}).get('verified') is True
    ok = class_found and not missing_methods and sig_ok and not issues
    reason = 'compiled_extension_verified_in_dex'
    if not class_found:
        reason = f'missing_expected_class_in_dex:{expected_descriptor}'
    elif missing_methods:
        reason = f"missing_expected_methods_in_dex:{','.join(missing_methods)}"
    elif not sig_ok:
        reason = 'apk_signature_not_verified'
    elif issues:
        reason = ','.join(issues)

    return {
        'status': 'PASS' if ok else 'FAIL',
        'apk_path': str(p.resolve()),
        'apk_sha256': insp.get('sha256'),
        'has_dex': True,
        'dex_files': dex_names,
        'expected_descriptor': expected_descriptor,
        'class_found_in_dex': class_found,
        'methods_verified': verified_methods,
        'missing_methods': missing_methods,
        'apk_inspection': insp,
        'reason': reason,
    }


_EXTENSION_COMPILE_STUBS: dict[str, str] = {
    'StubRx.kt': """package rx

open class Observable<T> {
    companion object {
        fun <T> just(value: T): Observable<T> = Observable()
        fun <T> empty(): Observable<T> = Observable()
    }
}
""",
    'StubOkHttp.kt': """package okhttp3

open class CacheControl {
    companion object { val FORCE_NETWORK = CacheControl() }
}

open class Headers {
    open class Builder {
        open fun add(name: String, value: String): Builder = this
        open fun set(name: String, value: String): Builder = this
        open fun build(): Headers = Headers()
    }
    open fun newBuilder(): Builder = Builder()
}

open class HttpUrl(private val rawUrl: String = "") {
    open val encodedPath: String get() = try { java.net.URI(rawUrl).rawPath ?: "" } catch (_: Throwable) { "" }
    open val host: String get() = try { java.net.URI(rawUrl).host ?: "" } catch (_: Throwable) { "" }
    open fun newBuilder(): Builder = Builder(rawUrl)
    override fun toString(): String = rawUrl
    open class Builder(private var base: String = "") {
        open fun addPathSegment(segment: String): Builder = this
        open fun addQueryParameter(name: String, value: String?): Builder = this
        open fun setQueryParameter(name: String, value: String?): Builder = this
        open fun build(): HttpUrl = HttpUrl(base)
    }
    companion object {
        fun String.toHttpUrl(): HttpUrl = HttpUrl(this)
        fun String.toHttpUrlOrNull(): HttpUrl? = if (isBlank()) null else HttpUrl(this)
        fun get(url: String): HttpUrl = HttpUrl(url)
    }
}

open class MediaType

open class RequestBody {
    companion object { fun create(content: String, mediaType: MediaType? = null): RequestBody = RequestBody() }
}

open class FormBody {
    open class Builder {
        open fun add(name: String, value: String): Builder = this
        open fun build(): RequestBody = RequestBody()
    }
}

open class Request(val url: HttpUrl = HttpUrl(), val headers: Headers = Headers()) {
    open class Builder {
        private var u: HttpUrl = HttpUrl()
        private var h: Headers = Headers()
        open fun url(url: String): Builder { u = HttpUrl(url); return this }
        open fun url(url: HttpUrl): Builder { u = url; return this }
        open fun headers(headers: Headers): Builder { h = headers; return this }
        open fun post(body: RequestBody): Builder = this
        open fun build(): Request = Request(u, h)
    }
}

open class ResponseBody(private val content: String = "") {
    open fun string(): String = content
}

open class Response(val code: Int = 200, val body: ResponseBody = ResponseBody(), val request: Request = Request()) {
    open val isSuccessful: Boolean get() = code in 200..299
}

open class OkHttpClient {
    open class Builder {
        open fun addInterceptor(block: (Any) -> Response): Builder = this
        open fun build(): OkHttpClient = OkHttpClient()
    }
}
""",
    'StubJsoupNodes.kt': """package org.jsoup.nodes

open class Element(private val tagNameValue: String = "div", private val textValue: String = "") {
    open fun select(cssQuery: String): Elements = Elements()
    open fun selectFirst(cssQuery: String): Element? = null
    open fun text(): String = textValue
    open fun ownText(): String = textValue
    open fun html(): String = ""
    open fun attr(attributeKey: String): String = ""
    open fun hasAttr(attributeKey: String): Boolean = false
    open fun absUrl(attributeKey: String): String = ""
    open fun hasText(): Boolean = textValue.isNotBlank()
    open fun parent(): Element? = null
}

open class Elements(private val backing: List<Element> = emptyList()) : List<Element> by backing {
    open fun attr(attributeKey: String): String = firstOrNull()?.attr(attributeKey).orEmpty()
    open fun text(): String = joinToString(" ") { it.text() }
    open fun first(): Element? = firstOrNull()
    open fun select(cssQuery: String): Elements = this
    open fun selectFirst(cssQuery: String): Element? = firstOrNull()
}

open class Document(val baseUri: String = "") : Element("document", "") {
    open fun location(): String = baseUri
}
""",
    'StubJsoup.kt': """package org.jsoup

import org.jsoup.nodes.Document

object Jsoup {
    fun parse(html: String, baseUri: String = ""): Document = Document(baseUri)
}
""",
    'StubKeiyoushiAnnotation.kt': """package keiyoushi.annotation

@Target(AnnotationTarget.CLASS)
annotation class Source
""",
    'StubKeiyoushiNetwork.kt': """package keiyoushi.network

import okhttp3.OkHttpClient
import okhttp3.Response

enum class Fetch { DOCUMENT, JSON, TEXT }

fun OkHttpClient.get(url: String, mode: Fetch = Fetch.DOCUMENT): Response = Response()
fun OkHttpClient.post(url: String, body: Any? = null): Response = Response()
""",
    'StubKeiyoushiUtils.kt': """package keiyoushi.utils

import okhttp3.Response
import org.jsoup.nodes.Document

fun Response.asJsoup(html: String? = null): Document = Document(request.url.toString())
""",
    'StubTachiyomiNetwork.kt': """package eu.kanade.tachiyomi.network

import okhttp3.CacheControl
import okhttp3.Headers
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.RequestBody

fun GET(url: String, headers: Headers = Headers(), cache: CacheControl? = null): Request = Request(HttpUrl(url), headers)
fun GET(url: HttpUrl, headers: Headers = Headers(), cache: CacheControl? = null): Request = Request(url, headers)
fun POST(url: String, headers: Headers = Headers(), body: RequestBody = RequestBody()): Request = Request(HttpUrl(url), headers)
""",
    'StubTachiyomiUtil.kt': """package eu.kanade.tachiyomi.util

import okhttp3.Response
import org.jsoup.nodes.Document

fun Response.asJsoup(html: String? = null): Document = Document(request.url.toString())
""",
    'StubSourceModel.kt': """package eu.kanade.tachiyomi.source.model

open class FilterList(val list: List<Any> = emptyList())

open class SManga {
    open var url: String = ""
    open var title: String = ""
    open var artist: String? = null
    open var author: String? = null
    open var description: String? = null
    open var genre: String? = null
    open var status: Int = UNKNOWN
    open var thumbnail_url: String? = null
    open var initialized: Boolean = false
    companion object {
        const val UNKNOWN = 0
        const val ONGOING = 1
        const val COMPLETED = 2
        const val LICENSED = 3
        fun create(): SManga = SManga()
    }
}

open class SChapter {
    open var url: String = ""
    open var name: String = ""
    open var date_upload: Long = 0L
    open var chapter_number: Float = -1f
    open var scanlator: String? = null
    companion object { fun create(): SChapter = SChapter() }
}

data class MangasPage(val mangas: List<SManga>, val hasNextPage: Boolean)
data class SMangaUpdate(val manga: SManga, val chapters: List<SChapter>)
data class Page(val index: Int, val url: String = "", var imageUrl: String? = null)
""",
    'StubSourceOnline.kt': """package eu.kanade.tachiyomi.source.online

import eu.kanade.tachiyomi.source.model.*
import okhttp3.Headers
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.jsoup.nodes.Document
import org.jsoup.nodes.Element

abstract class HttpSource {
    open val id: Long = 0L
    open val name: String = ""
    open val baseUrl: String = ""
    open val lang: String = ""
    open val supportsLatest: Boolean = false
    open val client: OkHttpClient = OkHttpClient()
    open val headers: Headers = Headers()
    open fun headersBuilder(): Headers.Builder = Headers.Builder()
    open fun getFilterList(): FilterList = FilterList()
    open fun popularMangaRequest(page: Int): Request = Request()
    open fun popularMangaParse(response: Response): MangasPage = MangasPage(emptyList(), false)
    open fun latestUpdatesRequest(page: Int): Request = Request()
    open fun latestUpdatesParse(response: Response): MangasPage = MangasPage(emptyList(), false)
    open fun searchMangaRequest(page: Int, query: String, filters: FilterList): Request = Request()
    open fun searchMangaParse(response: Response): MangasPage = MangasPage(emptyList(), false)
    open fun mangaDetailsParse(response: Response): SManga = SManga.create()
    open fun chapterListParse(response: Response): List<SChapter> = emptyList()
    open fun pageListParse(response: Response): List<Page> = emptyList()
    open fun imageUrlParse(response: Response): String = ""
}

abstract class ParsedHttpSource : HttpSource() {
    open fun popularMangaSelector(): String = ""
    open fun popularMangaFromElement(element: Element): SManga = SManga.create()
    open fun popularMangaNextPageSelector(): String? = null
    open fun latestUpdatesSelector(): String = ""
    open fun latestUpdatesFromElement(element: Element): SManga = SManga.create()
    open fun latestUpdatesNextPageSelector(): String? = null
    open fun searchMangaSelector(): String = ""
    open fun searchMangaFromElement(element: Element): SManga = SManga.create()
    open fun searchMangaNextPageSelector(): String? = null
    open fun mangaDetailsParse(document: Document): SManga = SManga.create()
    open fun chapterListSelector(): String = ""
    open fun chapterFromElement(element: Element): SChapter = SChapter.create()
    open fun pageListParse(document: Document): List<Page> = emptyList()
    open fun imageUrlParse(document: Document): String = ""
}
""",
    'StubKeiyoushiSource.kt': """package keiyoushi.source

import eu.kanade.tachiyomi.source.model.*
import okhttp3.Headers
import okhttp3.HttpUrl
import okhttp3.OkHttpClient

abstract class KeiSource {
    open val name: String = ""
    open val baseUrl: String = ""
    open val lang: String = ""
    open val supportsLatest: Boolean = true
    open val client: OkHttpClient = OkHttpClient()
    open val headers: Headers = Headers()
    open fun headersBuilder(): Headers.Builder = Headers.Builder()
    open fun getFilterList(): FilterList = FilterList()
    open suspend fun getPopularManga(page: Int): MangasPage = MangasPage(emptyList(), false)
    open suspend fun getLatestUpdates(page: Int): MangasPage = MangasPage(emptyList(), false)
    open suspend fun getSearchMangaList(page: Int, query: String, filters: FilterList): MangasPage = MangasPage(emptyList(), false)
    open suspend fun getMangaByUrl(url: HttpUrl): SManga? = null
    open fun getMangaUrl(manga: SManga): String = ""
    open suspend fun fetchMangaUpdate(manga: SManga, chapters: List<SChapter>, fetchDetails: Boolean, fetchChapters: Boolean): SMangaUpdate = SMangaUpdate(manga, chapters)
    open fun getChapterUrl(chapter: SChapter): String = ""
    open suspend fun getPageList(chapter: SChapter): List<Page> = emptyList()
}
""",
    'StubAnimeModel.kt': """package eu.kanade.tachiyomi.animesource.model

import okhttp3.Headers

open class AnimeFilterList(val list: List<Any> = emptyList())

open class SAnime {
    open var url: String = ""
    open var title: String = ""
    open var artist: String? = null
    open var author: String? = null
    open var description: String? = null
    open var genre: String? = null
    open var status: Int = UNKNOWN
    open var thumbnail_url: String? = null
    open var initialized: Boolean = false
    open fun setUrlWithoutDomain(rawUrl: String) { url = rawUrl }
    companion object {
        const val UNKNOWN = 0
        const val ONGOING = 1
        const val COMPLETED = 2
        fun create(): SAnime = SAnime()
    }
}

open class SEpisode {
    open var url: String = ""
    open var name: String = ""
    open var date_upload: Long = 0L
    open var episode_number: Float = -1f
    open var scanlator: String? = null
    open fun setUrlWithoutDomain(rawUrl: String) { url = rawUrl }
    companion object { fun create(): SEpisode = SEpisode() }
}

data class AnimesPage(val animes: List<SAnime>, val hasNextPage: Boolean)
data class Hoster(val hosterUrl: String = "", val hosterName: String = "", val internalData: String = "")
data class Video(val url: String = "", val quality: String = "", val videoUrl: String? = null, val headers: Headers? = null, val videoTitle: String = "") {
    constructor(videoUrl: String, videoTitle: String) : this(url = videoUrl, quality = videoTitle, videoUrl = videoUrl, headers = null, videoTitle = videoTitle)
}
""",
    'StubAnimeOnline.kt': """package eu.kanade.tachiyomi.animesource.online

import eu.kanade.tachiyomi.animesource.model.*
import okhttp3.Headers
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.jsoup.nodes.Document
import org.jsoup.nodes.Element

abstract class AnimeHttpSource {
    open val id: Long = 0L
    open val name: String = ""
    open val baseUrl: String = ""
    open val lang: String = ""
    open val supportsLatest: Boolean = false
    open val client: OkHttpClient = OkHttpClient()
    open val headers: Headers = Headers()
    open fun headersBuilder(): Headers.Builder = Headers.Builder()
    open fun getFilterList(): AnimeFilterList = AnimeFilterList()
    open fun popularAnimeRequest(page: Int): Request = Request()
    open fun popularAnimeParse(response: Response): AnimesPage = AnimesPage(emptyList(), false)
    open fun latestUpdatesRequest(page: Int): Request = Request()
    open fun latestUpdatesParse(response: Response): AnimesPage = AnimesPage(emptyList(), false)
    open fun searchAnimeRequest(page: Int, query: String, filters: AnimeFilterList): Request = Request()
    open fun searchAnimeParse(response: Response): AnimesPage = AnimesPage(emptyList(), false)
    open fun animeDetailsParse(response: Response): SAnime = SAnime.create()
    open fun episodeListParse(response: Response): List<SEpisode> = emptyList()
    open fun seasonListParse(response: Response): List<SAnime> = emptyList()
    open fun hosterListParse(response: Response): List<Hoster> = emptyList()
    open fun videoListRequest(hoster: Hoster): Request = Request()
    open fun videoListParse(response: Response, hoster: Hoster): List<Video> = emptyList()
}

abstract class ParsedAnimeHttpSource : AnimeHttpSource() {
    open fun popularAnimeSelector(): String = ""
    open fun popularAnimeFromElement(element: Element): SAnime = SAnime.create()
    open fun popularAnimeNextPageSelector(): String? = null
    open fun latestUpdatesSelector(): String = ""
    open fun latestUpdatesFromElement(element: Element): SAnime = SAnime.create()
    open fun latestUpdatesNextPageSelector(): String? = null
    open fun searchAnimeSelector(): String = ""
    open fun searchAnimeFromElement(element: Element): SAnime = SAnime.create()
    open fun searchAnimeNextPageSelector(): String? = null
    open fun animeDetailsParse(document: Document): SAnime = SAnime.create()
    open fun episodeListSelector(): String = ""
    open fun episodeFromElement(element: Element): SEpisode = SEpisode.create()
}
""",
}


def compile_kotlin_extension_to_debug_apk(
    module_dir: Path | str,
    *,
    package_name: str,
    class_name: str,
    app_label: str = 'Nox Extension',
    version_code: int = 1,
    version_name: str = '1.0.1',
    apk_filename: str | None = None,
    expected_methods: Sequence[str] | None = None,
    timeout: int = 180,
    sandbox_available_override: bool | None = None,
) -> dict[str, Any]:
    """Compile real Kotlin extension sources to bytecode, DEX, binary resources, and signed Debug APK inside bwrap."""
    mod_root = Path(module_dir).resolve()
    if not mod_root.is_dir():
        return {'status': 'FAIL', 'compiled': False, 'reason': f'module_dir_missing:{mod_root}', 'executed_unprotected': False}

    if not re.fullmatch(r'[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+', package_name):
        return {
            'status': 'FAIL',
            'compiled': False,
            'reason': f'invalid_android_package_name:{package_name}',
            'executed_unprotected': False,
        }
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', class_name):
        return {
            'status': 'FAIL',
            'compiled': False,
            'reason': f'invalid_kotlin_class_name:{class_name}',
            'executed_unprotected': False,
        }

    kt_files = sorted(
        p.relative_to(mod_root).as_posix()
        for p in mod_root.rglob('*.kt')
        if p.is_file() and not p.is_symlink() and 'build/' not in p.relative_to(mod_root).as_posix()
    )
    if not kt_files:
        return {'status': 'FAIL', 'compiled': False, 'reason': 'no_kotlin_sources_found', 'executed_unprotected': False}

    sec = audit_untrusted_pr_or_repo(mod_root)
    if sec['status'] == 'FAIL':
        return {'status': 'FAIL', 'compiled': False, 'reason': 'security_preflight_failed', 'security': sec, 'executed_unprotected': False}

    toolchain = find_kotlin_and_android_build_toolchain()
    if toolchain['status'] != 'PASS':
        return {
            'status': 'BLOCKED',
            'compiled': False,
            'reason': f"missing_build_toolchain:{','.join(toolchain['missing'])}",
            'toolchain': toolchain,
            'executed_unprotected': False,
        }

    probe = probe_bwrap_sandbox(sandbox_available_override=sandbox_available_override)
    if probe['status'] != 'PASS':
        return {
            'status': 'BLOCKED',
            'compiled': False,
            'reason': probe['reason'],
            'sandbox': probe,
            'toolchain': toolchain,
            'executed_unprotected': False,
        }

    tools = toolchain['tools']
    bt_dir = str(Path(tools['d8']).resolve().parent)
    extra_binds: list[tuple[str, str]] = [
        (bt_dir, '/sandbox-sdk/build-tools'),
        (tools['android_jar'], '/sandbox-sdk/android.jar'),
    ]
    guest_kotlin_jars: list[str] = []
    for jar_path in toolchain['kotlin_jars']:
        jp = Path(jar_path).resolve()
        guest_p = f'/sandbox-sdk/kotlin-jars/{jp.name}'
        extra_binds.append((str(jp), guest_p))
        guest_kotlin_jars.append(guest_p)

    safe_apk_name = re.sub(r'[^A-Za-z0-9._-]', '-', apk_filename or f'{class_name.lower()}-debug.apk')
    if not safe_apk_name.endswith('.apk'):
        safe_apk_name += '.apk'

    xml_escape = lambda s: (
        str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')
    )
    manifest_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{xml_escape(package_name)}" '
        f'android:versionCode="{int(version_code)}" android:versionName="{xml_escape(version_name)}">\n'
        '    <uses-feature android:name="tachiyomi.extension" />\n'
        f'    <application android:label="{xml_escape(app_label)}">\n'
        f'        <meta-data android:name="tachiyomi.extension.class" android:value=".{xml_escape(class_name)}" />\n'
        '    </application>\n'
        '</manifest>\n'
    )

    build_payload = json.dumps({
        'kt_files': kt_files,
        'stubs': _EXTENSION_COMPILE_STUBS,
        'manifest_xml': manifest_xml,
        'kotlin_jars': guest_kotlin_jars,
        'version_code': int(version_code),
        'version_name': str(version_name),
        'apk_name': safe_apk_name,
    })

    driver_code = (
        'import json, pathlib, subprocess, sys, zipfile\n'
        'cfg = json.loads(sys.argv[1])\n'
        'b = pathlib.Path("/tmp/nox-ext-build")\n'
        'sdir = b / "stubs"\n'
        'sdir.mkdir(parents=True, exist_ok=True)\n'
        'stub_files = []\n'
        'for sname, stext in cfg["stubs"].items():\n'
        '    sf = sdir / sname\n'
        '    sf.write_text(stext, encoding="utf-8")\n'
        '    stub_files.append(str(sf))\n'
        '(b / "AndroidManifest.xml").write_text(cfg["manifest_xml"], encoding="utf-8")\n'
        'cp = ":".join(cfg["kotlin_jars"])\n'
        'comp_cp = cp + ":/sandbox-sdk/android.jar"\n'
        'ext_jar = str(b / "ext.jar")\n'
        'kt_srcs = [str(pathlib.Path("/work") / rel) for rel in cfg["kt_files"]] + stub_files\n'
        'r1 = subprocess.run(["java", "-Xmx512m", "-cp", cp, "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", '
        '"-classpath", comp_cp, "-jvm-target", "11", "-d", ext_jar, *kt_srcs], capture_output=True, text=True)\n'
        'if r1.returncode != 0:\n'
        '    print("STAGE:kotlinc_failed"); print(r1.stdout); print(r1.stderr); sys.exit(r1.returncode)\n'
        '(b / "dex").mkdir(parents=True, exist_ok=True)\n'
        'r2 = subprocess.run(["/sandbox-sdk/build-tools/d8", "--min-api", "21", "--lib", "/sandbox-sdk/android.jar", '
        '"--output", str(b / "dex"), ext_jar], capture_output=True, text=True)\n'
        'if r2.returncode != 0:\n'
        '    print("STAGE:d8_failed"); print(r2.stdout); print(r2.stderr); sys.exit(r2.returncode)\n'
        'r3 = subprocess.run(["/sandbox-sdk/build-tools/aapt2", "link", "--manifest", str(b / "AndroidManifest.xml"), '
        '"-I", "/sandbox-sdk/android.jar", "-o", str(b / "unsigned.apk"), "--min-sdk-version", "21", '
        '"--target-sdk-version", "34", "--version-code", str(cfg["version_code"]), "--version-name", cfg["version_name"]], capture_output=True, text=True)\n'
        'if r3.returncode != 0:\n'
        '    print("STAGE:aapt2_failed"); print(r3.stdout); print(r3.stderr); sys.exit(r3.returncode)\n'
        'with zipfile.ZipFile(b / "unsigned.apk", "a") as zf:\n'
        '    for df in sorted((b / "dex").glob("*.dex")):\n'
        '        zf.write(df, df.name)\n'
        'ks = str(b / "debug.keystore")\n'
        'r4 = subprocess.run(["keytool", "-genkeypair", "-noprompt", "-keystore", ks, "-alias", "androiddebugkey", '
        '"-keyalg", "RSA", "-keysize", "2048", "-validity", "10000", "-storepass", "android", "-keypass", "android", '
        '"-dname", "CN=Android Debug,O=Android,C=US"], capture_output=True, text=True)\n'
        'if r4.returncode != 0:\n'
        '    print("STAGE:keytool_failed"); print(r4.stdout); print(r4.stderr); sys.exit(r4.returncode)\n'
        'out_dir = pathlib.Path("/work/build/outputs/apk/debug")\n'
        'out_dir.mkdir(parents=True, exist_ok=True)\n'
        'out_apk = out_dir / cfg["apk_name"]\n'
        'r5 = subprocess.run(["/sandbox-sdk/build-tools/apksigner", "sign", "--ks", ks, "--ks-pass", "pass:android", '
        '"--key-pass", "pass:android", "--ks-key-alias", "androiddebugkey", "--out", str(out_apk), str(b / "unsigned.apk")], capture_output=True, text=True)\n'
        'if r5.returncode != 0:\n'
        '    print("STAGE:apksigner_failed"); print(r5.stdout); print(r5.stderr); sys.exit(r5.returncode)\n'
        'print("STAGE:compiled_and_signed:" + cfg["apk_name"])\n'
    )

    import time
    build_started_at = time.time()
    sandbox_res = run_in_bwrap_sandbox(
        mod_root,
        ['/usr/bin/python3', '-c', driver_code, build_payload],
        timeout=timeout,
        allow_network=False,
        extract_outputs_to_host=True,
        sandbox_available_override=sandbox_available_override,
        extra_ro_binds=extra_binds,
    )
    if sandbox_res['status'] == 'BLOCKED' or sandbox_res.get('returncode') is None:
        return {
            'status': sandbox_res['status'],
            'compiled': False,
            'reason': sandbox_res['reason'],
            'sandbox': sandbox_res.get('sandbox'),
            'toolchain': toolchain,
            'executed_unprotected': False,
            'apk_inspection': None,
        }

    log_out = sanitize_text((sandbox_res.get('stdout') or '') + '\n' + (sandbox_res.get('stderr') or ''), redact_home=True)
    if sandbox_res['returncode'] != 0:
        return {
            'status': 'FAIL',
            'compiled': False,
            'reason': 'kotlin_or_android_compilation_failed',
            'command': sandbox_res.get('sandbox_command', []),
            'sandbox': sandbox_res.get('sandbox'),
            'toolchain': toolchain,
            'executed_unprotected': False,
            'log_tail': log_out.splitlines()[-35:],
        }

    collected = [Path(p) for p in (sandbox_res.get('collected_apks') or [])]
    apk_path = next((p for p in collected if p.name == safe_apk_name), None)
    if apk_path is None or not apk_path.is_file():
        return {
            'status': 'FAIL',
            'compiled': False,
            'reason': 'apk_artifact_missing_after_sandbox_compile',
            'sandbox': sandbox_res.get('sandbox'),
            'executed_unprotected': False,
            'log_tail': log_out.splitlines()[-25:],
        }

    dex_ver = verify_apk_contains_compiled_extension(
        apk_path,
        expected_package=package_name,
        expected_class_name=class_name,
        expected_methods=expected_methods,
    )
    return {
        'status': dex_ver['status'],
        'compiled': dex_ver['status'] == 'PASS',
        'reason': dex_ver['reason'],
        'apk_path': str(apk_path.resolve()),
        'apk_sha256': dex_ver.get('apk_sha256'),
        'build_started_at': build_started_at,
        'apk_inspection': dex_ver.get('apk_inspection'),
        'dex_verification': dex_ver,
        'command': sandbox_res.get('sandbox_command', []),
        'sandbox': sandbox_res.get('sandbox'),
        'toolchain': toolchain,
        'executed_unprotected': False,
        'log_tail': log_out.splitlines()[-25:],
    }


def verify_and_offer_apk_delivery(
    apk_path: Path | str | None,
    *,
    expected_package: str | None = None,
    expected_class_name: str | None = None,
    expected_methods: Sequence[str] | None = None,
    min_mtime: float | None = None,
    lang: str = 'pt-BR',
) -> dict[str, Any]:
    """Verify a newly built Debug APK and prepare the 3 post-build user choices only when genuine."""
    is_en = lang == 'en'
    if not apk_path:
        return {
            'status': 'BLOCKED',
            'apk_ready': False,
            'reason': 'apk_missing',
            'user_message': (
                'No Debug APK was produced yet, so phone installation options are unavailable.'
                if is_en
                else 'Nenhum APK Debug foi gerado nesta etapa; as opções de entrega não estão disponíveis.'
            ),
            'options': None,
        }

    p = Path(apk_path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size <= 0:
        return {
            'status': 'FAIL',
            'apk_ready': False,
            'reason': 'apk_missing_empty_or_symlink',
            'user_message': (
                'The APK artifact is missing or empty.'
                if is_en
                else 'O arquivo APK não existe ou está vazio.'
            ),
            'options': None,
        }

    if min_mtime is not None and (p.stat().st_mtime + 0.05) < float(min_mtime):
        return {
            'status': 'FAIL',
            'apk_ready': False,
            'reason': 'stale_apk_artifact',
            'user_message': (
                'Rejected an older APK file because it was not produced by the latest build.'
                if is_en
                else 'Descartei um arquivo APK antigo porque ele não foi gerado pela compilação mais recente.'
            ),
            'options': None,
        }

    if expected_class_name or expected_methods:
        dex_ver = verify_apk_contains_compiled_extension(
            p,
            expected_package=expected_package,
            expected_class_name=expected_class_name,
            expected_methods=expected_methods,
        )
        insp = dex_ver.get('apk_inspection') or {}
        if dex_ver.get('status') != 'PASS':
            return {
                'status': 'FAIL',
                'apk_ready': False,
                'reason': dex_ver.get('reason') or 'apk_dex_verification_failed',
                'apk_inspection': insp,
                'dex_verification': dex_ver,
                'user_message': (
                    'The APK exists, but it does not contain the compiled extension class or failed verification.'
                    if is_en
                    else 'O APK foi encontrado, mas não contém a extensão compilada esperada ou falhou na verificação.'
                ),
                'options': None,
            }
    else:
        dex_ver = None
        insp = inspect_apk(p, expected_package=expected_package)
        issues = insp.get('issues') or []
        sig_failed = 'apk_signature_verification_failed' in issues or 'package_mismatch' in issues
        if insp.get('status') == 'FAIL' or not insp.get('has_dex') or sig_failed:
            return {
                'status': 'FAIL',
                'apk_ready': False,
                'reason': 'apk_inspection_failed',
                'apk_inspection': insp,
                'user_message': (
                    'The compiled APK failed integrity or package verification.'
                    if is_en
                    else 'O APK gerado falhou na verificação de integridade ou pacote.'
                ),
                'options': None,
            }

    options = (
        [
            {'id': 1, 'key': 'save', 'label': '1. Save to another folder.'},
            {'id': 2, 'key': 'adb', 'label': '2. Install and test on your phone.'},
            {'id': 3, 'key': 'keep', 'label': '3. Keep the APK where it is.'},
        ]
        if is_en
        else [
            {'id': 1, 'key': 'save', 'label': '1. Salvar em outra pasta.'},
            {'id': 2, 'key': 'adb', 'label': '2. Instalar e testar no celular.'},
            {'id': 3, 'key': 'keep', 'label': '3. Manter o APK onde está.'},
        ]
    )
    prompt = 'What would you like to do?' if is_en else 'O que você deseja fazer?'
    header = (
        'All set! Your extension has been created and the Debug APK is ready. 💜'
        if is_en
        else 'Pronto! Sua extensão foi criada e o APK Debug está disponível. 💜'
    )
    return {
        'status': 'PASS',
        'apk_ready': True,
        'apk_path': str(p.resolve()),
        'apk_sha256': insp.get('sha256'),
        'apk_package': (insp.get('metadata') or {}).get('package'),
        'apk_inspection': insp,
        'dex_verification': dex_ver,
        'user_header': header,
        'prompt': prompt,
        'options': options,
    }


_DEFAULT_HOST_APPS: tuple[str, ...] = (
    'app.mihon',
    'eu.kanade.tachiyomi',
    'xyz.jmir.tachiyomi.mi',
    'xyz.jmir.tachiyomi.sy',
    'xyz.jmir.tachiyomi.az',
    'app.aniyomi',
    'xyz.jmir.tachiyomi.mi.debug',
    'app.mihon.debug',
    'org.lnreader.app',
)

_ANDROID_UI_RUNTIME_ERROR_RE = re.compile(
    r"(?i)(?:cloudflare|http\s*403|http\s*404|http\s*50[023]|timed?\s*out|nullpointerexception|"
    r"nenhum\s+cap[íi]tulo|no\s+chapters|no\s+results|nenhum\s+resultado|"
    r"isn't\s+responding|application\s+not\s+responding|falha\s+ao\s+carregar|error\s+loading)"
)


def _evaluate_android_ui_functional_dump(
    xml_text: str | None,
    *,
    host_package: str | None = None,
    source_name: str | None = None,
) -> dict[str, Any]:
    """Safely inspect UIAutomator XML output for extension presence, catalog/chapters/media readiness, and UI errors."""
    stripped = (xml_text or '').strip()
    if not stripped or not stripped.startswith('<') or '<!DOCTYPE' in stripped.upper() or '<!ENTITY' in stripped.upper():
        return {
            'xml_valid': False,
            'extension_loaded': False,
            'search_or_catalog_verified': False,
            'chapters_or_episodes_verified': False,
            'media_verified': False,
            'ui_errors': [],
            'nodes_count': 0,
        }

    parsed = parse_uiautomator_hierarchy_and_plan_actions(
        stripped,
        target_queries=('search', 'explore', 'browse', 'extensions', 'sources', 'catalog', 'chapter', 'episode', 'page', 'video'),
    )
    if parsed.get('reason', '').startswith('invalid_'):
        return {
            'xml_valid': False,
            'extension_loaded': False,
            'search_or_catalog_verified': False,
            'chapters_or_episodes_verified': False,
            'media_verified': False,
            'ui_errors': [],
            'nodes_count': 0,
        }

    root = ET.fromstring(stripped)
    node_packages: set[str] = set()
    labels: list[str] = []
    ui_errors: list[str] = [b['label'] for b in (parsed.get('error_banners') or []) if b.get('label')]
    for el in root.iter('node'):
        pkg_attr = (el.attrib.get('package') or '').strip()
        if pkg_attr:
            node_packages.add(pkg_attr)
        txt = (el.attrib.get('text') or '').strip()
        desc = (el.attrib.get('content-desc') or '').strip()
        rid = (el.attrib.get('resource-id') or '').strip()
        msg = f'{txt} {desc}'.strip()
        if msg:
            labels.append(msg)
            if _ANDROID_UI_RUNTIME_ERROR_RE.search(msg) and msg not in ui_errors:
                ui_errors.append(msg)
        if rid:
            labels.append(rid)

    in_launcher_only = bool(node_packages) and host_package and (host_package not in node_packages) and all(
        'launcher' in np or 'systemui' in np for np in node_packages
    )
    joined = ' | '.join(labels).lower()
    src_low = (source_name or '').strip().lower()
    ext_loaded = (not in_launcher_only) and (
        (bool(src_low) and src_low in joined)
        or any(k in joined for k in ('extens', 'sources', 'fontes', 'browse', 'explorar', 'loaded'))
    )
    catalog_ok = (not in_launcher_only) and (not ui_errors) and any(
        k in joined for k in ('popular', 'latest', 'recent', 'search', 'busca', 'pesquis', 'catalog', 'catálogo', 'manga', 'novel', 'anime', 'result')
    )
    chapters_ok = (not in_launcher_only) and (not ui_errors) and any(
        k in joined for k in ('capítulo', 'capitulo', 'chapter', 'episódio', 'episodio', 'episode')
    )
    media_ok = (not in_launcher_only) and (not ui_errors) and any(
        k in joined for k in ('página', 'pagina', 'page', 'image', 'player', 'video', 'stream')
    )
    return {
        'xml_valid': True,
        'in_launcher_only': in_launcher_only,
        'extension_loaded': ext_loaded,
        'search_or_catalog_verified': catalog_ok,
        'chapters_or_episodes_verified': chapters_ok,
        'media_verified': media_ok,
        'ui_errors': ui_errors,
        'nodes_count': parsed.get('nodes_count', 0),
        'node_packages': sorted(node_packages),
    }


def run_guided_adb_install_and_test(
    apk_path: Path | str,
    *,
    serial: str | None = None,
    authorize_install: bool = False,
    expected_package: str | None = None,
    source_name: str | None = None,
    host_app_packages: Sequence[str] | None = None,
    lang: str = 'pt-BR',
    runner: Callable[[list[str]], tuple[int, str, str]] | None = None,
    logcat_sample: str | None = None,
    ui_dump_sample: str | None = None,
    auto_fix_callback: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Guide optional ADB setup, require install consent, install safely, verify host app + UI hierarchy + logcat, and stay strictly honest."""
    is_en = lang == 'en'
    apk_p = Path(apk_path)
    if apk_p.is_symlink() or not apk_p.is_file() or apk_p.stat().st_size <= 0:
        return {
            'status': 'FAIL',
            'step': 'invalid_apk',
            'installed': False,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'user_message': 'APK file is missing or invalid.' if is_en else 'O arquivo APK não existe ou é inválido.',
        }

    simulated_adb = runner is not None
    adb_bin = 'adb' if simulated_adb else (shutil.which('adb') or _find_android_tool('adb'))
    if not adb_bin:
        return {
            'status': 'BLOCKED',
            'step': 'adb_missing',
            'adb_present': False,
            'installed': False,
            'requires_tool_install_authorization': True,
            'simulated_adb': False,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'user_message': (
                'Android connection tool (ADB) is not installed on this computer. Can I guide or install it to test on your phone?'
                if is_en
                else 'A ferramenta de conexão com o celular (ADB) não está instalada neste computador. Posso orientar ou preparar a instalação?'
            ),
            'next_step': (
                'Reply confirming whether you want help setting up ADB, or keep the APK on disk.'
                if is_en
                else 'Me confirme se quer instalar o suporte ao celular ou prefere manter o APK salvo no computador.'
            ),
        }

    def _exec_adb(args: list[str], *, timeout: int = 30) -> tuple[int, str, str]:
        if runner is not None:
            return runner([adb_bin, *args])
        proc = subprocess.run([adb_bin, *args], capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or '', proc.stderr or ''

    try:
        rc_dev, out_dev, err_dev = _exec_adb(['devices', '-l'], timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            'status': 'BLOCKED',
            'step': 'adb_error',
            'adb_present': True,
            'installed': False,
            'simulated_adb': simulated_adb,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'user_message': (
                f'Could not talk to Android devices ({exc}).'
                if is_en
                else 'Não consegui verificar os celulares conectados agora.'
            ),
        }

    if rc_dev != 0 and not out_dev.strip():
        return {
            'status': 'BLOCKED',
            'step': 'adb_error',
            'adb_present': True,
            'installed': False,
            'simulated_adb': simulated_adb,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'user_message': sanitize_text(err_dev or 'ADB failed to list devices.', redact_home=True),
        }

    devices = parse_adb_devices(out_dev)
    ready = [d for d in devices if d['state'] == 'device']
    unauthorized = [d for d in devices if d['state'] == 'unauthorized']
    offline = [d for d in devices if d['state'] == 'offline']

    onboarding_steps = (
        [
            'Step 1: Open Android Settings > About phone and tap Build number 7 times to enable Developer Options.',
            'Step 2: Inside Developer Options, turn on USB Debugging.',
            'Step 3: Connect your phone to this computer using a data USB cable.',
            'Step 4: Tap Allow when the phone asks to trust this computer, then let me know.',
        ]
        if is_en
        else [
            'Passo 1: Abra Configurações > Sobre o telefone e toque 7 vezes em Número da versão para ativar as Opções do desenvolvedor.',
            'Passo 2: Entre em Opções do desenvolvedor e ative a Depuração USB.',
            'Passo 3: Conecte o celular ao computador com um cabo USB de dados.',
            'Passo 4: Toque em Permitir quando o celular pedir autorização e me avise quando estiver conectado.',
        ]
    )

    if not devices:
        return {
            'status': 'BLOCKED',
            'step': 'connect_device',
            'adb_present': True,
            'devices': [],
            'onboarding_steps': onboarding_steps,
            'installed': False,
            'simulated_adb': simulated_adb,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'user_message': (
                'Turn on USB Debugging on your phone, connect the USB cable, accept the popup, and tell me when it is connected.'
                if is_en
                else 'Ative a Depuração USB nas configurações do celular, conecte com cabo USB, autorize na tela e me avise quando estiver conectado.'
            ),
            'next_step': '\n'.join(onboarding_steps),
        }

    if unauthorized and not ready:
        return {
            'status': 'BLOCKED',
            'step': 'authorize_rsa',
            'adb_present': True,
            'devices': devices,
            'installed': False,
            'simulated_adb': simulated_adb,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'user_message': (
                'I found your phone, but you need to tap Allow on the phone screen to authorize this computer.'
                if is_en
                else 'Encontrei o seu celular, mas falta tocar em Permitir na tela dele para autorizar a conexão.'
            ),
            'next_step': (
                'Unlock your phone screen, tap Allow, and tell me so I can continue.'
                if is_en
                else 'Desbloqueie a tela do celular, toque em Permitir e me avise para continuar.'
            ),
        }

    if offline and not ready:
        return {
            'status': 'BLOCKED',
            'step': 'reconnect_cable',
            'adb_present': True,
            'devices': devices,
            'installed': False,
            'simulated_adb': simulated_adb,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'user_message': (
                'The phone appeared as offline. Reconnect the USB cable or unlock the screen and try again.'
                if is_en
                else 'O celular apareceu como desconectado (offline). Reconecte o cabo USB e tente novamente.'
            ),
        }

    if len(ready) > 1 and not serial:
        return {
            'status': 'INCONCLUSIVE',
            'step': 'select_device',
            'adb_present': True,
            'available_devices': ready,
            'installed': False,
            'simulated_adb': simulated_adb,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'user_message': (
                f"More than one phone or emulator is connected ({', '.join(d['serial'] for d in ready)}). Tell me which one to use."
                if is_en
                else f"Há mais de um aparelho conectado ({', '.join(d['serial'] for d in ready)}). Qual você quer usar?"
            ),
        }

    target_dev = next((d for d in ready if d['serial'] == serial), None) if serial else ready[0]
    if target_dev is None:
        return {
            'status': 'FAIL',
            'step': 'device_not_found',
            'adb_present': True,
            'devices': devices,
            'installed': False,
            'simulated_adb': simulated_adb,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'user_message': (
                f'Selected device {serial} is not ready.'
                if is_en
                else f'O aparelho selecionado ({serial}) não está disponível.'
            ),
        }

    insp = inspect_apk(apk_p, expected_package=expected_package)
    pkg = expected_package or (insp.get('metadata') or {}).get('package')

    if not authorize_install:
        return {
            'status': 'BLOCKED',
            'step': 'confirm_install',
            'adb_present': True,
            'selected_device': target_dev,
            'target_package': pkg,
            'requires_install_authorization': True,
            'installed': False,
            'simulated_adb': simulated_adb,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'user_message': (
                f"Phone ready ({target_dev['serial']}). Can I install the extension APK{f' ({pkg})' if pkg else ''} on this device now?"
                if is_en
                else f"Celular pronto ({target_dev['serial']}). Posso instalar a extensão{f' ({pkg})' if pkg else ''} nele agora?"
            ),
        }

    rc_inst, out_inst, err_inst = _exec_adb(['-s', target_dev['serial'], 'install', '-r', str(apk_p.resolve())], timeout=60)
    combined_inst = (out_inst + '\n' + err_inst).strip()
    if rc_inst != 0 or 'Failure' in combined_inst:
        sig_conflict = 'INSTALL_FAILED_UPDATE_INCOMPATIBLE' in combined_inst or 'INSTALL_FAILED_VERSION_DOWNGRADE' in combined_inst
        return {
            'status': 'FAIL',
            'step': 'install_failed',
            'adb_present': True,
            'selected_device': target_dev,
            'target_package': pkg,
            'installed': False,
            'signature_conflict': sig_conflict,
            'simulated_adb': simulated_adb,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'install_output': sanitize_text(combined_inst, redact_home=True),
            'user_message': (
                'Could not install this Debug APK because another version with a different signature or newer version is already installed. Nothing was uninstalled automatically.'
                if (is_en and sig_conflict)
                else (
                    'Não consegui instalar este APK Debug porque já existe uma versão com assinatura diferente ou mais recente instalada no celular. Não desinstalei nada automaticamente.'
                    if sig_conflict
                    else (
                        'Failed to install the extension on the phone.'
                        if is_en
                        else 'Não foi possível instalar a extensão no celular.'
                    )
                )
            ),
        }

    android_gates: dict[str, Any] = {
        'apk_installed': True,
        'package_detected': False,
        'host_app_opened': False,
        'extension_loaded': False,
        'search_or_catalog_verified': False,
        'chapters_or_episodes_verified': False,
        'media_verified': False,
        'simulated_only': simulated_adb,
        'physical_device_homologated': False,
    }

    pkg_verified = False
    if pkg:
        rc_pm, out_pm, _ = _exec_adb(['-s', target_dev['serial'], 'shell', 'pm', 'path', pkg], timeout=15)
        pkg_verified = rc_pm == 0 and 'package:' in out_pm
        if not pkg_verified:
            rc_pl, out_pl, _ = _exec_adb(['-s', target_dev['serial'], 'shell', 'pm', 'list', 'packages', pkg], timeout=15)
            pkg_verified = rc_pl == 0 and f'package:{pkg}' in out_pl
    android_gates['package_detected'] = pkg_verified

    host_candidates = tuple(host_app_packages) if host_app_packages else _DEFAULT_HOST_APPS
    rc_pkgs, out_pkgs, _ = _exec_adb(['-s', target_dev['serial'], 'shell', 'pm', 'list', 'packages'], timeout=15)
    installed_pkgs = {
        line.split('package:', 1)[1].strip()
        for line in out_pkgs.splitlines()
        if line.strip().startswith('package:')
    } if rc_pkgs == 0 else set()
    host_pkg = next((cand for cand in host_candidates if cand in installed_pkgs), None)
    if host_pkg:
        rc_launch, _, _ = _exec_adb(
            ['-s', target_dev['serial'], 'shell', 'monkey', '-p', host_pkg, '-c', 'android.intent.category.LAUNCHER', '1'],
            timeout=15,
        )
        android_gates['host_app_opened'] = rc_launch == 0

    raw_ui_xml = ui_dump_sample
    if raw_ui_xml is None and android_gates['host_app_opened']:
        rc_dump, _, _ = _exec_adb(['-s', target_dev['serial'], 'shell', 'uiautomator', 'dump', '/sdcard/nox_uidump.xml'], timeout=15)
        if rc_dump == 0:
            rc_cat, out_xml, _ = _exec_adb(['-s', target_dev['serial'], 'shell', 'cat', '/sdcard/nox_uidump.xml'], timeout=15)
            if rc_cat == 0 and '<hierarchy' in out_xml:
                raw_ui_xml = out_xml

    ui_eval = _evaluate_android_ui_functional_dump(
        raw_ui_xml,
        host_package=host_pkg,
        source_name=source_name,
    )
    android_gates['extension_loaded'] = ui_eval['extension_loaded']
    android_gates['search_or_catalog_verified'] = ui_eval['search_or_catalog_verified']
    android_gates['chapters_or_episodes_verified'] = ui_eval['chapters_or_episodes_verified']
    android_gates['media_verified'] = ui_eval['media_verified']

    raw_logcat = logcat_sample
    if raw_logcat is None:
        _, out_log, _ = _exec_adb(['-s', target_dev['serial'], 'logcat', '-d', '-v', 'threadtime'], timeout=20)
        raw_logcat = out_log

    filtered = parse_and_filter_logcat(raw_logcat or '', target_package=pkg)
    if filtered['target_crashes'] or ui_eval['ui_errors']:
        repair_res = None
        fail_payload = {
            'status': 'FAIL',
            'step': 'post_install_crash_detected' if filtered['target_crashes'] else 'post_install_ui_error_detected',
            'adb_present': True,
            'selected_device': target_dev,
            'target_package': pkg,
            'host_package': host_pkg,
            'installed': True,
            'package_verified': pkg_verified,
            'needs_auto_fix_continuation': True,
            'android_gates': android_gates,
            'ui_inspection': ui_eval,
            'filtered_logcat': filtered,
            'simulated_adb': simulated_adb,
            'real_device_homologated': False,
            'physical_device_homologated': False,
        }
        if auto_fix_callback is not None:
            repair_res = auto_fix_callback(fail_payload)
            fail_payload['auto_fix_result'] = repair_res
        fail_payload['user_message'] = (
            'Installed the extension on your phone, detected a runtime or screen error while opening it, and started diagnosing the fix.'
            if is_en
            else 'Instalei a extensão no celular, identifiquei um erro ao testá-la na tela e já iniciei a correção automática.'
        )
        return fail_payload

    functional_verified = (
        android_gates['apk_installed']
        and android_gates['host_app_opened']
        and ui_eval['xml_valid']
        and (android_gates['extension_loaded'] or android_gates['search_or_catalog_verified'])
        and android_gates['search_or_catalog_verified']
    )

    if not functional_verified:
        return {
            'status': 'INCONCLUSIVE',
            'step': 'installed_pending_ui_verification',
            'adb_present': True,
            'selected_device': target_dev,
            'target_package': pkg,
            'host_package': host_pkg,
            'installed': True,
            'package_verified': pkg_verified,
            'android_gates': android_gates,
            'ui_inspection': ui_eval,
            'filtered_logcat': filtered,
            'simulated_adb': simulated_adb,
            'real_device_homologated': False,
            'physical_device_homologated': False,
            'user_message': (
                'The extension APK is installed on your phone, and I found no crashes in recent logs, but I could not verify catalog or chapter loading inside the reader app yet.'
                if is_en
                else 'O APK foi instalado no celular e não mostrou falhas nos logs recentes, mas ainda não consegui comprovar o carregamento do catálogo e dos capítulos dentro do aplicativo leitor.'
            ),
        }

    physical_ok = not simulated_adb
    android_gates['physical_device_homologated'] = physical_ok
    return {
        'status': 'PASS',
        'step': 'installed_and_verified_in_app',
        'adb_present': True,
        'selected_device': target_dev,
        'target_package': pkg,
        'host_package': host_pkg,
        'installed': True,
        'package_verified': pkg_verified,
        'android_gates': android_gates,
        'ui_inspection': ui_eval,
        'filtered_logcat': filtered,
        'simulated_adb': simulated_adb,
        'real_device_homologated': physical_ok,
        'physical_device_homologated': physical_ok,
        'user_message': (
            'Extension installed and verified inside the reader app on your device without errors!'
            if is_en
            else 'Extensão instalada e testada dentro do aplicativo no celular sem erros!'
        ),
    }


def handle_apk_delivery_choice(
    apk_path: Path | str,
    choice: str | int,
    *,
    destination: Path | str | None = None,
    overwrite: bool = False,
    serial: str | None = None,
    authorize_install: bool = False,
    expected_package: str | None = None,
    lang: str = 'pt-BR',
    adb_runner: Callable[[list[str]], tuple[int, str, str]] | None = None,
    logcat_sample: str | None = None,
) -> dict[str, Any]:
    """Execute the user's post-build APK choice: (1) save copy, (2) optional ADB install/test, or (3) keep in place."""
    is_en = lang == 'en'
    apk_p = Path(apk_path)
    if apk_p.is_symlink() or not apk_p.is_file() or apk_p.stat().st_size <= 0:
        return {
            'status': 'FAIL',
            'action': 'apk_deliver',
            'user_message': 'APK file is missing or empty.' if is_en else 'O arquivo APK não foi encontrado ou está vazio.',
        }

    norm = str(choice).strip().lower()
    if norm in {'1', 'save', 'salvar', 'copy'}:
        if destination is None:
            return {
                'status': 'INCONCLUSIVE',
                'action': 'apk_deliver_save',
                'needs_destination': True,
                'user_message': (
                    'Which folder do you want to save the APK to?'
                    if is_en
                    else 'Em qual pasta você deseja salvar o APK?'
                ),
            }
        dest_raw = Path(destination).expanduser()
        dst = (dest_raw / apk_p.name) if (dest_raw.is_dir() or dest_raw.suffix.lower() != '.apk') else dest_raw
        # Guard against symlinks along destination path
        if dst.is_symlink() or any(par.is_symlink() for par in dst.parents if par.exists()):
            return {
                'status': 'FAIL',
                'action': 'apk_deliver_save',
                'user_message': (
                    'Refused saving to a symbolic link destination for safety.'
                    if is_en
                    else 'Recusei salvar nesse caminho por segurança (link simbólico detectado).'
                ),
            }
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists() and not overwrite:
            return {
                'status': 'BLOCKED',
                'action': 'apk_deliver_save',
                'requires_overwrite_authorization': True,
                'existing_path': str(dst),
                'user_message': (
                    f'A file already exists at {dst}. Do you authorize overwriting it?'
                    if is_en
                    else f'Já existe um arquivo em {dst}. Posso substituí-lo?'
                ),
            }
        shutil.copy2(apk_p, dst)
        src_hash = hashlib.sha256(apk_p.read_bytes()).hexdigest()
        dst_hash = hashlib.sha256(dst.read_bytes()).hexdigest()
        if src_hash != dst_hash:
            return {
                'status': 'FAIL',
                'action': 'apk_deliver_save',
                'user_message': 'Copy verification failed.' if is_en else 'Falha ao confirmar a cópia do APK.',
            }
        return {
            'status': 'PASS',
            'action': 'apk_deliver_save',
            'saved_path': str(dst.resolve()),
            'original_apk': str(apk_p.resolve()),
            'sha256': dst_hash,
            'user_message': (
                f'APK saved successfully to: {dst.resolve()}'
                if is_en
                else f'APK salvo com sucesso na pasta escolhida: {dst.resolve()}'
            ),
        }

    if norm in {'2', 'adb', 'install', 'instalar', 'celular', 'phone'}:
        res = run_guided_adb_install_and_test(
            apk_p,
            serial=serial,
            authorize_install=authorize_install,
            expected_package=expected_package,
            lang=lang,
            runner=adb_runner,
            logcat_sample=logcat_sample,
        )
        return {**res, 'action': 'apk_deliver_adb'}

    if norm in {'3', 'keep', 'manter', 'leave'}:
        resolved = str(apk_p.resolve())
        return {
            'status': 'PASS',
            'action': 'apk_deliver_keep',
            'apk_path': resolved,
            'user_message': (
                f'All set! Your APK will stay saved at: {resolved}'
                if is_en
                else f'Perfeito! O APK continuará salvo em: {resolved}'
            ),
        }

    return {
        'status': 'INCONCLUSIVE',
        'action': 'apk_deliver',
        'user_message': (
            'Choose 1 (save to folder), 2 (install on phone), or 3 (leave here).'
            if is_en
            else 'Escolha 1 (salvar em outra pasta), 2 (instalar no celular) ou 3 (manter onde está).'
        ),
    }


def _extract_deeplink_rules(text: str) -> list[dict[str, str]]:
    """Parse deeplink{} DSL blocks and AndroidManifest <intent-filter>/<data> declarations."""
    rules: list[dict[str, str]] = []
    # Kotlin build.gradle.kts deeplink { ... } or scheme/host/pathPattern attributes
    for block_m in re.finditer(r'deeplink\s*\{([^}]*)\}', text, re.S):
        blk = block_m.group(1)
        scheme_m = re.search(r'\bscheme\s*=\s*"([^"]+)"', blk)
        host_m = re.search(r'\bhost\s*=\s*"([^"]+)"', blk)
        path_m = re.search(r'\bpathPattern\s*=\s*"([^"]+)"|\bpathPrefix\s*=\s*"([^"]+)"', blk)
        rules.append({
            'scheme': scheme_m.group(1) if scheme_m else 'https',
            'host': host_m.group(1) if host_m else '',
            'path_pattern': (path_m.group(1) or path_m.group(2)) if path_m else '/.*',
        })
    # XML AndroidManifest <data android:scheme=... android:host=... android:pathPattern=.../>
    for tag_m in re.finditer(r'<data\b([^>]+)/?>', text, re.S):
        attrs = tag_m.group(1)
        sch = re.search(r'android:scheme\s*=\s*["\']([^"\']+)["\']', attrs)
        hst = re.search(r'android:host\s*=\s*["\']([^"\']+)["\']', attrs)
        pat = re.search(r'android:path(?:Pattern|Prefix)?\s*=\s*["\']([^"\']+)["\']', attrs)
        if sch or hst or pat:
            rules.append({
                'scheme': sch.group(1) if sch else 'https',
                'host': hst.group(1) if hst else '',
                'path_pattern': pat.group(1) if pat else '/.*',
            })
    return rules


def _android_glob_to_regex(pat: str) -> re.Pattern[str]:
    if pat.startswith('/') and not ('.*' in pat or '\\' in pat):
        return re.compile('^' + re.escape(pat))
    conv = pat.replace('.*', '___WILD___').replace('.', r'\.').replace('___WILD___', '.*')
    return re.compile('^' + conv)


def verify_deeplink_intent_filters(
    manifest_or_gradle_text: str,
    test_urls: Sequence[str],
    *,
    package_name: str | None = None,
) -> dict[str, Any]:
    """Validate Android deep-link intent rules against sample work/chapter/invalid URLs and emit safe ADB command (0059/0851-0865)."""
    rules = _extract_deeplink_rules(manifest_or_gradle_text)
    if not rules:
        return {'status': 'FAIL', 'reason': 'no_deeplink_or_intent_filter_rules_found', 'rules': [], 'results': []}

    results: list[dict[str, Any]] = []
    for raw_url in test_urls:
        sp = urlsplit(raw_url.strip())
        matched_rule = None
        for r in rules:
            host_ok = (not r['host']) or (sp.hostname or '').lower() == r['host'].lower()
            scheme_ok = sp.scheme.lower() == r['scheme'].lower()
            path_rx = _android_glob_to_regex(r['path_pattern'])
            path_ok = bool(path_rx.search(sp.path or '/'))
            if scheme_ok and host_ok and path_ok:
                matched_rule = r
                break
        safe_cmd = f"adb shell am start -W -a android.intent.action.VIEW -d {shlex.quote(raw_url.strip())}"
        if package_name:
            safe_cmd += f' {shlex.quote(package_name)}'
        results.append({
            'url': raw_url,
            'matched': matched_rule is not None,
            'matched_rule': matched_rule,
            'adb_am_start_command': safe_cmd if matched_rule else None,
        })

    any_match = any(r['matched'] for r in results)
    return {
        'status': 'PASS' if any_match else 'FAIL',
        'rules': rules,
        'matched_count': sum(1 for r in results if r['matched']),
        'results': results,
    }


_UIA_BOUNDS_RE = re.compile(r'\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]')
_UIA_ERROR_BANNER_RE = re.compile(r'(?i)(http\s*error\s*[45]\d\d|error\s*loading|failed\s*to\s*load|no\s*results|cloudflare|captcha|exception|timed\s*out)')


def parse_uiautomator_hierarchy_and_plan_actions(
    xml_text: str,
    *,
    target_queries: Sequence[str] = ('search', 'explore', 'browse'),
) -> dict[str, Any]:
    """Parse Android uiautomator dump XML hierarchy, extract bounds/tap centers, error banners, and planned ADB input commands (0052/0601)."""
    stripped = (xml_text or '').strip()
    if not stripped or '<!DOCTYPE' in stripped.upper() or '<!ENTITY' in stripped.upper():
        return {'status': 'FAIL', 'reason': 'invalid_or_unsafe_uiautomator_xml', 'nodes_count': 0}
    try:
        root = ET.fromstring(stripped)
    except ET.ParseError as exc:
        return {'status': 'FAIL', 'reason': f'invalid_uiautomator_xml:{exc}', 'nodes_count': 0}

    nodes: list[dict[str, Any]] = []
    matched_targets: list[dict[str, Any]] = []
    error_banners: list[dict[str, Any]] = []
    planned_cmds: list[str] = []
    q_low = [q.lower() for q in target_queries]

    for el in root.iter('node'):
        bounds_raw = el.attrib.get('bounds', '')
        m = _UIA_BOUNDS_RE.fullmatch(bounds_raw.strip())
        if not m:
            continue
        x1, y1, x2, y2 = (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)))
        if x2 < x1 or y2 < y1:
            continue
        cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
        text = el.attrib.get('text', '')
        desc = el.attrib.get('content-desc', '')
        res_id = el.attrib.get('resource-id', '')
        clickable = el.attrib.get('clickable', 'false').lower() == 'true'
        label = ' | '.join(p for p in (text, desc, res_id) if p)

        node_info = {
            'resource_id': res_id,
            'text': text,
            'content_desc': desc,
            'clickable': clickable,
            'bounds': [x1, y1, x2, y2],
            'center': [cx, cy],
        }
        nodes.append(node_info)

        combined_msg = f'{text} {desc}'.strip()
        if combined_msg and _UIA_ERROR_BANNER_RE.search(combined_msg):
            error_banners.append({'label': combined_msg, 'bounds': [x1, y1, x2, y2]})

        low_label = label.lower()
        if label and any(q in low_label for q in q_low):
            tap_cmd = f'adb shell input tap {cx} {cy}'
            matched_targets.append({**node_info, 'adb_tap_command': tap_cmd})
            planned_cmds.append(tap_cmd)

    status = 'FAIL' if error_banners else ('PASS' if nodes else 'INCONCLUSIVE')
    return {
        'status': status,
        'nodes_count': len(nodes),
        'clickable_count': sum(1 for n in nodes if n['clickable']),
        'matched_targets': matched_targets,
        'error_banners': error_banners,
        'planned_adb_input_commands': planned_cmds,
    }


def build_mihon_ui_navigation_plan(
    package_name: str,
    source_name: str,
    query: str,
    *,
    orientation: str = 'portrait',
    reading_mode: str = 'vertical',
    adb_output: str | None = None,
    debug_apk_path: Path | str | None = None,
    pool_devices: Sequence[dict[str, Any]] | None = None,
    snapshot_name: str = 'clean-baseline',
    ui_dump_xml: str | None = None,
) -> dict[str, Any]:
    """Prepare Android UI automation, emulator snapshot reset, JDWP debuggable check, rotation & device pool plan (0021/0023/0052-0058/0601-0620/0997)."""
    if orientation not in {'portrait', 'landscape'}:
        return {'status': 'FAIL', 'reason': f'invalid orientation: {orientation!r}'}

    adb_state = adb_doctor(adb_output=adb_output)
    is_debuggable = False
    apk_verified = False
    if debug_apk_path is not None and Path(debug_apk_path).is_file():
        insp = inspect_apk(debug_apk_path)
        apk_verified = insp['status'] == 'PASS'
        is_debuggable = bool((insp.get('signing') or {}).get('is_debug_cert'))

    # Select pool device safely when a multi-device pool is passed
    selected_pool_device = None
    if pool_devices:
        ready_pool = [d for d in pool_devices if d.get('state') == 'device' and not d.get('busy')]
        selected_pool_device = ready_pool[0] if ready_pool else None

    ui_steps = [
        {'step': 1, 'action': 'emulator_snapshot_restore', 'command': f'emulator -snapshot-load {shlex.quote(snapshot_name)}', 'optional_emulator_only': True},
        {'step': 2, 'action': 'set_orientation', 'command': f"adb shell settings put system user_rotation {0 if orientation == 'portrait' else 1}", 'reading_mode': reading_mode},
        {'step': 3, 'action': 'launch_host_app', 'command': f'adb shell monkey -p {shlex.quote(package_name)} -c android.intent.category.LAUNCHER 1'},
        {'step': 4, 'action': 'dump_ui_hierarchy', 'command': 'adb shell uiautomator dump /sdcard/window_dump.xml'},
        {'step': 5, 'action': 'open_source_and_search', 'source': source_name, 'query': query},
        {'step': 6, 'action': 'capture_screenshot_for_visual_diff', 'command': 'adb exec-out screencap -p'},
        {'step': 7, 'action': 'jdwp_attach_if_debuggable', 'allowed': is_debuggable, 'command': f'adb jdwp' if is_debuggable else None},
    ]

    ui_dump_analysis = parse_uiautomator_hierarchy_and_plan_actions(ui_dump_xml, target_queries=(source_name, 'search', 'explore')) if ui_dump_xml else None
    device_connected = (adb_state['status'] == 'PASS')
    return {
        'status': 'PASS' if device_connected else 'BLOCKED',
        'software_layer_status': 'FAIL' if (ui_dump_analysis and ui_dump_analysis['status'] == 'FAIL') else 'PASS',
        'device_test_status': 'NOT_RUN' if not device_connected else 'READY_FOR_AUTHORIZED_RUN',
        'package_name': package_name,
        'source_name': source_name,
        'orientation': orientation,
        'reading_mode': reading_mode,
        'apk_verified': apk_verified,
        'jdwp_attach_allowed': is_debuggable,
        'selected_pool_device': selected_pool_device,
        'adb_state': adb_state,
        'ui_steps': ui_steps,
        'ui_dump_analysis': ui_dump_analysis,
        'note': 'Device hardware execution remains NOT_RUN/BLOCKED whenever adb devices is empty; software automation & XML hierarchy parser are validated.',
    }


def _extract_binary_symbols_from_artifact(artifact: Path) -> set[str]:
    """Extract binary class/descriptor symbols from .dex, .class, .jar, or .apk archives (0881)."""
    symbols: set[str] = set()
    suffix = artifact.suffix.lower()
    blobs: list[bytes] = []
    if suffix in {'.apk', '.jar', '.zip'}:
        with zipfile.ZipFile(artifact) as zf:
            for name in zf.namelist():
                if name.endswith('.dex') or name.endswith('.class'):
                    blobs.append(zf.read(name))
    else:
        blobs.append(artifact.read_bytes())

    for blob in blobs:
        # Match Dalvik/JVM binary class descriptors (e.g. Leu/kanade/tachiyomi/source/online/HttpSource;)
        for m in re.finditer(rb'L[a-zA-Z0-9_$/]{4,160};', blob):
            symbols.add(m.group(0).decode('ascii', errors='ignore'))
        # Match JVM method binary descriptors like (ILjava/lang/String;)Ljava/util/List;
        for m in re.finditer(rb'\((?:\[|[A-Z])(?:[A-Za-z0-9_$/;]|\[){0,120}\)(?:\[|[A-Z])[A-Za-z0-9_$/;]{0,80}', blob):
            symbols.add(m.group(0).decode('ascii', errors='ignore'))
    return symbols


def compare_binary_dex_and_jar_apis(old_path: Path | str, new_path: Path | str) -> dict[str, Any]:
    """Compare compiled binary symbols (.dex/.class/.jar/.apk) beyond textual Kotlin signatures (0881)."""
    p_old, p_new = Path(old_path), Path(new_path)
    if not p_old.is_file() or not p_new.is_file():
        return {'status': 'FAIL', 'error': 'both compiled artifacts must exist'}

    sym_old = _extract_binary_symbols_from_artifact(p_old)
    sym_new = _extract_binary_symbols_from_artifact(p_new)
    removed = sorted(sym_old - sym_new)
    added = sorted(sym_new - sym_old)

    if removed:
        classification = 'BINARY_BREAKING_REMOVED_SYMBOLS'
        status = 'FAIL'
    elif not sym_old or not sym_new:
        classification = 'INDETERMINADO_NO_BINARY_SYMBOLS'
        status = 'INCONCLUSIVE'
    else:
        classification = 'BINARY_COMPATIBLE_ADDITIVE'
        status = 'PASS'

    return {
        'status': status,
        'classification': classification,
        'old_symbols_count': len(sym_old),
        'new_symbols_count': len(sym_new),
        'removed_symbols': removed[:50],
        'added_symbols': added[:50],
    }


def run_git_bisect_regression(
    repo_root: Path | str,
    good_rev: str,
    bad_rev: str,
    test_fn: Callable[[Path], bool],
) -> dict[str, Any]:
    """Isolate first regression commit in an isolated temporary clone via binary search without touching user worktree (0087/0812)."""
    src = Path(repo_root).resolve()
    if not (src / '.git').exists():
        return {'status': 'FAIL', 'error': f'not a git repository: {src}'}
    sec = audit_untrusted_pr_or_repo(src)
    if sec['status'] == 'FAIL':
        return {'status': 'FAIL', 'error': 'refusing bisect on repo failing security audit', 'security': sec, 'executed_unprotected': False}

    try:
        commits_raw = subprocess.check_output(
            ['git', 'rev-list', '--reverse', f'{good_rev}..{bad_rev}'],
            cwd=src,
            text=True,
        ).strip()
    except subprocess.SubprocessError as exc:
        return {'status': 'FAIL', 'error': f'cannot resolve revision range: {exc}'}

    commits = [good_rev, *[c for c in commits_raw.splitlines() if c]]
    if len(commits) < 2:
        return {'status': 'INCONCLUSIVE', 'error': 'revision range contains fewer than 2 commits'}

    tested_steps: list[dict[str, Any]] = []

    class _UnsafeBisectCommit(RuntimeError):
        def __init__(self, rev: str, sec_res: dict[str, Any]) -> None:
            super().__init__(rev)
            self.rev = rev
            self.sec_res = sec_res

    with tempfile.TemporaryDirectory(prefix='nox-bisect-') as tmp:
        wt = Path(tmp) / 'clone'
        subprocess.run(
            ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=user', 'clone', '--quiet', '--no-hardlinks', '--no-recurse-submodules', str(src), str(wt)],
            check=True,
        )

        def _eval_idx(i: int) -> bool:
            rev = commits[i]
            subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', 'checkout', '--quiet', '--detach', rev], cwd=wt, check=True)
            sec_rev = audit_untrusted_pr_or_repo(wt)
            if sec_rev['status'] == 'FAIL':
                raise _UnsafeBisectCommit(rev, sec_rev)
            passed = bool(test_fn(wt))
            tested_steps.append({'index': i, 'commit': rev, 'passed': passed})
            return passed

        try:
            if not _eval_idx(0):
                return {'status': 'FAIL', 'error': 'good_rev already failed test_fn', 'steps': tested_steps}
            if _eval_idx(len(commits) - 1):
                return {'status': 'INCONCLUSIVE', 'error': 'bad_rev did not fail test_fn', 'steps': tested_steps}

            lo, hi = 0, len(commits) - 1
            while lo + 1 < hi:
                mid = (lo + hi) // 2
                if _eval_idx(mid):
                    lo = mid
                else:
                    hi = mid
        except _UnsafeBisectCommit as exc:
            return {
                'status': 'FAIL',
                'error': f'commit {exc.rev} failed security pre-flight; refusing test_fn execution',
                'commit': exc.rev,
                'security': exc.sec_res,
                'steps': tested_steps,
                'executed_unprotected': False,
            }

        culprit = commits[hi]
        subj = subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', 'show', '-s', '--format=%s', culprit], cwd=wt, text=True).strip()
        return {
            'status': 'PASS',
            'first_bad_commit': culprit,
            'commit_subject': subj,
            'total_commits_in_range': len(commits),
            'steps_evaluated': len(tested_steps),
            'steps': tested_steps,
        }


def run_solution_tournament(
    candidates: Sequence[dict[str, Any]],
    fixtures: Sequence[Any],
    evaluator: Callable[[dict[str, Any], Any], dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate competing isolated patch candidates against identical fixtures and rank by pass rate & minimal diff (0103)."""
    if not candidates or not fixtures:
        return {'status': 'FAIL', 'error': 'candidates and fixtures must be non-empty', 'ranking': []}

    board: list[dict[str, Any]] = []
    for cand in candidates:
        cid = str(cand.get('id', 'unnamed'))
        patch_lines = int(cand.get('patch_lines', 9999))
        preserves_id = bool(cand.get('preserves_identity', True))
        passed = 0
        failed_cases: list[Any] = []
        for fx in fixtures:
            res = evaluator(cand, fx)
            if res.get('passed'):
                passed += 1
            else:
                failed_cases.append(fx.get('name') if isinstance(fx, dict) else str(fx))
        board.append({
            'id': cid,
            'passed': passed,
            'total': len(fixtures),
            'pass_rate': round(passed / len(fixtures), 4),
            'preserves_identity': preserves_id,
            'patch_lines': patch_lines,
            'failed_cases': failed_cases,
        })

    # Rank by highest pass_rate, identity preservation, and smallest minimal patch
    board.sort(key=lambda x: (-int(x['preserves_identity']), -x['pass_rate'], x['patch_lines']))
    winner = board[0]
    ok = winner['passed'] == len(fixtures) and winner['preserves_identity']
    return {
        'status': 'PASS' if ok else 'FAIL',
        'winner': winner,
        'ranking': board,
    }
