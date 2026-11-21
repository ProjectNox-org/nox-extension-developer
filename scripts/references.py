#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fetch complete, commit-pinned reference snapshots; never execute their content."""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import uuid

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from nox_core import safe_http_fetch_detailed  # noqa: E402

SOURCES = {
    'keiyoushi': ('keiyoushi/extensions-source', ['AGENTS.md', 'CONTRIBUTING.md']),
    'yuzono': ('yuzono/anime-extensions', ['AGENTS.md', 'CONTRIBUTING.md']),
    'lnreader': ('LNReader/lnreader-plugins', ['AGENTS.md', 'docs/quickstart.md', 'docs/docs.md', 'docs/testing.md']),
}
MAX_BYTES = 4_000_000


def get(url):
    parsed = urlsplit(str(url).strip())
    if parsed.scheme.lower() != 'https':
        raise ValueError(f'references.get requires https URL: {url}')
    res = safe_http_fetch_detailed(
        url,
        allow_local_fixture=False,
        timeout=20,
        max_bytes=MAX_BYTES,
        headers={'User-Agent': 'nox-extension-developer/1', 'Accept': 'application/vnd.github+json'},
    )
    if res.get('error') or int(res.get('status') or 0) >= 400:
        raise OSError(res.get('error') or f"HTTP {res.get('status')}")
    data = bytes(res['body'])
    if len(data) > MAX_BYTES:
        raise ValueError('response too large')
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_snapshot(root, name, sha):
    try:
        if not re.fullmatch(r'[0-9a-f]{40}', sha):
            return None
        snapshot = root / name / 'snapshots' / sha
        manifest = json.loads((snapshot / 'manifest.json').read_text())
        repo, paths = SOURCES[name]
        if manifest['commit'] != sha or manifest['repository'] != repo or set(manifest['files']) != set(paths):
            return None
        if not isinstance(manifest['branch'], str) or not manifest['branch']:
            return None
        dt.datetime.fromisoformat(manifest['retrieved_at'])
        for path in paths:
            if manifest['files'][path]['url'] != f'https://raw.githubusercontent.com/{repo}/{sha}/{path}':
                return None
            if digest((snapshot / 'docs' / path).read_bytes()) != manifest['files'][path]['sha256']:
                return None
        return snapshot, manifest
    except (OSError, ValueError, KeyError, TypeError):
        return None


def read_cache(root, name):
    try:
        pointer = json.loads((root / name / 'current.json').read_text())
        return read_snapshot(root, name, pointer['commit'])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def previous_cache(root, name):
    directory = root / name / 'snapshots'
    if not directory.is_dir():
        return None
    candidates = []
    for path in directory.iterdir():
        if not re.fullmatch(r'[0-9a-f]{40}', path.name):
            continue
        snapshot = read_snapshot(root, name, path.name)
        if snapshot:
            candidates.append(snapshot)
    return max(candidates, key=lambda item: item[1].get('retrieved_at', '')) if candidates else None


def resolve(repo, timeout=30):
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
    command = ['git', 'ls-remote', '--symref', f'https://github.com/{repo}.git', 'HEAD']
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, command, stdout, stderr)
    branch = re.search(r'^ref: refs/heads/(.+)\s+HEAD$', stdout, re.M)
    commit = re.search(r'^([0-9a-f]{40})\s+HEAD$', stdout, re.M)
    if not branch or not commit:
        raise ValueError('cannot resolve upstream HEAD')
    return branch.group(1), commit.group(1)


def set_current(base, commit, timestamp):
    with tempfile.NamedTemporaryFile(mode='w', dir=base, prefix='.current-', delete=False) as f:
        json.dump({'commit': commit, 'checked_at': timestamp}, f)
        temporary = f.name
    try:
        os.replace(temporary, base / 'current.json')
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sync(name, root, fetch=get, now=None, resolver=resolve):
    root = Path(root)
    base = root / name
    base.mkdir(parents=True, exist_ok=True)
    with (base / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _sync(name, root, fetch, now, resolver)


def _sync(name, root, fetch, now, resolver):
    old = read_cache(root, name)
    recovered = old is None
    if not old:
        old = previous_cache(root, name)
    recovered = bool(recovered and old)
    repo, paths = SOURCES[name]
    try:
        branch, commit = resolver(repo)
        if not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise ValueError('invalid commit SHA')
        timestamp = (now or dt.datetime.now(dt.timezone.utc)).isoformat()
        base = root / name
        if old and old[1]['commit'] == commit:
            set_current(base, commit, timestamp)
            return {'status': 'verified', 'snapshot': str(old[0]), 'commit': commit, 'previous_commit': commit, 'upstream_changed': False, 'api_compatibility': 'not_automatically_checked', 'branch': branch, 'checked_at': timestamp, 'changed_files': [], 'manifest': str(old[0] / 'manifest.json'), 'recovered_from_previous': recovered}
        contents = {}
        for path in paths:
            url = f'https://raw.githubusercontent.com/{repo}/{commit}/{path}'
            data = fetch(url)
            data.decode('utf-8')
            if not data.strip():
                raise ValueError(f'empty document: {path}')
            contents[path] = (url, data)
        files = {p: {'url': u, 'sha256': digest(b)} for p, (u, b) in contents.items()}
        manifest = {'repository': repo, 'branch': branch, 'commit': commit, 'retrieved_at': timestamp, 'files': files}
        changed = [p for p in paths if not old or old[1]['files'][p]['sha256'] != files[p]['sha256']]
        snapshots = base / 'snapshots'
        snapshots.mkdir(parents=True, exist_ok=True)
        target = snapshots / commit
        if not read_snapshot(root, name, commit):
            with tempfile.TemporaryDirectory(prefix='.snapshot-', dir=snapshots) as tmp:
                staging = Path(tmp) / 'snapshot'
                for path, (_, data) in contents.items():
                    dest = staging / 'docs' / path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(data)
                (staging / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
                if target.exists():
                    target.rename(snapshots / f'{commit}.corrupt-{uuid.uuid4().hex}')
                staging.rename(target)
        # Verify an existing snapshot as well; do not overwrite corruption.
        existing = json.loads((target / 'manifest.json').read_text())
        if existing['commit'] != commit or existing['repository'] != repo or set(existing['files']) != set(paths) or any(digest((target / 'docs' / p).read_bytes()) != files[p]['sha256'] or existing['files'][p]['sha256'] != files[p]['sha256'] for p in paths):
            raise ValueError('snapshot integrity check failed')
        set_current(base, commit, timestamp)
        return {'status': 'verified', 'snapshot': str(target), 'commit': commit, 'previous_commit': old[1]['commit'] if old else None, 'upstream_changed': bool(old and old[1]['commit'] != commit), 'api_compatibility': 'requires_manual_review', 'branch': branch, 'checked_at': timestamp, 'changed_files': changed, 'manifest': str(target / 'manifest.json')}
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as exc:
        if old:
            if recovered:
                set_current(root / name, old[1]['commit'], old[1]['retrieved_at'])
            return {'status': 'offline_or_unverified', 'warning': str(exc), 'snapshot': str(old[0]), 'commit': old[1]['commit'], 'retrieved_at': old[1]['retrieved_at'], 'changed_files': [], 'recovered_from_previous': recovered}
        raise RuntimeError(f'No complete verified cache; reference check failed: {exc}') from exc


def status(name, root, max_age_hours=72, now=None):
    """Inspect local verified snapshot without network access and report freshness and injection signals."""
    root = Path(root)
    snap = read_cache(root, name)
    recovered = False
    if not snap:
        snap = previous_cache(root, name)
        recovered = bool(snap)
    if not snap:
        return {
            'status': 'MISSING',
            'ecosystem': name,
            'snapshot': None,
            'commit': None,
            'is_stale': True,
            'warning': 'No intact verified snapshot cached; run sync when online.',
        }
    snapshot_path, manifest = snap
    current_time = now or dt.datetime.now(dt.timezone.utc)
    retrieved = dt.datetime.fromisoformat(manifest['retrieved_at'])
    if retrieved.tzinfo is None:
        retrieved = retrieved.replace(tzinfo=dt.timezone.utc)
    age_hours = round(max(0.0, (current_time - retrieved).total_seconds() / 3600.0), 2)
    injection_warnings = []
    for rel in manifest['files']:
        content = (snapshot_path / 'docs' / rel).read_text(errors='replace')
        if re.search(r'(?i)\b(ignore|disregard)\s+(?:all\s+)?(?:previous|prior|system)\s+instructions?\b', content):
            injection_warnings.append(rel)
    return {
        'status': 'verified_cached',
        'ecosystem': name,
        'repository': manifest['repository'],
        'branch': manifest['branch'],
        'commit': manifest['commit'],
        'retrieved_at': manifest['retrieved_at'],
        'age_hours': age_hours,
        'is_stale': age_hours > max_age_hours,
        'snapshot': str(snapshot_path),
        'files': sorted(manifest['files'].keys()),
        'recovered_from_previous': recovered,
        'prompt_injection_signals_in_docs': injection_warnings,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['sync', 'status'])
    parser.add_argument('ecosystem', choices=SOURCES)
    args = parser.parse_args()
    cache = Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'opencode/nox-workspace/nox-extension-developer'
    try:
        if args.action == 'status':
            print(json.dumps(status(args.ecosystem, cache), indent=2, ensure_ascii=False))
        else:
            print(json.dumps(sync(args.ecosystem, cache), indent=2, ensure_ascii=False))
    except RuntimeError as exc:
        parser.exit(1, f'{exc}\n')


if __name__ == '__main__':
    main()
