import ast
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import nox_android
import nox_core
import nox_issues
import nox_scaffold
import references


class _NovelSiteHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path.startswith('/novels/mist-village'):
            html = (
                '<html><head><title>Mist Village</title></head><body>'
                '<h1>Mist Village</h1><p class="desc">Foggy cultivation tale.</p>'
                '<ul class="chapters"><li><a href="/ch/1">Chapter 1</a></li></ul>'
                '</body></html>'
            )
        elif self.path.startswith('/ch/1'):
            html = (
                '<html><body><div class="chapter-content">'
                '<p>The mist parted across the stone valley as the bell rang.</p>'
                '<p>Every disciple gathered along the narrow ridge.</p>'
                '</div></body></html>'
            )
        elif self.path.startswith('/novels?q=Mist'):
            html = '<html><body><a class="novel-card" href="/novels/mist-village">Mist Village</a></body></html>'
        elif self.path.startswith('/novels?q='):
            html = '<html><body><div class="empty">No results</div></body></html>'
        else:
            html = '<html><body><a class="novel-card" href="/novels/mist-village">Mist Village</a></body></html>'
        raw = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class SecurityContainmentV211Tests(unittest.TestCase):
    def test_lnreader_sandbox_isolates_fs_env_write_and_direct_network(self):
        if nox_android.probe_bwrap_sandbox()['status'] != 'PASS' or not shutil.which('node'):
            self.skipTest('bwrap or node not available in test environment')

        forbidden_hits: list[str] = []

        class _ForbiddenHandler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                forbidden_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'FORBIDDEN_REACHED')

        allowed_srv = ThreadingHTTPServer(('127.0.0.1', 0), _NovelSiteHandler)
        forbidden_srv = ThreadingHTTPServer(('127.0.0.1', 0), _ForbiddenHandler)
        t1 = threading.Thread(target=allowed_srv.serve_forever, daemon=True)
        t2 = threading.Thread(target=forbidden_srv.serve_forever, daemon=True)
        t1.start()
        t2.start()

        canary_fd, canary_path = tempfile.mkstemp(prefix='nox-host-canary-')
        os.close(canary_fd)
        Path(canary_path).write_text('CANARY_HOST_SECRET_DO_NOT_READ', encoding='utf-8')
        prev_env = os.environ.get('NOX_TEST_CANARY_ENV')
        os.environ['NOX_TEST_CANARY_ENV'] = 'CANARY_ENV_SECRET_XYZ'

        try:
            base_url = f'http://127.0.0.1:{allowed_srv.server_port}'
            forbidden_url = f'http://127.0.0.1:{forbidden_srv.server_port}/leak'
            with tempfile.TemporaryDirectory() as tmp:
                plugin_ts = Path(tmp) / 'adversarial_plugin.ts'
                plugin_ts.write_text(
                    "import fs from 'node:fs';\n"
                    "import * as cheerio from 'cheerio';\n"
                    "import { fetchApi } from '@libs/fetch';\n"
                    "import { Plugin } from '@typings/plugin';\n"
                    'class AdversarialNovelPlugin implements Plugin.PluginBase {\n'
                    "  id = 'adv';\n"
                    "  name = 'Adv';\n"
                    f"  site = '{base_url}';\n"
                    '  async popularNovels(page: number) {\n'
                    '    let fsBlocked = false;\n'
                    '    try {\n'
                    f'      const leak = fs.readFileSync({canary_path!r}, "utf8");\n'
                    '      if (leak.includes("CANARY_HOST_SECRET")) fsBlocked = false;\n'
                    '    } catch { fsBlocked = true; }\n'
                    '    const envBlocked = process.env.NOX_TEST_CANARY_ENV === undefined;\n'
                    '    let roBlocked = false;\n'
                    '    try {\n'
                    '      fs.writeFileSync("/work/pwned.txt", "owned");\n'
                    '    } catch { roBlocked = true; }\n'
                    '    let netBlocked = false;\n'
                    '    try {\n'
                    f'      await globalThis.fetch({forbidden_url!r});\n'
                    '    } catch { netBlocked = true; }\n'
                    '    let bridgeSsrfBlocked = false;\n'
                    '    try {\n'
                    f'      await fetchApi({forbidden_url!r});\n'
                    '    } catch { bridgeSsrfBlocked = true; }\n'
                    '    const res = await fetchApi(`${this.site}/novels`);\n'
                    '    const html = await res.text();\n'
                    '    const $ = cheerio.load(html);\n'
                    '    const items = $("a.novel-card").map((_, el) => ({ name: $(el).text().trim(), path: $(el).attr("href") || "" })).get();\n'
                    '    const first = items[0] || { name: "", path: "" };\n'
                    '    const allSafe = fsBlocked && envBlocked && roBlocked && netBlocked && bridgeSsrfBlocked;\n'
                    '    const prefix = allSafe ? "CONTAINED_" : `LEAK_fs=${!fsBlocked}_env=${!envBlocked}_ro=${!roBlocked}_net=${!netBlocked}_br=${!bridgeSsrfBlocked}_`;\n'
                    '    return [{ name: prefix + first.name, path: first.path }];\n'
                    '  }\n'
                    '  async searchNovels(q: string, page: number) {\n'
                    '    if (q.includes("NoxZeroResultProbe999")) return [];\n'
                    '    const res = await fetchApi(`${this.site}/novels?q=Mist`);\n'
                    '    const $ = cheerio.load(await res.text());\n'
                    '    return $("a.novel-card").map((_, el) => ({ name: $(el).text().trim(), path: $(el).attr("href") || "" })).get();\n'
                    '  }\n'
                    '  async parseNovel(path: string) {\n'
                    '    const res = await fetchApi(new URL(path, this.site).toString());\n'
                    '    const $ = cheerio.load(await res.text());\n'
                    '    const chapters = $("ul.chapters a").map((_, el) => ({ name: $(el).text().trim(), path: $(el).attr("href") || "" })).get();\n'
                    '    return { name: $("h1").text().trim(), path, chapters };\n'
                    '  }\n'
                    '  async parseChapter(path: string) {\n'
                    '    const res = await fetchApi(new URL(path, this.site).toString());\n'
                    '    const $ = cheerio.load(await res.text());\n'
                    '    return $(".chapter-content").html() || "";\n'
                    '  }\n'
                    '}\n'
                    'export default new AdversarialNovelPlugin();\n',
                    encoding='utf-8',
                )
                res = nox_scaffold._execute_lnreader_ts_in_node(
                    plugin_ts,
                    base_url,
                    allow_local_fixture=True,
                    timeout=15,
                )
                self.assertEqual(res['status'], 'PASS', res)
                self.assertTrue(res.get('sandboxed'))
                self.assertIs(res.get('executed_unprotected'), False)
                self.assertTrue(res['details']['popular_first']['name'].startswith('CONTAINED_'), res['details'])
                self.assertEqual(forbidden_hits, [])
        finally:
            allowed_srv.shutdown()
            forbidden_srv.shutdown()
            allowed_srv.server_close()
            forbidden_srv.server_close()
            if os.path.exists(canary_path):
                os.unlink(canary_path)
            if prev_env is None:
                os.environ.pop('NOX_TEST_CANARY_ENV', None)
            else:
                os.environ['NOX_TEST_CANARY_ENV'] = prev_env

    def test_lnreader_sandbox_fails_closed_everywhere_when_bwrap_unavailable(self):
        srv = ThreadingHTTPServer(('127.0.0.1', 0), _NovelSiteHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            base_url = f'http://127.0.0.1:{srv.server_port}'
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                plugin_ts = tmp_path / 'sample.ts'
                plugin_ts.write_text('export default { popularNovels: async () => [] };\n', encoding='utf-8')

                direct = nox_scaffold._execute_lnreader_ts_in_node(
                    plugin_ts,
                    base_url,
                    allow_local_fixture=True,
                    sandbox_available_override=False,
                )
                self.assertEqual(direct['status'], 'BLOCKED')
                self.assertIs(direct['executed'], False)
                self.assertIs(direct['executed_unprotected'], False)
                self.assertIn('Nenhum código não confiável foi executado', direct['beginner_message'])

                beh = nox_scaffold.execute_extension_behavior(
                    'lnreader',
                    [plugin_ts],
                    base_url,
                    allow_local_fixture=True,
                    sandbox_available_override=False,
                )
                self.assertEqual(beh['status'], 'BLOCKED')
                self.assertIs(beh['executed_unprotected'], False)

                created = nox_scaffold.auto_create_extension(
                    f'Crie um plugin LNReader para {base_url}',
                    name='MistNovel',
                    ecosystem='lnreader',
                    ui_lang='pt-BR',
                    output_dir=tmp_path / 'out',
                    site_url=base_url,
                    allow_local_fixture=True,
                    sandbox_available_override=False,
                )
                self.assertEqual(created['status'], 'BLOCKED', created)
                self.assertNotEqual(created['status'], 'PASS')
                self.assertIs(created['agent_continuation']['task_complete'], False)
                self.assertIn('Nenhum código não confiável foi executado', created['user_message'])

                # Broken-selector plugin repaired into auto_fix must still stay BLOCKED without bwrap
                fix_dir = tmp_path / 'fix-lnr'
                nox_scaffold.scaffold_extension('lnreader', 'MistFix', base_url, output_dir=fix_dir)
                fixed = nox_scaffold.auto_fix_extension(
                    fix_dir,
                    'parou de carregar',
                    ecosystem='lnreader',
                    ui_lang='pt-BR',
                    site_url=base_url,
                    allow_local_fixture=True,
                    sandbox_available_override=False,
                )
                self.assertEqual(fixed['status'], 'BLOCKED', fixed)
                self.assertNotEqual(fixed['status'], 'PASS')
                self.assertIs(fixed['agent_continuation']['task_complete'], False)
                self.assertIn('Nenhum código não confiável foi executado', fixed['user_message'])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_lnreader_sandbox_terminates_infinite_loop_on_timeout(self):
        if nox_android.probe_bwrap_sandbox()['status'] != 'PASS' or not shutil.which('node'):
            self.skipTest('bwrap or node not available in test environment')
        srv = ThreadingHTTPServer(('127.0.0.1', 0), _NovelSiteHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            base_url = f'http://127.0.0.1:{srv.server_port}'
            with tempfile.TemporaryDirectory() as tmp:
                loop_ts = Path(tmp) / 'loop.ts'
                loop_ts.write_text(
                    'export default {\n'
                    '  async popularNovels() { while (true) {} },\n'
                    '  async searchNovels() { return []; },\n'
                    '  async parseNovel() { return { chapters: [] }; },\n'
                    '  async parseChapter() { return ""; },\n'
                    '};\n',
                    encoding='utf-8',
                )
                res = nox_scaffold._execute_lnreader_ts_in_node(
                    loop_ts,
                    base_url,
                    allow_local_fixture=True,
                    timeout=2,
                )
                self.assertEqual(res['status'], 'FAIL')
                self.assertIs(res['executed_unprotected'], False)
                self.assertIn('sandbox_timeout', res.get('error', ''))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_ssrf_blocks_private_special_alternate_ip_formats_and_malformed_urls(self):
        blocked_urls = [
            'http://127.0.0.1/',
            'http://10.0.0.1/',
            'http://169.254.169.254/latest/meta-data/',
            'http://172.16.0.1/',
            'http://192.168.1.1/',
            'http://0.0.0.0/',
            'http://100.64.0.1/',
            'http://[::1]/',
            'http://[::ffff:127.0.0.1]/',
            'http://[::ffff:169.254.169.254]/',
            'http://[::ffff:7f00:1]/',
            'http://[64:ff9b::127.0.0.1]/',
            'http://[2002:7f00:0001::]/',
            'http://[fe80::1%eth0]/',
            'http://0x7f000001/',
            'http://2130706433/',
            'http://0177.0.0.1/',
            'http://127.1/',
            'http://127.0.0.1./',
            'http://93.184.216.34./',
            'http://example.com\\@127.0.0.1/',
            'http://user:pass@93.184.216.34/',
            'file:///etc/passwd',
        ]
        for target in blocked_urls:
            ok, _ = nox_core.is_safe_public_url(target, allow_private_fixture=False, resolve_dns=False)
            self.assertFalse(ok, f'Expected is_safe_public_url to reject {target}')
            res = nox_core.safe_http_fetch_detailed(target, allow_local_fixture=False, timeout=2)
            self.assertEqual(res['status'], 0, f'Expected fetch block for {target}: {res}')

        # Even with allow_local_fixture=True, ONLY canonical loopback is permitted; metadata & private LAN remain blocked
        for must_still_block in (
            'http://169.254.169.254/latest/meta-data/',
            'http://10.0.0.1/',
            'http://172.16.0.1/',
            'http://192.168.1.1/',
            'http://0.0.0.0/',
            'http://100.64.0.1/',
            'http://0x7f000001/',
            'http://2130706433/',
            'http://0177.0.0.1/',
            'http://127.1/',
            'http://[::ffff:127.0.0.1]/',
            'http://metadata.google.internal/',
        ):
            res = nox_core.safe_http_fetch_detailed(must_still_block, allow_local_fixture=True, timeout=2)
            self.assertEqual(res['status'], 0, f'allow_local_fixture leaked {must_still_block}: {res}')

    def test_ssrf_blocks_private_and_mixed_dns_and_pins_ip_against_rebinding(self):
        res_priv = nox_core.safe_http_fetch_detailed(
            'https://rebind.example/items',
            resolver=lambda h, p: ['169.254.169.254'],
        )
        self.assertEqual(res_priv['status'], 0)
        self.assertIn('non-public IP', res_priv['error'])

        res_mixed = nox_core.safe_http_fetch_detailed(
            'https://mixed.example/items',
            resolver=lambda h, p: ['93.184.216.34', '10.0.0.8'],
        )
        self.assertEqual(res_mixed['status'], 0)
        self.assertIn('non-public IP', res_mixed['error'])

        resolve_calls = {'n': 0}
        connected_ips: list[tuple[str, str, int]] = []

        def _rebinding_resolver(host, port):
            resolve_calls['n'] += 1
            return ['93.184.216.34'] if resolve_calls['n'] == 1 else ['127.0.0.1']

        class _FakeResp:
            status = 200

            def getheader(self, name):
                return 'text/html' if name.lower() == 'content-type' else None

            def read(self, n=-1):
                return b'<html>pinned-ok</html>'

        class _FakeConn:
            def __init__(self, scheme, pinned_ip, host, port, timeout, ctx):
                connected_ips.append((scheme, pinned_ip, port))

            def request(self, method, path, headers=None):
                return None

            def getresponse(self):
                return _FakeResp()

            def close(self):
                return None

        res_pin = nox_core.safe_http_fetch_detailed(
            'https://pin.example/catalog',
            resolver=_rebinding_resolver,
            _connection_factory=_FakeConn,
        )
        self.assertEqual(res_pin['status'], 200)
        self.assertEqual(resolve_calls['n'], 1)
        self.assertEqual(connected_ips, [('https', '93.184.216.34', 443)])

    def test_ssrf_blocks_redirect_hops_to_loopback_metadata_and_http_downgrade(self):
        scenarios = [
            ('https://pub.example/start', 'http://127.0.0.1/admin', False),
            ('https://pub.example/start', 'http://127.0.0.1/admin', True),
            ('https://pub.example/start', 'http://169.254.169.254/latest/meta-data/', True),
            ('https://pub.example/start', 'http://pub.example/downgraded', False),
            ('https://pub.example/start', 'https://priv-dns.example/secret', False),
        ]

        for start_url, location, allow_fix in scenarios:
            connected_hosts: list[str] = []

            def _resolver(host, port):
                if host == 'pub.example':
                    return ['93.184.216.34']
                if host == 'priv-dns.example':
                    return ['10.20.30.40']
                return ['93.184.216.34']

            class _RedirResp:
                status = 302

                def getheader(self, name):
                    if name.lower() == 'location':
                        return location
                    return ''

                def read(self, n=-1):
                    return b''

            class _RedirConn:
                def __init__(self, scheme, pinned_ip, host, port, timeout, ctx):
                    connected_hosts.append(f'{scheme}://{host}:{pinned_ip}')

                def request(self, method, path, headers=None):
                    return None

                def getresponse(self):
                    return _RedirResp()

                def close(self):
                    return None

            res = nox_core.safe_http_fetch_detailed(
                start_url,
                allow_local_fixture=allow_fix,
                resolver=_resolver,
                _connection_factory=_RedirConn,
            )
            self.assertEqual(res['status'], 0, f'Expected redirect block for {start_url} -> {location}: {res}')
            self.assertEqual(len(connected_hosts), 1, f'Should never connect to second redirect target {location}')

    def test_proxy_env_variables_are_ignored_on_safe_fetch(self):
        srv = ThreadingHTTPServer(('127.0.0.1', 0), _NovelSiteHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        prev_http = os.environ.get('HTTP_PROXY')
        prev_https = os.environ.get('HTTPS_PROXY')
        prev_all = os.environ.get('ALL_PROXY')
        # Broken/hostile loopback proxy port that would fail if urllib/socket used proxy env
        os.environ['HTTP_PROXY'] = 'http://127.0.0.1:1'
        os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:1'
        os.environ['ALL_PROXY'] = 'socks5://127.0.0.1:1'
        try:
            res = nox_core.safe_http_fetch_detailed(
                f'http://127.0.0.1:{srv.server_port}/novels',
                allow_local_fixture=True,
            )
            self.assertEqual(res['status'], 200, res)
            self.assertIn(b'Mist Village', res['body'])
        finally:
            srv.shutdown()
            srv.server_close()
            for key, prev in (('HTTP_PROXY', prev_http), ('HTTPS_PROXY', prev_https), ('ALL_PROXY', prev_all)):
                if prev is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = prev

    def test_pinned_https_enforces_tls_cert_and_sni_hostname(self):
        if not shutil.which('openssl'):
            self.skipTest('openssl CLI required to generate ephemeral test cert')
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            cert_p = tpath / 'srv.crt'
            key_p = tpath / 'srv.key'
            proc = subprocess.run(
                [
                    'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key_p), '-out', str(cert_p), '-days', '1',
                    '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=DNS:localhost',
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode != 0:
                self.skipTest(f'openssl cert generation unavailable: {proc.stderr}')

            srv = ThreadingHTTPServer(('127.0.0.1', 0), _NovelSiteHandler)
            srv_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            srv_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            srv_ctx.load_cert_chain(certfile=str(cert_p), keyfile=str(key_p))
            srv.socket = srv_ctx.wrap_socket(srv.socket, server_side=True)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                trusted_ctx = ssl.create_default_context(cafile=str(cert_p))
                trusted_ctx.check_hostname = True
                trusted_ctx.verify_mode = ssl.CERT_REQUIRED

                # Valid TLS cert + matching SNI hostname succeeds via pinned IP
                ok_res = nox_core.safe_http_fetch_detailed(
                    f'https://localhost:{srv.server_port}/novels',
                    allow_local_fixture=True,
                    resolver=lambda h, p: ['127.0.0.1'],
                    ssl_context=trusted_ctx,
                )
                self.assertEqual(ok_res['status'], 200, ok_res)
                self.assertEqual(ok_res['pinned_ip'], '127.0.0.1')

                # Untrusted system CA rejects self-signed cert
                untrusted_res = nox_core.safe_http_fetch_detailed(
                    f'https://localhost:{srv.server_port}/novels',
                    allow_local_fixture=True,
                    resolver=lambda h, p: ['127.0.0.1'],
                )
                self.assertEqual(untrusted_res['status'], 0)
                self.assertTrue(untrusted_res['error'])

                # Mismatched SAN hostname (127.0.0.1 vs SAN DNS:localhost) MUST fail hostname verification
                mismatch_res = nox_core.safe_http_fetch_detailed(
                    f'https://127.0.0.1:{srv.server_port}/novels',
                    allow_local_fixture=True,
                    ssl_context=trusted_ctx,
                )
                self.assertEqual(mismatch_res['status'], 0)
                self.assertTrue(mismatch_res['error'])
            finally:
                srv.shutdown()
                srv.server_close()

    def test_references_and_issues_and_static_no_raw_urlopen(self):
        with self.assertRaises(ValueError):
            references.get('http://127.0.0.1/unsafe')
        with self.assertRaises(OSError):
            references.get('https://169.254.169.254/latest/meta-data/')

        # Static verification: no remaining urllib.request.urlopen in hardened scripts
        repo_scripts = Path(__file__).resolve().parents[1] / 'scripts'
        for mod_name in ('nox_core.py', 'nox_scaffold.py', 'nox_issues.py', 'references.py'):
            tree = ast.parse((repo_scripts / mod_name).read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == 'urlopen':
                    self.fail(f'Unexpected urlopen reference in {mod_name}:{node.lineno}')


if __name__ == '__main__':
    unittest.main()
