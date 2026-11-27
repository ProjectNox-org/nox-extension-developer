from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import nox
import nox_android
import nox_env
import nox_scaffold


def _has_lnreader_sandbox() -> bool:
    """Return True when both Bubblewrap userns sandbox and Node.js runtime are usable."""
    return nox_android.probe_bwrap_sandbox()['status'] == 'PASS' and bool(shutil.which('node'))


_HAS_ANDROID_COMPILE_SANDBOX = (
    nox_android.find_kotlin_and_android_build_toolchain()['status'] == 'PASS'
    and nox_android.probe_bwrap_sandbox()['status'] == 'PASS'
)


class ScaffoldAndFunctionalScenariosTests(unittest.TestCase):
    def test_scaffold_produces_official_non_mixed_ecosystems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            k = nox_scaffold.scaffold_extension('keiyoushi', 'ScanManga', 'https://scan.example', lang='pt-BR', output_dir=root / 'k')
            y = nox_scaffold.scaffold_extension('yuzono', 'AnimeBox', 'https://anime.example', lang='pt-BR', output_dir=root / 'y')
            l = nox_scaffold.scaffold_extension('lnreader', 'NovelHub', 'https://novel.example', lang='en', output_dir=root / 'l')

            self.assertEqual(k['inspection']['ecosystem'], 'keiyoushi')
            self.assertEqual(k['inspection']['architecture'], 'modern-ksp')
            self.assertIn('KeiSource', Path(k['created_files'][1]).read_text())

            self.assertEqual(y['inspection']['ecosystem'], 'yuzono')
            self.assertEqual(y['inspection']['architecture'], 'modern-ksp')
            self.assertIn('AnimeHttpSource', Path(y['created_files'][1]).read_text())

            self.assertEqual(l['inspection']['ecosystem'], 'lnreader')
            self.assertEqual(l['inspection']['architecture'], 'lnreader-standalone')
            self.assertIn('@libs/fetch', Path(l['created_files'][0]).read_text())

    def test_end_to_end_http_scenarios_creation_repair_update(self):
        res = nox_scaffold.run_functional_scenarios()
        self.assertEqual(res['status'], 'PASS')
        self.assertEqual(res['scenario_a_creation']['status'], 'PASS')
        self.assertEqual(res['scenario_b_repair']['before_statuses'], ['FAIL', 'FAIL', 'FAIL'])
        self.assertEqual(res['scenario_b_repair']['after_statuses'], ['PASS', 'PASS', 'PASS'])
        self.assertEqual(res['scenario_c_update']['status'], 'PASS')
        self.assertTrue(res['scenario_c_update']['rename_blocked'])


def _setup_sandbox_gradle_repo(repo_dir: Path, tp: Path, *, gradlew_body: str | None = None, fail_build: bool = False) -> bool:
    """Create a valid Gradle Wrapper tree (and real debug-signed template APK when Android SDK tools are present)."""
    gw_dir = repo_dir / 'gradle' / 'wrapper'
    gw_dir.mkdir(parents=True, exist_ok=True)
    (gw_dir / 'gradle-wrapper.properties').write_text(
        'distributionBase=GRADLE_USER_HOME\n'
        'distributionPath=wrapper/dists\n'
        'distributionUrl=https\\://services.gradle.org/distributions/gradle-8.10.2-bin.zip\n'
        'distributionSha256Sum=31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26\n',
        encoding='utf-8',
    )
    with zipfile.ZipFile(gw_dir / 'gradle-wrapper.jar', 'w') as zf:
        zf.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\nMain-Class: org.gradle.wrapper.GradleWrapperMain\n')
        zf.writestr('org/gradle/wrapper/GradleWrapperMain.class', b'\xca\xfe\xba\xbe' + b'\x00' * 1200)
    (repo_dir / 'settings.gradle.kts').write_text('rootProject.name = "demo"\n', encoding='utf-8')

    tpl_apk = repo_dir / 'template.apk'
    aapt2_bin = nox_android._find_android_tool('aapt2')
    apksigner_bin = nox_android._find_android_tool('apksigner')
    keytool_bin = shutil.which('keytool')
    sdk_root = Path(os.environ.get('ANDROID_HOME', str(Path.home() / '.local/share/android-sdk')))
    android_jars = sorted((sdk_root / 'platforms').glob('android-*/android.jar')) if (sdk_root / 'platforms').is_dir() else []

    signed_real = False
    if aapt2_bin and apksigner_bin and keytool_bin and android_jars:
        manifest_xml = tp / 'AndroidManifest.xml'
        manifest_xml.write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
            '    package="eu.kanade.tachiyomi.extension.en.noxauto"\n'
            '    android:versionCode="1"\n'
            '    android:versionName="1.0">\n'
            '    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34" />\n'
            '    <application android:label="NoxAuto" />\n'
            '</manifest>\n',
            encoding='utf-8',
        )
        subprocess.run([aapt2_bin, 'link', '--manifest', str(manifest_xml), '-I', str(android_jars[-1]), '-o', str(tpl_apk)], check=True, capture_output=True)
        with zipfile.ZipFile(tpl_apk, 'a') as zf:
            zf.writestr('classes.dex', b'dex\n035\x00')
        ks = tp / 'dbg.keystore'
        if not ks.exists():
            subprocess.run(
                [
                    keytool_bin, '-genkeypair', '-noprompt',
                    '-keystore', str(ks), '-storepass', 'android',
                    '-alias', 'androiddebugkey', '-keypass', 'android',
                    '-keyalg', 'RSA', '-keysize', '2048', '-validity', '1000',
                    '-dname', 'CN=Android Debug,O=Android,C=US',
                ],
                check=True,
                capture_output=True,
            )
        subprocess.run(
            [
                apksigner_bin, 'sign',
                '--ks', str(ks), '--ks-pass', 'pass:android',
                '--ks-key-alias', 'androiddebugkey', '--key-pass', 'pass:android',
                '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
                str(tpl_apk),
            ],
            check=True,
            capture_output=True,
        )
        signed_real = True
    else:
        with zipfile.ZipFile(tpl_apk, 'w') as zf:
            zf.writestr('AndroidManifest.xml', b'manifest')
            zf.writestr('classes.dex', b'dex\n035\x00')

    body = gradlew_body or (
        '#!/bin/sh\necho "Synthetic compile failure" >&2\nexit 1\n'
        if fail_build
        else '#!/bin/sh\nset -e\nmkdir -p app/build/outputs/apk/debug\ncp template.apk app/build/outputs/apk/debug/app-debug.apk\n'
    )
    gw = repo_dir / 'gradlew'
    gw.write_text(body, encoding='utf-8')
    gw.chmod(0o755)
    return signed_real


class FullAutomationEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), nox_scaffold._FixtureHandler)
        self.port = self.server.server_address[1]
        self.base_url = f'http://127.0.0.1:{self.port}'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _assert_lnreader_behavior_blocked(self, res: dict) -> None:
        """Assert fail-closed LNReader behavior block with zero host fallback."""
        self.assertEqual(res['status'], 'BLOCKED')
        self.assertIs(res['executed'], False)
        self.assertIs(res['executed_unprotected'], False)

    def _assert_lnreader_create_blocked(self, res: dict) -> None:
        """Assert fail-closed LNReader auto_create_extension result when sandbox is unavailable."""
        self.assertEqual(res['status'], 'BLOCKED')
        self.assertFalse(res['code_implemented'])
        self.assertFalse(res['tests_verified'])
        self.assertEqual(res['execution_stages']['extension_functions_tested'], 'BLOCKED')
        self.assertFalse(res['agent_continuation']['task_complete'])

    def _assert_lnreader_fix_blocked(self, res: dict) -> None:
        """Assert fail-closed LNReader auto_fix_extension result with preserved safe source fixes."""
        self.assertEqual(res['status'], 'BLOCKED')
        self.assertTrue(res['code_modified'])
        self.assertFalse(res['tests_verified'])
        self.assertEqual(res['before_verification']['behavior']['status'], 'BLOCKED')
        self.assertIs(res['before_verification']['behavior']['executed_unprotected'], False)
        self.assertEqual(res['after_verification']['status'], 'BLOCKED')
        self.assertIs(res['after_verification']['behavior']['executed_unprotected'], False)
        self.assertFalse(res['agent_continuation']['task_complete'])

    def test_A_B_C_D_G_I_real_create_fix_across_three_ecosystems_and_beginner_ux(self):
        with tempfile.TemporaryDirectory() as tmp:
            tp = Path(tmp)

            # TEST A: Real manga creation (Keiyoushi) adapts selectors, executes behavior, & compiles APK when SDK+bwrap present
            out_a = tp / 'manga_out'
            res_a = nox_scaffold.auto_create_extension(
                f'Crie uma extensao para este site: {self.base_url}',
                allow_local_fixture=True,
                output_dir=out_a,
                ui_lang='pt-BR',
            )
            self.assertEqual(res_a['ecosystem'], 'keiyoushi')
            self.assertTrue(res_a['code_implemented'])
            self.assertTrue(res_a['tests_verified'])
            self.assertEqual(res_a['execution_stages']['extension_functions_tested'], 'PASS')
            if _HAS_ANDROID_COMPILE_SANDBOX:
                self.assertEqual(res_a['status'], 'PASS')
                self.assertTrue(res_a['apk_ready'])
                self.assertEqual(res_a['execution_stages']['code_compiled'], 'PASS')
                self.assertEqual(res_a['execution_stages']['apk_inspected'], 'PASS')
            else:
                self.assertEqual(res_a['status'], 'BLOCKED')
                self.assertFalse(res_a['apk_ready'])
                self.assertEqual(res_a['execution_stages']['apk_generated'], 'BLOCKED')
            self.assertEqual(res_a['mode'], 'beginner')
            self.assertNotIn('technical_details', res_a)
            self.assertTrue(Path(res_a['diagnostics_file']).is_file())
            kt_a = Path(res_a['persisted_files'][1])
            self.assertTrue(kt_a.is_file())
            self.assertNotIn('/pt-BR/', kt_a.as_posix())
            kt_a_text = kt_a.read_text(encoding='utf-8')
            self.assertIn('package eu.kanade.tachiyomi.extension.pt.', kt_a_text)
            self.assertIn('data-src', kt_a_text)
            self.assertIn('headersBuilder', kt_a_text)
            self.assertIn('parseChapterNumber', kt_a_text)

            # TEST B: Real manga repair reproduces FAIL -> edits .kt on disk -> verifies PASS
            broken_manga = tp / 'broken_manga'
            nox_scaffold.scaffold_extension(
                'keiyoushi', 'BrokenManga', self.base_url, lang='pt-BR', output_dir=broken_manga, search_param='search', image_attr='src',
            )
            kt_b = next(broken_manga.rglob('*.kt'))
            orig_b = kt_b.read_text(encoding='utf-8')
            kt_b.write_text(
                orig_b
                .replace('a.chapter[href]', 'a.broken-chapter[href]')
                .replace('img.absUrl("src").ifBlank { img.absUrl("data-lazy-src") }.ifBlank { img.absUrl("src") }', 'img.absUrl("src")')
                .replace('    override fun headersBuilder() = super.headersBuilder().add("Referer", "$baseUrl/")\n\n', ''),
                encoding='utf-8',
            )
            res_b = nox_scaffold.auto_fix_extension(
                broken_manga,
                'Os capitulos e imagens nao estao carregando',
                allow_local_fixture=True,
                technical=True,
            )
            self.assertEqual(res_b['before_verification']['status'], 'FAIL')
            self.assertTrue(res_b['code_modified'])
            self.assertGreaterEqual(len(res_b['modified_files']), 1)
            self.assertEqual(res_b['after_verification']['status'], 'PASS')
            self.assertEqual(res_b['identity_continuity']['status'], 'PASS')
            self.assertEqual(res_b['status'], 'PASS')
            fixed_b_text = kt_b.read_text(encoding='utf-8')
            self.assertIn('a.chapter[href]', fixed_b_text)
            self.assertIn('absUrl("data-src")', fixed_b_text)
            self.assertIn('addQueryParameter("q"', fixed_b_text)

            # TEST C: Yuzono anime creation & repair
            out_c = tp / 'anime_out'
            res_c = nox_scaffold.auto_create_extension(
                f'Crie uma extensao de anime para {self.base_url}',
                ecosystem='yuzono',
                allow_local_fixture=True,
                output_dir=out_c,
            )
            self.assertEqual(res_c['ecosystem'], 'yuzono')
            self.assertTrue(res_c['code_implemented'])
            self.assertTrue(res_c['tests_verified'])
            if _HAS_ANDROID_COMPILE_SANDBOX:
                self.assertEqual(res_c['status'], 'PASS')
                self.assertTrue(res_c['apk_ready'])
            else:
                self.assertEqual(res_c['status'], 'BLOCKED')
            kt_c = Path(res_c['persisted_files'][1])
            kt_c.write_text(
                kt_c.read_text(encoding='utf-8')
                .replace('a.episode[href]', 'a.broken-episode[href]')
                .replace('a.server[href]', 'a.broken-server[href]'),
                encoding='utf-8',
            )
            fix_c = nox_scaffold.auto_fix_extension(out_c, 'episodios nao aparecem', ecosystem='yuzono', allow_local_fixture=True, technical=True)
            self.assertEqual(fix_c['status'], 'PASS')
            self.assertTrue(fix_c['code_modified'])
            self.assertIn('a.episode[href]', kt_c.read_text(encoding='utf-8'))

            # TEST D: LNReader novel creation & repair (PASS when sandboxed, BLOCKED fail-closed when bwrap unavailable)
            lnreader_sandbox_ok = _has_lnreader_sandbox()
            out_d = tp / 'novel_out'
            res_d = nox_scaffold.auto_create_extension(
                f'Crie um plugin de novel para {self.base_url}',
                ecosystem='lnreader',
                allow_local_fixture=True,
                output_dir=out_d,
            )
            self.assertEqual(res_d['ecosystem'], 'lnreader')
            self.assertEqual(res_d['execution_stages']['site_analyzed'], 'PASS')
            self.assertEqual(res_d['execution_stages']['code_generated'], 'PASS')
            self.assertEqual(res_d['execution_stages']['code_validated_statically'], 'PASS')
            ts_d = Path(res_d['persisted_files'][0])
            self.assertTrue(ts_d.is_file())
            if lnreader_sandbox_ok:
                self.assertEqual(res_d['status'], 'PASS')
                self.assertTrue(res_d['code_implemented'])
                self.assertTrue(res_d['tests_verified'])
                self.assertEqual(res_d['execution_stages']['extension_functions_tested'], 'PASS')
            else:
                self._assert_lnreader_create_blocked(res_d)

            ts_d.write_text(
                ts_d.read_text(encoding='utf-8')
                .replace('.chapter-content', '.broken-content')
                .replace("    $('script, style, nav').remove();\n", ''),
                encoding='utf-8',
            )
            fix_d = nox_scaffold.auto_fix_extension(out_d, 'capitulo vazio', ecosystem='lnreader', allow_local_fixture=True, technical=True)
            self.assertTrue(fix_d['code_modified'])
            fixed_d_text = ts_d.read_text(encoding='utf-8')
            self.assertIn('.chapter-content', fixed_d_text)
            self.assertIn("remove()", fixed_d_text)
            if lnreader_sandbox_ok:
                self.assertEqual(fix_d['status'], 'PASS')
                self.assertTrue(fix_d['tests_verified'])
                self.assertEqual(fix_d['after_verification']['status'], 'PASS')
            else:
                self._assert_lnreader_fix_blocked(fix_d)

            # TEST G: Blocked/failed build preserves source code, never offers fake APK or install menu
            blocked_repo = tp / 'blocked_gradle'
            _setup_sandbox_gradle_repo(blocked_repo, tp)
            res_g_blocked = nox_scaffold.auto_create_extension(
                f'Crie uma extensao de manga para {self.base_url}',
                repo_root=blocked_repo,
                build_task=':app:assembleDebug',
                allow_local_fixture=True,
                sandbox_available_override=False,
            )
            self.assertEqual(res_g_blocked['status'], 'BLOCKED')
            self.assertFalse(res_g_blocked['apk_ready'])
            self.assertIsNone(res_g_blocked['apk_options'])
            self.assertTrue(Path(res_g_blocked['persisted_files'][0]).is_file())

            # TEST I: CLI --beginner output emits plain guidance without JSON/Gradle dumps
            cli_out = tp / 'cli_beginner_out'
            buf_beg = io.StringIO()
            with redirect_stdout(buf_beg):
                rc = nox.main([
                    'auto-create',
                    f'Crie uma extensao de manga para {self.base_url}',
                    '--output', str(cli_out),
                    '--allow-local-fixture',
                    '--beginner',
                ])
            self.assertIn(rc, {0} if _HAS_ANDROID_COMPILE_SANDBOX else {0, 2})
            spoken = buf_beg.getvalue()
            self.assertNotIn('{', spoken)
            self.assertNotIn('./gradlew', spoken)
            self.assertNotIn('K2JVMCompiler', spoken)
            self.assertNotIn('Traceback', spoken)
            if _HAS_ANDROID_COMPILE_SANDBOX:
                self.assertIn('O que você deseja fazer?', spoken)
                self.assertIn('1. Salvar em outra pasta.', spoken)
                self.assertIn('2. Instalar e testar no celular.', spoken)
                self.assertIn('3. Manter o APK onde está.', spoken)

    @unittest.skipUnless(nox_android.probe_bwrap_sandbox()['status'] == 'PASS', 'Bubblewrap sandbox unavailable on runner')
    def test_E_F_real_sandboxed_apk_build_and_post_build_delivery_choices(self):
        with tempfile.TemporaryDirectory() as tmp:
            tp = Path(tmp)
            repo = tp / 'android_repo'
            signed_real = _setup_sandbox_gradle_repo(repo, tp)

            res = nox_scaffold.auto_create_extension(
                f'Crie uma extensao para este site: {self.base_url}',
                name='ShadowReal',
                repo_root=repo,
                build_task=':app:assembleDebug',
                allow_local_fixture=True,
                ui_lang='pt-BR',
            )
            if signed_real:
                self.assertEqual(res['status'], 'PASS')
                self.assertTrue(res['apk_ready'])
                self.assertEqual(len(res['apk_options']), 3)
                apk_p = Path(res['apk_path'])
                self.assertTrue(apk_p.is_file())
                self.assertGreater(apk_p.stat().st_size, 0)

                # Stale APK protection: reject an older min_mtime window
                import time
                stale = nox_android.verify_and_offer_apk_delivery(apk_p, min_mtime=time.time() + 120.0, lang='pt-BR')
                self.assertFalse(stale['apk_ready'])
                self.assertIsNone(stale['options'])

                # Option 1: missing destination asks folder simply
                ask_dest = nox_android.handle_apk_delivery_choice(apk_p, '1', lang='pt-BR')
                self.assertEqual(ask_dest['status'], 'INCONCLUSIVE')
                self.assertTrue(ask_dest['needs_destination'])

                # Option 1: save copy preserves original & verifies SHA-256
                dest_dir = tp / 'user_downloads'
                saved = nox_android.handle_apk_delivery_choice(apk_p, '1', destination=dest_dir, lang='pt-BR')
                self.assertEqual(saved['status'], 'PASS')
                self.assertTrue(Path(saved['saved_path']).is_file())
                self.assertTrue(apk_p.is_file())

                # Option 1 without overwrite blocks replacing existing file
                dup = nox_android.handle_apk_delivery_choice(apk_p, 'save', destination=dest_dir, overwrite=False, lang='pt-BR')
                self.assertEqual(dup['status'], 'BLOCKED')
                self.assertTrue(dup['requires_overwrite_authorization'])

                # Option 3 via CLI keeps APK cleanly
                buf_keep = io.StringIO()
                with redirect_stdout(buf_keep):
                    rc_keep = nox.main(['apk-deliver', str(apk_p), '--choice', '3', '--beginner'])
                self.assertEqual(rc_keep, 0)
                self.assertIn(str(apk_p.resolve()), buf_keep.getvalue())

            # Simulated build error returns FAIL without fake APK
            fail_repo = tp / 'fail_repo'
            _setup_sandbox_gradle_repo(fail_repo, tp, fail_build=True)
            res_fail = nox_scaffold.auto_create_extension(
                f'Crie uma extensao para este site: {self.base_url}',
                repo_root=fail_repo,
                build_task=':app:assembleDebug',
                allow_local_fixture=True,
            )
            self.assertEqual(res_fail['status'], 'FAIL')
            self.assertFalse(res_fail['apk_ready'])
            self.assertIsNone(res_fail['apk_options'])

    def test_01_02_03_04_05_07_language_separation_real_execution_and_pass2_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            tp = Path(tmp)

            # Test 1: pt-BR metadata vs pt package/dir separation + sourceId continuity
            norm_pt = nox_scaffold.normalize_ecosystem_language('keiyoushi', 'pt-BR')
            self.assertEqual(norm_pt['metadata_lang'], 'pt-BR')
            self.assertEqual(norm_pt['dir_lang'], 'pt')
            self.assertEqual(norm_pt['package_lang'], 'pt')
            sc_pt = nox_scaffold.scaffold_extension('keiyoushi', 'ScanBrasil', self.base_url, lang='pt-BR', output_dir=tp / 'pt_kei')
            self.assertEqual(sc_pt['status'], 'PASS')
            self.assertEqual(sc_pt['package_name'], 'eu.kanade.tachiyomi.extension.pt.scanbrasil')
            self.assertEqual(sc_pt['source_id'], nox_env.compute_source_id('ScanBrasil', 'pt-BR', 1))
            self.assertTrue(sc_pt['module_path'].endswith('/src/pt/scanbrasil'))
            self.assertIn('lang = "pt-BR"', Path(sc_pt['created_files'][0]).read_text(encoding='utf-8'))

            # Test 2: EN prompt auto-detects ui_lang='en' and compiles cleanly when toolchain present
            out_en = tp / 'en_out'
            res_en = nox_scaffold.auto_create_extension(
                f'Create an extension for this manga site: {self.base_url}',
                name='EnglishScan',
                source_lang='en',
                allow_local_fixture=True,
                output_dir=out_en,
            )
            self.assertEqual(res_en['ui_lang'], 'en')
            self.assertEqual(res_en['package_name'], 'eu.kanade.tachiyomi.extension.en.englishscan')
            self.assertIn('/src/en/englishscan/', res_en['persisted_files'][1])
            if _HAS_ANDROID_COMPILE_SANDBOX:
                self.assertEqual(res_en['status'], 'PASS')
                self.assertTrue(res_en['apk_ready'])
                self.assertEqual(res_en['apk_options'][0]['label'], '1. Save to another folder.')

            # Test 3: Yuzono pt-BR separation + sourceId
            norm_yuz = nox_scaffold.normalize_ecosystem_language('yuzono', 'pt-BR')
            self.assertEqual(norm_yuz['package_lang'], 'pt')
            sc_yuz = nox_scaffold.scaffold_extension('yuzono', 'AnimeBR', self.base_url, lang='pt-BR', output_dir=tp / 'pt_yuz')
            self.assertEqual(sc_yuz['package_name'], 'eu.kanade.tachiyomi.animeextension.pt.animebr')
            self.assertEqual(sc_yuz['source_id'], nox_env.compute_source_id('AnimeBR', 'pt-BR', 1))

            # Test 4: LNReader real Node.js execution fails cleanly on broken selector, passes when intact (or blocks fail-closed without bwrap)
            lnr_dir = tp / 'pt_lnr'
            sc_lnr = nox_scaffold.scaffold_extension(
                'lnreader', 'NovelBrasil', self.base_url, lang='pt-BR', output_dir=lnr_dir,
                catalog_path='/novels', catalog_selector='a.novel-card', chapter_selector='a.chapter', novel_content_selector='.chapter-content',
            )
            self.assertIn('/plugins/portuguese/', sc_lnr['module_path'])
            ts_file = Path(sc_lnr['module_path'])
            exec_ok = nox_scaffold.execute_extension_behavior('lnreader', [ts_file], self.base_url, allow_local_fixture=True)
            saved_ts = ts_file.read_text(encoding='utf-8')
            ts_file.write_text(saved_ts.replace('.chapter-content', '.selector-inexistente'), encoding='utf-8')
            exec_fail = nox_scaffold.execute_extension_behavior('lnreader', [ts_file], self.base_url, allow_local_fixture=True)
            if _has_lnreader_sandbox():
                self.assertEqual(exec_ok['status'], 'PASS')
                self.assertEqual(exec_ok['engine'], 'node')
                self.assertEqual(exec_fail['status'], 'FAIL')
            else:
                self._assert_lnreader_behavior_blocked(exec_ok)
                self._assert_lnreader_behavior_blocked(exec_fail)

            # Test 5: Negative check — invalid Kotlin syntax or hyphenated pt-BR package MUST FAIL compilation & validation
            bad_mod = tp / 'bad_kt'
            bad_src = bad_mod / 'src/pt-BR/badext' / 'src/eu/kanade/tachiyomi/extension/pt-BR/badext'
            bad_src.mkdir(parents=True)
            bad_kt = bad_src / 'BadExt.kt'
            bad_kt.write_text('package eu.kanade.tachiyomi.extension.pt-BR.badext\nclass BadExt { fun broken( {', encoding='utf-8')
            bad_val = nox_scaffold.validate_generated_package_and_paths(
                'keiyoushi', bad_mod / 'src/pt-BR/badext', [str(bad_kt)],
                {'metadata_lang': 'pt-BR', 'dir_lang': 'pt', 'package_lang': 'pt'},
            )
            self.assertEqual(bad_val['status'], 'FAIL')
            self.assertTrue(any('invalid_hyphen_in_kotlin_package' in i for i in bad_val['issues']))
            if _HAS_ANDROID_COMPILE_SANDBOX:
                comp_bad = nox_android.compile_kotlin_extension_to_debug_apk(
                    bad_mod / 'src/pt-BR/badext',
                    package_name='eu.kanade.tachiyomi.extension.pt.badext',
                    class_name='BadExt',
                )
                self.assertEqual(comp_bad['status'], 'FAIL')
                self.assertFalse(comp_bad['compiled'])

            # Test 7a: Pass 2 non-regex repair fixes unexpected non-"broken" CSS selector, wrong endpoint path, & emptyList() body
            unexp_dir = tp / 'unexpected_kei'
            sc_unexp = nox_scaffold.scaffold_extension('keiyoushi', 'UnexpectedManga', self.base_url, lang='pt-BR', output_dir=unexp_dir)
            uk_kt = Path(sc_unexp['created_files'][1])
            orig_uk = uk_kt.read_text(encoding='utf-8')
            mutated_uk = (
                orig_uk
                .replace('"$baseUrl/manga"', '"$baseUrl/wrong-catalog-endpoint"')
                .replace('doc.select("a.manga-card[href]")', 'doc.select("section.weird-grid a.wrong-card")')
                .replace(
                    '    override suspend fun getPageList(chapter: SChapter): List<Page> {\n'
                    '        val doc = client.get(getChapterUrl(chapter), Fetch.DOCUMENT).asJsoup()\n'
                    '        return doc.select("img.page").mapIndexed { idx, img ->\n'
                    '            val src = img.absUrl("data-src").ifBlank { img.absUrl("data-lazy-src") }.ifBlank { img.absUrl("src") }\n'
                    '            Page(idx, imageUrl = src)\n'
                    '        }\n'
                    '    }',
                    '    override suspend fun getPageList(chapter: SChapter): List<Page> = emptyList()',
                )
            )
            uk_kt.write_text(mutated_uk, encoding='utf-8')
            fix_unexp = nox_scaffold.auto_fix_extension(
                unexp_dir, 'não carrega catálogo nem páginas', allow_local_fixture=True, technical=True,
            )
            self.assertEqual(fix_unexp['before_verification']['status'], 'FAIL')
            self.assertEqual(fix_unexp['status'], 'PASS')
            self.assertTrue(fix_unexp['code_modified'])
            self.assertTrue(fix_unexp['tests_verified'])
            repaired_uk = uk_kt.read_text(encoding='utf-8')
            self.assertIn('"$baseUrl/manga"', repaired_uk)
            self.assertIn('doc.select("a.manga-card[href]")', repaired_uk)
            self.assertIn('doc.select("img.page")', repaired_uk)

            # Test 7b: Unsolvable custom defect against unreachable/unknown bug never fakes PASS & exposes agent_solver
            custom_dir = tp / 'unsolvable_custom'
            sc_cust = nox_scaffold.scaffold_extension('keiyoushi', 'CustomCrypt', 'https://unknown.example', lang='en', output_dir=custom_dir)
            fix_cust = nox_scaffold.auto_fix_extension(custom_dir, 'custom AES decryption fails', technical=True)
            self.assertEqual(fix_cust['status'], 'INCONCLUSIVE')
            self.assertIsNotNone(fix_cust.get('agent_solver'))
            self.assertTrue(fix_cust['agent_continuation']['must_continue_automatically'])

    def test_lnreader_fail_closed_under_simulated_bwrap_unavailability(self):
        """Controlled simulation: without bwrap, LNReader create/fix/execute all return BLOCKED with zero host execution."""
        real_which = shutil.which

        def _which_without_bwrap(cmd, mode=os.F_OK | os.X_OK, path=None):
            if cmd == 'bwrap':
                return None
            return real_which(cmd, mode=mode, path=path)

        with tempfile.TemporaryDirectory() as tmp:
            tp = Path(tmp)
            host_marker = tp / 'host_exec_marker.txt'
            rogue_ts = tp / 'rogue_plugin.ts'
            rogue_ts.write_text(
                "import fs from 'node:fs';\n"
                f'fs.writeFileSync({str(host_marker)!r}, "UNPROTECTED_HOST_EXECUTION");\n'
                'export default {\n'
                '  async popularNovels() { return []; },\n'
                '  async searchNovels() { return []; },\n'
                '  async parseNovel() { return { chapters: [] }; },\n'
                '  async parseChapter() { return ""; },\n'
                '};\n',
                encoding='utf-8',
            )

            with mock.patch('nox_android.shutil.which', side_effect=_which_without_bwrap):
                self.assertFalse(_has_lnreader_sandbox())

                exec_blocked = nox_scaffold.execute_extension_behavior(
                    'lnreader',
                    [rogue_ts],
                    self.base_url,
                    allow_local_fixture=True,
                )
                self._assert_lnreader_behavior_blocked(exec_blocked)
                self.assertIn('bubblewrap_sandbox_unavailable', exec_blocked.get('failures', []))
                self.assertFalse(host_marker.exists())

                out_sim = tp / 'sim_novel_out'
                created_blocked = nox_scaffold.auto_create_extension(
                    f'Crie um plugin de novel para {self.base_url}',
                    ecosystem='lnreader',
                    allow_local_fixture=True,
                    output_dir=out_sim,
                )
                self._assert_lnreader_create_blocked(created_blocked)
                sim_ts = Path(created_blocked['persisted_files'][0])
                self.assertTrue(sim_ts.is_file())

                sim_ts.write_text(
                    sim_ts.read_text(encoding='utf-8')
                    .replace('.chapter-content', '.broken-content')
                    .replace("    $('script, style, nav').remove();\n", ''),
                    encoding='utf-8',
                )
                fixed_blocked = nox_scaffold.auto_fix_extension(
                    out_sim,
                    'capitulo vazio',
                    ecosystem='lnreader',
                    allow_local_fixture=True,
                    technical=True,
                )
                self._assert_lnreader_fix_blocked(fixed_blocked)
                self.assertIn('.chapter-content', sim_ts.read_text(encoding='utf-8'))
                self.assertIn('remove()', sim_ts.read_text(encoding='utf-8'))
                self.assertFalse(host_marker.exists())


if __name__ == '__main__':
    unittest.main()
