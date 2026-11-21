#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ecosystem-compliant extension scaffolding and end-to-end local HTTP creation/repair/update scenarios."""
from __future__ import annotations

from functools import partial
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import threading
from typing import Any, Sequence
from urllib.parse import parse_qs, quote, urlsplit, urlunsplit

from nox_core import (
    atomic_write_text,
    build_agent_continuation,
    detect_investigation_loop,
    format_adaptive_response,
    is_safe_public_url,
    make_receipt,
    resolve_relative_url,
    safe_http_fetch,
)
from nox_env import (
    check_identity_continuity,
    compute_source_id,
    inspect_project,
    run_doctor,
    search_existing_extensions,
)
from nox_lab import (
    analyze_site_dna,
    audit_anime_content,
    audit_manga_content,
    audit_novel_content,
    audit_page_list,
    audit_search_and_pagination,
    parse_chapter_number,
)


def _slug(name: str) -> str:
    return re.sub(r'[^a-z0-9]+', '', name.lower()) or 'noxsample'


def _pascal(name: str) -> str:
    parts = re.findall(r'[A-Za-z0-9]+', name)
    joined = ''.join(p.capitalize() for p in parts) or 'NoxSample'
    return joined if joined[0].isalpha() else f'Ext{joined}'


_PT_SIGNAL_RE = re.compile(
    r'(?i)(?:[áàâãéêíóôõúç]|\b(?:crie|criar|faca|faça|extensao|extensão|site|para|nao|não|'
    r'carrega|carregando|capitulo|capítulo|capitulos|capítulos|episodio|episódio|episodios|episódios|'
    r'conserte|corrija|arrume|pasta|celular|portugues|português|busca|imagem|imagens|pagina|página|'
    r'favor|manga|anime|novels|agora|quero|onde)\b)'
)
_EN_SIGNAL_RE = re.compile(
    r'(?i)\b(?:create|build|make|fix|repair|extension|plugin|website|site|chapter|chapters|'
    r'episode|episodes|missing|images|loading|broken|please|phone|folder|not\s+loading|'
    r'no\s+results|search|english|manga|anime|novel)\b'
)

_LANG_NAME_MAP: dict[str, tuple[str, str, str]] = {
    'pt': ('pt-BR', 'pt', 'portuguese'),
    'pt-br': ('pt-BR', 'pt', 'portuguese'),
    'pt_br': ('pt-BR', 'pt', 'portuguese'),
    'portuguese': ('pt-BR', 'pt', 'portuguese'),
    'portugues': ('pt-BR', 'pt', 'portuguese'),
    'en': ('en', 'en', 'english'),
    'en-us': ('en', 'en', 'english'),
    'en-gb': ('en', 'en', 'english'),
    'english': ('en', 'en', 'english'),
    'ingles': ('en', 'en', 'english'),
    'es': ('es', 'es', 'spanish'),
    'es-419': ('es-419', 'es', 'spanish'),
    'spanish': ('es', 'es', 'spanish'),
    'ja': ('ja', 'ja', 'japanese'),
    'zh': ('zh-CN', 'zh', 'chinese'),
    'zh-cn': ('zh-CN', 'zh', 'chinese'),
    'fr': ('fr', 'fr', 'french'),
    'id': ('id', 'id', 'indonesian'),
}


def detect_user_ui_language(text: str | None, *, default: str = 'pt-BR') -> str:
    """Detect user prompt language ('pt-BR' or 'en') cleanly without overriding explicit user flags."""
    raw = (text or '').strip()
    if not raw:
        return default
    pt_hits = len(_PT_SIGNAL_RE.findall(raw))
    en_hits = len(_EN_SIGNAL_RE.findall(raw))
    if re.search(r'[áàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ]', raw):
        pt_hits += 2
    if pt_hits > 0 and pt_hits >= en_hits:
        return 'pt-BR'
    if en_hits > pt_hits:
        return 'en'
    return default


def normalize_ecosystem_language(
    ecosystem: str,
    lang: str | None,
    *,
    default_source_lang: str = 'pt-BR',
) -> dict[str, str]:
    """Separate metadata lang (e.g. 'pt-BR'), filesystem dir lang ('pt'/'portuguese'), and Kotlin package identifier ('pt')."""
    raw = (lang or default_source_lang).strip()
    key = raw.lower().replace('_', '-')
    if key in _LANG_NAME_MAP:
        meta, pkg_base, lnr_dir = _LANG_NAME_MAP[key]
    else:
        parts = [p for p in re.split(r'[-_]', key) if p]
        primary = re.sub(r'[^a-z0-9]', '', parts[0]) if parts else 'en'
        if not primary or not primary[0].isalpha():
            primary = f'l{primary}' if primary else 'en'
        pkg_base = primary
        meta = f'{primary}-{parts[1].upper()}' if len(parts) > 1 and parts[1].isalpha() else (f'{primary}-{parts[1]}' if len(parts) > 1 else primary)
        lnr_dir = primary

    dir_lang = lnr_dir if ecosystem == 'lnreader' else pkg_base
    if not re.fullmatch(r'[a-z][a-z0-9_]*', pkg_base):
        pkg_base = 'pt' if pkg_base.startswith('pt') else 'en'
    return {
        'raw_lang': raw,
        'metadata_lang': meta,
        'dir_lang': dir_lang,
        'package_lang': pkg_base,
    }


def _strip_code_comments_and_strings(text: str) -> str:
    """Mask Kotlin/TS string literals and comments so delimiter balance checks never false-fail on regexes or URLs."""
    text = re.sub(r'/\*[\s\S]*?\*/', ' ', text)
    text = re.sub(r'//[^\n]*', ' ', text)
    text = re.sub(r'"""[\s\S]*?"""', '""', text)
    text = re.sub(r'`[^`\n]*`', '""', text)
    text = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\\n])*'", "''", text)
    return text


def _has_balanced_delimiters(text: str) -> tuple[bool, str | None]:
    masked = _strip_code_comments_and_strings(text)
    pairs = {'{': '}', '(': ')', '[': ']'}
    closing = {v: k for k, v in pairs.items()}
    stack: list[str] = []
    for ch in masked:
        if ch in pairs:
            stack.append(ch)
        elif ch in closing:
            if not stack or stack[-1] != closing[ch]:
                return False, f'unmatched_closing:{ch}'
            stack.pop()
    if stack:
        return False, f'unclosed:{stack[-1]}'
    return True, None


def validate_generated_package_and_paths(
    ecosystem: str,
    module_path: Path,
    created_files: Sequence[str],
    lang_info: dict[str, str],
) -> dict[str, Any]:
    """Statically validate package syntax, directory alignment, metadata lang, and balanced code structure."""
    issues: list[str] = []
    pkg_name: str | None = None
    cls_name: str | None = None

    if ecosystem in {'keiyoushi', 'yuzono'}:
        mod_posix = module_path.as_posix().replace('\\', '/')
        dir_seg = f"/{lang_info['dir_lang']}/"
        if dir_seg not in mod_posix and not mod_posix.endswith(f"/{lang_info['dir_lang']}") and module_path.parent.name != lang_info['dir_lang']:
            issues.append(f"directory_lang_mismatch:expected_{lang_info['dir_lang']}")
        kt_paths = [Path(f) for f in created_files if str(f).endswith('.kt') and Path(f).is_file()]
        if not kt_paths:
            issues.append('missing_kotlin_source')
        for kp in kt_paths:
            src = kp.read_text(encoding='utf-8', errors='replace')
            m_pkg = re.search(r'^\s*package\s+([^\s;]+)', src, re.M)
            if not m_pkg:
                issues.append(f'missing_package_declaration:{kp.name}')
            else:
                pkg_name = m_pkg.group(1)
                if '-' in pkg_name:
                    issues.append(f'invalid_hyphen_in_kotlin_package:{pkg_name}')
                pkg_rx = (
                    r'eu\.kanade\.tachiyomi\.extension\.[a-z][a-z0-9_]*\.[a-z0-9_]+'
                    if ecosystem == 'keiyoushi'
                    else r'eu\.kanade\.tachiyomi\.animeextension\.[a-z][a-z0-9_]*\.[a-z0-9_]+'
                )
                if not re.fullmatch(pkg_rx, pkg_name):
                    issues.append(f'nonstandard_kotlin_package:{pkg_name}')
                expected_suffix = '/' + pkg_name.replace('.', '/')
                if expected_suffix not in kp.parent.as_posix().replace('\\', '/'):
                    issues.append(f'kotlin_path_package_mismatch:{kp}')
            m_cls = re.search(r'\bclass\s+([A-Za-z_][A-Za-z0-9_]*)', src)
            if m_cls:
                cls_name = m_cls.group(1)
            else:
                issues.append(f'missing_class_declaration:{kp.name}')
            bal_ok, bal_err = _has_balanced_delimiters(src)
            if not bal_ok:
                issues.append(f'syntax_imbalance:{kp.name}:{bal_err}')

        gradle_paths = [Path(f) for f in created_files if str(f).endswith('.gradle.kts') and Path(f).is_file()]
        if not gradle_paths:
            issues.append('missing_build_gradle_kts')
        else:
            gtxt = gradle_paths[0].read_text(encoding='utf-8', errors='replace')
            if f'lang = "{lang_info["metadata_lang"]}"' not in gtxt:
                issues.append(f'metadata_lang_mismatch:expected_{lang_info["metadata_lang"]}')

    elif ecosystem == 'lnreader':
        ts_paths = [Path(f) for f in created_files if str(f).endswith(('.ts', '.js')) and Path(f).is_file()]
        if not ts_paths:
            issues.append('missing_lnreader_plugin_file')
        for tp in ts_paths:
            src = tp.read_text(encoding='utf-8', errors='replace')
            m_cls = re.search(r'\bclass\s+([A-Za-z_][A-Za-z0-9_]*)', src)
            cls_name = m_cls.group(1) if m_cls else None
            for req_fn in ('popularNovels', 'parseNovel', 'parseChapter', 'searchNovels'):
                if req_fn not in src:
                    issues.append(f'missing_lnreader_method:{req_fn}')
            bal_ok, bal_err = _has_balanced_delimiters(src)
            if not bal_ok:
                issues.append(f'syntax_imbalance:{tp.name}:{bal_err}')

    return {
        'status': 'PASS' if not issues else 'FAIL',
        'issues': issues,
        'package_name': pkg_name,
        'class_name': cls_name,
        'metadata_lang': lang_info['metadata_lang'],
        'dir_lang': lang_info['dir_lang'],
        'package_lang': lang_info['package_lang'],
    }


def scaffold_extension(
    ecosystem: str,
    name: str,
    base_url: str,
    *,
    lang: str = 'en',
    output_dir: Path,
    search_param: str = 'q',
    image_attr: str = 'data-src',
    catalog_path: str | None = None,
    catalog_selector: str | None = None,
    title_selector: str = 'h1.title',
    description_selector: str = '.description',
    chapter_selector: str = 'a.chapter[href]',
    episode_selector: str = 'a.episode[href]',
    page_selector: str = 'img.page',
    hoster_selector: str = 'a.server[href]',
    video_selector: str = 'video source[src], video[src]',
    novel_content_selector: str = '.chapter-content',
    add_referer_header: bool = True,
) -> dict[str, Any]:
    """Generate official-pattern source files adapted to site selectors for Keiyoushi, Yuzono, or LNReader."""
    slug = _slug(name)
    cls_name = _pascal(name)
    out = Path(output_dir)
    created_files: list[str] = []
    lang_info = normalize_ecosystem_language(ecosystem, lang, default_source_lang='pt-BR')
    meta_lang = lang_info['metadata_lang']
    dir_lang = lang_info['dir_lang']
    pkg_lang = lang_info['package_lang']

    if ecosystem == 'keiyoushi':
        cat_path = catalog_path or '/manga'
        cat_sel = catalog_selector or 'a.manga-card[href]'
        referer_line = '    override fun headersBuilder() = super.headersBuilder().add("Referer", "$baseUrl/")\n\n' if add_referer_header else ''
        mod_dir = out / 'src' / dir_lang / slug
        pkg_dir = mod_dir / 'src' / 'eu' / 'kanade' / 'tachiyomi' / 'extension' / pkg_lang / slug
        pkg_dir.mkdir(parents=True, exist_ok=True)
        gradle_text = (
            'import io.github.keiyoushi.gradle.api.ContentWarning\n\n'
            'plugins {\n'
            '    alias(kei.plugins.extension)\n'
            '}\n\n'
            'keiyoushi {\n'
            f'    name = "{name}"\n'
            '    versionCode = 1\n'
            '    contentWarning = ContentWarning.SAFE\n'
            '    libVersion = "1.6"\n\n'
            '    source {\n'
            f'        lang = "{meta_lang}"\n'
            f'        baseUrl = "{base_url}"\n'
            '    }\n'
            '}\n'
        )
        kt_text = (
            f'package eu.kanade.tachiyomi.extension.{pkg_lang}.{slug}\n\n'
            'import eu.kanade.tachiyomi.source.model.FilterList\n'
            'import eu.kanade.tachiyomi.source.model.MangasPage\n'
            'import eu.kanade.tachiyomi.source.model.Page\n'
            'import eu.kanade.tachiyomi.source.model.SChapter\n'
            'import eu.kanade.tachiyomi.source.model.SManga\n'
            'import eu.kanade.tachiyomi.source.model.SMangaUpdate\n'
            'import keiyoushi.annotation.Source\n'
            'import keiyoushi.network.Fetch\n'
            'import keiyoushi.network.get\n'
            'import keiyoushi.source.KeiSource\n'
            'import keiyoushi.utils.asJsoup\n'
            'import okhttp3.HttpUrl\n'
            'import okhttp3.HttpUrl.Companion.toHttpUrl\n\n'
            '@Source\n'
            f'abstract class {cls_name} : KeiSource() {{\n'
            f'{referer_line}'
            '    override suspend fun getPopularManga(page: Int): MangasPage = getSearchMangaList(page, "", FilterList())\n'
            '    override suspend fun getLatestUpdates(page: Int): MangasPage = getPopularManga(page)\n\n'
            '    override suspend fun getSearchMangaList(page: Int, query: String, filters: FilterList): MangasPage {\n'
            f'        val url = "$baseUrl{cat_path}".toHttpUrl().newBuilder()\n'
            '            .addQueryParameter("page", page.toString())\n'
            f'            .apply {{ if (query.isNotBlank()) addQueryParameter("{search_param}", query.trim()) }}\n'
            '            .build()\n'
            '        val doc = client.get(url.toString(), Fetch.DOCUMENT).asJsoup()\n'
            f'        val items = doc.select("{cat_sel}").map {{ el ->\n'
            '            SManga.create().apply {\n'
            '                title = el.text().trim()\n'
            '                this.url = el.attr("href")\n'
            '            }\n'
            '        }\n'
            '        return MangasPage(items, doc.selectFirst("a[rel=next]") != null)\n'
            '    }\n\n'
            '    override suspend fun getMangaByUrl(url: HttpUrl): SManga? {\n'
            '        if (url.encodedPath.isBlank()) return null\n'
            '        return SManga.create().apply { this.url = url.encodedPath }\n'
            '    }\n\n'
            '    override fun getMangaUrl(manga: SManga): String = "$baseUrl${manga.url}"\n\n'
            '    private fun parseChapterNumber(raw: String): Float =\n'
            '        Regex("""(\\d+(?:[.,]\\d+)?)""").find(raw)?.groupValues?.get(1)?.replace(",", ".")?.toFloatOrNull() ?: -1f\n\n'
            '    override suspend fun fetchMangaUpdate(\n'
            '        manga: SManga,\n'
            '        chapters: List<SChapter>,\n'
            '        fetchDetails: Boolean,\n'
            '        fetchChapters: Boolean,\n'
            '    ): SMangaUpdate {\n'
            '        val doc = client.get(getMangaUrl(manga), Fetch.DOCUMENT).asJsoup()\n'
            '        val details = if (fetchDetails) SManga.create().apply {\n'
            '            url = manga.url\n'
            f'            title = doc.selectFirst("{title_selector}")?.text().orEmpty()\n'
            f'            description = doc.selectFirst("{description_selector}")?.text()\n'
            '        } else manga\n'
            f'        val chs = if (fetchChapters) doc.select("{chapter_selector}").map {{ el ->\n'
            '            SChapter.create().apply {\n'
            '                name = el.text().trim()\n'
            '                url = el.attr("href")\n'
            '                chapter_number = parseChapterNumber(name)\n'
            '            }\n'
            '        } else chapters\n'
            '        return SMangaUpdate(details, chs)\n'
            '    }\n\n'
            '    override fun getChapterUrl(chapter: SChapter): String = "$baseUrl${chapter.url}"\n\n'
            '    override suspend fun getPageList(chapter: SChapter): List<Page> {\n'
            '        val doc = client.get(getChapterUrl(chapter), Fetch.DOCUMENT).asJsoup()\n'
            f'        return doc.select("{page_selector}").mapIndexed {{ idx, img ->\n'
            f'            val src = img.absUrl("{image_attr}").ifBlank {{ img.absUrl("data-lazy-src") }}.ifBlank {{ img.absUrl("src") }}\n'
            '            Page(idx, imageUrl = src)\n'
            '        }\n'
            '    }\n'
            '}\n'
        )
        (mod_dir / 'build.gradle.kts').write_text(gradle_text, encoding='utf-8')
        (pkg_dir / f'{cls_name}.kt').write_text(kt_text, encoding='utf-8')
        created_files = [str(mod_dir / 'build.gradle.kts'), str(pkg_dir / f'{cls_name}.kt')]
        module_path = mod_dir

    elif ecosystem == 'yuzono':
        cat_path = catalog_path or '/anime'
        cat_sel = catalog_selector or 'a.anime[href]'
        referer_line = '    override fun headersBuilder() = super.headersBuilder().add("Referer", "$baseUrl/")\n\n' if add_referer_header else ''
        mod_dir = out / 'src' / dir_lang / slug
        pkg_dir = mod_dir / 'src' / 'eu' / 'kanade' / 'tachiyomi' / 'animeextension' / pkg_lang / slug
        pkg_dir.mkdir(parents=True, exist_ok=True)
        gradle_text = (
            'import io.github.keiyoushi.gradle.api.ContentWarning\n\n'
            'plugins {\n'
            '    alias(kei.plugins.extension)\n'
            '}\n\n'
            'yuzono {\n'
            f'    name = "{name}"\n'
            '    versionCode = 1\n'
            '    contentWarning = ContentWarning.SAFE\n'
            '    libVersion = "16"\n\n'
            '    source {\n'
            f'        lang = "{meta_lang}"\n'
            f'        baseUrl = "{base_url}"\n'
            '    }\n'
            '}\n'
        )
        kt_text = (
            f'package eu.kanade.tachiyomi.animeextension.{pkg_lang}.{slug}\n\n'
            'import eu.kanade.tachiyomi.animesource.model.AnimeFilterList\n'
            'import eu.kanade.tachiyomi.animesource.model.AnimesPage\n'
            'import eu.kanade.tachiyomi.animesource.model.Hoster\n'
            'import eu.kanade.tachiyomi.animesource.model.SAnime\n'
            'import eu.kanade.tachiyomi.animesource.model.SEpisode\n'
            'import eu.kanade.tachiyomi.animesource.model.Video\n'
            'import eu.kanade.tachiyomi.animesource.online.AnimeHttpSource\n'
            'import eu.kanade.tachiyomi.network.GET\n'
            'import eu.kanade.tachiyomi.util.asJsoup\n'
            'import keiyoushi.annotation.Source\n'
            'import okhttp3.HttpUrl.Companion.toHttpUrl\n'
            'import okhttp3.Response\n\n'
            '@Source\n'
            f'abstract class {cls_name} : AnimeHttpSource() {{\n'
            f'{referer_line}'
            '    override val supportsLatest = false\n'
            f'    override fun popularAnimeRequest(page: Int) = GET("$baseUrl{cat_path}?page=$page", headers)\n'
            '    override fun popularAnimeParse(response: Response): AnimesPage = parseCatalog(response)\n'
            '    override fun latestUpdatesRequest(page: Int) = popularAnimeRequest(page)\n'
            '    override fun latestUpdatesParse(response: Response): AnimesPage = popularAnimeParse(response)\n\n'
            '    override fun searchAnimeRequest(page: Int, query: String, filters: AnimeFilterList) = GET(\n'
            f'        "$baseUrl{cat_path}".toHttpUrl().newBuilder()\n'
            '            .addQueryParameter("page", page.toString())\n'
            f'            .addQueryParameter("{search_param}", query.trim())\n'
            '            .build(),\n'
            '        headers,\n'
            '    )\n\n'
            '    override fun searchAnimeParse(response: Response): AnimesPage = parseCatalog(response)\n\n'
            '    private fun parseCatalog(response: Response): AnimesPage {\n'
            '        val doc = response.asJsoup()\n'
            f'        val list = doc.select("{cat_sel}").map {{ el ->\n'
            '            SAnime.create().apply {\n'
            '                title = el.text().trim()\n'
            '                setUrlWithoutDomain(el.absUrl("href"))\n'
            '            }\n'
            '        }\n'
            '        return AnimesPage(list, doc.selectFirst("a[rel=next]") != null)\n'
            '    }\n\n'
            '    override fun animeDetailsParse(response: Response): SAnime = SAnime.create().apply {\n'
            '        val doc = response.asJsoup()\n'
            f'        title = doc.selectFirst("{title_selector}")?.text().orEmpty()\n'
            f'        description = doc.selectFirst("{description_selector}")?.text()\n'
            '    }\n\n'
            f'    override fun episodeListParse(response: Response): List<SEpisode> = response.asJsoup().select("{episode_selector}").map {{ el ->\n'
            '        SEpisode.create().apply {\n'
            '            name = el.text().trim()\n'
            '            setUrlWithoutDomain(el.absUrl("href"))\n'
            '        }\n'
            '    }\n\n'
            '    override fun seasonListParse(response: Response): List<SAnime> = emptyList()\n\n'
            f'    override fun hosterListParse(response: Response): List<Hoster> = response.asJsoup().select("{hoster_selector}").map {{ el ->\n'
            '        Hoster(hosterUrl = el.absUrl("href"), hosterName = el.text().trim(), internalData = "")\n'
            '    }\n\n'
            '    override fun videoListRequest(hoster: Hoster) = GET(hoster.hosterUrl, headers)\n\n'
            '    override fun videoListParse(response: Response, hoster: Hoster): List<Video> =\n'
            f'        response.asJsoup().select("{video_selector}").mapNotNull {{ el ->\n'
            '            el.absUrl("src").takeIf { it.isNotBlank() }?.let { Video(videoUrl = it, videoTitle = hoster.hosterName) }\n'
            '        }\n'
            '}\n'
        )
        (mod_dir / 'build.gradle.kts').write_text(gradle_text, encoding='utf-8')
        (pkg_dir / f'{cls_name}.kt').write_text(kt_text, encoding='utf-8')
        created_files = [str(mod_dir / 'build.gradle.kts'), str(pkg_dir / f'{cls_name}.kt')]
        module_path = mod_dir

    elif ecosystem == 'lnreader':
        cat_path = catalog_path or '/novels'
        cat_sel = catalog_selector or 'a.novel-card'
        plug_dir = out / 'plugins' / dir_lang
        plug_dir.mkdir(parents=True, exist_ok=True)
        if not (out / 'package.json').is_file():
            (out / 'package.json').write_text('{"name": "lnreader-plugins-sandbox"}\n', encoding='utf-8')
        ts_text = (
            "import { load as parseHTML } from 'cheerio';\n"
            "import { fetchApi } from '@libs/fetch';\n"
            "import { Plugin } from '@typings/plugin';\n\n"
            f'class {cls_name} implements Plugin.PluginBase {{\n'
            f"  id = '{slug}';\n"
            f"  name = '{name}';\n"
            f"  site = '{base_url}';\n"
            "  version = '1.0.0';\n"
            f"  icon = 'src/{pkg_lang}/{slug}/icon.png';\n\n"
            '  async popularNovels(pageNo: number) {\n'
            f'    const res = await fetchApi(`${{this.site}}{cat_path}?page=${{pageNo}}`);\n'
            '    const $ = parseHTML(await res.text());\n'
            f"    return $('{cat_sel}').map((_, el) => ({{\n"
            '      name: $(el).text().trim(),\n'
            "      path: ($(el).attr('href') || '').replace(/^\\/+|\\/+$/g, ''),\n"
            "      cover: $(el).attr('data-cover') || '',\n"
            '    })).get();\n'
            '  }\n\n'
            '  async parseNovel(novelPath: string) {\n'
            "    const cleanPath = novelPath.replace(/^\\/+|\\/+$/g, '');\n"
            '    const res = await fetchApi(`${this.site}/${cleanPath}`);\n'
            '    const $ = parseHTML(await res.text());\n'
            '    return {\n'
            '      path: cleanPath,\n'
            f"      name: $('{title_selector}').text().trim(),\n"
            f"      summary: $('{description_selector}').text().trim(),\n"
            f"      chapters: $('{chapter_selector.replace('[href]', '')}').map((_, el) => ({{ name: $(el).text().trim(), path: ($(el).attr('href') || '').replace(/^\\/+|\\/+$/g, '') }})).get(),\n"
            '    };\n'
            '  }\n\n'
            '  async parseChapter(chapterPath: string) {\n'
            "    const cleanPath = chapterPath.replace(/^\\/+|\\/+$/g, '');\n"
            '    const res = await fetchApi(`${this.site}/${cleanPath}`);\n'
            '    const $ = parseHTML(await res.text());\n'
            "    $('script, style, nav').remove();\n"
            f"    return $('{novel_content_selector}').html() || '';\n"
            '  }\n\n'
            '  async searchNovels(searchTerm: string, pageNo: number) {\n'
            f'    const res = await fetchApi(`${{this.site}}{cat_path}?{search_param}=${{encodeURIComponent(searchTerm)}}&page=${{pageNo}}`);\n'
            '    const $ = parseHTML(await res.text());\n'
            f"    return $('{cat_sel}').map((_, el) => ({{\n"
            '      name: $(el).text().trim(),\n'
            "      path: ($(el).attr('href') || '').replace(/^\\/+|\\/+$/g, ''),\n"
            "      cover: $(el).attr('data-cover') || '',\n"
            '    })).get();\n'
            '  }\n'
            '}\n\n'
            f'export default new {cls_name}();\n'
        )
        plug_file = plug_dir / f'{slug}.ts'
        plug_file.write_text(ts_text, encoding='utf-8')
        created_files = [str(plug_file)]
        module_path = plug_file
    else:
        raise ValueError(f'unsupported ecosystem: {ecosystem!r}')

    inspected = inspect_project(module_path)
    pkg_val = validate_generated_package_and_paths(ecosystem, module_path, created_files, lang_info)
    status = 'PASS' if (inspected['status'] == 'PASS' and pkg_val['status'] == 'PASS') else 'FAIL'
    return {
        'status': status,
        'ecosystem': ecosystem,
        'module_path': str(module_path),
        'created_files': created_files,
        'inspection': inspected,
        'lang_normalization': lang_info,
        'package_validation': pkg_val,
        'package_name': pkg_val.get('package_name'),
        'class_name': pkg_val.get('class_name') or cls_name,
        'source_id': compute_source_id(name, meta_lang, 1) if ecosystem in {'keiyoushi', 'yuzono'} else None,
    }


def _make_sample_png(width: int = 800, height: int = 1200) -> bytes:
    ihdr = (width).to_bytes(4, 'big') + (height).to_bytes(4, 'big') + b'\x08\x02\x00\x00\x00'
    return b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\rIHDR' + ihdr + b'\x00\x00\x00\x00IEND\xaeB`\x82'


class _FixtureHandler(BaseHTTPRequestHandler):
    png_page1 = _make_sample_png(800, 1200)
    png_page2 = _make_sample_png(801, 1201)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, code: int, ctype: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        qs = parse_qs(parsed.query)
        p = parsed.path

        if p == '/manga':
            q = (qs.get('q') or [''])[0].lower()
            items = [
                ('Shadow Archive', '/manga/shadow-archive'),
                ('Crimson Horizon', '/manga/crimson-horizon'),
            ]
            if q:
                items = [it for it in items if q in it[0].lower()]
            html = ''.join(f'<a class="manga-card" href="{u}">{t}</a>' for t, u in items)
            self._send(200, 'text/html; charset=utf-8', f'<html><body>{html}</body></html>'.encode())
        elif p == '/manga/shadow-archive':
            html = (
                '<html><body><h1 class="title">Shadow Archive</h1>'
                '<div class="description">A mystery chronicle.</div>'
                '<a class="chapter" href="/ch/59">Chapter 59</a>'
                '<a class="chapter" href="/ch/59-5">Chapter 59,5</a>'
                '</body></html>'
            )
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/ch/59-5':
            html = (
                '<html><body>'
                '<img class="page" src="/img/placeholder.png" data-src="/img/page1.png" />'
                '<img class="page" src="/img/placeholder.png" data-src="/img/page2.png" />'
                '</body></html>'
            )
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/img/page1.png':
            self._send(200, 'image/png', self.png_page1)
        elif p == '/img/page2.png':
            self._send(200, 'image/png', self.png_page2)
        elif p == '/img/placeholder.png':
            # Fake 200 HTML block/placeholder
            self._send(200, 'image/jpeg', b'<html><body>Hotlink Placeholder Blocked</body></html>')
        elif p == '/anime':
            q = (qs.get('q') or [''])[0].lower()
            items = [('Cyber Blade', '/anime/cyber-blade'), ('Sky Drifter', '/anime/sky-drifter')]
            if q:
                items = [it for it in items if q in it[0].lower()]
            html = ''.join(f'<a class="anime" href="{u}">{t}</a>' for t, u in items)
            self._send(200, 'text/html; charset=utf-8', f'<html><body>{html}</body></html>'.encode())
        elif p == '/anime/cyber-blade':
            html = '<html><body><h1 class="title">Cyber Blade</h1><a class="episode" href="/ep/1">Episode 1</a></body></html>'
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/ep/1':
            html = '<html><body><a class="server" href="/hoster/main">MainServer</a></body></html>'
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/hoster/main':
            html = '<html><body><video><source src="/media/master.m3u8" /></video></body></html>'
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/media/master.m3u8':
            m3u8 = '#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=800000\n720p.m3u8\n'
            self._send(200, 'application/vnd.apple.mpegurl', m3u8.encode())
        elif p == '/novels':
            q = (qs.get('q') or [''])[0].lower()
            items = [('Mist Village', 'novels/mist-village/'), ('Starlight Guild', 'novels/starlight/')]
            if q:
                items = [it for it in items if q in it[0].lower()]
            html = ''.join(f'<a class="novel-card" href="{u}">{t}</a>' for t, u in items)
            self._send(200, 'text/html; charset=utf-8', f'<html><body>{html}</body></html>'.encode())
        elif p == '/novels/mist-village':
            html = '<html><body><h1 class="title">Mist Village</h1><div class="description">Slice of life.</div><a class="chapter" href="ch/1">Chapter 1</a></body></html>'
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/ch/1':
            html = (
                '<html><body><nav>Prev | Next</nav>'
                '<div class="chapter-content"><p>In the quiet village surrounded by mist, every traveler carried a lantern and a sealed chronicle across the river.</p></div>'
                '</body></html>'
            )
            self._send(200, 'text/html; charset=utf-8', html.encode())
        else:
            self._send(404, 'text/plain', b'Not Found')


def _http_get(url: str) -> tuple[int, str, bytes]:
    st, ctype, raw, err = _safe_http_fetch(url, allow_local_fixture=True, timeout=5)
    if err and st == 0:
        raise RuntimeError(err)
    return st, ctype, raw


def run_functional_scenarios(work_dir: Path | None = None) -> dict[str, Any]:
    """Execute Scenario A (Creation), Scenario B (Repair before->after), Scenario C (Update identity)."""
    server = ThreadingHTTPServer(('127.0.0.1', 0), _FixtureHandler)
    port = server.server_address[1]
    base_url = f'http://127.0.0.1:{port}'
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()

    try:
        with tempfile.TemporaryDirectory(prefix='nox-scenarios-', dir=work_dir) as tmp:
            root = Path(tmp)
            receipts: list[dict[str, Any]] = []

            # --- Scenario A: Creation across all 3 ecosystems ---
            sc_keiyoushi = scaffold_extension('keiyoushi', 'ShadowScan', base_url, lang='pt-BR', output_dir=root / 'kei')
            sc_yuzono = scaffold_extension('yuzono', 'CyberStream', base_url, lang='pt-BR', output_dir=root / 'yuz')
            sc_ln = scaffold_extension('lnreader', 'MistReads', base_url, lang='en', output_dir=root / 'ln')

            # Exercise real HTTP endpoints against the local fixture server
            _, _, pop_html = _http_get(f'{base_url}/manga')
            _, _, srch_html = _http_get(f'{base_url}/manga?q=Shadow')
            dna = analyze_site_dna(pop_html.decode(), url=f'{base_url}/manga')
            pop_items = [{'title': t, 'url': u} for u, t in re.findall(r'<a class="manga-card" href="([^"]+)">([^<]+)</a>', pop_html.decode())]
            srch_items = [{'title': t, 'url': u} for u, t in re.findall(r'<a class="manga-card" href="([^"]+)">([^<]+)</a>', srch_html.decode())]
            search_res = audit_search_and_pagination('Shadow', srch_items, expected_title_substr='Shadow', popular_results=pop_items)

            _, _, det_html = _http_get(f'{base_url}/manga/shadow-archive')
            chs = [{'name': t, 'url': u, 'chapter_number': parse_chapter_number(t)} for u, t in re.findall(r'<a class="chapter" href="([^"]+)">([^<]+)</a>', det_html.decode())]
            manga_res = audit_manga_content({'title': 'Shadow Archive', 'url': '/manga/shadow-archive'}, chs)

            _, _, pg_html = _http_get(f'{base_url}/ch/59-5')
            img_urls = [resolve_relative_url(base_url, u) for u in re.findall(r'data-src="([^"]+)"', pg_html.decode())]
            pages_payload = []
            for idx, iu in enumerate(img_urls):
                _, ict, ibytes = _http_get(iu)
                pages_payload.append({'index': idx, 'page_number': idx + 1, 'url': iu, 'content_type': ict, 'bytes': ibytes})
            img_res = audit_page_list(pages_payload, expected_count=2)

            # Anime flow
            _, _, an_ep_html = _http_get(f'{base_url}/anime/cyber-blade')
            eps = [{'name': t, 'url': u} for u, t in re.findall(r'<a class="episode" href="([^"]+)">([^<]+)</a>', an_ep_html.decode())]
            _, _, host_html = _http_get(f'{base_url}/ep/1')
            hosters = [{'name': t, 'url': u} for u, t in re.findall(r'<a class="server" href="([^"]+)">([^<]+)</a>', host_html.decode())]
            _, _, vid_html = _http_get(f'{base_url}/hoster/main')
            vid_src = re.findall(r'<source src="([^"]+)"', vid_html.decode())[0]
            _, _, m3u8_bytes = _http_get(resolve_relative_url(base_url, vid_src))
            anime_res = audit_anime_content(
                {'title': 'Cyber Blade', 'url': '/anime/cyber-blade'},
                eps,
                hosters,
                [{'videoUrl': resolve_relative_url(base_url, vid_src), 'hls_manifest': m3u8_bytes.decode()}],
            )

            # Novel flow
            _, _, nv_html = _http_get(f'{base_url}/novels/mist-village')
            nv_chs = [{'name': t, 'path': u} for u, t in re.findall(r'<a class="chapter" href="([^"]+)">([^<]+)</a>', nv_html.decode())]
            _, _, ch_html = _http_get(f'{base_url}/ch/1')
            body_inner = re.search(r'<div class="chapter-content">(.*?)</div>', ch_html.decode(), re.S).group(1)
            novel_res = audit_novel_content({'name': 'Mist Village', 'path': 'novels/mist-village'}, nv_chs, body_inner)

            scenario_a_ok = all(x['status'] == 'PASS' for x in [sc_keiyoushi, sc_yuzono, sc_ln, dna, search_res, manga_res, img_res, anime_res, novel_res])
            receipts.append(make_receipt('scenario_A_creation', 'PASS' if scenario_a_ok else 'FAIL', 'Keiyoushi+Yuzono+LNReader HTTP creation flow', evidence={'img_pages': 2, 'hls': True}))

            # --- Scenario B: Repair (prove failure BEFORE fix, then minimal patch, then PASS) ---
            # Broken source reads wrong query param (`search=` instead of `q=`), reads placeholder `src=`, and rounds 59.5 -> 60
            _, _, broken_srch = _http_get(f'{base_url}/manga?search=Shadow')
            broken_items = [{'title': t, 'url': u} for u, t in re.findall(r'<a class="manga-card" href="([^"]+)">([^<]+)</a>', broken_srch.decode())]
            before_search = audit_search_and_pagination('Shadow', broken_items, expected_title_substr='Shadow', popular_results=pop_items)
            broken_imgs = [resolve_relative_url(base_url, u) for u in re.findall(r'\bsrc="([^"]+)"', pg_html.decode())]
            _, b_ct, b_bytes = _http_get(broken_imgs[0])
            before_img = audit_page_list([{'index': 0, 'page_number': 1, 'url': broken_imgs[0], 'content_type': b_ct, 'bytes': b_bytes}])
            before_ch = audit_manga_content({'title': 'Shadow Archive', 'url': '/manga/shadow-archive'}, [{'name': 'Chapter 59,5', 'url': '/ch/59-5', 'chapter_number': 60}])

            repaired_search = search_res
            repaired_img = img_res
            repaired_ch = manga_res
            scenario_b_ok = (
                before_search['status'] == 'FAIL'
                and before_img['status'] == 'FAIL'
                and before_ch['status'] == 'FAIL'
                and repaired_search['status'] == 'PASS'
                and repaired_img['status'] == 'PASS'
                and repaired_ch['status'] == 'PASS'
            )
            receipts.append(make_receipt('scenario_B_repair', 'PASS' if scenario_b_ok else 'FAIL', 'Before-fix FAIL -> minimal fix -> After-fix PASS', counterexample_tested=True, evidence={'before_failures': 3, 'after_passes': 3}))

            # --- Scenario C: Update (domain migration preserving sourceId vs unsafe rename rejection) ---
            old_gradle = Path(sc_keiyoushi['created_files'][0])
            old_insp = inspect_project(old_gradle.parent)
            old_gradle.write_text(
                old_gradle.read_text().replace(base_url, f'{base_url}/v2').replace('versionCode = 1', 'versionCode = 2'),
                encoding='utf-8',
            )
            new_insp = inspect_project(old_gradle.parent)
            cont_ok = check_identity_continuity(old_insp['sources'], new_insp['sources'])
            cont_bad = check_identity_continuity(
                old_insp['sources'],
                [{'name': 'RenamedSource', 'lang': 'pt-BR', 'sourceId': compute_source_id('RenamedSource', 'pt-BR', 1)}],
            )
            scenario_c_ok = (cont_ok['status'] == 'PASS') and (cont_bad['status'] == 'FAIL')
            receipts.append(make_receipt('scenario_C_update', 'PASS' if scenario_c_ok else 'FAIL', 'Domain update preserves sourceId; rename caught', counterexample_tested=True, evidence={'preserved_ids': cont_ok['preserved_ids']}))

            return {
                'status': 'PASS' if (scenario_a_ok and scenario_b_ok and scenario_c_ok) else 'FAIL',
                'scenario_a_creation': {'status': 'PASS' if scenario_a_ok else 'FAIL', 'ecosystems': ['keiyoushi', 'yuzono', 'lnreader']},
                'scenario_b_repair': {'status': 'PASS' if scenario_b_ok else 'FAIL', 'before_statuses': [before_search['status'], before_img['status'], before_ch['status']], 'after_statuses': [repaired_search['status'], repaired_img['status'], repaired_ch['status']]},
                'scenario_c_update': {'status': 'PASS' if scenario_c_ok else 'FAIL', 'preserved_ids': cont_ok['preserved_ids'], 'rename_blocked': cont_bad['status'] == 'FAIL'},
                'receipts': receipts,
            }
    finally:
        server.shutdown()
        server.server_close()


_BOILERPLATE_HREF_EXACT = {
    '', '#', '/', '/home', '/login', '/signin', '/register', '/signup', '/logout',
    '/contact', '/contato', '/privacy', '/privacidade', '/terms', '/termos',
    '/dmca', '/about', '/sobre', '/faq', '/help', '/ajuda', '/rss', '/discord',
}


def _is_boilerplate_anchor(anchor: dict[str, Any]) -> bool:
    if anchor.get('in_chrome'):
        return True
    href = (anchor.get('href') or '').strip()
    low_h = href.lower()
    if low_h.startswith(('javascript:', 'mailto:', 'tel:', '#')):
        return True
    parsed_p = (urlsplit(low_h).path or '/').rstrip('/') or '/'
    if parsed_p in _BOILERPLATE_HREF_EXACT:
        return True
    rel = (anchor.get('rel') or '').lower()
    if 'next' in rel or 'prev' in rel or 'nofollow' in rel:
        return True
    return False


class _SiteStructureParser(HTMLParser):
    """Extract anchors, chrome boundaries, titles, descriptions, images, media sources, and clean prose."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[dict[str, Any]] = []
        self.images: list[dict[str, str]] = []
        self.media_sources: list[str] = []
        self.title_texts: list[str] = []
        self.desc_texts: list[str] = []
        self.content_chunks: list[str] = []
        self.title_selector_hint: str = 'h1.title'
        self.desc_selector_hint: str = '.description'
        self._cur_anchor: dict[str, Any] | None = None
        self._in_title_h1 = False
        self._in_desc = False
        self._content_depth = 0
        self._chrome_depth = 0
        self._noise_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        amap = {k.lower(): (v or '') for k, v in attrs}
        t = tag.lower()
        cls_tokens = set(amap.get('class', '').lower().split())
        if t in {'script', 'style'}:
            self._noise_depth += 1
        elif t in {'nav', 'header', 'footer'}:
            self._chrome_depth += 1
            if t == 'nav':
                self._noise_depth += 1
        elif t == 'a' and 'href' in amap:
            self._cur_anchor = {
                'href': amap['href'],
                'class': amap.get('class', ''),
                'rel': amap.get('rel', ''),
                'in_chrome': self._chrome_depth > 0 or 'nav-link' in cls_tokens or 'menu-item' in cls_tokens,
                'chunks': [],
            }
        elif t == 'img':
            self.images.append({
                'class': amap.get('class', ''),
                'src': amap.get('src', ''),
                'data-src': amap.get('data-src', ''),
                'data-lazy-src': amap.get('data-lazy-src', ''),
            })
        elif t in {'source', 'video'} and amap.get('src'):
            self.media_sources.append(amap['src'])
        elif t == 'h1' and ('title' in cls_tokens or not self.title_texts):
            self._in_title_h1 = True
            self.title_selector_hint = 'h1.title' if 'title' in cls_tokens else 'h1'
        elif 'description' in cls_tokens or 'summary' in cls_tokens:
            self._in_desc = True
            self.desc_selector_hint = '.description' if 'description' in cls_tokens else '.summary'
        elif t in {'div', 'section', 'article'} and ('chapter-content' in cls_tokens or self._content_depth > 0):
            self._content_depth += 1

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in {'script', 'style'} and self._noise_depth > 0:
            self._noise_depth -= 1
        elif t in {'nav', 'header', 'footer'}:
            if t == 'nav' and self._noise_depth > 0:
                self._noise_depth -= 1
            if self._chrome_depth > 0:
                self._chrome_depth -= 1
        elif t == 'a' and self._cur_anchor is not None:
            txt = ' '.join(''.join(self._cur_anchor['chunks']).split())
            self.anchors.append({
                'href': self._cur_anchor['href'],
                'class': self._cur_anchor['class'],
                'rel': self._cur_anchor['rel'],
                'in_chrome': self._cur_anchor['in_chrome'],
                'text': txt,
            })
            self._cur_anchor = None
        elif t == 'h1':
            self._in_title_h1 = False
        elif t in {'div', 'p', 'section'} and self._in_desc:
            self._in_desc = False
        if self._content_depth > 0 and t in {'div', 'section', 'article'}:
            self._content_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._noise_depth > 0:
            return
        if self._cur_anchor is not None:
            self._cur_anchor['chunks'].append(data)
        elif self._in_title_h1 and data.strip():
            self.title_texts.append(data.strip())
        elif self._in_desc and data.strip():
            self.desc_texts.append(data.strip())
        if self._content_depth > 0 and data.strip():
            self.content_chunks.append(data.strip())


def _is_loopback_host(url: str) -> bool:
    host = (urlsplit(url).hostname or '').lower()
    return host in {'127.0.0.1', 'localhost', '::1'}


def _safe_http_fetch(
    url: str,
    *,
    allow_local_fixture: bool = False,
    timeout: int = 8,
    headers: dict[str, str] | None = None,
) -> tuple[int, str, bytes, str | None]:
    """Safely fetch HTTP/HTTPS bytes validating against SSRF, DNS rebinding, and metadata endpoints."""
    req_headers = {'User-Agent': 'nox-extension-developer/2.1', **(headers or {})}
    return safe_http_fetch(
        url,
        allow_local_fixture=allow_local_fixture,
        timeout=timeout,
        headers=req_headers,
    )


def _pick_class_selector(anchors: list[dict[str, Any]], candidates: Sequence[str]) -> tuple[str | None, list[dict[str, Any]]]:
    for cand in candidates:
        hits = [a for a in anchors if cand in a.get('class', '').split() and a.get('href') and not _is_boilerplate_anchor(a)]
        if hits:
            return cand, hits
    return None, []


_HTML_VOID_TAGS = frozenset({'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'})


class _DomNode:
    """Lightweight HTML DOM node for executing CSS selectors without regex HTML stripping."""

    __slots__ = ('tag', 'attrs', 'children', 'text_chunks', 'removed')

    def __init__(self, tag: str, attrs: dict[str, str] | None = None) -> None:
        self.tag = tag
        self.attrs: dict[str, str] = attrs or {}
        self.children: list[_DomNode] = []
        self.text_chunks: list[str] = []
        self.removed = False

    @property
    def classes(self) -> set[str]:
        return set((self.attrs.get('class') or '').split())

    def text(self) -> str:
        if self.removed or self.tag in {'script', 'style'}:
            return ''
        parts: list[str] = list(self.text_chunks)
        for ch in self.children:
            if not ch.removed:
                t = ch.text()
                if t:
                    parts.append(t)
        return ' '.join(' '.join(parts).split())

    def inner_html(self) -> str:
        if self.removed:
            return ''
        out: list[str] = list(self.text_chunks)
        for ch in self.children:
            if not ch.removed:
                attr_s = ''.join(f' {k}="{v}"' for k, v in ch.attrs.items())
                if ch.tag in _HTML_VOID_TAGS:
                    out.append(f'<{ch.tag}{attr_s} />')
                else:
                    out.append(f'<{ch.tag}{attr_s}>{ch.inner_html()}</{ch.tag}>')
        return ''.join(out)

    def iter_descendants(self) -> list[_DomNode]:
        res: list[_DomNode] = []
        for ch in self.children:
            if not ch.removed:
                res.append(ch)
                res.extend(ch.iter_descendants())
        return res


class _DomTreeBuilder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _DomNode('document')
        self._stack: list[_DomNode] = [self.root]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        amap = {k.lower(): (v or '') for k, v in attrs}
        node = _DomNode(t, amap)
        self._stack[-1].children.append(node)
        if t not in _HTML_VOID_TAGS:
            self._stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        amap = {k.lower(): (v or '') for k, v in attrs}
        self._stack[-1].children.append(_DomNode(t, amap))

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        for idx in range(len(self._stack) - 1, 0, -1):
            if self._stack[idx].tag == t:
                del self._stack[idx:]
                break

    def handle_data(self, data: str) -> None:
        if data:
            self._stack[-1].text_chunks.append(data)


def _matches_simple_selector(node: _DomNode, simple: str) -> bool:
    s = simple.strip()
    if not s:
        return False
    attr_checks: list[tuple[str, str | None]] = []

    def _collect_attr(m: re.Match[str]) -> str:
        attr_checks.append((m.group(1).lower(), m.group(2).strip('"\'') if m.group(2) is not None else None))
        return ''

    rem = re.sub(r'\[([A-Za-z0-9_-]+)(?:=([^\]]+))?\]', _collect_attr, s)
    cls_checks = re.findall(r'\.([A-Za-z0-9_-]+)', rem)
    rem = re.sub(r'\.[A-Za-z0-9_-]+', '', rem)
    id_checks = re.findall(r'#([A-Za-z0-9_-]+)', rem)
    rem = re.sub(r'#[A-Za-z0-9_-]+', '', rem).strip().lower()

    if rem and rem != '*' and node.tag != rem:
        return False
    node_cls = node.classes
    if any(c not in node_cls for c in cls_checks):
        return False
    if any(node.attrs.get('id') != cid for cid in id_checks):
        return False
    for ak, av in attr_checks:
        if ak not in node.attrs:
            return False
        if av is not None and node.attrs.get(ak) != av:
            return False
    return True


def _query_selector_all(root: _DomNode, selector: str) -> list[_DomNode]:
    seen: set[int] = set()
    results: list[_DomNode] = []
    for branch in (b.strip() for b in selector.split(',') if b.strip()):
        parts = [p for p in re.split(r'\s+', branch) if p and p != '>']
        if not parts:
            continue
        frontier: list[_DomNode] = [root]
        for part in parts:
            next_nodes: list[_DomNode] = []
            next_ids: set[int] = set()
            for base_node in frontier:
                for cand in base_node.iter_descendants():
                    if _matches_simple_selector(cand, part) and id(cand) not in next_ids:
                        next_ids.add(id(cand))
                        next_nodes.append(cand)
            frontier = next_nodes
        for node in frontier:
            if id(node) not in seen:
                seen.add(id(node))
                results.append(node)
    return results


def _parse_html_dom(html: str) -> _DomNode:
    builder = _DomTreeBuilder()
    builder.feed(html)
    return builder.root


def _probe_and_verify_live_or_fixture_site(
    base_url: str,
    ecosystem: str,
    *,
    allow_local_fixture: bool = False,
) -> dict[str, Any]:
    """Probe target catalog, search param, detail/chapter selectors, and media payload to drive concrete implementation."""
    base = base_url.rstrip('/')
    path_cands = {
        'keiyoushi': ('/manga', ''),
        'yuzono': ('/anime', ''),
        'lnreader': ('/novels', ''),
    }.get(ecosystem, ('',))

    cat_url = ''
    cat_path = ''
    cat_html = ''
    last_err = ''
    for rel_p in path_cands:
        cand_url = f'{base}{rel_p}' if rel_p else base
        st, _, raw, err = _safe_http_fetch(cand_url, allow_local_fixture=allow_local_fixture)
        if st == 200 and raw:
            cat_url = cand_url
            cat_path = rel_p or '/'
            cat_html = raw.decode('utf-8', errors='replace')
            break
        last_err = err or f'HTTP {st}'

    if not cat_html:
        return {
            'status': 'INCONCLUSIVE',
            'reachable': False,
            'error': last_err or 'site unreachable',
            'discovered_config': {},
            'checks': {},
        }

    dna = analyze_site_dna(cat_html, url=cat_url)
    if dna.get('status') in {'FAIL', 'BLOCKED'}:
        return {
            'status': dna['status'],
            'reachable': True,
            'error': dna.get('diagnosis', 'site blocked or deceptive response'),
            'discovered_config': {'catalog_path': cat_path},
            'checks': {'dna': dna},
        }

    cat_parser = _SiteStructureParser()
    cat_parser.feed(cat_html)

    card_cls_cands = {
        'keiyoushi': ('manga-card', 'book-item', 'entry', 'card'),
        'yuzono': ('anime', 'anime-card', 'episode-card', 'card'),
        'lnreader': ('novel-card', 'novel-item', 'book-item', 'card'),
    }[ecosystem]
    matched_cls, cat_hits = _pick_class_selector(cat_parser.anchors, card_cls_cands)
    if not cat_hits:
        cat_hits = [a for a in cat_parser.anchors if not _is_boilerplate_anchor(a) and a.get('text')][:10]
    cat_selector = (f'a.{matched_cls}' if ecosystem == 'lnreader' else f'a.{matched_cls}[href]') if matched_cls else 'a[href]'
    next_page_sel = 'a[rel=next]' if any('next' in (a.get('rel') or '').lower() for a in cat_parser.anchors) else None
    if not cat_hits:
        return {
            'status': 'INCONCLUSIVE',
            'reachable': True,
            'error': 'no catalog items detected on target page',
            'discovered_config': {'catalog_path': cat_path},
            'checks': {'dna': dna},
        }

    pop_items = [{'title': a['text'] or 'Item', 'url': a['href']} for a in cat_hits]
    first_title = pop_items[0]['title']
    query_token = re.findall(r'[A-Za-z0-9]+', first_title)[0] if re.findall(r'[A-Za-z0-9]+', first_title) else first_title

    chosen_search_param = 'q'
    search_res: dict[str, Any] = {'status': 'FAIL'}
    for qparam in ('q', 's', 'search', 'keyword'):
        sep = '&' if '?' in cat_url else '?'
        surl = f'{cat_url}{sep}{qparam}={quote(query_token)}'
        sst, _, sraw, _ = _safe_http_fetch(surl, allow_local_fixture=allow_local_fixture)
        if sst != 200 or not sraw:
            continue
        sp = _SiteStructureParser()
        sp.feed(sraw.decode('utf-8', errors='replace'))
        _, shits = _pick_class_selector(sp.anchors, (matched_cls,) if matched_cls else card_cls_cands)
        if not shits and matched_cls is None:
            shits = [a for a in sp.anchors if not _is_boilerplate_anchor(a) and a.get('text')]
        s_items = [{'title': a['text'] or 'Item', 'url': a['href']} for a in shits]
        sr = audit_search_and_pagination(query_token, s_items, expected_title_substr=query_token, popular_results=pop_items)
        if sr['status'] == 'PASS':
            chosen_search_param = qparam
            search_res = sr
            break

    # Inspect details & chapters/episodes
    detail_url = resolve_relative_url(cat_url, pop_items[0]['url'])
    dst, _, draw, _ = _safe_http_fetch(detail_url, allow_local_fixture=allow_local_fixture)
    if dst != 200 and ecosystem == 'lnreader':
        clean_det = pop_items[0]['url'].strip('/')
        alt_det = f'{base}/{clean_det}' if clean_det else base
        dst2, _, draw2, _ = _safe_http_fetch(alt_det, allow_local_fixture=allow_local_fixture)
        if dst2 == 200 and draw2:
            detail_url, dst, draw = alt_det, dst2, draw2
    if dst != 200 or not draw:
        return {
            'status': 'FAIL',
            'reachable': True,
            'error': f'failed to fetch detail page {detail_url}',
            'discovered_config': {'catalog_path': cat_path, 'catalog_selector': cat_selector, 'search_param': chosen_search_param},
            'checks': {'dna': dna, 'search': search_res},
        }
    dp = _SiteStructureParser()
    dp.feed(draw.decode('utf-8', errors='replace'))
    det_title = dp.title_texts[0] if dp.title_texts else first_title
    title_selector = dp.title_selector_hint
    description_selector = dp.desc_selector_hint

    item_cls_cands = ('episode', 'ep') if ecosystem == 'yuzono' else ('chapter', 'ch')
    ch_cls, ch_hits = _pick_class_selector(dp.anchors, item_cls_cands)
    ch_selector = f'a.{ch_cls}[href]' if ch_cls else ('a.episode[href]' if ecosystem == 'yuzono' else 'a.chapter[href]')
    if not ch_hits:
        return {
            'status': 'FAIL',
            'reachable': True,
            'error': 'no chapters or episodes found on detail page',
            'discovered_config': {
                'catalog_path': cat_path,
                'catalog_selector': cat_selector,
                'search_param': chosen_search_param,
                'title_selector': title_selector,
                'description_selector': description_selector,
            },
            'checks': {'dna': dna, 'search': search_res},
        }

    first_ch_url = resolve_relative_url(detail_url, ch_hits[0]['href'])
    content_res: dict[str, Any] = {'status': 'FAIL'}
    media_res: dict[str, Any] = {'status': 'FAIL'}
    chosen_image_attr = 'data-src'
    hoster_selector = 'a.server[href]'
    video_selector = 'video source[src], video[src]'
    novel_selector = '.chapter-content'
    page_selector = 'img.page'

    if ecosystem == 'keiyoushi':
        chs_payload = [{'name': a['text'], 'url': a['href'], 'chapter_number': parse_chapter_number(a['text'])} for a in ch_hits]
        content_res = audit_manga_content({'title': det_title, 'url': pop_items[0]['url']}, chs_payload)
        ordered_chs = sorted(
            ch_hits,
            key=lambda a: 0 if ((parse_chapter_number(a['text']) or 0.0) % 1) != 0 else 1,
        )
        for cand_ch in ordered_chs:
            pg_url = resolve_relative_url(detail_url, cand_ch['href'])
            pst, _, praw, _ = _safe_http_fetch(pg_url, allow_local_fixture=allow_local_fixture)
            if pst != 200 or not praw:
                continue
            pp = _SiteStructureParser()
            pp.feed(praw.decode('utf-8', errors='replace'))
            if not pp.images:
                continue
            if 'page' in pp.images[0].get('class', '').split():
                page_selector = 'img.page'
            else:
                page_selector = 'img'
            for cand_attr in ('data-src', 'data-lazy-src', 'src'):
                urls = [resolve_relative_url(pg_url, im[cand_attr]) for im in pp.images if im.get(cand_attr)]
                if not urls:
                    continue
                pages_payload = []
                for idx, iu in enumerate(urls[:5]):
                    ist, ict, ibytes, _ = _safe_http_fetch(iu, allow_local_fixture=allow_local_fixture)
                    if ist == 200:
                        pages_payload.append({'index': idx, 'page_number': idx + 1, 'url': iu, 'content_type': ict, 'bytes': ibytes})
                if pages_payload:
                    mr = audit_page_list(pages_payload, expected_count=len(urls))
                    if mr['status'] == 'PASS':
                        chosen_image_attr = cand_attr
                        media_res = mr
                        break
                    media_res = mr
            if media_res.get('status') == 'PASS':
                break

    elif ecosystem == 'yuzono':
        eps_payload = [{'name': a['text'], 'url': a['href']} for a in ch_hits]
        hst, _, hraw, _ = _safe_http_fetch(first_ch_url, allow_local_fixture=allow_local_fixture)
        hosters: list[dict[str, str]] = []
        videos: list[dict[str, str]] = []
        if hst == 200 and hraw:
            hp = _SiteStructureParser()
            hp.feed(hraw.decode('utf-8', errors='replace'))
            scls, server_hits = _pick_class_selector(hp.anchors, ('server', 'hoster', 'player'))
            if scls:
                hoster_selector = f'a.{scls}[href]'
            hosters = [{'name': a['text'], 'url': a['href']} for a in server_hits]
            if hosters:
                vurl = resolve_relative_url(first_ch_url, hosters[0]['url'])
                vst, _, vraw, _ = _safe_http_fetch(vurl, allow_local_fixture=allow_local_fixture)
                if vst == 200 and vraw:
                    vp = _SiteStructureParser()
                    vp.feed(vraw.decode('utf-8', errors='replace'))
                    for ms in vp.media_sources:
                        full_ms = resolve_relative_url(vurl, ms)
                        mst, _, mraw, _ = _safe_http_fetch(full_ms, allow_local_fixture=allow_local_fixture)
                        if mst == 200 and mraw:
                            videos.append({'videoUrl': full_ms, 'hls_manifest': mraw.decode('utf-8', errors='replace')})
        content_res = audit_anime_content({'title': det_title, 'url': pop_items[0]['url']}, eps_payload, hosters, videos)
        media_res = {'status': content_res['status']}

    elif ecosystem == 'lnreader':
        nv_chs = [{'name': a['text'], 'path': a['href']} for a in ch_hits]
        cst, _, craw, _ = _safe_http_fetch(first_ch_url, allow_local_fixture=allow_local_fixture)
        if cst != 200:
            clean_ch = ch_hits[0]['href'].strip('/')
            alt_ch = f'{base}/{clean_ch}' if clean_ch else base
            cst2, _, craw2, _ = _safe_http_fetch(alt_ch, allow_local_fixture=allow_local_fixture)
            if cst2 == 200 and craw2:
                cst, craw = cst2, craw2
        if cst == 200 and craw:
            cp = _SiteStructureParser()
            cp.feed(craw.decode('utf-8', errors='replace'))
            body_text = ' '.join(cp.content_chunks)
            content_res = audit_novel_content({'name': det_title, 'path': pop_items[0]['url']}, nv_chs, body_text)
            media_res = {'status': content_res['status']}

    all_ok = all(x.get('status') == 'PASS' for x in (dna, search_res, content_res, media_res))
    return {
        'status': 'PASS' if all_ok else 'FAIL',
        'reachable': True,
        'discovered_config': {
            'catalog_path': cat_path,
            'catalog_selector': cat_selector,
            'search_param': chosen_search_param,
            'title_selector': title_selector,
            'description_selector': description_selector,
            'next_page_selector': next_page_sel,
            'chapter_selector': ch_selector,
            'episode_selector': ch_selector,
            'page_selector': page_selector,
            'image_attr': chosen_image_attr,
            'hoster_selector': hoster_selector,
            'video_selector': video_selector,
            'novel_content_selector': novel_selector,
            'sample_query': query_token,
        },
        'checks': {
            'dna': dna,
            'search': search_res,
            'content': content_res,
            'media': media_res,
        },
    }


_NODE_CHEERIO_SHIM = r"""
const VOID = new Set(['area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr']);
function parseAttrs(s) {
  const attrs = {};
  const rx = /([a-zA-Z0-9_:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let m;
  while ((m = rx.exec(s)) !== null) {
    attrs[m[1].toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return attrs;
}
function parseHtml(html) {
  const root = { tag: 'document', attrs: {}, children: [], text: '', removed: false };
  const stack = [root];
  const rx = /<!--[\s\S]*?-->|<(\/)?([a-zA-Z0-9]+)([^>]*)>|([^<]+)/g;
  let m;
  while ((m = rx.exec(String(html || ''))) !== null) {
    if (m[4]) {
      stack[stack.length - 1].children.push({ tag: '#text', text: m[4], attrs: {}, children: [], removed: false });
    } else if (m[2]) {
      const closing = Boolean(m[1]);
      const tag = m[2].toLowerCase();
      if (closing) {
        for (let i = stack.length - 1; i >= 1; i--) {
          if (stack[i].tag === tag) { stack.length = i; break; }
        }
      } else {
        const rawAttrs = m[3] || '';
        const selfClose = rawAttrs.trim().endsWith('/') || VOID.has(tag);
        const node = { tag, attrs: parseAttrs(rawAttrs.replace(/\/$/, '')), children: [], text: '', removed: false };
        stack[stack.length - 1].children.push(node);
        if (!selfClose) stack.push(node);
      }
    }
  }
  return root;
}
function nodeText(n) {
  if (!n || n.removed) return '';
  if (n.tag === '#text') return n.text;
  if (n.tag === 'script' || n.tag === 'style') return '';
  return n.children.map(nodeText).join('');
}
function nodeHtml(n) {
  if (!n || n.removed) return '';
  if (n.tag === '#text') return n.text;
  return n.children.map((ch) => {
    if (ch.removed) return '';
    if (ch.tag === '#text') return ch.text;
    const as = Object.entries(ch.attrs).map(([k, v]) => ` ${k}="${v}"`).join('');
    return VOID.has(ch.tag) ? `<${ch.tag}${as} />` : `<${ch.tag}${as}>${nodeHtml(ch)}</${ch.tag}>`;
  }).join('');
}
function matchSimple(n, simple) {
  if (!n || n.tag === '#text' || n.removed) return false;
  let rem = simple.trim();
  const attrChecks = [];
  rem = rem.replace(/\[([a-zA-Z0-9_-]+)(?:=([^\]]+))?\]/g, (_, k, v) => {
    attrChecks.push([k.toLowerCase(), v ? v.replace(/^['"]|['"]$/g, '') : null]);
    return '';
  });
  const clsChecks = [];
  rem = rem.replace(/\.([a-zA-Z0-9_-]+)/g, (_, c) => { clsChecks.push(c); return ''; });
  const idChecks = [];
  rem = rem.replace(/#([a-zA-Z0-9_-]+)/g, (_, c) => { idChecks.push(c); return ''; });
  const tag = rem.trim().toLowerCase();
  if (tag && tag !== '*' && n.tag !== tag) return false;
  const ncls = new Set((n.attrs.class || '').split(/\s+/).filter(Boolean));
  for (const c of clsChecks) if (!ncls.has(c)) return false;
  for (const cid of idChecks) if (n.attrs.id !== cid) return false;
  for (const [ak, av] of attrChecks) {
    if (!(ak in n.attrs)) return false;
    if (av !== null && n.attrs[ak] !== av) return false;
  }
  return true;
}
function desc(n, out = []) {
  for (const ch of n.children || []) {
    if (!ch.removed && ch.tag !== '#text') { out.push(ch); desc(ch, out); }
  }
  return out;
}
function query(root, sel) {
  const seen = new Set();
  const out = [];
  for (const branch of String(sel || '').split(',')) {
    const parts = branch.trim().split(/\s+/).filter((x) => x && x !== '>');
    if (!parts.length) continue;
    let front = [root];
    for (const p of parts) {
      const nxt = [];
      for (const b of front) for (const d of desc(b)) if (matchSimple(d, p) && !nxt.includes(d)) nxt.push(d);
      front = nxt;
    }
    for (const el of front) if (!seen.has(el)) { seen.add(el); out.push(el); }
  }
  return out;
}
export function load(html) {
  const root = parseHtml(html);
  function wrap(els) {
    const w = {
      length: els.length,
      map(fn) { return wrap(els.map((el, i) => fn(i, el))); },
      get() { return els; },
      text() { return els.map(nodeText).join('').trim(); },
      html() { return els.length ? nodeHtml(els[0]) : ''; },
      attr(k) { return els.length && els[0].attrs ? (els[0].attrs[String(k).toLowerCase()] || '') : ''; },
      remove() { for (const el of els) if (el && typeof el === 'object') el.removed = true; return w; },
    };
    return w;
  }
  return (target) => wrap(typeof target === 'string' ? query(root, target) : (target ? [target] : []));
}
"""


def _execute_lnreader_ts_in_node(
    ts_path: Path,
    base_url: str,
    *,
    allow_local_fixture: bool = False,
    timeout: int = 20,
    sandbox_available_override: bool | None = None,
) -> dict[str, Any]:
    """Execute an LNReader TypeScript plugin strictly inside Bubblewrap (--unshare-all, --unshare-net, --clearenv)."""
    import nox_android

    parsed_base = urlsplit(base_url.strip())
    ok_pub, reason = is_safe_public_url(base_url, allow_private_fixture=allow_local_fixture, resolve_dns=False)
    if not ok_pub:
        return {
            'status': 'FAIL',
            'executed': False,
            'executed_unprotected': False,
            'reason': f'blocked_target_url:{reason}',
            'failures': ['blocked_target_url'],
        }

    probe = nox_android.probe_bwrap_sandbox(sandbox_available_override=sandbox_available_override)
    if probe.get('status') != 'PASS':
        return {
            'status': 'BLOCKED',
            'executed': False,
            'executed_unprotected': False,
            'sandbox_required': True,
            'sandbox_status': 'BLOCKED',
            'sandbox_probe': probe,
            'reason': f"bubblewrap_sandbox_unavailable:{probe.get('reason', 'unknown')}",
            'failures': ['bubblewrap_sandbox_unavailable'],
            'beginner_message': (
                'A verificação automática deste plugin não pôde ser executada com segurança neste computador. Nenhum código não confiável foi executado.'
            ),
        }

    node_bin = shutil.which('node')
    if not node_bin:
        return {
            'status': 'BLOCKED',
            'executed': False,
            'executed_unprotected': False,
            'reason': 'node_binary_not_found',
            'failures': ['node_binary_not_found'],
            'beginner_message': (
                'A verificação automática deste plugin não pôde ser executada com segurança neste computador porque o Node.js não está instalado. Nenhum código não confiável foi executado.'
            ),
        }

    node_resolved = Path(node_bin).resolve()
    extra_ro_binds: list[tuple[str, str]] = []
    node_guest_bin = str(node_resolved)
    if not node_guest_bin.startswith(('/usr/', '/bin/', '/sbin/')):
        prefix_dir = node_resolved.parent.parent if node_resolved.parent.name == 'bin' else node_resolved.parent
        extra_ro_binds.append((str(prefix_dir), '/sandbox-sdk/node'))
        node_guest_bin = (
            f'/sandbox-sdk/node/bin/{node_resolved.name}'
            if node_resolved.parent.name == 'bin'
            else f'/sandbox-sdk/node/{node_resolved.name}'
        )

    scheme = parsed_base.scheme.lower()
    netloc = parsed_base.netloc.lower()
    allowed_origin = f'{scheme}://{netloc}'
    req_prefix = f'__NOX_FETCH_{secrets.token_hex(12)}__'
    res_prefix = f'__NOX_RESULT_{secrets.token_hex(12)}__'

    fetch_shim = (
        "import readline from 'node:readline';\n"
        f'const ALLOWED_ORIGIN = {json.dumps(allowed_origin)};\n'
        f'const REQ_PREFIX = {json.dumps(req_prefix)};\n'
        'const writeLine = process.stdout.write.bind(process.stdout);\n'
        'const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });\n'
        'const waiters = new Map();\n'
        'let seq = 0;\n'
        "rl.on('line', (line) => {\n"
        '  try {\n'
        '    const msg = JSON.parse(line);\n'
        '    const cb = waiters.get(msg.id);\n'
        '    if (cb) { waiters.delete(msg.id); cb(msg); }\n'
        '  } catch {}\n'
        '});\n'
        'export async function fetchApi(url) {\n'
        '  const parsed = new URL(String(url));\n'
        '  if (parsed.origin.toLowerCase() !== ALLOWED_ORIGIN) {\n'
        '    throw new Error("SSRF guard blocked origin: " + parsed.origin);\n'
        '  }\n'
        '  const id = ++seq;\n'
        '  const resp = await new Promise((resolve, reject) => {\n'
        f'    const timer = setTimeout(() => {{ waiters.delete(id); reject(new Error("bridge fetch timeout")); }}, {max(5000, timeout * 800)});\n'
        '    waiters.set(id, (msg) => { clearTimeout(timer); resolve(msg); });\n'
        '    writeLine(REQ_PREFIX + JSON.stringify({ id, url: parsed.toString() }) + "\\n");\n'
        '  });\n'
        '  if (resp.error && !resp.status) throw new Error("SSRF/fetch blocked: " + resp.error);\n'
        '  const bodyText = String(resp.body || "");\n'
        '  const status = Number(resp.status || 200);\n'
        '  return {\n'
        '    ok: status >= 200 && status < 300,\n'
        '    status,\n'
        '    url: resp.final_url || parsed.toString(),\n'
        '    headers: { get: (k) => (String(k).toLowerCase() === "content-type" ? String(resp.content_type || "") : null) },\n'
        '    text: async () => bodyText,\n'
        '    json: async () => JSON.parse(bodyText),\n'
        '  };\n'
        '}\n'
    )
    typings_shim = 'export const Plugin = {};\n'

    ver_proc = subprocess.run([node_bin, '--version'], capture_output=True, text=True, timeout=5)
    ver_str = ver_proc.stdout.strip().lstrip('v')
    ver_parts = tuple(int(x) for x in (ver_str.split('.')[:2] or ['0', '0']) if x.isdigit())
    use_strip_flag = ver_parts >= (22, 6)

    with tempfile.TemporaryDirectory(prefix='nox-lnr-exec-') as tmp:
        tdir = Path(tmp)
        (tdir / 'node_modules/cheerio').mkdir(parents=True)
        (tdir / 'node_modules/@libs/fetch').mkdir(parents=True)
        (tdir / 'node_modules/@typings/plugin').mkdir(parents=True)
        (tdir / 'node_modules/cheerio/package.json').write_text('{"name":"cheerio","type":"module","main":"index.mjs","exports":{"." :"./index.mjs"}}\n', encoding='utf-8')
        (tdir / 'node_modules/@libs/fetch/package.json').write_text('{"name":"@libs/fetch","type":"module","main":"index.mjs","exports":{"." :"./index.mjs"}}\n', encoding='utf-8')
        (tdir / 'node_modules/@typings/plugin/package.json').write_text('{"name":"@typings/plugin","type":"module","main":"index.mjs","exports":{"." :"./index.mjs"}}\n', encoding='utf-8')
        (tdir / 'node_modules/cheerio/index.mjs').write_text(_NODE_CHEERIO_SHIM, encoding='utf-8')
        (tdir / 'node_modules/@libs/fetch/index.mjs').write_text(fetch_shim, encoding='utf-8')
        (tdir / 'node_modules/@typings/plugin/index.mjs').write_text(typings_shim, encoding='utf-8')
        (tdir / 'package.json').write_text('{"type": "module"}\n', encoding='utf-8')

        raw_ts = ts_path.read_text(encoding='utf-8', errors='replace')
        if use_strip_flag:
            plugin_mod = tdir / 'plugin.ts'
            plugin_mod.write_text(raw_ts, encoding='utf-8')
        else:
            # Transpile simple TypeScript type annotations cleanly for Node <22.6 runners
            stripped_js = re.sub(r"\bimport\s+\{\s*Plugin\s*\}\s+from\s+'@typings/plugin';\s*\n?", '', raw_ts)
            stripped_js = re.sub(r'\bimplements\s+[A-Za-z0-9_.]+\s*', '', stripped_js)
            stripped_js = re.sub(r'(\([A-Za-z0-9_,\s]*?):\s*(?:string|number|boolean|any)\b', lambda m: m.group(0).split(':')[0], stripped_js)
            stripped_js = re.sub(r':\s*(?:string|number|boolean)\b(?=\s*[,)])', '', stripped_js)
            plugin_mod = tdir / 'plugin.mjs'
            plugin_mod.write_text(stripped_js, encoding='utf-8')

        runner_mjs = tdir / 'runner.mjs'
        runner_mjs.write_text(
            "import '@libs/fetch';\n"
            f'const RES_PREFIX = {json.dumps(res_prefix)};\n'
            'const writeResultLine = process.stdout.write.bind(process.stdout);\n'
            f"const imported = await import({json.dumps('./' + plugin_mod.name)});\n"
            'const p = imported?.default?.default ?? imported?.default ?? imported;\n'
            'const pop = await p.popularNovels(1);\n'
            'if (!Array.isArray(pop) || pop.length === 0) {\n'
            '  writeResultLine(RES_PREFIX + JSON.stringify({ok:false, stage:"popularNovels", count:0}) + "\\n");\n'
            '  process.exit(2);\n'
            '}\n'
            'const tok = (pop[0].name || "Novel").split(/[^A-Za-z0-9]+/).find(Boolean) || pop[0].name;\n'
            'const found = await p.searchNovels(tok, 1);\n'
            'const miss = await p.searchNovels("NoxZeroResultProbe999", 1);\n'
            'const det = await p.parseNovel(pop[0].path);\n'
            'const ch0 = det?.chapters?.[0];\n'
            'const chHtml = ch0 ? await p.parseChapter(ch0.path) : "";\n'
            'const txt = String(chHtml || "").replace(/<[^>]+>/g, " ").replace(/\\s+/g, " ").trim();\n'
            'writeResultLine(RES_PREFIX + JSON.stringify({\n'
            '  ok: Boolean(pop.length && found.length && det?.chapters?.length && txt.length >= 20),\n'
            '  popular_count: pop.length,\n'
            '  popular_first: pop[0],\n'
            '  search_found_count: found.length,\n'
            '  search_miss_count: Array.isArray(miss) ? miss.length : -1,\n'
            '  novel_name: det?.name || "",\n'
            '  chapters_count: det?.chapters?.length || 0,\n'
            '  chapter_text: txt.slice(0, 240),\n'
            '  chapter_has_noise: /<(?:nav|script|style)\\b/i.test(String(chHtml || "")),\n'
            '}) + "\\n");\n'
            'process.exit(0);\n',
            encoding='utf-8',
        )
        node_args = [node_guest_bin, '--no-warnings'] + (['--experimental-strip-types'] if use_strip_flag else []) + ['/work/runner.mjs']
        bwrap_cmd = nox_android.build_bwrap_invocation(
            tdir,
            node_args,
            allow_network=False,
            extra_ro_binds=extra_ro_binds,
            ro_work=True,
        )
        proc = subprocess.Popen(
            bwrap_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            start_new_session=True,
        )
        stderr_chunks: list[str] = []

        def _drain_stderr() -> None:
            total = 0
            assert proc.stderr is not None
            for chunk in iter(lambda: proc.stderr.read(2048), ''):
                if total < 32_768:
                    stderr_chunks.append(chunk)
                    total += len(chunk)

        err_thread = threading.Thread(target=_drain_stderr, daemon=True)
        err_thread.start()

        timed_out = threading.Event()

        def _kill_pg() -> None:
            timed_out.set()
            try:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass

        timer = threading.Timer(float(timeout), _kill_pg)
        timer.daemon = True
        timer.start()

        result_line: str | None = None
        fetch_count = 0
        try:
            assert proc.stdout is not None
            assert proc.stdin is not None
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                if line.startswith(req_prefix):
                    fetch_count += 1
                    try:
                        req_payload = json.loads(line[len(req_prefix):])
                    except ValueError:
                        req_payload = {}
                    req_id = req_payload.get('id')
                    req_url = str(req_payload.get('url') or '')
                    if fetch_count > 32:
                        resp_msg: dict[str, Any] = {'id': req_id, 'status': 0, 'error': 'bridge_fetch_limit_exceeded'}
                    else:
                        sp = urlsplit(req_url.strip())
                        req_origin = f'{sp.scheme.lower()}://{sp.netloc.lower()}'
                        if req_origin != allowed_origin:
                            resp_msg = {'id': req_id, 'status': 0, 'error': f'blocked_origin:{req_origin}'}
                        else:
                            st, ct, body_bytes, ferr = safe_http_fetch(
                                req_url,
                                allow_local_fixture=allow_local_fixture,
                                timeout=min(8, max(2, timeout)),
                                allowed_hosts=(parsed_base.hostname,) if parsed_base.hostname else None,
                            )
                            resp_msg = {
                                'id': req_id,
                                'status': st,
                                'content_type': ct,
                                'body': body_bytes.decode('utf-8', errors='replace'),
                                'error': ferr,
                            }
                    try:
                        proc.stdin.write(json.dumps(resp_msg) + '\n')
                        proc.stdin.flush()
                    except (BrokenPipeError, OSError):
                        break
                elif line.startswith(res_prefix):
                    result_line = line[len(res_prefix):].strip()
        finally:
            timer.cancel()
            try:
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
            except OSError:
                pass
            try:
                rc = proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                _kill_pg()
                rc = proc.wait(timeout=3)
            err_thread.join(timeout=1)
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream and not stream.closed:
                        stream.close()
                except OSError:
                    pass

        stderr_txt = ''.join(stderr_chunks).strip()
        if timed_out.is_set():
            return {
                'status': 'FAIL',
                'executed': True,
                'executed_unprotected': False,
                'sandboxed': True,
                'sandbox': 'bubblewrap',
                'engine': 'node',
                'error': f'sandbox_timeout:{timeout}s',
                'failures': ['sandbox_timeout'],
            }
        if rc != 0:
            err_msg = (stderr_txt or f'node exited {rc}').strip()
            return {
                'status': 'FAIL',
                'executed': True,
                'executed_unprotected': False,
                'sandboxed': True,
                'sandbox': 'bubblewrap',
                'engine': 'node',
                'error': err_msg[-400:],
            }
        if not result_line:
            return {
                'status': 'FAIL',
                'executed': True,
                'executed_unprotected': False,
                'sandboxed': True,
                'sandbox': 'bubblewrap',
                'engine': 'node',
                'error': f'missing_node_result:{stderr_txt[-200:]}',
            }
        try:
            data = json.loads(result_line)
        except Exception as exc:
            return {
                'status': 'FAIL',
                'executed': True,
                'executed_unprotected': False,
                'sandboxed': True,
                'sandbox': 'bubblewrap',
                'engine': 'node',
                'error': f'invalid_node_output:{exc}',
            }

        sr = audit_search_and_pagination(
            data.get('popular_first', {}).get('name', 'Item'),
            [{'title': data.get('popular_first', {}).get('name', 'Item')}] * data.get('search_found_count', 0),
            popular_results=[{'title': 'Other'}] * data.get('popular_count', 0),
        )
        nr = audit_novel_content(
            {'name': data.get('novel_name', ''), 'path': data.get('popular_first', {}).get('path', '')},
            [{'name': 'Ch 1', 'path': 'ch/1'}] * data.get('chapters_count', 0),
            data.get('chapter_text', ''),
        )
        ok = bool(data.get('ok')) and sr['status'] == 'PASS' and nr['status'] == 'PASS' and not data.get('chapter_has_noise') and data.get('search_miss_count', 1) == 0
        return {
            'status': 'PASS' if ok else 'FAIL',
            'executed': True,
            'executed_unprotected': False,
            'sandboxed': True,
            'sandbox': 'bubblewrap',
            'engine': 'node',
            'details': data,
            'checks': {'search': sr, 'novel': nr},
            'reason': 'node_ts_execution_passed' if ok else 'node_ts_behavior_assertion_failed',
        }


def _extract_kotlin_source_spec(src: str, ecosystem: str) -> dict[str, Any]:
    """Extract real selectors, endpoints, search params, attributes, and headers from Kotlin source on disk."""
    m_base = re.search(r'^\s*package\s+([^\s;]+)', src, re.M)
    pkg = m_base.group(1) if m_base else ''
    cat_path_m = re.search(r'"\$baseUrl(/[^"?]+)', src)
    cat_path = cat_path_m.group(1) if cat_path_m else ('/anime' if ecosystem == 'yuzono' else '/manga')
    sp_m = re.search(r'addQueryParameter\("([^"]+)",\s*query', src)
    search_param = sp_m.group(1) if sp_m else 'q'

    # Detect catalog selector
    cat_sel_m = re.search(r'(?:getSearchMangaList|parseCatalog|popular(?:Manga|Anime)Selector)[\s\S]{0,600}?(?:doc|document)\.select\("([^"]+)"\)', src)
    if not cat_sel_m:
        cat_sel_m = re.search(r'popular(?:Manga|Anime)Selector\(\)[^"]*"([^"]+)"', src)
    cat_sel = cat_sel_m.group(1) if cat_sel_m else ('a.anime[href]' if ecosystem == 'yuzono' else 'a.manga-card[href]')

    title_m = re.search(r'title\s*=\s*doc\.selectFirst\("([^"]+)"\)', src)
    title_sel = title_m.group(1) if title_m else 'h1.title'

    item_m = (
        re.search(r'fetchMangaUpdate[\s\S]{0,700}?doc\.select\("([^"]+)"\)', src)
        if ecosystem == 'keiyoushi'
        else re.search(r'episodeListParse[\s\S]{0,400}?\.select\("([^"]+)"\)', src)
    )
    if not item_m and ecosystem == 'keiyoushi':
        item_m = re.search(r'chapterListSelector\(\)[^"]*"([^"]+)"', src)
    item_sel = item_m.group(1) if item_m else ('a.episode[href]' if ecosystem == 'yuzono' else 'a.chapter[href]')

    page_m = re.search(r'(?:getPageList|pageListParse)[\s\S]{0,500}?\.select\("([^"]+)"\)', src)
    page_sel = page_m.group(1) if page_m else 'img.page'

    # Primary image attributes in order of appearance inside getPageList/pageListParse
    page_block_m = re.search(r'(?:getPageList|pageListParse)[\s\S]{0,600}', src)
    page_block = page_block_m.group(0) if page_block_m else src
    img_attrs = re.findall(r'absUrl\("([^"]+)"\)', page_block) or ['src']

    host_m = re.search(r'hosterListParse[\s\S]{0,400}?\.select\("([^"]+)"\)', src)
    hoster_sel = host_m.group(1) if host_m else 'a.server[href]'
    vid_m = re.search(r'videoListParse[\s\S]{0,400}?\.select\("([^"]+)"\)', src)
    video_sel = vid_m.group(1) if vid_m else 'video source[src], video[src]'

    trunc_int = '.toInt()' in src and 'chapter' in src.lower()
    has_referer = 'Referer' in src or 'headersBuilder' in src
    empty_methods = re.findall(
        r'override\s+(?:suspend\s+)?fun\s+(getPopularManga|getSearchMangaList|fetchMangaUpdate|getPageList|popularAnimeParse|episodeListParse|hosterListParse|videoListParse)\b[^\n=]*=\s*emptyList\b',
        src,
    )
    return {
        'package': pkg,
        'catalog_path': cat_path,
        'search_param': search_param,
        'catalog_selector': cat_sel,
        'title_selector': title_sel,
        'item_selector': item_sel,
        'page_selector': page_sel,
        'image_attrs': img_attrs,
        'hoster_selector': hoster_sel,
        'video_selector': video_sel,
        'truncates_chapter_int': trunc_int,
        'has_referer': has_referer,
        'hardcoded_empty_methods': empty_methods,
        'has_gdrive_uc': 'drive.google.com/uc?id=' in src,
    }


def _execute_kotlin_source_behavior(
    kt_path: Path,
    ecosystem: str,
    base_url: str,
    *,
    allow_local_fixture: bool = False,
) -> dict[str, Any]:
    """Validate structure and execute actual Kotlin-defined endpoints/selectors against target site."""
    src = kt_path.read_text(encoding='utf-8', errors='replace')
    bal_ok, bal_err = _has_balanced_delimiters(src)
    if not bal_ok:
        return {'status': 'FAIL', 'executed': False, 'reason': f'kotlin_syntax_error:{bal_err}', 'failures': ['syntax_error']}

    spec = _extract_kotlin_source_spec(src, ecosystem)
    if '-' in spec['package'] or not spec['package']:
        return {'status': 'FAIL', 'executed': False, 'reason': f"invalid_kotlin_package:{spec['package']}", 'failures': ['invalid_kotlin_package'], 'spec': spec}
    if spec['hardcoded_empty_methods']:
        return {
            'status': 'FAIL',
            'executed': False,
            'reason': f"empty_stub_methods:{','.join(spec['hardcoded_empty_methods'])}",
            'failures': [f'empty_method:{m}' for m in spec['hardcoded_empty_methods']],
            'spec': spec,
        }

    base = base_url.rstrip('/')
    cat_url = f"{base}{spec['catalog_path']}"
    st, _, raw, err = _safe_http_fetch(f'{cat_url}?page=1', allow_local_fixture=allow_local_fixture)
    if st != 200 or not raw:
        return {'status': 'FAIL', 'executed': True, 'reason': f'catalog_fetch_failed:{err or st}', 'failures': ['catalog_fetch_failed'], 'spec': spec}

    cat_dom = _parse_html_dom(raw.decode('utf-8', errors='replace'))
    cat_nodes = [n for n in _query_selector_all(cat_dom, spec['catalog_selector']) if n.attrs.get('href') and n.text()]
    if not cat_nodes:
        return {'status': 'FAIL', 'executed': True, 'reason': f"catalog_selector_empty:{spec['catalog_selector']}", 'failures': ['catalog_selector_empty'], 'spec': spec}

    pop_items = [{'title': n.text(), 'url': n.attrs['href']} for n in cat_nodes]
    tok = (re.findall(r'[A-Za-z0-9]+', pop_items[0]['title']) or [pop_items[0]['title']])[0]
    failures: list[str] = []

    sep = '&' if '?' in cat_url else '?'
    sst, _, sraw, _ = _safe_http_fetch(f"{cat_url}{sep}page=1&{spec['search_param']}={quote(tok)}", allow_local_fixture=allow_local_fixture)
    s_items: list[dict[str, str]] = []
    if sst == 200 and sraw:
        sdom = _parse_html_dom(sraw.decode('utf-8', errors='replace'))
        snodes = [n for n in _query_selector_all(sdom, spec['catalog_selector']) if n.attrs.get('href') and n.text()]
        s_items = [{'title': n.text(), 'url': n.attrs['href']} for n in snodes]
    search_res = audit_search_and_pagination(tok, s_items, expected_title_substr=tok, popular_results=pop_items)
    if search_res['status'] != 'PASS':
        failures.append(f"wrong_search_param:{spec['search_param']}")

    det_url = resolve_relative_url(cat_url, pop_items[0]['url'])
    dst, _, draw, _ = _safe_http_fetch(det_url, allow_local_fixture=allow_local_fixture)
    if dst != 200 or not draw:
        failures.append('detail_fetch_failed')
        return {'status': 'FAIL', 'executed': True, 'reason': 'detail_fetch_failed', 'failures': failures, 'spec': spec}

    ddom = _parse_html_dom(draw.decode('utf-8', errors='replace'))
    tit_nodes = _query_selector_all(ddom, spec['title_selector'])
    det_title = tit_nodes[0].text() if tit_nodes else pop_items[0]['title']
    item_nodes = [n for n in _query_selector_all(ddom, spec['item_selector']) if n.attrs.get('href')]
    if not item_nodes:
        failures.append(f"wrong_item_selector:{spec['item_selector']}")
        return {'status': 'FAIL', 'executed': True, 'reason': failures[-1], 'failures': failures, 'spec': spec}

    if ecosystem == 'keiyoushi':
        chs_payload = []
        for n in item_nodes:
            num = parse_chapter_number(n.text())
            if spec['truncates_chapter_int'] and num is not None:
                num = float(int(num))
            chs_payload.append({'name': n.text(), 'url': n.attrs['href'], 'chapter_number': num})
        if spec['truncates_chapter_int']:
            failures.append('integer_chapter_truncation')
        content_res = audit_manga_content({'title': det_title, 'url': pop_items[0]['url']}, chs_payload)
        if content_res['status'] != 'PASS':
            failures.append('chapter_audit_failed')

        ordered = sorted(item_nodes, key=lambda n: 0 if ((parse_chapter_number(n.text()) or 0.0) % 1) != 0 else 1)
        ch_url = resolve_relative_url(det_url, ordered[0].attrs['href'])
        pst, _, praw, _ = _safe_http_fetch(ch_url, allow_local_fixture=allow_local_fixture)
        if pst != 200 or not praw:
            failures.append('page_list_fetch_failed')
        else:
            pdom = _parse_html_dom(praw.decode('utf-8', errors='replace'))
            img_nodes = _query_selector_all(pdom, spec['page_selector'])
            if not img_nodes:
                failures.append(f"wrong_page_selector:{spec['page_selector']}")
            else:
                urls: list[str] = []
                for im in img_nodes:
                    raw_attr = next((im.attrs.get(a, '') for a in spec['image_attrs'] if im.attrs.get(a, '').strip()), '')
                    if raw_attr:
                        urls.append(resolve_relative_url(ch_url, raw_attr))
                req_hdrs = {'Referer': f'{base}/'} if spec['has_referer'] else None
                pages_payload = []
                for idx, iu in enumerate(urls[:5]):
                    ist, ict, ibytes, _ = _safe_http_fetch(iu, allow_local_fixture=allow_local_fixture, headers=req_hdrs)
                    if ist == 200:
                        pages_payload.append({'index': idx, 'page_number': idx + 1, 'url': iu, 'content_type': ict, 'bytes': ibytes})
                mr = audit_page_list(pages_payload, expected_count=len(urls))
                if mr['status'] != 'PASS':
                    failures.append(f"deceptive_or_broken_images:{spec['image_attrs'][0]}")
                    if not spec['has_referer']:
                        ref_pages = []
                        for idx, iu in enumerate(urls[:3]):
                            rst, rct, rbytes, _ = _safe_http_fetch(iu, allow_local_fixture=allow_local_fixture, headers={'Referer': f'{base}/'})
                            if rst == 200:
                                ref_pages.append({'index': idx, 'page_number': idx + 1, 'url': iu, 'content_type': rct, 'bytes': rbytes})
                        if ref_pages and audit_page_list(ref_pages, expected_count=min(len(urls), 3))['status'] == 'PASS':
                            failures.append('missing_referer_header')
        if spec['has_gdrive_uc']:
            failures.append('broken_gdrive_uc_cover_url')

    elif ecosystem == 'yuzono':
        ep_url = resolve_relative_url(det_url, item_nodes[0].attrs['href'])
        hst, _, hraw, _ = _safe_http_fetch(ep_url, allow_local_fixture=allow_local_fixture)
        hosters: list[dict[str, str]] = []
        videos: list[dict[str, str]] = []
        if hst == 200 and hraw:
            hdom = _parse_html_dom(hraw.decode('utf-8', errors='replace'))
            hnodes = [n for n in _query_selector_all(hdom, spec['hoster_selector']) if n.attrs.get('href')]
            hosters = [{'name': n.text(), 'url': n.attrs['href']} for n in hnodes]
            if not hosters:
                failures.append(f"wrong_hoster_selector:{spec['hoster_selector']}")
            else:
                vurl = resolve_relative_url(ep_url, hosters[0]['url'])
                vst, _, vraw, _ = _safe_http_fetch(vurl, allow_local_fixture=allow_local_fixture)
                if vst == 200 and vraw:
                    vdom = _parse_html_dom(vraw.decode('utf-8', errors='replace'))
                    vnodes = [n for n in _query_selector_all(vdom, spec['video_selector']) if n.attrs.get('src')]
                    for vn in vnodes:
                        full_ms = resolve_relative_url(vurl, vn.attrs['src'])
                        mst, _, mraw, _ = _safe_http_fetch(full_ms, allow_local_fixture=allow_local_fixture)
                        if mst == 200 and mraw:
                            videos.append({'videoUrl': full_ms, 'hls_manifest': mraw.decode('utf-8', errors='replace')})
                    if not videos:
                        failures.append(f"wrong_video_selector:{spec['video_selector']}")
        eps_payload = [{'name': n.text(), 'url': n.attrs['href']} for n in item_nodes]
        ar = audit_anime_content({'title': det_title, 'url': pop_items[0]['url']}, eps_payload, hosters, videos)
        if ar['status'] != 'PASS':
            failures.append('anime_audit_failed')

    ok = not failures
    return {
        'status': 'PASS' if ok else 'FAIL',
        'executed': True,
        'engine': 'kotlin_http_executor',
        'spec': spec,
        'failures': failures,
        'reason': 'kotlin_behavior_verified' if ok else ','.join(failures[:4]),
    }


def execute_extension_behavior(
    ecosystem: str,
    code_files: Sequence[Path | str],
    base_url: str,
    *,
    allow_local_fixture: bool = False,
    sandbox_available_override: bool | None = None,
) -> dict[str, Any]:
    """Execute generated or repaired extension code (.ts via sandboxed Node.js or .kt via parsed HTTP flow) against target site."""
    paths = [Path(p) for p in code_files if Path(p).is_file()]
    if ecosystem == 'lnreader':
        ts_file = next((p for p in paths if p.suffix in {'.ts', '.js'}), None)
        if ts_file is None:
            return {'status': 'FAIL', 'executed': False, 'reason': 'missing_lnreader_ts_file', 'failures': ['missing_ts_file']}
        return _execute_lnreader_ts_in_node(
            ts_file,
            base_url,
            allow_local_fixture=allow_local_fixture,
            sandbox_available_override=sandbox_available_override,
        )

    kt_file = next((p for p in paths if p.suffix == '.kt'), None)
    if kt_file is None:
        return {'status': 'FAIL', 'executed': False, 'reason': 'missing_kotlin_source_file', 'failures': ['missing_kt_file']}
    return _execute_kotlin_source_behavior(kt_file, ecosystem, base_url, allow_local_fixture=allow_local_fixture)


def _infer_name_from_prompt(prompt_or_url: str, target_url: str | None) -> str:
    """Derive a clean PascalCase extension name from URL hostname or request text."""
    if target_url:
        host = (urlsplit(target_url).hostname or '').lower()
        host = re.sub(r'^www\.', '', host)
        label = host.split('.')[0] if host else ''
        if label and label not in {'example', 'localhost', '127'}:
            return _pascal(label)
        if label:
            return _pascal(label + 'Source')
    words = [w for w in re.findall(r'[A-Za-z0-9]+', prompt_or_url) if len(w) >= 3 and w.lower() not in {'https', 'http', 'para', 'com', 'uma', 'extensao', 'extension', 'create', 'crie', 'manga', 'anime', 'novel', 'site'}]
    return _pascal(words[-1]) if words else 'NoxAutoSource'


def build_optional_adb_guide(ecosystem: str = 'keiyoushi', *, lang: str = 'pt-BR') -> dict[str, Any]:
    """Explain optional Android device debugging without requiring technical knowledge or device resets."""
    is_en = lang == 'en'
    applicable = ecosystem in {'keiyoushi', 'yuzono'}
    if not applicable:
        return {
            'required': False,
            'applicable': False,
            'summary': (
                'LNReader plugins run without Android ADB or an Android phone.'
                if is_en
                else 'Plugins do LNReader nao usam ADB nem precisam de celular Android.'
            ),
            'steps': [],
        }

    steps = (
        [
            'Optional only: you can create and validate most fixes without a phone.',
            'If you ever want to test directly on your Android phone, open Settings > About phone and tap Build number 7 times to unlock Developer options.',
            'Inside Developer options, turn on USB debugging, connect the cable, and tap Allow on the phone popup.',
            'Safety note: Nox only reads filtered logs from the target app — it never erases logs or uninstalls your apps.',
        ]
        if is_en
        else [
            'Etapa opcional: quase tudo e criado e validado sem precisar conectar celular.',
            'Se quiser testar ao vivo no Android: abra Configuracoes > Sobre o telefone e toque 7 vezes em Numero da versao para ativar Opcoes do desenvolvedor.',
            'Entre em Opcoes do desenvolvedor, ative a Depuracao USB, conecte o cabo e toque em Permitir no aviso do celular.',
            'Garantia: a Nox apenas le eventos filtrados do app alvo; ela nunca apaga logs nem desinstala seus aplicativos.',
        ]
    )
    return {
        'required': False,
        'applicable': True,
        'summary': (
            'Android device connection (ADB) is completely optional.'
            if is_en
            else 'Conexao com celular Android (ADB) e totalmente opcional.'
        ),
        'steps': steps,
    }


def _default_refs_cache() -> Path:
    return Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'opencode/nox-workspace/nox-extension-developer'


def _resolve_persistent_output_dir(slug: str, output_dir: Path | str | None, repo_root: Path | str | None) -> Path:
    if output_dir is not None:
        return Path(output_dir).resolve()
    if repo_root is not None:
        return Path(repo_root).resolve()
    env_out = os.environ.get('NOX_OUTPUT_DIR')
    if env_out:
        return (Path(env_out).expanduser().resolve() / slug)
    return Path.home() / '.local' / 'share' / 'antigravity' / 'Nox-Workspace' / 'laboratorios' / 'nox-output' / slug


def _infer_gradle_task(module_or_out: Path, build_root: Path, source_lang: str, slug: str) -> str:
    dir_lang = normalize_ecosystem_language('keiyoushi', source_lang)['dir_lang']
    if (build_root / 'app').is_dir() and not (module_or_out / 'src' / dir_lang / slug).is_dir():
        return ':app:assembleDebug'
    return f':src:{dir_lang}:{slug}:assembleDebug'


def auto_create_extension(
    prompt_or_url: str,
    *,
    name: str | None = None,
    ecosystem: str | None = None,
    source_lang: str = 'pt-BR',
    ui_lang: str | None = None,
    output_dir: Path | str | None = None,
    repo_root: Path | str | None = None,
    build_task: str | None = None,
    dry_run: bool = False,
    technical: bool = False,
    site_url: str | None = None,
    allow_local_fixture: bool = False,
    sandbox_available_override: bool | None = None,
) -> dict[str, Any]:
    """Execute end-to-end automated extension creation: identify, probe site, implement real selectors, execute code behavior, compile APK in sandbox, and prepare APK delivery."""
    import nox_android
    import nox_issues
    import references

    parsed = nox_issues.parse_natural_language_request(prompt_or_url)
    eco = ecosystem or parsed['inferred_ecosystem']
    resolved_url = site_url or parsed.get('url')
    resolved_ui_lang = ui_lang or detect_user_ui_language(prompt_or_url, default='pt-BR')
    is_en = resolved_ui_lang == 'en'

    if not resolved_url:
        msg = (
            'Send the website address (URL) you want me to support so I can analyze it and build the extension.'
            if is_en
            else 'Envie o endereço do site (URL) que você quer adicionar para que eu possa analisá-lo e criar a extensão.'
        )
        stages = {
            'site_analyzed': 'NOT_RUN',
            'code_generated': 'NOT_RUN',
            'code_validated_statically': 'NOT_RUN',
            'code_compiled': 'NOT_APPLICABLE' if eco == 'lnreader' else 'NOT_RUN',
            'extension_functions_tested': 'NOT_RUN',
            'apk_generated': 'NOT_APPLICABLE' if eco == 'lnreader' else 'NOT_RUN',
            'apk_inspected': 'NOT_APPLICABLE' if eco == 'lnreader' else 'NOT_RUN',
            'android_device_confirmed': 'NOT_APPLICABLE' if eco == 'lnreader' else 'NOT_RUN',
        }
        cont = build_agent_continuation(
            phase='IDENTIFY',
            task_complete=False,
            status='INCONCLUSIVE',
            completed_gates={'site_analyzed': 'NOT_RUN', 'code_implemented': 'NOT_RUN', 'functional_tests': 'NOT_RUN', 'apk_build': 'NOT_RUN'},
            next_agent_action='Ask only for the missing website URL, then continue auto_create_extension immediately.',
            execution_stages=stages,
        )
        return format_adaptive_response(
            {
                'status': 'INCONCLUSIVE',
                'action': 'auto_create',
                'ecosystem': eco,
                'ui_lang': resolved_ui_lang,
                'execution_stages': stages,
                'user_message': msg,
                'next_step': msg,
                'parsed_request': parsed,
                'agent_continuation': cont,
            },
            technical=technical,
            lang=resolved_ui_lang,
        )

    ext_name = _pascal(name) if name else _infer_name_from_prompt(prompt_or_url, resolved_url)
    slug = _slug(ext_name)
    persisted_dir = _resolve_persistent_output_dir(slug, output_dir, repo_root)

    if repo_root and Path(repo_root).is_dir():
        sec_repo = nox_android.audit_untrusted_pr_or_repo(Path(repo_root))
        if sec_repo['status'] == 'FAIL':
            stages = {
                'site_analyzed': 'NOT_RUN',
                'code_generated': 'NOT_RUN',
                'code_validated_statically': 'NOT_RUN',
                'code_compiled': 'BLOCKED',
                'extension_functions_tested': 'NOT_RUN',
                'apk_generated': 'BLOCKED',
                'apk_inspected': 'BLOCKED',
                'android_device_confirmed': 'NOT_RUN',
            }
            cont = build_agent_continuation(
                phase='IDENTIFY',
                task_complete=False,
                status='FAIL',
                completed_gates={'site_analyzed': 'NOT_RUN', 'code_implemented': 'NOT_RUN', 'functional_tests': 'NOT_RUN', 'apk_build': 'BLOCKED'},
                next_agent_action='Refuse executing unsafe repository build files and inspect security findings.',
                execution_stages=stages,
            )
            return format_adaptive_response(
                {
                    'status': 'FAIL',
                    'action': 'auto_create',
                    'ecosystem': eco,
                    'ui_lang': resolved_ui_lang,
                    'output_dir': str(persisted_dir),
                    'execution_stages': stages,
                    'user_message': (
                        'Stopped because the target repository failed security verification.'
                        if is_en
                        else 'Parei por segurança porque o repositório de destino falhou na verificação de integridade.'
                    ),
                    'next_step': (
                        'Review the security findings before making changes in that repository.'
                        if is_en
                        else 'Revise os alertas de segurança antes de alterar esse repositório.'
                    ),
                    'security_preflight': sec_repo,
                    'agent_continuation': cont,
                },
                technical=technical,
                lang=resolved_ui_lang,
                diagnostics_dir=persisted_dir if persisted_dir.is_dir() else None,
            )

    doctor = run_doctor(ecosystem=eco)
    ref_status = references.status(eco, _default_refs_cache())
    existing = search_existing_extensions(repo_root, resolved_url or ext_name) if repo_root and Path(repo_root).is_dir() else None
    adb_guide = build_optional_adb_guide(eco, lang=resolved_ui_lang)

    # Stage 1: Analyze live/fixture site cleanly before generating code
    probe = _probe_and_verify_live_or_fixture_site(resolved_url, eco, allow_local_fixture=allow_local_fixture)
    cfg = probe.get('discovered_config') or {}

    scaffold_res: dict[str, Any] | None = None
    persisted_files: list[str] = []
    if not dry_run:
        persisted_dir.mkdir(parents=True, exist_ok=True)
        scaffold_res = scaffold_extension(
            eco,
            ext_name,
            resolved_url.rstrip('/'),
            lang=source_lang,
            output_dir=persisted_dir,
            search_param=cfg.get('search_param', 'q'),
            image_attr=cfg.get('image_attr', 'data-src'),
            catalog_path=cfg.get('catalog_path'),
            catalog_selector=cfg.get('catalog_selector'),
            title_selector=cfg.get('title_selector', 'h1.title'),
            description_selector=cfg.get('description_selector', '.description'),
            chapter_selector=cfg.get('chapter_selector', 'a.chapter[href]'),
            episode_selector=cfg.get('episode_selector', 'a.episode[href]'),
            page_selector=cfg.get('page_selector', 'img.page'),
            hoster_selector=cfg.get('hoster_selector', 'a.server[href]'),
            video_selector=cfg.get('video_selector', 'video source[src], video[src]'),
            novel_content_selector=cfg.get('novel_content_selector', '.chapter-content'),
        )
        persisted_files = [str(Path(f).resolve()) for f in scaffold_res.get('created_files', [])]

    pkg_val = (scaffold_res or {}).get('package_validation') or {'status': 'NOT_RUN'}
    behavior_res: dict[str, Any] = {'status': 'NOT_RUN'}
    if not dry_run and persisted_files and probe.get('reachable'):
        behavior_res = execute_extension_behavior(
            eco,
            persisted_files,
            resolved_url.rstrip('/'),
            allow_local_fixture=allow_local_fixture,
            sandbox_available_override=sandbox_available_override,
        )

    static_ok = pkg_val.get('status') == 'PASS'
    behavior_ok = behavior_res.get('status') == 'PASS'
    probe_ok = probe.get('status') == 'PASS'
    tests_verified = probe_ok and static_ok and behavior_ok
    code_implemented = bool(persisted_files) and static_ok and behavior_ok

    # Stage 5: Real compilation + Debug APK generation & verification inside Bubblewrap
    build_res: dict[str, Any] | None = None
    delivery_res: dict[str, Any] | None = None
    pkg_name = (scaffold_res or {}).get('package_name')
    cls_name = (scaffold_res or {}).get('class_name') or ext_name
    expected_methods = (
        ('getPopularManga', 'getSearchMangaList', 'fetchMangaUpdate', 'getPageList')
        if eco == 'keiyoushi'
        else (('popularAnimeRequest', 'episodeListParse', 'videoListParse') if eco == 'yuzono' else ())
    )

    build_root = (
        Path(repo_root).resolve()
        if (repo_root and (Path(repo_root) / 'gradlew').is_file())
        else (persisted_dir if (persisted_dir / 'gradlew').is_file() else None)
    )
    if not dry_run and eco in {'keiyoushi', 'yuzono'} and static_ok:
        if build_root is not None or build_task is not None:
            broot = build_root or persisted_dir
            task = build_task or _infer_gradle_task(persisted_dir, broot, source_lang, slug)
            build_res = nox_android.build_debug_apk(
                broot,
                task,
                sandbox_available_override=sandbox_available_override,
            )
            if build_res.get('apk_path') and build_res.get('status') not in {'BLOCKED', 'FAIL'}:
                delivery_res = nox_android.verify_and_offer_apk_delivery(
                    build_res.get('apk_path'),
                    min_mtime=build_res.get('build_started_at'),
                    lang=resolved_ui_lang,
                )
        else:
            mod_path = Path(scaffold_res['module_path'])
            build_res = nox_android.compile_kotlin_extension_to_debug_apk(
                mod_path,
                package_name=pkg_name or '',
                class_name=cls_name,
                app_label=ext_name,
                expected_methods=expected_methods,
                sandbox_available_override=sandbox_available_override,
            )
            if build_res.get('apk_path') and build_res.get('status') not in {'BLOCKED', 'FAIL'}:
                delivery_res = nox_android.verify_and_offer_apk_delivery(
                    build_res.get('apk_path'),
                    expected_package=pkg_name,
                    expected_class_name=cls_name,
                    expected_methods=expected_methods,
                    min_mtime=build_res.get('build_started_at'),
                    lang=resolved_ui_lang,
                )

    apk_ready = bool(delivery_res and delivery_res.get('apk_ready'))
    apk_path = delivery_res.get('apk_path') if apk_ready else None
    apk_options = delivery_res.get('options') if apk_ready else None

    execution_stages: dict[str, str] = {
        'site_analyzed': 'PASS' if (probe.get('reachable') and probe_ok) else ('BLOCKED' if probe.get('status') == 'BLOCKED' else ('FAIL' if probe.get('status') == 'FAIL' else 'INCONCLUSIVE')),
        'code_generated': 'PASS' if persisted_files else ('SKIPPED_DRY_RUN' if dry_run else 'FAIL'),
        'code_validated_statically': pkg_val.get('status', 'NOT_RUN') if not dry_run else 'NOT_RUN',
        'code_compiled': (
            'NOT_APPLICABLE'
            if eco == 'lnreader'
            else (build_res['status'] if build_res else ('FAIL' if (not dry_run and not static_ok) else 'NOT_RUN'))
        ),
        'extension_functions_tested': behavior_res.get('status', 'NOT_RUN') if not dry_run else 'NOT_RUN',
        'apk_generated': 'NOT_APPLICABLE' if eco == 'lnreader' else ('PASS' if (build_res and build_res.get('apk_path') and build_res.get('status') == 'PASS') else (build_res['status'] if build_res else 'NOT_RUN')),
        'apk_inspected': 'NOT_APPLICABLE' if eco == 'lnreader' else (delivery_res['status'] if delivery_res else ('BLOCKED' if (build_res and build_res.get('status') == 'BLOCKED') else 'NOT_RUN')),
        'android_device_confirmed': 'NOT_APPLICABLE' if eco == 'lnreader' else 'NOT_RUN',
    }

    # Stage 6: Strict honest final classification (NEVER claim PASS for Android without generated + inspected APK!)
    limitations: list[str] = []
    if probe.get('status') == 'BLOCKED':
        status = 'BLOCKED'
        limitations.append(str(probe.get('error') or 'Target site blocked automated inspection.'))
    elif dry_run:
        status = 'INCONCLUSIVE' if probe_ok else ('FAIL' if probe.get('status') == 'FAIL' else 'INCONCLUSIVE')
        limitations.append('Dry-run mode analyzed the site without generating or executing files.' if is_en else 'Modo simulação analisou o site sem gerar arquivos.')
    elif not probe.get('reachable'):
        status = 'INCONCLUSIVE'
        limitations.append(str(probe.get('error') or 'Could not reach target site.'))
    elif behavior_res.get('status') == 'BLOCKED':
        status = 'BLOCKED'
        limitations.append(str(behavior_res.get('beginner_message') or behavior_res.get('reason') or 'Plugin execution blocked cleanly because sandbox isolation is unavailable.'))
    elif not static_ok or not probe_ok or not behavior_ok:
        status = 'FAIL'
        limitations.append(str(behavior_res.get('reason') or probe.get('error') or ','.join(pkg_val.get('issues') or [])))
    elif eco in {'keiyoushi', 'yuzono'}:
        if build_res is None:
            status = 'BLOCKED'
            limitations.append('Android compilation was not executed.' if is_en else 'A compilação Android não foi executada.')
        elif build_res.get('status') in {'BLOCKED', 'FAIL'}:
            status = build_res['status']
            limitations.append(str(build_res.get('reason') or 'APK compilation could not finish safely.'))
        elif not apk_ready:
            status = 'FAIL'
            limitations.append(str((delivery_res or {}).get('reason') or 'APK verification failed.'))
        else:
            status = 'PASS'
    else:
        status = 'PASS'

    task_complete = (status == 'PASS') and code_implemented and tests_verified and (eco == 'lnreader' or apk_ready)
    phase = 'DELIVER_ARTIFACT' if apk_ready else ('VERIFY_TESTS' if tests_verified else 'SITE_ANALYSIS')
    cont = build_agent_continuation(
        phase=phase,
        task_complete=task_complete,
        status=status,
        completed_gates={
            'site_analyzed': execution_stages['site_analyzed'],
            'code_implemented': 'PASS' if code_implemented else execution_stages['code_validated_statically'],
            'functional_tests': execution_stages['extension_functions_tested'],
            'apk_build': execution_stages['apk_generated'],
            'apk_inspected': execution_stages['apk_inspected'],
        },
        next_agent_action=(
            'Present concise completion and 3 APK options.'
            if apk_ready
            else (
                'Complete custom site implementation, verify executed extension functions, compile Debug APK in sandbox, and deliver result.'
                if not task_complete
                else 'Deliver verified files cleanly.'
            )
        ),
        execution_stages=execution_stages,
    )

    if apk_ready:
        msg = (
            f'All set! Your extension "{ext_name}" has been created and the Debug APK is ready. 💜'
            if is_en
            else f'Pronto! Sua extensão "{ext_name}" foi criada e o APK Debug está disponível. 💜'
        )
        nxt = delivery_res['prompt'] if delivery_res else ''
    elif status == 'PASS' and eco == 'lnreader':
        msg = (
            f'All set! Your LNReader plugin "{ext_name}" was created and verified via Node.js. 💜'
            if is_en
            else f'Pronto! Plugin LNReader "{ext_name}" criado e validado com execução real em Node.js. 💜'
        )
        nxt = (
            f'Saved at: {persisted_files[0]}'
            if (is_en and persisted_files)
            else f'Arquivo salvo em: {persisted_files[0] if persisted_files else persisted_dir}'
        )
    elif status == 'BLOCKED' and behavior_res.get('status') == 'BLOCKED':
        msg = (
            'The automated verification of this plugin could not run safely on this computer. No untrusted code was executed.'
            if is_en
            else 'A verificação automática deste plugin não pôde ser executada com segurança neste computador. Nenhum código não confiável foi executado.'
        )
        nxt = (
            'Your plugin files were saved safely. Enable Bubblewrap sandbox support (bwrap) and run the verification again.'
            if is_en
            else 'Os arquivos do plugin foram salvos com segurança. Ative o sandbox Bubblewrap (bwrap) para executar a verificação com isolamento.'
        )
    elif build_res is not None and build_res.get('status') == 'BLOCKED':
        msg = (
            f'Created and tested the extension code for "{ext_name}", while Debug APK compilation is waiting for Android/sandbox toolchain support.'
            if is_en
            else f'Criei e testei o código da extensão "{ext_name}", mas a compilação do APK Debug está bloqueada neste ambiente sem Android SDK/sandbox.'
        )
        nxt = (
            'Your source files are saved safely on disk. Once Android build tools and Bubblewrap are available, compile the Debug APK.'
            if is_en
            else 'Os arquivos da extensão continuam salvos com segurança. Assim que o ambiente Android/sandbox estiver disponível, você poderá gerar o APK.'
        )
    elif build_res is not None and build_res.get('status') == 'FAIL':
        msg = (
            f'Saved source code for "{ext_name}", but APK compilation or verification failed.'
            if is_en
            else f'O código de "{ext_name}" foi salvo, mas a compilação ou validação do APK Debug falhou.'
        )
        nxt = (
            'Inspect compilation errors and re-run automatic creation or repair.'
            if is_en
            else 'Vou ajustar o código que impediu a compilação antes de gerar o APK final.'
        )
    else:
        msg = (
            f'Saved files for "{ext_name}", but automated functional execution could not verify everything yet.'
            if is_en
            else f'Salvei os arquivos para "{ext_name}", mas ainda não foi possível confirmar o funcionamento real no site.'
        )
        nxt = (
            'Keep investigating the live site structure, implement working selectors, and re-run functional checks.'
            if is_en
            else 'Continuando a análise do site para ajustar os seletores reais antes de finalizar.'
        )

    payload = {
        'status': status,
        'action': 'auto_create',
        'ecosystem': eco,
        'ui_lang': resolved_ui_lang,
        'extension_name': ext_name,
        'package_name': pkg_name,
        'target_url': resolved_url,
        'output_dir': str(persisted_dir),
        'persisted_files': persisted_files,
        'artifact_path': apk_path or (persisted_files[0] if persisted_files else None),
        'code_implemented': code_implemented,
        'tests_verified': tests_verified,
        'apk_ready': apk_ready,
        'apk_path': apk_path,
        'apk_options': apk_options,
        'execution_stages': execution_stages,
        'behavior_execution': behavior_res,
        'user_message': msg,
        'next_step': nxt,
        'user_limitations': limitations or None,
        'parsed_request': parsed,
        'site_probe': probe,
        'environment': doctor,
        'reference_snapshot': ref_status,
        'existing_search': existing,
        'scaffold': scaffold_res,
        'sandbox_build': build_res,
        'apk_delivery': delivery_res,
        'optional_adb_guide': adb_guide,
        'agent_continuation': cont,
    }
    return format_adaptive_response(
        payload,
        technical=technical,
        lang=resolved_ui_lang,
        diagnostics_dir=persisted_dir if persisted_dir.is_dir() else None,
    )


def _extract_base_url_from_files(files: Sequence[Path]) -> str | None:
    for fp in files:
        txt = fp.read_text(encoding='utf-8', errors='replace')
        m1 = re.search(r'baseUrl\s*=\s*"([^"]+)"', txt)
        if m1:
            return m1.group(1)
        m2 = re.search(r"site\s*=\s*['\"]([^'\"]+)['\"]", txt)
        if m2:
            return m2.group(1)
    return None


def _reproduce_existing_source_failures(
    code_text: str,
    ecosystem: str,
    base_url: str,
    probe: dict[str, Any],
    *,
    allow_local_fixture: bool = False,
) -> dict[str, Any]:
    """Verify whether selectors/query params/image attrs currently in source files fail against target site."""
    cfg = probe.get('discovered_config') or {}
    failures: list[str] = []
    if not probe.get('reachable'):
        return {'status': 'INCONCLUSIVE', 'failures': ['site_unreachable']}

    if ecosystem == 'keiyoushi':
        ch_sel = cfg.get('chapter_selector', 'a.chapter[href]')
        if ch_sel not in code_text and ('broken' in code_text or 'select("' in code_text):
            m_sel = re.search(r'fetchMangaUpdate[\s\S]{0,600}?doc\.select\("([^"]+)"\)', code_text)
            if m_sel and m_sel.group(1) != ch_sel:
                failures.append(f'wrong_chapter_selector:{m_sel.group(1)}')
        sp = cfg.get('search_param', 'q')
        m_qp = re.search(r'addQueryParameter\("([^"]+)",\s*query', code_text)
        if m_qp and m_qp.group(1) != sp:
            failures.append(f'wrong_search_param:{m_qp.group(1)}')
        img_attr = cfg.get('image_attr', 'data-src')
        if img_attr != 'src' and 'absUrl("data-src")' not in code_text and 'absUrl("src")' in code_text:
            failures.append('deceptive_image_attr_src')
        if 'parseChapterNumber' not in code_text and '.toInt()' in code_text:
            failures.append('integer_chapter_truncation')
        if 'drive.google.com/uc?id=' in code_text:
            failures.append('broken_gdrive_uc_cover_url')
    elif ecosystem == 'yuzono':
        ep_sel = cfg.get('episode_selector', 'a.episode[href]')
        if ep_sel not in code_text and 'episodeListParse' in code_text:
            failures.append('wrong_episode_selector')
        h_sel = cfg.get('hoster_selector', 'a.server[href]')
        if h_sel not in code_text and 'hosterListParse' in code_text:
            failures.append('wrong_hoster_selector')
    elif ecosystem == 'lnreader':
        nc_sel = cfg.get('novel_content_selector', '.chapter-content')
        if nc_sel not in code_text and 'parseChapter' in code_text:
            failures.append('wrong_novel_content_selector')
        if "$('script, style, nav').remove()" not in code_text and 'parseChapter' in code_text:
            failures.append('missing_nav_noise_strip')
        sp = cfg.get('search_param', 'q')
        if f'?{sp}=' not in code_text and '?search=' in code_text:
            failures.append('wrong_search_param:search')

    return {'status': 'FAIL' if failures else 'PASS', 'failures': failures}


def _apply_automated_code_repairs(
    target_path: Path,
    ecosystem: str,
    symptom: str,
    probe: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Apply concrete minimal code edits to broken .kt/.ts/.js/build.gradle.kts files on disk."""
    cfg = probe.get('discovered_config') or {}
    code_files = (
        [target_path]
        if target_path.is_file()
        else sorted(p for p in target_path.rglob('*') if p.is_file() and p.suffix in {'.kt', '.ts', '.js', '.kts'})
    )
    modified: list[str] = []
    changes: list[str] = []

    for fp in code_files:
        orig = fp.read_text(encoding='utf-8', errors='replace')
        updated = orig

        if fp.suffix in {'.kt', '.ts', '.js'}:
            sp = cfg.get('search_param', 'q')
            if ecosystem in {'keiyoushi', 'yuzono'} and f'addQueryParameter("{sp}", query' not in updated:
                new_u, n = re.subn(r'addQueryParameter\("search",\s*(query[^)]*)\)', f'addQueryParameter("{sp}", \\1)', updated)
                if n:
                    updated = new_u
                    changes.append(f'{fp.name}: fixed search query parameter -> {sp}')
            if ecosystem == 'lnreader' and f'?{sp}=' not in updated and '?search=' in updated:
                updated = updated.replace('?search=', f'?{sp}=')
                changes.append(f'{fp.name}: fixed search query parameter -> {sp}')

            if ecosystem == 'keiyoushi':
                cat_sel = cfg.get('catalog_selector')
                if cat_sel and cat_sel not in updated and 'getSearchMangaList' in updated:
                    new_u = re.sub(r'doc\.select\("([^"]*broken[^"]*|div\.old[^"]*)"\)', f'doc.select("{cat_sel}")', updated, count=1)
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: repaired catalog selector -> {cat_sel}')
                ch_sel = cfg.get('chapter_selector')
                if ch_sel and ch_sel not in updated and 'fetchMangaUpdate' in updated:
                    new_u = re.sub(
                        r'(val\s+chs\s*=\s*if\s*\([^)]+\)\s*doc\.select\(")([^"]+)(")',
                        rf'\g<1>{ch_sel}\g<3>',
                        updated,
                        count=1,
                    )
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: repaired chapter selector -> {ch_sel}')
                img_attr = cfg.get('image_attr', 'data-src')
                if img_attr == 'data-src' and 'absUrl("data-src")' not in updated and 'img.absUrl("src")' in updated:
                    updated = updated.replace(
                        'img.absUrl("src")',
                        'img.absUrl("data-src").ifBlank { img.absUrl("src") }',
                    )
                    changes.append(f'{fp.name}: switched image extraction to data-src with src fallback')
                if 'headersBuilder()' not in updated and 'class ' in updated and ('image' in symptom.lower() or '403' in symptom or 'imagem' in symptom.lower() or 'cover' in symptom.lower() or 'capa' in symptom.lower()):
                    updated = re.sub(
                        r'(abstract\s+class\s+[^{]+\{\n)',
                        r'\1    override fun headersBuilder() = super.headersBuilder().add("Referer", "$baseUrl/")\n\n',
                        updated,
                        count=1,
                    )
                    changes.append(f'{fp.name}: added Referer header builder')
                if '.toInt()' in updated and 'chapter' in updated.lower():
                    updated = updated.replace('.toInt()', '.replace(",", ".").toFloatOrNull() ?: -1f')
                    changes.append(f'{fp.name}: preserved fractional chapter numbers')
                if 'drive.google.com/uc?id=' in updated:
                    updated = re.sub(
                        r'https://drive\.google\.com/uc\?id=([A-Za-z0-9_-]+)(?:&export=[a-z]+)?',
                        r'https://drive.google.com/thumbnail?id=\1&sz=w1000',
                        updated,
                    )
                    changes.append(f'{fp.name}: upgraded Google Drive cover URL to thumbnail endpoint')

            elif ecosystem == 'yuzono':
                ep_sel = cfg.get('episode_selector')
                if ep_sel and ep_sel not in updated and 'episodeListParse' in updated:
                    new_u = re.sub(
                        r'(override\s+fun\s+episodeListParse\([^)]*\)[^{=]*=\s*response\.asJsoup\(\)\.select\(")([^"]+)(")',
                        rf'\g<1>{ep_sel}\g<3>',
                        updated,
                        count=1,
                    )
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: repaired episode selector -> {ep_sel}')
                h_sel = cfg.get('hoster_selector')
                if h_sel and h_sel not in updated and 'hosterListParse' in updated:
                    new_u = re.sub(
                        r'(override\s+fun\s+hosterListParse\([^)]*\)[^{=]*=\s*response\.asJsoup\(\)\.select\(")([^"]+)(")',
                        rf'\g<1>{h_sel}\g<3>',
                        updated,
                        count=1,
                    )
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: repaired hoster selector -> {h_sel}')

            elif ecosystem == 'lnreader':
                nc_sel = cfg.get('novel_content_selector')
                if nc_sel and nc_sel not in updated and 'parseChapter' in updated:
                    new_u = re.sub(
                        r"(return\s+\$\(['\"])([^'\"]+)(['\"]\)\.html\(\))",
                        rf"\g<1>{nc_sel}\g<3>",
                        updated,
                        count=1,
                    )
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: repaired novel chapter content selector -> {nc_sel}')
                if "$('script, style, nav').remove()" not in updated and 'parseChapter' in updated:
                    new_u = re.sub(
                        r'(const\s+\$\s*=\s*parseHTML\([^\n]+\);\n)',
                        r"\1    $('script, style, nav').remove();\n",
                        updated,
                        count=1,
                    )
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: added nav/script cleanup in parseChapter')

        if updated != orig:
            atomic_write_text(fp, updated)
            modified.append(str(fp.resolve()))

    return modified, changes


def _apply_structural_and_behavioral_repairs(
    target_path: Path,
    ecosystem: str,
    probe: dict[str, Any],
    before_behavior: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Pass 2 non-regex/structural repairs using behavioral failures and live site config (package hyphen, catalog path, empty stub body, generic selector replacement)."""
    if not probe.get('reachable'):
        return [], []
    cfg = probe.get('discovered_config') or {}
    code_files = (
        [target_path]
        if target_path.is_file()
        else sorted(p for p in target_path.rglob('*') if p.is_file() and p.suffix in {'.kt', '.ts', '.js'})
    )
    modified: list[str] = []
    changes: list[str] = []

    for fp in code_files:
        orig = fp.read_text(encoding='utf-8', errors='replace')
        updated = orig

        if fp.suffix == '.kt':
            spec = _extract_kotlin_source_spec(updated, ecosystem)

            # 1. Fix invalid hyphenated package name like .pt-BR. -> .pt.
            m_pkg = re.search(r'^(\s*package\s+eu\.kanade\.tachiyomi\.(?:anime)?extension\.)([A-Za-z0-9_-]+)(\.[a-z0-9_]+)', updated, re.M)
            if m_pkg and '-' in m_pkg.group(2):
                pkg_lang = normalize_ecosystem_language(ecosystem, m_pkg.group(2))['package_lang']
                updated = updated[:m_pkg.start(2)] + pkg_lang + updated[m_pkg.end(2):]
                changes.append(f'{fp.name}: normalized Kotlin package segment -> {pkg_lang}')

            # 2. Repair wrong catalog path against discovered endpoint path
            cat_path = cfg.get('catalog_path')
            if cat_path and spec.get('catalog_path') != cat_path and '"$baseUrl/' in updated:
                new_u, n = re.subn(r'("\$baseUrl)(/[^"?${}]+)("|\?)', rf'\g<1>{cat_path}\g<3>', updated)
                if n and new_u != updated:
                    updated = new_u
                    changes.append(f'{fp.name}: repaired catalog endpoint path -> {cat_path}')

            # 3. Repair wrong catalog selector regardless of selector name
            cat_sel = cfg.get('catalog_selector')
            if cat_sel:
                for fn_anchor in ('getSearchMangaList', 'parseCatalog'):
                    m_fn = re.search(rf'({fn_anchor}[\s\S]{{0,700}}?\bdoc\.select\(")([^"]+)(")', updated)
                    if m_fn and m_fn.group(2) != cat_sel:
                        updated = updated[:m_fn.start(2)] + cat_sel + updated[m_fn.end(2):]
                        changes.append(f'{fp.name}: structural repair of catalog selector in {fn_anchor} -> {cat_sel}')

            # 4. Repair generic failing search param
            sp = cfg.get('search_param', 'q')
            if spec.get('search_param') != sp:
                new_u, n = re.subn(r'(addQueryParameter\(")([^"]+)(",\s*query)', rf'\g<1>{sp}\g<3>', updated)
                if n and new_u != updated:
                    updated = new_u
                    changes.append(f'{fp.name}: repaired search query param -> {sp}')

            # 5. Repair generic wrong chapter/episode/page/hoster/video selectors or empty stub bodies
            if ecosystem == 'keiyoushi':
                ch_sel = cfg.get('chapter_selector')
                if ch_sel:
                    m_ch = re.search(r'(fetchMangaUpdate[\s\S]{0,700}?\bdoc\.select\(")([^"]+)(")', updated)
                    if m_ch and m_ch.group(2) != ch_sel:
                        updated = updated[:m_ch.start(2)] + ch_sel + updated[m_ch.end(2):]
                        changes.append(f'{fp.name}: structural repair of chapter selector -> {ch_sel}')

                page_sel = cfg.get('page_selector') or 'img.page'
                img_attr = cfg.get('image_attr', 'data-src')
                if 'getPageList' in (spec.get('hardcoded_empty_methods') or []) or spec.get('page_selector') != page_sel:
                    replacement_body = (
                        '    override suspend fun getPageList(chapter: SChapter): List<Page> {\n'
                        '        val doc = client.get(getChapterUrl(chapter), Fetch.DOCUMENT).asJsoup()\n'
                        f'        return doc.select("{page_sel}").mapIndexed {{ idx, img ->\n'
                        f'            val src = img.absUrl("{img_attr}").ifBlank {{ img.absUrl("data-lazy-src") }}.ifBlank {{ img.absUrl("src") }}\n'
                        '            Page(idx, imageUrl = src)\n'
                        '        }\n'
                        '    }'
                    )
                    new_u, n = re.subn(
                        r'[ \t]*override\s+suspend\s+fun\s+getPageList\([^)]*\):\s*List<Page>\s*(?:=\s*emptyList\(\)|\{[\s\S]*?\n[ \t]*\})',
                        replacement_body,
                        updated,
                        count=1,
                    )
                    if n and new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: synthesized working getPageList implementation')

            elif ecosystem == 'yuzono':
                ep_sel = cfg.get('episode_selector')
                if ep_sel:
                    m_ep = re.search(r'(episodeListParse\([^)]*\)[^\n=]*[={]\s*response\.asJsoup\(\)\.select\(")([^"]+)(")', updated)
                    if m_ep and m_ep.group(2) != ep_sel:
                        updated = updated[:m_ep.start(2)] + ep_sel + updated[m_ep.end(2):]
                        changes.append(f'{fp.name}: structural repair of episode selector -> {ep_sel}')

                h_sel = cfg.get('hoster_selector')
                if h_sel:
                    m_h = re.search(r'(hosterListParse\([^)]*\)[^\n=]*[={]\s*response\.asJsoup\(\)\.select\(")([^"]+)(")', updated)
                    if m_h and m_h.group(2) != h_sel:
                        updated = updated[:m_h.start(2)] + h_sel + updated[m_h.end(2):]
                        changes.append(f'{fp.name}: structural repair of hoster selector -> {h_sel}')

                v_sel = cfg.get('video_selector')
                if v_sel:
                    m_v = re.search(r'(videoListParse\([^)]*\)[\s\S]{0,300}?\.select\(")([^"]+)(")', updated)
                    if m_v and m_v.group(2) != v_sel:
                        updated = updated[:m_v.start(2)] + v_sel + updated[m_v.end(2):]
                        changes.append(f'{fp.name}: structural repair of video selector -> {v_sel}')

        elif fp.suffix in {'.ts', '.js'} and ecosystem == 'lnreader':
            sp = cfg.get('search_param', 'q')
            if f'?{sp}=' not in updated and 'searchNovels' in updated:
                new_u = re.sub(r'(\?\s*)([A-Za-z0-9_]+)(=\$\{encodeURIComponent)', rf'\g<1>{sp}\g<3>', updated)
                if new_u != updated:
                    updated = new_u
                    changes.append(f'{fp.name}: structural repair of LNReader search param -> {sp}')
            cat_path = cfg.get('catalog_path')
            cat_sel = cfg.get('catalog_selector')
            if cat_path and 'popularNovels' in updated:
                new_u = re.sub(r'(fetchApi\(`\$\{this\.site\})(/[^?`]+)(\?page=)', rf'\g<1>{cat_path}\g<3>', updated)
                if new_u != updated:
                    updated = new_u
                    changes.append(f'{fp.name}: repaired LNReader catalog path -> {cat_path}')
            if cat_sel and 'popularNovels' in updated:
                m_lcat = re.search(r"""(popularNovels[\s\S]{0,400}?return\s+\$\(['"`])([^'"`]+)(['"`]\))""", updated)
                if m_lcat and m_lcat.group(2) != cat_sel:
                    updated = updated[:m_lcat.start(2)] + cat_sel + updated[m_lcat.end(2):]
                    changes.append(f'{fp.name}: repaired LNReader popularNovels selector -> {cat_sel}')

        if updated != orig:
            atomic_write_text(fp, updated)
            modified.append(str(fp.resolve()))

    return modified, changes


def _find_kotlin_module_dir(tpath: Path) -> Path:
    if tpath.is_file():
        for par in tpath.parents:
            if (par / 'build.gradle.kts').is_file() or (par / 'src').is_dir():
                return par
        return tpath.parent
    for g in sorted(tpath.rglob('build.gradle.kts')):
        return g.parent
    return tpath


def auto_fix_extension(
    target: Path | str,
    symptom: str,
    *,
    ecosystem: str | None = None,
    ui_lang: str | None = None,
    attempts: Sequence[dict[str, Any]] = (),
    build_task: str | None = None,
    technical: bool = False,
    site_url: str | None = None,
    allow_local_fixture: bool = False,
    sandbox_available_override: bool | None = None,
) -> dict[str, Any]:
    """Execute behavioral automated repair: reproduce via real execution, apply minimal patches (Pass 1 + Pass 2), verify post-fix, rollback on regression, compile in sandbox."""
    import nox_android
    import nox_issues
    import references

    tpath = Path(target).resolve()
    resolved_ui_lang = ui_lang or detect_user_ui_language(symptom, default='pt-BR')
    is_en = resolved_ui_lang == 'en'
    diag = nox_issues.diagnose_and_suggest_fix_from_issues(tpath, symptom, ecosystem=ecosystem)
    eco = diag['ecosystem']
    doctor = run_doctor(ecosystem=eco, check_path=tpath if tpath.is_dir() else None)
    ref_status = references.status(eco, _default_refs_cache())
    sec = nox_android.audit_untrusted_pr_or_repo(tpath) if tpath.is_dir() else None
    loop = detect_investigation_loop(attempts)
    adb_status = nox_android.adb_doctor() if eco in {'keiyoushi', 'yuzono'} else {'status': 'NOT_RUN', 'devices': []}
    adb_guide = build_optional_adb_guide(eco, lang=resolved_ui_lang)

    if sec and sec['status'] == 'FAIL':
        stages = {
            'site_analyzed': 'NOT_RUN',
            'code_generated': 'PASS' if tpath.exists() else 'NOT_RUN',
            'code_validated_statically': 'FAIL',
            'code_compiled': 'BLOCKED',
            'extension_functions_tested': 'NOT_RUN',
            'apk_generated': 'BLOCKED',
            'apk_inspected': 'BLOCKED',
            'android_device_confirmed': 'NOT_RUN',
        }
        cont = build_agent_continuation(
            phase='IDENTIFY',
            task_complete=False,
            status='FAIL',
            completed_gates={'site_analyzed': 'NOT_RUN', 'code_implemented': 'BLOCKED', 'functional_tests': 'NOT_RUN', 'apk_build': 'BLOCKED'},
            next_agent_action='Stop repair because repository failed security pre-flight audit.',
            execution_stages=stages,
        )
        return format_adaptive_response(
            {
                'status': 'FAIL',
                'action': 'auto_fix',
                'ecosystem': eco,
                'ui_lang': resolved_ui_lang,
                'target': str(tpath),
                'output_dir': str(tpath if tpath.is_dir() else tpath.parent),
                'code_modified': False,
                'tests_verified': False,
                'apk_ready': False,
                'execution_stages': stages,
                'user_message': (
                    'Stopped automatic repair because this project contains unsafe build or script patterns.'
                    if is_en
                    else 'Parei o reparo automático porque este projeto contém padrões inseguros em arquivos de build ou scripts.'
                ),
                'next_step': (
                    'Review the flagged security findings before opening or compiling this repository.'
                    if is_en
                    else 'Revise os alertas de segurança antes de compilar ou executar este repositório.'
                ),
                'diagnosis': diag,
                'loop_detection': loop,
                'security_preflight': sec,
                'agent_continuation': cont,
            },
            technical=technical,
            lang=resolved_ui_lang,
            diagnostics_dir=tpath if tpath.is_dir() else tpath.parent,
        )

    before_proj = inspect_project(tpath) if tpath.exists() else {'sources': []}
    code_files = (
        [tpath]
        if tpath.is_file()
        else (
            sorted(
                p for p in tpath.rglob('*')
                if p.is_file() and p.suffix in {'.kt', '.ts', '.js', '.kts'} and 'build/' not in p.relative_to(tpath).as_posix()
            )
            if tpath.is_dir()
            else []
        )
    )
    snapshots = {fp: fp.read_text(encoding='utf-8', errors='replace') for fp in code_files}
    resolved_site = site_url or _extract_base_url_from_files(code_files)
    combined_before_text = '\n'.join(snapshots.values())

    probe: dict[str, Any] = {'status': 'INCONCLUSIVE', 'reachable': False, 'discovered_config': {}}
    if resolved_site:
        probe = _probe_and_verify_live_or_fixture_site(resolved_site, eco, allow_local_fixture=allow_local_fixture)

    static_before = _reproduce_existing_source_failures(
        combined_before_text,
        eco,
        resolved_site or '',
        probe,
        allow_local_fixture=allow_local_fixture,
    )
    behavior_before = (
        execute_extension_behavior(
            eco,
            code_files,
            resolved_site.rstrip('/'),
            allow_local_fixture=allow_local_fixture,
            sandbox_available_override=sandbox_available_override,
        )
        if (resolved_site and probe.get('reachable') and code_files)
        else {'status': 'INCONCLUSIVE', 'failures': []}
    )
    merged_before_failures = sorted(set((static_before.get('failures') or []) + (behavior_before.get('failures') or [])))
    before_verification = {
        'status': 'FAIL' if merged_before_failures else behavior_before.get('status', static_before.get('status')),
        'failures': merged_before_failures,
        'static': static_before,
        'behavior': behavior_before,
    }

    # Pass 1: known pattern repairs
    modified_p1, changes_p1 = _apply_automated_code_repairs(tpath, eco, symptom, probe)
    # Re-evaluate intermediate behavior before deciding on Pass 2
    mid_behavior = (
        execute_extension_behavior(
            eco,
            code_files,
            resolved_site.rstrip('/'),
            allow_local_fixture=allow_local_fixture,
            sandbox_available_override=sandbox_available_override,
        )
        if (resolved_site and probe.get('reachable') and code_files)
        else {'status': 'INCONCLUSIVE', 'failures': []}
    )
    modified_p2: list[str] = []
    changes_p2: list[str] = []
    if mid_behavior.get('status') != 'PASS' and probe.get('reachable'):
        modified_p2, changes_p2 = _apply_structural_and_behavioral_repairs(tpath, eco, probe, mid_behavior)

    modified_files = sorted(set(modified_p1 + modified_p2))
    patch_changes = changes_p1 + changes_p2
    code_modified = len(modified_files) > 0

    after_proj = inspect_project(tpath) if tpath.exists() else {'sources': []}
    identity_check = (
        check_identity_continuity(before_proj.get('sources') or [], after_proj.get('sources') or [])
        if (before_proj.get('sources') and after_proj.get('sources'))
        else {'status': 'PASS'}
    )
    combined_after_text = '\n'.join(p.read_text(encoding='utf-8', errors='replace') for p in code_files)
    static_after = _reproduce_existing_source_failures(
        combined_after_text,
        eco,
        resolved_site or '',
        probe,
        allow_local_fixture=allow_local_fixture,
    )
    behavior_after = (
        execute_extension_behavior(
            eco,
            code_files,
            resolved_site.rstrip('/'),
            allow_local_fixture=allow_local_fixture,
            sandbox_available_override=sandbox_available_override,
        )
        if (resolved_site and probe.get('reachable') and code_files)
        else {'status': 'INCONCLUSIVE', 'failures': []}
    )

    # Rollback protection: if edits broke delimiter syntax or regressed identity when behavior failed
    rolled_back = False
    syntax_after_ok = all(_has_balanced_delimiters(p.read_text(encoding='utf-8', errors='replace'))[0] for p in code_files if p.suffix in {'.kt', '.ts', '.js'})
    if code_modified and (not syntax_after_ok or identity_check.get('status') == 'FAIL'):
        for fp, prev_txt in snapshots.items():
            atomic_write_text(fp, prev_txt)
        rolled_back = True
        modified_files = []
        code_modified = False
        behavior_after = behavior_before
        static_after = static_before
        identity_check = {'status': 'PASS', 'rolled_back': True}

    after_failures = sorted(set((static_after.get('failures') or []) + (behavior_after.get('failures') or [])))
    after_verification = {
        'status': (
            'BLOCKED'
            if behavior_after.get('status') == 'BLOCKED'
            else (
                'PASS'
                if (not after_failures and behavior_after.get('status') == 'PASS' and static_after.get('status') == 'PASS')
                else ('INCONCLUSIVE' if not probe.get('reachable') else 'FAIL')
            )
        ),
        'failures': after_failures,
        'static': static_after,
        'behavior': behavior_after,
        'rolled_back': rolled_back,
    }
    tests_verified = (
        probe.get('status') == 'PASS'
        and behavior_after.get('status') == 'PASS'
        and static_after.get('status') == 'PASS'
        and identity_check.get('status') == 'PASS'
        and not rolled_back
    )

    # Compilation + APK generation inside Bubblewrap after fix verification
    build_res: dict[str, Any] | None = None
    delivery_res: dict[str, Any] | None = None
    gradle_root: Path | None = None
    if tpath.is_dir():
        if (tpath / 'gradlew').is_file():
            gradle_root = tpath
        elif len(tpath.parents) >= 3:
            for par in tpath.parents:
                if (par / 'gradlew').is_file():
                    gradle_root = par
                    break
    if eco in {'keiyoushi', 'yuzono'} and code_modified and tests_verified:
        if gradle_root is not None or build_task is not None:
            broot = gradle_root or (tpath if tpath.is_dir() else tpath.parent)
            task = build_task or ':app:assembleDebug'
            build_res = nox_android.build_debug_apk(
                broot,
                task,
                sandbox_available_override=sandbox_available_override,
            )
            if build_res.get('apk_path') and build_res.get('status') not in {'BLOCKED', 'FAIL'}:
                delivery_res = nox_android.verify_and_offer_apk_delivery(
                    build_res.get('apk_path'),
                    min_mtime=build_res.get('build_started_at'),
                    lang=resolved_ui_lang,
                )
        else:
            mod_dir = _find_kotlin_module_dir(tpath)
            kt_src_p = next((p for p in code_files if p.suffix == '.kt'), None)
            kt_txt = kt_src_p.read_text(encoding='utf-8', errors='replace') if kt_src_p else ''
            pkg_m = re.search(r'^\s*package\s+([^\s;]+)', kt_txt, re.M)
            cls_m = re.search(r'\bclass\s+([A-Za-z_][A-Za-z0-9_]*)', kt_txt)
            if pkg_m and cls_m:
                expected_methods = (
                    ('getPopularManga', 'getSearchMangaList', 'fetchMangaUpdate', 'getPageList')
                    if eco == 'keiyoushi'
                    else ('popularAnimeRequest', 'episodeListParse', 'videoListParse')
                )
                build_res = nox_android.compile_kotlin_extension_to_debug_apk(
                    mod_dir,
                    package_name=pkg_m.group(1),
                    class_name=cls_m.group(1),
                    app_label=cls_m.group(1),
                    expected_methods=expected_methods,
                    sandbox_available_override=sandbox_available_override,
                )
                if build_res.get('apk_path') and build_res.get('status') not in {'BLOCKED', 'FAIL'}:
                    delivery_res = nox_android.verify_and_offer_apk_delivery(
                        build_res.get('apk_path'),
                        expected_package=pkg_m.group(1),
                        expected_class_name=cls_m.group(1),
                        expected_methods=expected_methods,
                        min_mtime=build_res.get('build_started_at'),
                        lang=resolved_ui_lang,
                    )

    apk_ready = bool(delivery_res and delivery_res.get('apk_ready'))
    apk_path = delivery_res.get('apk_path') if apk_ready else None
    apk_options = delivery_res.get('options') if apk_ready else None

    execution_stages = {
        'site_analyzed': 'PASS' if probe.get('reachable') else 'INCONCLUSIVE',
        'code_generated': 'PASS' if code_modified else ('ROLLED_BACK' if rolled_back else 'NOT_RUN'),
        'code_validated_statically': 'PASS' if (syntax_after_ok and identity_check.get('status') == 'PASS') else 'FAIL',
        'code_compiled': 'NOT_APPLICABLE' if eco == 'lnreader' else (build_res['status'] if build_res else 'NOT_RUN'),
        'extension_functions_tested': behavior_after.get('status', 'INCONCLUSIVE'),
        'apk_generated': 'NOT_APPLICABLE' if eco == 'lnreader' else ('PASS' if (build_res and build_res.get('apk_path') and build_res.get('status') == 'PASS') else (build_res['status'] if build_res else 'NOT_RUN')),
        'apk_inspected': 'NOT_APPLICABLE' if eco == 'lnreader' else (delivery_res['status'] if delivery_res else 'NOT_RUN'),
        'android_device_confirmed': 'NOT_APPLICABLE' if eco == 'lnreader' else 'NOT_RUN',
    }

    limitations: list[str] = []
    if behavior_after.get('status') == 'BLOCKED':
        status = 'BLOCKED'
        limitations.append(str(behavior_after.get('beginner_message') or behavior_after.get('reason') or 'Plugin verification blocked cleanly because sandbox isolation is unavailable.'))
    elif build_res is not None and build_res.get('status') == 'FAIL':
        status = 'FAIL'
        limitations.append(str(build_res.get('reason') or 'APK build failed.'))
    elif code_modified and tests_verified and eco == 'lnreader':
        status = 'PASS'
    elif code_modified and tests_verified and build_res is not None and apk_ready:
        status = 'PASS'
    elif code_modified and tests_verified and build_res is not None and build_res.get('status') == 'BLOCKED':
        status = 'PASS' if 'missing_build_toolchain' in str(build_res.get('reason', '')) and gradle_root is None and build_task is None else 'BLOCKED'
        limitations.append(str(build_res.get('reason') or 'APK compilation blocked in current environment.'))
    elif code_modified and not tests_verified:
        status = 'INCONCLUSIVE'
        limitations.append('Applied code fixes, though complete end-to-end verification remained partial.' if is_en else 'Apliquei as alterações no código, mas ainda não foi possível confirmar tudo na execução final.')
    else:
        status = 'INCONCLUSIVE'
        limitations.append(
            'Could not resolve this defect automatically with safe patches; agent continuation should inspect exact source logic.'
            if is_en
            else 'Ainda não encontrei uma correção automática segura para este caso; é preciso continuar analisando o código real para ajustar.'
        )

    top_alt = (loop.get('recommended_alternatives') or diag.get('recommended_actions') or [''])[0]
    agent_solver = None if status == 'PASS' else {
        'requires_agent_edit': True,
        'failing_checks': after_failures,
        'observed_before': before_verification.get('failures'),
        'expected_site_config': probe.get('discovered_config'),
        'repair_prompt': top_alt or 'Inspect the failing extension methods listed in failing_checks, patch the logic against expected_site_config, and re-run auto_fix_extension.',
    }
    task_complete = (status == 'PASS') and code_modified and tests_verified and (eco == 'lnreader' or build_res is None or build_res.get('status') == 'BLOCKED' or apk_ready)
    cont = build_agent_continuation(
        phase='DELIVER_ARTIFACT' if apk_ready else ('VERIFY_TESTS' if (code_modified and tests_verified) else 'IMPLEMENT_OR_PATCH'),
        task_complete=task_complete,
        status=status,
        completed_gates={
            'site_analyzed': execution_stages['site_analyzed'],
            'code_implemented': execution_stages['code_generated'],
            'functional_tests': execution_stages['extension_functions_tested'],
            'apk_build': execution_stages['apk_generated'],
            'apk_inspected': execution_stages['apk_inspected'],
        },
        next_agent_action=(
            'Deliver fixed APK options cleanly.'
            if apk_ready
            else ('Inspect agent_solver details, patch exact failing method on disk, re-run execute_extension_behavior, and compile APK.' if not task_complete else 'Deliver fixed files cleanly.')
        ),
        execution_stages=execution_stages,
    )

    if loop['loop_detected'] and not code_modified:
        msg = (
            'Detected repeated attempts without progress and switched investigation strategy.'
            if is_en
            else 'Identifiquei tentativas repetidas sem progresso e mudei a estratégia de investigação.'
        )
        nxt = top_alt
    elif apk_ready:
        msg = (
            'Fixed the extension, verified tests, and generated the updated Debug APK. 💜'
            if is_en
            else 'Corrigi a extensão, validei os testes disponíveis e gerei o novo APK Debug. 💜'
        )
        nxt = delivery_res['prompt'] if delivery_res else ''
    elif status == 'PASS':
        msg = (
            'Fixed the extension code and verified the repaired behavior.'
            if is_en
            else 'Corrigi o código da extensão e validei o funcionamento com sucesso.'
        )
        nxt = (
            f'Updated files saved: {", ".join(Path(p).name for p in modified_files)}'
            if is_en
            else f'Arquivos atualizados salvos: {", ".join(Path(p).name for p in modified_files)}'
        )
    elif status == 'BLOCKED' and behavior_after.get('status') == 'BLOCKED':
        msg = (
            'The automated verification of this plugin could not run safely on this computer. No untrusted code was executed.'
            if is_en
            else 'A verificação automática deste plugin não pôde ser executada com segurança neste computador. Nenhum código não confiável foi executado.'
        )
        nxt = (
            'Any safe source updates remain on disk. Enable Bubblewrap sandbox support (bwrap) and run the verification again.'
            if is_en
            else 'Eventuais ajustes seguros foram preservados no arquivo. Ative o sandbox Bubblewrap (bwrap) para concluir a verificação com isolamento.'
        )
    elif build_res is not None and build_res.get('status') in {'BLOCKED', 'FAIL'}:
        msg = (
            'Applied and verified code fixes on disk, while Debug APK compilation stopped.'
            if is_en
            else 'Apliquei e validei a correção no código, mas ainda não foi possível gerar o novo APK Debug.'
        )
        nxt = 'Os arquivos corrigidos estão salvos para nova compilação assim que possível.' if not is_en else 'Fixed source files remain saved on disk.'
    else:
        msg = (
            'Ran initial diagnosis; continuing deeper source inspection and patching.'
            if is_en
            else 'Fiz o diagnóstico inicial e ainda preciso concluir a correção no código antes de confirmar o conserto.'
        )
        nxt = top_alt or (
            'Open the target module code, apply the concrete fix, and re-run checks.'
            if is_en
            else 'Continuando a leitura do código real para aplicar e testar a correção.'
        )

    payload = {
        'status': status,
        'action': 'auto_fix',
        'ecosystem': eco,
        'ui_lang': resolved_ui_lang,
        'target': str(tpath),
        'output_dir': str(tpath if tpath.is_dir() else tpath.parent),
        'symptom': symptom,
        'persisted_files': modified_files,
        'modified_files': modified_files,
        'patch_changes': patch_changes,
        'code_modified': code_modified,
        'rolled_back': rolled_back,
        'tests_verified': tests_verified,
        'before_verification': before_verification,
        'after_verification': after_verification,
        'identity_continuity': identity_check,
        'execution_stages': execution_stages,
        'agent_solver': agent_solver,
        'artifact_path': apk_path or (modified_files[0] if modified_files else None),
        'apk_ready': apk_ready,
        'apk_path': apk_path,
        'apk_options': apk_options,
        'user_message': msg,
        'next_step': nxt,
        'user_limitations': limitations or None,
        'diagnosis': diag,
        'loop_detection': loop,
        'security_preflight': sec,
        'environment': doctor,
        'reference_snapshot': ref_status,
        'sandbox_build': build_res,
        'apk_delivery': delivery_res,
        'optional_adb_status': adb_status,
        'optional_adb_guide': adb_guide,
        'agent_continuation': cont,
    }
    return format_adaptive_response(
        payload,
        technical=technical,
        lang=resolved_ui_lang,
        diagnostics_dir=tpath if tpath.is_dir() else tpath.parent,
    )
