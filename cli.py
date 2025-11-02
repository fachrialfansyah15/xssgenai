# cli.py

import argparse
import logging
import os
import sys
import re
import copy
from collections import Counter
from pathlib import Path
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from threading import RLock

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.logging import RichHandler

from config import LOG_FILE, MAX_DEPTH_CRAWL, MAX_URLS_TO_CRAWL
from payloads import DEFAULT_XSS_PAYLOADS
from utils import (
    load_payloads_from_yaml,
    parse_raw_http_request,
    build_surfaces_from_raw_request,
)
from network import (
    session,
    register_waf,
    set_waf_throttle,
    make_request,
    DEFAULT_VERIFY,
    ensure_insecure_warning_suppressed,
)
from tester import XSSTester, configure_ui, summarize_filter_profile
from ai_analysis import AIAnalyzer
from dynamic_dom_tester import dynamic_dom_inspect
import graphql_scanner
from parsers.context_parser import ContextParser
from parsers.xss_classifier import classify_categories, summarize_categories
from waf_detector import WAFDetector
from sanitization_analyzer import analyze_param_sanitizer, analyze_keyword_mangling, CHARSET_PROBE
from i18n import tr

logger = logging.getLogger("xsscanner")
console = Console(highlight=False)
_PRINT_LOCK = RLock()
_ORIGINAL_CONSOLE_PRINT = console.print


def _threadsafe_print(*args, **kwargs):
    with _PRINT_LOCK:
        _ORIGINAL_CONSOLE_PRINT(*args, **kwargs)


console.print = _threadsafe_print  # type: ignore[attr-defined]

# Best-effort: ensure UTF-8-capable output to avoid Windows cp1252 crashes
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:
    pass


def _friendly_waf_name(vendor: str) -> str:
    mapping = {
        'cloudflare': 'Cloudflare',
        'cloudfront': 'CloudFront',
        'akamai': 'Akamai',
        'aws_waf': 'AWS WAF',
        'imperva': 'Imperva (Incapsula)',
        'barracuda': 'Barracuda WAF',
        'bigip_asm': 'F5 BIG-IP ASM',
        'sucuri': 'Sucuri',
        'azure_waf': 'Azure WAF',
        'fastly': 'Fastly',
        'stackpath': 'StackPath',
        'naxsi': 'NAXSI',
        'sophos': 'Sophos UTM',
        'mod_security': 'ModSecurity',
        'shield': 'ShieldSquare',
        'dosarrest': 'DOSarrest',
        'comodo': 'Comodo WAF',
        'generic': 'WAF generik',
    }
    key = (vendor or '').strip().lower()
    if not key:
        return 'WAF tidak diketahui'
    return mapping.get(key, key.replace('_', ' ').title())


def display_banner():
    banner = r"""
██╗  ██╗███████╗███████╗ ██████╗ ███████╗███╗   ██╗ █████╗ ██╗
╚██╗██╔╝██╔════╝██╔════╝██╔════╝ ██╔════╝████╗  ██║██╔══██╗██║
 ╚███╔╝ ███████╗███████╗██║  ███╗█████╗  ██╔██╗ ██║███████║██║
 ██╔██╗ ╚════██║╚════██║██║   ██║██╔══╝  ██║╚██╗██║██╔══██║██║
██╔╝ ██╗███████║███████║╚██████╔╝███████╗██║ ╚████║██║  ██║██║
╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝
                    MerdekaSiberLab - Version 2.2.2 (Semeru)
    """
    try:
        console.print(f"[bold bright_red]{banner}[/bold bright_red]")
        console.print(
            Panel(
                "XSS Scanner (Enhanced with [bold]Gemini AI Analysis[/bold] & Advanced Crawler)",
                title="[bold]Welcome[/bold]",
                subtitle="[italic]A Modern XSS Scanning Tool[/italic]",
                border_style="cyan"
            )
        )
    except UnicodeEncodeError:
        print("XSS Scanner - MerdekaSiberLab (ASCII mode)")
        print("XSS Scanner: Gemini AI & Advanced Crawler Ready")




def _shorten(text: str, limit: int = 80) -> str:
    if not text:
        return '-'
    cleaned = str(text).strip().replace('\n', ' ').replace('\r', '')
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(0, limit - 3)] + '...'


def _format_char_label(ch: str) -> str:
    if not ch:
        return '-'
    if ch == ' ':
        return '<sp>'
    if ch == '\n':
        return '<nl>'
    if ch == '\t':
        return '<tab>'
    if len(ch) == 1 and 32 <= ord(ch) <= 126:
        return ch
    if len(ch) == 1:
        return f"0x{ord(ch):02x}"
    return repr(ch)


def _normalize_target_url(url: str) -> Optional[str]:
    if not url:
        return None
    candidate = url.strip()
    if not candidate:
        return None
    if not candidate.lower().startswith(("http://", "https://")):
        candidate = f"http://{candidate}"
    return candidate


def _origin_key(url: str) -> tuple[str, str]:
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        netloc = (parsed.netloc or "").lower()
        return scheme, netloc
    except Exception:
        return ("http", url.lower())


def _extract_urls_from_text(text: str) -> List[str]:
    targets: List[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        norm = _normalize_target_url(line)
        if norm:
            targets.append(norm)
    return targets


def _infer_default_scheme(specs: List[Dict[str, Any]]) -> str:
    for spec in specs:
        try:
            parsed = urlparse(spec.get("url") or "")
            if parsed.scheme:
                return parsed.scheme
        except Exception:
            continue
    return "https"


def _prepare_target_specs(args, stdin_data: Optional[str] = None) -> tuple[List[Dict[str, Any]], List[str]]:
    specs: List[Dict[str, Any]] = []
    spec_map: Dict[str, Dict[str, Any]] = {}
    warnings: List[str] = []

    def _add_target(url: str, source: str, skip_crawl: bool = False) -> Optional[Dict[str, Any]]:
        norm = _normalize_target_url(url)
        if not norm:
            warnings.append(f"Target kosong dari {source} diabaikan.")
            return None
        if norm in spec_map:
            return spec_map[norm]
        spec = {
            "url": norm,
            "source": source,
            "raw_requests": [],
            "skip_crawl": bool(skip_crawl),
        }
        spec_map[norm] = spec
        specs.append(spec)
        return spec

    if getattr(args, "url", None):
        _add_target(args.url, "cli")

    if getattr(args, "urls_file", None):
        try:
            content = Path(args.urls_file).read_text(encoding="utf-8")
        except FileNotFoundError:
            warnings.append(f"File target tidak ditemukan: {args.urls_file}")
            content = ""
        except UnicodeDecodeError:
            content = Path(args.urls_file).read_text(encoding="latin-1", errors="ignore")
        for target in _extract_urls_from_text(content):
            _add_target(target, "file")

    if getattr(args, "stdin", False):
        for target in _extract_urls_from_text(stdin_data or ""):
            _add_target(target, "stdin")

    raw_input = getattr(args, "raw_request", None)
    if raw_input:
        raw_payload = ""
        if raw_input == "-":
            raw_payload = stdin_data or ""
            if not raw_payload.strip():
                warnings.append("STDIN tidak berisi request HTTP mentah.")
        else:
            try:
                raw_payload = Path(raw_input).read_text(encoding="utf-8")
            except FileNotFoundError:
                warnings.append(f"File raw request tidak ditemukan: {raw_input}")
            except UnicodeDecodeError:
                try:
                    raw_payload = Path(raw_input).read_text(encoding="latin-1", errors="ignore")
                except Exception as exc:
                    warnings.append(f"Gagal membaca raw request: {exc}")
        if raw_payload:
            try:
                parsed = parse_raw_http_request(raw_payload, default_scheme=_infer_default_scheme(specs))
                match = None
                for spec in specs:
                    if _origin_key(spec["url"]) == _origin_key(parsed["url"]):
                        match = spec
                        break
                if match is None:
                    match = _add_target(parsed["url"], "raw", skip_crawl=True)
                if match is not None:
                    match.setdefault("raw_requests", []).append(parsed)
                    if match.get("source") == "raw":
                        match["skip_crawl"] = True
            except ValueError as exc:
                warnings.append(f"Gagal parsing raw request: {exc}")

    return specs, warnings


DEFAULT_PARAM_WORDLIST: List[str] = [
    "_method",
    "_token",
    "_csrf",
    "callback",
    "cb",
    "json",
    "format",
    "redirect",
    "return_to",
    "next",
    "continue",
    "dest",
    "path",
    "state",
    "lang",
    "locale",
    "theme",
    "style",
    "view",
    "mode",
    "action",
    "template",
    "query",
    "search",
    "filter",
    "sort",
    "order",
    "type",
    "id",
    "item",
]


def _build_oob_config(provider: str) -> Dict[str, Any]:
    provider = (provider or "internal").lower()
    if provider == "interactsh":
        base_url = os.getenv("INTERACTSH_BASE_URL", "").strip()
        poll_url = os.getenv("INTERACTSH_POLL_URL", "").strip()
        headers = {}
        auth_header = os.getenv("INTERACTSH_AUTH_HEADER")
        auth_value = os.getenv("INTERACTSH_AUTH_VALUE")
        if auth_header and auth_value:
            headers[auth_header.strip()] = auth_value.strip()
        attempts = int(os.getenv("INTERACTSH_POLL_ATTEMPTS", "20") or 20)
        interval = int(os.getenv("INTERACTSH_POLL_INTERVAL", "6") or 6)
        return {
            "provider": "interactsh",
            "base_url": base_url,
            "poll_url": poll_url,
            "headers": headers,
            "poll_attempts": attempts,
            "poll_interval": interval,
        }
    if provider == "xsshunter":
        base_url = os.getenv("XSSHUNTER_BASE_URL", "").strip()
        poll_url = os.getenv("XSSHUNTER_POLL_URL", "").strip()
        api_key = os.getenv("XSSHUNTER_TOKEN", "").strip()
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        attempts = int(os.getenv("XSSHUNTER_POLL_ATTEMPTS", "20") or 20)
        interval = int(os.getenv("XSSHUNTER_POLL_INTERVAL", "6") or 6)
        return {
            "provider": "xsshunter",
            "base_url": base_url,
            "poll_url": poll_url,
            "headers": headers,
            "poll_attempts": attempts,
            "poll_interval": interval,
        }
    return {"provider": "internal"}
def _render_sanitizer_overview(param_name: str, sanitizer_map: dict) -> dict:
    if not sanitizer_map:
        console.print('[yellow]Tidak ada karakter yang terpantau pada baseline refleksi.[/yellow]')
        return {'filtered': 0, 'encoded': 0, 'reflected': 0, 'total': 0}
    counts = Counter(sanitizer_map.values())
    table = Table(show_header=True, header_style='bold cyan', border_style='yellow')
    table.add_column(tr('Status', 'Status'), style='cyan')
    table.add_column(tr('Jumlah', 'Count'), justify='right', style='yellow')
    table.add_column(tr('Contoh', 'Samples'), style='magenta', overflow='fold')
    for status in ('reflected', 'encoded', 'filtered'):
        chars = [
            _format_char_label(ch)
            for ch, st in sanitizer_map.items()
            if st == status
        ]
        preview_items = list(dict.fromkeys(chars))
        preview = ' '.join(preview_items) if preview_items else '-'
        table.add_row(status.title(), str(counts.get(status, 0) or 0), preview)
    subtitle = tr('Total sampel: {total}', 'Total samples: {total}').format(total=sum(counts.values()))
    console.print(Panel(table, title=tr("[bold yellow]Fingerprint Sanitizer '{param}'[/bold yellow]", "[bold yellow]Sanitizer Fingerprint '{param}'[/bold yellow]").format(param=param_name), border_style='yellow', subtitle=subtitle))
    return {
        'filtered': int(counts.get('filtered', 0) or 0),
        'encoded': int(counts.get('encoded', 0) or 0),
        'reflected': int(counts.get('reflected', 0) or 0),
        'total': int(sum(counts.values())),
    }


def _render_mangling_overview(mangling: dict) -> None:
    try:
        events = mangling.get('events', {}) if isinstance(mangling, dict) else {}
        schemes = mangling.get('schemes', {}) if isinstance(mangling, dict) else {}
    except Exception:
        events, schemes = {}, {}
    if not events and not schemes:
        return
    table = Table(title='[bold]Deteksi Mangling & Scheme[/bold]', border_style='cyan', show_lines=True)
    table.add_column('Jenis', style='magenta')
    table.add_column('Nama', style='cyan')
    table.add_column('Status', style='yellow')
    for k in sorted(events.keys()):
        table.add_row('Event Attr', k, str(events[k]))
    for k in sorted(schemes.keys()):
        table.add_row('URI Scheme', k, str(schemes[k]))
    console.print(table)


def _render_vuln_summary(vulns: List[dict]) -> None:
    # Hanya tampilkan payload yang benar-benar tereksekusi
    exec_vulns = []
    try:
        exec_vulns = [
            v for v in (vulns or [])
            if (str(v.get('class', '')).lower() == 'executed') or (str(v.get('type', '')).lower() == 'executed')
        ]
    except Exception:
        exec_vulns = []
    if not exec_vulns:
        console.print('[yellow]Belum ada payload yang terbukti dieksekusi.[/yellow]')
        return
    table = Table(title='[bold red]Payload Tereksekusi[/bold red]', border_style='red', show_lines=True)
    table.add_column('Jenis', style='red')
    table.add_column('Payload', style='magenta')
    table.add_column('Endpoint', style='green')
    for item in exec_vulns:
        table.add_row(
            item.get('type', '-') or '-',
            _shorten(item.get('payload', '-'), 70),
            _shorten(item.get('url', '-') or '-', 70)
        )
    console.print(table)


def _render_final_report(findings: List[dict]) -> None:
    if not findings:
        return
    table = Table(title='[bold red]XSS Findings Report[/bold red]', border_style='red', show_lines=True)
    table.add_column('Param', style='cyan')
    table.add_column('Sink', style='magenta')
    table.add_column('Kategori', style='yellow')
    table.add_column('Effect', style='green')
    table.add_column('Filter', style='magenta', overflow='fold')
    table.add_column('Payload', style='white', overflow='fold')
    table.add_column('URL', style='white', overflow='fold')
    for item in findings:
        sinks = ', '.join(item.get('sinks') or []) or '-'
        cats = ', '.join(item.get('categories') or []) or '-'
        filt = item.get('filter') or {}
        filter_text = ', '.join(filt.get('fingerprints') or [])
        if not filter_text:
            flags = filt.get('flags') or {}
            blocked = [name for name, allowed in flags.items() if allowed is False]
            if blocked:
                filter_text = "Blocks: " + ", ".join(blocked)
        if not filter_text:
            filter_text = '-'
        table.add_row(
            item.get('param') or '-',
            sinks,
            cats,
            item.get('effect') or '-',
            filter_text,
            _shorten(item.get('payload') or '-', 60),
            _shorten(item.get('url') or '-', 60),
        )
    console.print(table)


def _render_recommendations(rec: dict) -> None:
    if not rec:
        return
    sections = [
        ("Input/Output Encoding", rec.get('input_output') or []),
        ("DOM API", rec.get('dom_api') or []),
        ("CSP", rec.get('csp') or []),
        ("Headers", rec.get('headers') or []),
        ("Framework", rec.get('framework') or []),
    ]
    for title, items in sections:
        if not items:
            continue
        body = "\n".join(f"- {it}" for it in items)
        console.print(Panel(body, title=f"[bold green]{title} Recommendations[/bold green]", border_style='green'))


def _prompt_analysis_actions(analyzer_available: bool) -> str:
    table = Table(title='[bold]Pilihan Analisis Parameter[/bold]', border_style='cyan', show_lines=True)
    table.add_column('Pilihan', style='bold yellow', justify='center')
    table.add_column('Aksi', style='cyan')
    table.add_column('Deskripsi', style='magenta')
    table.add_row('1', 'Full pipeline', 'Fingerprint + inspeksi DOM + fuzzing multi-phase')
    table.add_row('2', 'Inspeksi DOM dinamis', 'Render headless untuk mendeteksi sink runtime')
    if analyzer_available:
        table.add_row('3', 'Analisis HTML/JS (Gemini)', 'Gunakan Gemini untuk ringkas HTML, JS, CSP')
    else:
        table.add_row('3', 'Analisis HTML/JS (Gemini)', 'Tidak tersedia - butuh API key GEMINI')
    table.add_row('4', 'Lewati parameter', 'Lanjut tanpa pengujian tambahan')
    console.print(table)
    choice_map = {'1': 'full', '2': 'dom', '3': 'ai', '4': 'skip', '': 'full'}
    while True:
        choice = console.input('[bold cyan]Pilih mode analisis (default 1) > [/bold cyan]').strip().lower()
        if choice in choice_map:
            return choice_map[choice]
        if not choice:
            return 'full'
        console.print(f"[yellow]Pilihan '{choice}' tidak dikenali.[/yellow]")
def parse_args():
    parser = argparse.ArgumentParser(
        description="Advanced XSS Scanner CLI (Enhanced dengan GenAI & Dynamic Crawler)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("url", nargs="?", help="URL awal untuk dipindai (harus pakai http:// atau https://)")
    parser.add_argument("--api-key", "-A", help="API key Google GenAI (atau set ENV GENAI_API_KEY)")
    parser.add_argument("--mode", "-m", choices=['quick', 'deep'], default='quick',
                        help="Pilih mode crawling: 'quick' atau 'deep'")
    parser.add_argument("--summary-only", "-s", action="store_true",
                        help="Hanya tampilkan ringkasan akhir, tanpa detail proses")
    parser.add_argument("--payloads", "-p", metavar="FILE",
                        help="Path ke file YAML berisi XSS payloads kustom.")
    parser.add_argument("--cookie", "-c", metavar="COOKIE_STRING",
                        help="Masukkan Cookie header (misal: 'name=val; name2=val2').")
    parser.add_argument("--insecure", action="store_true",
                        help="Izinkan koneksi HTTPS tanpa verifikasi sertifikat")
    parser.add_argument("--depth", "-d", type=int, default=MAX_DEPTH_CRAWL,
                        help="Kedalaman maksimal crawling")
    parser.add_argument("--max-urls", type=int, default=MAX_URLS_TO_CRAWL,
                        help="Maks jumlah URL untuk dicrawl")
    parser.add_argument("--graphql", action="store_true",
                        help="Scan endpoint GraphQL untuk potensi XSS lewat introspection")
    parser.add_argument("--user-selector",
                        help="CSS selector untuk field username (default: input[name=username])")
    parser.add_argument("--pass-selector",
                        help="CSS selector untuk field password (default: input[type=password])")
    parser.add_argument("--submit-selector",
                        help="CSS selector untuk tombol submit (default: button[type=submit])")
    parser.add_argument("--login-url",
                        help="URL halaman login (misal: https://target.com/login)")
    parser.add_argument("--username", help="Username untuk login")
    parser.add_argument("--password", help="Password untuk login")
    parser.add_argument("--workers", "-w", type=int, default=10,
                        help="Jumlah thread worker untuk paralelisme pengujian payload (default: 10)")
    parser.add_argument("--manual-login", action="store_true",
                        help="Gunakan sesi headful; selesaikan login/CAPTCHA secara manual lalu lanjut scan.")
    parser.add_argument("--cookie-file", default="cookies.json",
                        help="Path file untuk memuat / menyimpan cookie Playwright.")
    parser.add_argument("--auto-full", action="store_true",
                        help="Jalankan seluruh parameter dengan pipeline lengkap tanpa prompt interaktif.")
    parser.add_argument("--fast", action="store_true",
                        help="Lewati tahap brute-force encoding dan fokus ke engine kontekstual & tahap lain.")
    parser.add_argument("--js-scope", choices=["all", "first", "dom"], default="first",
                        help="Ruang lingkup analisis JS: 'all' (semua), 'first' (first-party saja), 'dom' (prioritas file dengan DOM sinks).")
    parser.add_argument("--param", action="append",
                        help="Tambahkan parameter manual (format name atau name=value) untuk diuji pada halaman awal.")
    parser.add_argument("--param-wordlist",
                        help="File berisi daftar parameter tambahan untuk brute-force (default wordlist internal dipakai bila tidak diatur).")
    parser.add_argument("--oob-provider", choices=["internal", "interactsh", "xsshunter"], default="internal",
                        help="Pilih penyedia OOB untuk Blind XSS (default: internal).")
    parser.add_argument("--urls-file",
                        help="File yang berisi daftar URL target (satu per baris).")
    parser.add_argument("--stdin", action="store_true",
                        help="Baca daftar URL target dari STDIN (satu per baris).")
    parser.add_argument("--threads", type=int, default=1,
                        help="Jumlah target yang dipindai paralel (default: 1).")
    parser.add_argument("--raw-request", metavar="FILE",
                        help="Path ke request HTTP mentah (gunakan '-' untuk membaca dari STDIN).")
    return parser.parse_args()




_JS_SINK_HINTS = [
    ("innerHTML assignment", r"innerHTML\s*="),
    ("document.write", r"document\.(write|writeln)\s*\("),
    ("eval()", r"\beval\s*\("),
    ("Function()", r"\bFunction\s*\("),
    ("new Function", r"new\s+Function\s*\("),
    ("setTimeout string", r"setTimeout\s*\(\s*['\"]"),
    ("insertAdjacentHTML", r"insertAdjacentHTML\s*\("),
    ("createContextualFragment", r"createContextualFragment\s*\("),
    ("jQuery.html", r"\.(html|append|prepend|before|after|replaceWith)\s*\("),
]

_JS_SOURCE_HINTS = [
    ("location.*", r"location\.(hash|search|href)"),
    ("document.cookie", r"document\.cookie"),
    ("URLSearchParams", r"URLSearchParams\s*\("),
    ("postMessage", r"postMessage\s*\("),
    ("localStorage", r"localStorage\.(getItem|setItem)"),
]


def _extract_js_snippet(code: str, start: int, end: int, radius: int = 90) -> str:
    lower = max(0, start - radius)
    upper = min(len(code), end + radius)
    snippet = code[lower:upper]
    snippet = snippet.replace('\r', ' ').replace('\n', ' ')
    return re.sub(r'\s+', ' ', snippet).strip()
    return re.sub(r'\s+', ' ', snippet).strip()


def _fetch_js_metadata(js_url: str) -> Dict:
    try:
        resp = make_request(js_url)
    except Exception as exc:
        logger.debug(f"JS fetch failed for {js_url}: {exc}")
        return {'url': js_url, 'error': str(exc)}
    if not resp or not (resp.text or '').strip():
        return {'url': js_url, 'error': 'empty'}

    code = resp.text or ''
    contexts = ContextParser.parse(code, content_type="application/javascript")

    sink_hits: List[str] = []
    sink_snippets: List[Dict[str, str]] = []
    for label, pattern in _JS_SINK_HINTS:
        match = re.search(pattern, code, re.IGNORECASE)
        if match:
            sink_hits.append(label)
            sink_snippets.append({'label': label, 'snippet': _extract_js_snippet(code, match.start(), match.end())})

    source_hits: List[str] = []
    for label, pattern in _JS_SOURCE_HINTS:
        if re.search(pattern, code, re.IGNORECASE):
            source_hits.append(label)

    size = len(code)
    score = len(sink_hits) * 5 + len(source_hits) * 2 + min(size // 5000, 6)
    if 'eval()' in sink_hits:
        score += 2
    if any('Function' in hit for hit in sink_hits):
        score += 2

    return {
        'url': js_url,
        'code': code if len(code) <= 400000 else code[:400000],
        'contexts': contexts,
        'sink_hits': sink_hits,
        'source_hits': source_hits,
        'sink_snippets': sink_snippets,
        'size': size,
        'score': score,
        'error': None,
    }


def _prepare_js_overview(js_urls: List[str]) -> List[Dict]:
    metas: List[Dict] = []
    for url in js_urls:
        meta = _fetch_js_metadata(url)
        if not meta:
            continue
        metas.append(meta)
    metas.sort(key=lambda m: (m.get('score', 0), len(m.get('sink_hits', [])), len(m.get('source_hits', []))), reverse=True)
    return metas


def _render_js_overview(metas: List[Dict]) -> Dict[str, Dict]:
    table = Table(title='[bold]Prioritas File JavaScript[/bold]', border_style='cyan', show_lines=True)
    table.add_column('Pilihan', style='bold yellow', justify='center')
    table.add_column('Score', justify='right', style='magenta')
    table.add_column('Sinks', style='red')
    table.add_column('Sources', style='cyan')
    table.add_column('Size', justify='right', style='green')
    table.add_column('URL', style='white', overflow='fold')
    choice_map: Dict[str, Dict] = {}
    for idx, meta in enumerate(metas, start=1):
        sink_hits = list(meta.get('sink_hits') or [])
        source_hits = list(meta.get('source_hits') or [])
        sinks = ', '.join(sink_hits[:3]) if sink_hits else '-'
        sources = ', '.join(source_hits[:3]) if source_hits else '-'
        size_kb = f"{meta.get('size', 0) / 1024:.1f} KB"
        table.add_row(str(idx), str(meta.get('score', 0)), sinks, sources, size_kb, meta.get('url', '-'))
        choice_map[str(idx)] = meta
    console.print(table)
    return choice_map


def _prompt_js_selection(metas: List[Dict]) -> List[Dict]:
    if not metas:
        return []
    choice_map = _render_js_overview(metas)
    while True:
        raw = console.input("[bold cyan]Pilih file JS (misal 1,3 atau 'top3'/'semua') > [/bold cyan]").strip().lower()
        if raw in {'', 'top', 'top1'}:
            return metas[:1]
        if raw in {'semua', 'all'}:
            return metas
        if raw.startswith('top'):
            try:
                num = int(raw[3:]) if len(raw) > 3 else 3
            except ValueError:
                num = 3
            num = max(1, min(num, len(metas)))
            return metas[:num]
        picks: List[Dict] = []
        valid = True
        for part in raw.split(','):
            key = part.strip()
            if not key:
                continue
            meta = choice_map.get(key)
            if not meta:
                valid = False
                break
            if meta not in picks:
                picks.append(meta)
        if valid and picks:
            return picks
        console.print(f"[yellow]Pilihan '{raw}' tidak dikenali.[/yellow]")


def _prompt_js_action(analyzer_available: bool) -> str:
    table = Table(title='[bold]Mode Analisis JS[/bold]', border_style='cyan', show_lines=True)
    table.add_column('Pilihan', style='bold yellow', justify='center')
    table.add_column('Aksi', style='cyan')
    table.add_column('Deskripsi', style='magenta')
    table.add_row('1', 'Ringkasan cepat', 'Deteksi sink & sumber tanpa AI')
    if analyzer_available:
        table.add_row('2', 'Analisis Gemini', 'Kirim ke Gemini untuk laporan lengkap')
    else:
        table.add_row('2', 'Analisis Gemini', 'Tidak tersedia - butuh API key')
    table.add_row('3', 'Lewati', 'Jangan analisis file ini')
    console.print(table)
    choice_map = {'1': 'summary', '2': 'ai', '3': 'skip', '': 'summary'}
    while True:
        choice = console.input('[bold cyan]Pilih mode untuk file ini (default 1) > [/bold cyan]').strip().lower()
        if choice in choice_map:
            return choice_map[choice]
        if not choice:
            return 'summary'
        console.print(f"[yellow]Pilihan '{choice}' tidak dikenali.[/yellow]")


def _print_js_quick_summary(meta: Dict) -> None:
    sinks = meta.get('sink_hits') or []
    sources = meta.get('source_hits') or []
    snippets = meta.get('sink_snippets') or []
    try:
        cls = classify_categories(contexts=meta.get('contexts') or [], code=meta.get('code'))
        cats = summarize_categories(cls)
        cats_line = ', '.join(cats) if cats else '-'
    except Exception:
        cats_line = '-'
    snippet_lines = "\n".join(
        f"- {item['label']}: {item['snippet']}" for item in snippets[:5]
    )
    if not snippet_lines:
        snippet_lines = '-'
    body = (
        f"Score: {meta.get('score', 0)}\n"
        f"Konsekuensi: Sinks={len(sinks)} | Sources={len(sources)}\n"
        f"Contexts: {', '.join(meta.get('contexts') or []) or '-'}\n"
        f"Kategori: {cats_line}\n\n"
        f"Snippet sink:\n{snippet_lines}"
    )
    console.print(Panel(body, title='[bold cyan]Ringkasan JS[/bold cyan]', border_style='cyan'))

def _same_site(base_host: str, host: str) -> bool:
    try:
        b = (base_host or '').lower()
        h = (host or '').lower()
        if not b or not h:
            return False
        if b == h:
            return True
        return h.endswith('.' + b)
    except Exception:
        return False

def _filter_js_files(base_url: str, js_urls: List[str], scope: str) -> List[str]:
    if not js_urls or not scope or scope == 'all':
        return list(js_urls or [])
    from urllib.parse import urlparse
    base_host = urlparse(base_url).hostname or ''
    out: List[str] = []
    skip_patterns = (
        'analytics', 'gtm', 'googletagmanager', 'google-analytics', 'ga.js', 'gtag',
        'doubleclick', 'hotjar', 'segment', 'mixpanel', 'matomo', 'piwik', 'adservice', 'statcounter'
    )
    for u in js_urls:
        try:
            parsed = urlparse(u)
            h = parsed.hostname or ''
            path_l = (parsed.path or '').lower()
            if scope in ('first', 'dom') and not _same_site(base_host, h):
                continue
            if any(tok in path_l for tok in skip_patterns):
                continue
            out.append(u)
        except Exception:
            continue
    return out
def setup_logging(verbose: bool):
    logger.setLevel(logging.DEBUG)
    console_handler = RichHandler(
        rich_tracebacks=True, console=console, show_path=False, show_level=False
    )
    # 💡 Pakai DEBUG kalau verbose, bukan INFO
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)


def run(target_args=None, shared=None, stdin_data=None):
    if target_args is None:
        args = parse_args()
        if getattr(args, "stdin", False) and getattr(args, "raw_request", "") == "-":
            console.print("[bold red]Tidak dapat menggunakan --stdin dan --raw-request - secara bersamaan.[/bold red]")
            return
        if stdin_data is None and (getattr(args, "stdin", False) or getattr(args, "raw_request", "") == "-"):
            try:
                stdin_data = sys.stdin.read()
            except Exception:
                stdin_data = ""

        specs, warnings = _prepare_target_specs(args, stdin_data)
        if not specs:
            console.print("[bold red]Setidaknya satu URL atau raw request diperlukan untuk memulai pemindaian.[/bold red]")
            return
        for msg in warnings:
            console.print(f"[yellow]{msg}[/yellow]")

        mass_mode = len(specs) > 1
        threads = max(1, int(getattr(args, "threads", 1) or 1))
        if mass_mode and not getattr(args, "auto_full", False):
            args.auto_full = True
        if mass_mode and not getattr(args, "summary_only", False):
            args.summary_only = True
        args._mass_mode = mass_mode
        args.threads = threads

        setup_logging(not args.summary_only)
        if args.insecure:
            session.verify = False
            try:
                import urllib3
                from urllib3.exceptions import InsecureRequestWarning
                urllib3.disable_warnings(InsecureRequestWarning)
            except Exception:
                pass
            ensure_insecure_warning_suppressed()
        else:
            session.verify = DEFAULT_VERIFY

        payloads = DEFAULT_XSS_PAYLOADS
        if args.payloads:
            path = Path(args.payloads)
            if path.is_file():
                payloads = load_payloads_from_yaml(path)
            else:
                console.print(f"[bold red][!] File payload tidak ditemukan: {args.payloads}[/bold red]")

        analyzer = None

        param_wordlist = list(dict.fromkeys(DEFAULT_PARAM_WORDLIST))
        if args.param_wordlist:
            try:
                content = Path(args.param_wordlist).read_text(encoding="utf-8")
            except FileNotFoundError:
                console.print(f"[bold red]File wordlist parameter tidak ditemukan: {args.param_wordlist}[/bold red]")
                content = ""
            except UnicodeDecodeError:
                content = Path(args.param_wordlist).read_text(encoding="latin-1", errors="ignore")
            for line in content.splitlines():
                name = line.strip()
                if not name or name.startswith("#"):
                    continue
                param_wordlist.append(name)
        param_wordlist = list(dict.fromkeys(param_wordlist))
        console.print(f"[cyan]Wordlist parameter aktif: {len(param_wordlist)} entri.[/cyan]")

        oob_config = _build_oob_config(getattr(args, "oob_provider", "internal"))
        if oob_config.get("provider") != "internal" and (not oob_config.get("base_url") or not oob_config.get("poll_url")):
            console.print("[yellow]Penyedia OOB eksternal membutuhkan konfigurasi lingkungan (BASE dan POLL URL). Gunakan --oob-provider internal jika belum siap.[/yellow]")

        shared = {
            "payloads": payloads,
            "analyzer": analyzer,
            "stdin_data": stdin_data,
            "param_wordlist": param_wordlist,
            "oob_config": oob_config,
        }

        def _prepare_args_for_spec(spec, index: int, total: int):
            target_args = copy.deepcopy(args)
            target_args.url = spec["url"]
            target_args._raw_requests = spec.get("raw_requests", [])
            target_args._skip_crawl = spec.get("skip_crawl", False)
            target_args._target_index = index
            target_args._target_total = total
            target_args._source = spec.get("source")
            target_args._mass_mode = mass_mode
            return target_args

        if threads > 1 and len(specs) > 1:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for idx, spec in enumerate(specs, start=1):
                    spec_args = _prepare_args_for_spec(spec, idx, len(specs))
                    futures.append(executor.submit(run, spec_args, shared, stdin_data))
                for future in futures:
                    future.result()
        else:
            for idx, spec in enumerate(specs, start=1):
                spec_args = _prepare_args_for_spec(spec, idx, len(specs))
                run(spec_args, shared, stdin_data)
        return

    args = target_args or args  # ensure args bound when recursing
    payloads = shared.get("payloads") if shared else DEFAULT_XSS_PAYLOADS
    analyzer = shared.get("analyzer") if shared else None
    param_wordlist = shared.get("param_wordlist") if shared else list(DEFAULT_PARAM_WORDLIST)
    oob_config = shared.get("oob_config") if shared else _build_oob_config(getattr(args, "oob_provider", "internal"))

    # Preflight: validate target host resolvable to avoid noisy network/Playwright errors
    try:
        from urllib.parse import urlparse as _urlparse
        import socket as _socket
        host = _urlparse(args.url).hostname
        if not host:
            console.print('[bold red]URL target tidak valid.[/bold red]')
            return
        try:
            _socket.getaddrinfo(host, 443 if args.url.startswith('https') else 80)
        except Exception:
            console.print('[bold yellow]Host target tidak dapat di-resolve (DNS). Periksa koneksi internet/DNS Anda dan coba lagi.[/bold yellow]')
            return
    except Exception:
        pass

    login_cfg: dict | None = None
    waf_plan: dict | None = None
    target_idx = int(getattr(args, "_target_index", 1) or 1)
    target_total = int(getattr(args, "_target_total", 1) or 1)
    try:
        label = f"[bold cyan]Target {target_idx}/{target_total}: {args.url}[/bold cyan]" if target_total > 1 else f"[bold cyan]Target: {args.url}[/bold cyan]"
        console.print(Rule(label, style="cyan"))
    except UnicodeEncodeError:
        print(f"Target {target_idx}/{target_total}: {args.url}")
    # 1) Muat payloads

    # 2) Inisialisasi AI Analyzer (jika ada API key)
    api_key = args.api_key or os.getenv("GENAI_API_KEY", "")
    analyzer = None
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            analyzer = AIAnalyzer(client, console_obj=console)
            console.print("[bold green]✔ Klien GenAI berhasil diinisialisasi.[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Gagal inisialisasi GenAI Client: {e}[/bold red]")
            console.print("[yellow]Analisis AI akan dilewati.[/yellow]")
    else:
        console.print("[yellow]Analisis AI akan dilewati (no API key).[/yellow]")

    # 3) Tampilkan banner & cookie
    if args.cookie:
        session.headers.update({"Cookie": args.cookie})
        console.print(f"[green]✔ Cookie diset:[/green] [dim]{args.cookie}[/dim]")

    waf_detector = None
    fingerprints_path = Path(__file__).resolve().parent / "waf_fingerprints.yaml"
    if fingerprints_path.exists():
        try:
            waf_detector = WAFDetector(fingerprints_path=fingerprints_path)
            profile = waf_detector.detect(args.url)
            register_waf(waf_detector)
            matches = profile.matches or {}
            friendly_vendor = _friendly_waf_name(profile.vendor)
            waf_lines = [
                f"{friendly_vendor} terdeteksi",
                f"Origin : {profile.origin}",
                f"Vendor : {profile.vendor} (confidence: {profile.confidence})",
                f"Challenge : {profile.challenge} | Rate limit: {'yes' if profile.rate_limit else 'no'}",
                f"Safe RPS : {profile.safe_rps:.2f} req/s | Backoff: {profile.backoff_ms} ms",
            ]
            if matches.get("headers"):
                waf_lines.append("Header hits: " + ", ".join(matches["headers"][:3]))
            if matches.get("cookies"):
                waf_lines.append("Cookie hits: " + ", ".join(matches["cookies"][:3]))
            if matches.get("body"):
                waf_lines.append("Body markers: " + ", ".join(matches["body"][:2]))
            if profile.notes:
                waf_lines.append(f"Notes: {profile.notes}")
            console.print(Panel("\n".join(waf_lines), title='[bold yellow]WAF Detection[/bold yellow]', border_style='yellow'))
            set_waf_throttle(profile.origin, profile.safe_rps, profile.backoff_ms)
            auto_accept = bool(getattr(args, "auto_full", False) or getattr(args, "summary_only", False) or getattr(args, "_mass_mode", False))
            if profile.vendor != 'unknown':
                if not auto_accept:
                    decision = console.input('[bold yellow]Lanjutkan dengan strategi bypass ini? (y/n) > [/]').strip().lower()
                    if decision not in {'y', 'ya', 'yes'}:
                        console.print('[yellow]Pemindaian dibatalkan oleh pengguna.[/yellow]')
                        return
                if profile.challenge in ('js', 'captcha') and args.mode == 'quick':
                    if auto_accept:
                        args.mode = 'deep'
                    else:
                        switch = console.input('[cyan]WAF memerlukan eksekusi JavaScript. Beralih ke mode dynamic? (Y/n) > [/cyan]').strip().lower()
                        if switch in {'', 'y', 'ya', 'yes'}:
                            args.mode = 'deep'
                waf_plan = {
                    'vendor': profile.vendor,
                    'bypass_level': profile.bypass_level,
                    'no_javascript_url': profile.metadata.get('no_javascript_url', profile.challenge in ('js', 'captcha')),
                    'reduce_inline_handlers': profile.metadata.get('reduce_inline_handlers', profile.challenge == 'js'),
                    'short_payloads': profile.metadata.get('short_payloads', profile.rate_limit or profile.safe_rps < 1.0),
                    'prefer_minimal_attr': True,
                }
            else:
                console.print('[green]Tidak ada fingerprint WAF yang dikenali secara pasti.[/green]')
        except Exception as exc:
            logger.debug(f'WAF detection failed: {exc}')
    else:
        logger.debug(f'Fingerprint WAF tidak ditemukan di {fingerprints_path}')

# ------------------------------------------------------------------
    # BLOK BARU: handle --manual-login
    # ------------------------------------------------------------------
    if args.manual_login and args.login_url:
        import json
        from login_flow import manual_login_capture  # helper yg Anda buat

        cookie_file = Path(args.cookie_file)

        if cookie_file.exists():
            console.print(f"[green]\u2714 Memuat cookie dari {cookie_file}[/green]")
            state = json.loads(cookie_file.read_text(encoding="utf-8"))
            for c in state["cookies"]:
                session.cookies.set(
                    c["name"],
                    c["value"],
                    domain=c.get("domain"),
                    path=c.get("path"),
                )
        else:
            cookies = manual_login_capture(
                args.login_url,
                Path(args.cookie_file),
                headless=False,  # Google perlu visible
            )
            for c in cookies:
                session.cookies.set(
                    c["name"],
                    c["value"],
                    domain=c.get("domain"),
                    path=c.get("path"),
                )
        # Matikan auto-login Playwright karena kita sudah punya sesi
        login_cfg = None

    # 4) Inisialisasi tester dengan thread pool
    tester = XSSTester(payloads, max_workers=args.workers, waf_plan=waf_plan, skip_encoding=bool(getattr(args, 'fast', False)))
    tester.oob_provider = (oob_config or {}).get("provider", getattr(args, "oob_provider", "internal"))
    tester.oob_config = oob_config or {}
    configure_ui(console=console, progress_style="log")

    if args.auto_full or args.summary_only:
        original_console_print = console.print

        def _safe_print(*messages, **kwargs):
            try:
                original_console_print(*messages, **kwargs)
            except UnicodeEncodeError:
                try:
                    text = " ".join(str(m) for m in messages)
                    plain = re.sub(r"\[/?[^\]]+\]", "", text)
                    print(plain)
                except Exception:
                    print(" ".join(str(m) for m in messages))

        console.print = _safe_print  # type: ignore[attr-defined]

    # 5) Siapkan konfigurasi login (jika ada, dan belum diganti mode manual)
    if (not args.manual_login) and args.login_url and args.username and args.password:
        login_cfg = {
            "url":        args.login_url,
            "username":   args.username,
            "password":   args.password,
            "user_field": args.user_selector,
            "pass_field": args.pass_selector,
            "submit_sel": args.submit_selector,
        }


    skip_crawl = bool(getattr(args, "_skip_crawl", False))
    if skip_crawl:
        from crawler.crawler import XSSCrawler
        crawler = XSSCrawler(
            start_url=args.url,
            max_depth=0,
            max_urls=0,
            verbose=not args.summary_only
        )
        try:
            console.print(Rule("[bold yellow][Skip] Melewati proses crawling (raw request mode)[/bold yellow]", style="yellow"))
        except UnicodeEncodeError:
            print("[Skip] Melewati proses crawling (raw request mode)")
    else:
        if args.mode == 'quick':
            from crawler.crawler import XSSCrawler
            try:
                console.print(Rule("[bold yellow][Quick] Memulai Quick Static Crawler[/bold yellow]", style="yellow"))
            except UnicodeEncodeError:
                print("[Quick] Memulai Quick Static Crawler")
            crawler = XSSCrawler(
                start_url=args.url,
                max_depth=args.depth,
                max_urls=args.max_urls,
                verbose=not args.summary_only
            )
        else:
            from crawler.advanced_crawler import AdvancedXSSCrawler
            try:
                console.print(Rule("[bold cyan] Memulai Advanced Dynamic Crawler[/bold cyan]", style="cyan"))
            except UnicodeEncodeError:
                print("[Dynamic] Memulai Advanced Dynamic Crawler")
            crawler = AdvancedXSSCrawler(
                start_url=args.url,
                max_depth=args.depth,
                max_urls=args.max_urls,
                verbose=not args.summary_only,
                login_cfg=login_cfg,
                storage_state_file=args.cookie_file
            )

# 7) Crawl & temukan parameter/JS
    if not skip_crawl:
        crawler.crawl_and_discover_parameters()
    try:
        parsed_start = urlparse(args.url)
        initial_qs = parse_qs(parsed_start.query, keep_blank_values=True)
        base_surface = parsed_start._replace(query="", fragment="").geturl()
        for name, values in (initial_qs or {}).items():
            if not name:
                continue
            value = values[0] if values else ""
            try:
                crawler._add_param_if_new({
                    "url": base_surface,
                    "method": "GET",
                    "data_template": {name: value},
                    "is_form": False
                })
            except Exception:
                logger.debug("Failed to register initial query param '%s'", name)
        for manual in args.param or []:
            if not manual:
                continue
            if "=" in manual:
                pname, pval = manual.split("=", 1)
            else:
                pname, pval = manual, ""
            pname = pname.strip()
            if not pname:
                continue
            try:
                crawler._add_param_if_new({
                    "url": base_surface,
                    "method": "GET",
                    "data_template": {pname: pval},
                    "is_form": False
                })
            except Exception:
                logger.debug("Failed to register manual param '%s'", pname)
        for brute_name in param_wordlist or []:
            brute_name = brute_name.strip()
            if not brute_name:
                continue
            try:
                crawler._add_param_if_new({
                    "url": base_surface,
                    "method": "GET",
                    "data_template": {brute_name: ""},
                    "is_form": False
                })
            except Exception:
                logger.debug("Failed to register wordlist param '%s'", brute_name)
    except Exception:
        logger.debug("Unable to process initial query parameters for %s", args.url)
    try:
        console.print(Rule("[bold green][Done] Crawler Selesai[/bold green]", style="green"))
    except UnicodeEncodeError:
        print("[Done] Crawler Selesai")

    params = list(crawler.discovered_parameters)
    js_files = list(crawler.discovered_js)

    raw_requests = getattr(args, "_raw_requests", []) or []
    raw_surfaces: List[Dict[str, Any]] = []
    for parsed in raw_requests:
        try:
            surfaces = build_surfaces_from_raw_request(parsed)
            raw_surfaces.extend(surfaces)
        except Exception as exc:
            logger.debug(f"Gagal membangun surface dari raw request: {exc}")
    if raw_surfaces:
        params.extend(raw_surfaces)
        console.print(f"[cyan]Menambahkan {len(raw_surfaces)} parameter dari raw HTTP request.[/cyan]")
    try:
        js_files = _filter_js_files(args.url, js_files, args.js_scope)
    except Exception:
        pass

    if not params and not js_files:
        console.print("[yellow]Tidak ada parameter atau file JavaScript yang ditemukan untuk diuji.[/yellow]")
        return

    auto_full = bool(getattr(args, "auto_full", False))

    # 8) Loop testing
    processed_once = False
    while True:
        table = Table(
            title="[bold]Target Pengujian yang Ditemukan[/bold]",
            border_style="cyan", show_lines=True
        )
        table.add_column("Pilihan", style="bold yellow", justify="center")
        table.add_column("Parameter/File", style="cyan")
        table.add_column("Method/Jenis", style="magenta")
        table.add_column("Endpoint (Agregat)", style="green", overflow="fold")

        # Kelompokkan parameter per endpoint
        grouped = {}
        for p in params:
            key = (p['url'], p['method'])
            grouped.setdefault(key, {'names': set(), 'entries': []})
            grouped[key]['names'].add(p['name'])
            grouped[key]['entries'].append(p)

        choice_map = {}
        idx = 1
        for (url, method), info in grouped.items():
            names = ", ".join(sorted(info['names']))
            table.add_row(str(idx), names, method, url)
            choice_map[str(idx)] = info['entries']
            idx += 1

        if js_files:
            table.add_section()
            table.add_row("js", f"Analisis Semua JS ({len(js_files)} file)", "-", "DOM-based XSS scan")

        console.print(table)

        selected_params: List[dict] = []
        selected_js: List[str] = []

        if auto_full:
            selected_params = params.copy()
            selected_js = list(js_files)
        else:
            choice = console.input("[bold]Pilihan Anda ('semua', js, 'q' untuk keluar) > [/bold]").strip().lower()
            if choice in ("q", "keluar"):
                break
            if choice == "semua":
                selected_params = params.copy()
            elif choice == "js":
                selected_js = list(js_files)
            else:
                for part in choice.split(","):
                    part = part.strip()
                    if part in choice_map:
                        selected_params.extend(choice_map[part])
                    else:
                        console.print(f"[yellow]Pilihan '{part}' tidak valid.[/yellow]")

        if not selected_params and not selected_js:
            if auto_full:
                console.print("[yellow]Tidak ada target yang dapat diuji secara otomatis.[/yellow]")
                break
            console.print("[red]Tidak ada pilihan yang valid.[/red]")
            continue

        # Uji parameter dengan pipeline bertahap (static -> dynamic -> AI)
        for p in selected_params:
            try:
                tester.set_filter_profile({})
            except Exception:
                pass
            console.print(Panel(
                (
                    f"[bold]Parameter:[/bold] [yellow]{p['name']}[/yellow]\n"
                    f"[bold]URL/Action:[/bold] [underline]{p['url']}[/underline]\n"
                    f"[bold]Method:[/bold] [magenta]{p['method']}[/magenta]"
                ),
                title='[bold bright_magenta]Menguji Parameter[/bold bright_magenta]',
                border_style='magenta'
            ))
            template = dict(p.get('data_template', {}))
            sanitizer_map: dict = {}
            sanitizer_summary = {}
            sanitizer_error = None
            mangling: dict | None = None
            status_message = '[cyan]Memprofilkan refleksi statis (HTML/CSS/JS)...[/cyan]'
            san_meta: Dict[str, Any] = {}
            with console.status(status_message, spinner='dots') as status:
                def _static_progress(idx: int, total: int, ch: str) -> None:
                    try:
                        note = ""
                        base_ch = ch
                        if ch.endswith(")") and "(" in ch:
                            paren_idx = ch.rfind("(")
                            base_ch = ch[:paren_idx]
                            meta = ch[paren_idx + 1:-1]
                            if meta:
                                if meta == "timeout":
                                    note = " (timeout)"
                                elif meta == "sending":
                                    note = " (mengirim...)"
                                else:
                                    note = f" ({meta})"
                        label = _format_char_label(base_ch)
                        status.update(
                            status=f"{status_message} [dim]{idx}/{total} karakter: {label}{note}[/dim]"
                        )
                    except Exception:
                        pass
                try:
                    probe_timeout = 2.0 if getattr(args, "fast", False) else None
                    sanitizer_map = analyze_param_sanitizer(
                        p['url'],
                        p['name'],
                        template,
                        p['method'],
                        p['is_form'],
                        progress_callback=_static_progress,
                        meta_out=san_meta,
                        per_probe_timeout=probe_timeout,
                    ) or {}
                except Exception as exc:
                    sanitizer_error = exc
                finally:
                    try:
                        status.update(status='[cyan]Profil statis selesai.[/cyan]')
                    except Exception:
                        pass
            if sanitizer_error:
                console.print(f'[red]Gagal menganalisis sanitizer: {sanitizer_error}[/red]')
                sanitizer_map = {}
            else:
                processed = int(san_meta.get("processed", len(sanitizer_map)) or 0)
                total_chars = int(san_meta.get("total", len(CHARSET_PROBE)) or len(CHARSET_PROBE))
                timeout_chars = list(dict.fromkeys(san_meta.get("timeouts", ())))
                if san_meta.get("aborted"):
                    console.print(
                        f"[yellow]Profil statis dihentikan setelah {processed}/{total_chars} karakter "
                        f"karena {san_meta.get('timeout_limit', 0)} timeout beruntun.[/yellow]"
                    )
                elif timeout_chars:
                    preview = ", ".join(_format_char_label(ch) for ch in timeout_chars[:5])
                    if len(timeout_chars) > 5:
                        preview += ", ..."
                    console.print(
                        f"[yellow]{len(timeout_chars)} karakter timeout saat profiling: {preview}[/yellow]"
                    )
                sanitizer_summary = _render_sanitizer_overview(p['name'], sanitizer_map)
                # Deteksi attribute mangling & scheme handling
                try:
                    mangling = analyze_keyword_mangling(
                        p['url'],
                        p['name'],
                        template,
                        p['method'],
                        p['is_form'],
                        request_meta=p.get('request_meta')
                    )
                    _render_mangling_overview(mangling)
                except Exception as exc:
                    logger.debug(f"Mangling analysis failed: {exc}")
                    mangling = mangling or {}

            filter_profile = summarize_filter_profile(sanitizer_map, mangling or {})
            try:
                body_lines = [f"- {text}" for text in (filter_profile.get("reasons") or [])]
                if filter_profile.get("fingerprints"):
                    body_lines.append("")
                    body_lines.append("Fingerprint: " + ", ".join(filter_profile.get("fingerprints")))
                console.print(Panel("\n".join(body_lines) or "-", title='[bold cyan]Filter Insights[/bold cyan]', border_style='cyan'))
            except Exception:
                pass
            try:
                tester.set_filter_profile(filter_profile)
            except Exception:
                logger.debug("Tidak dapat menetapkan filter profile ke tester.")

            if auto_full:
                mode = 'full'
            else:
                mode = _prompt_analysis_actions(analyzer is not None)

            runtime_findings: List[dict] = []

            if mode == 'skip':
                console.print('[yellow]Parameter dilewati sesuai permintaan pengguna.[/yellow]')
                continue

            if mode in {'full', 'dom'}:
                with console.status('[cyan]Menjalankan inspeksi DOM dinamis...[/cyan]', spinner='dots'):
                    try:
                        runtime_findings = dynamic_dom_inspect(p['url']) or []
                    except Exception as exc:
                        logger.debug(f'DOM inspect gagal: {exc}')
                        runtime_findings = []
                if runtime_findings:
                    console.print(Panel(f"{len(runtime_findings)} temuan runtime sink/mutation.", title='[cyan]Dynamic Findings[/cyan]'))
                else:
                    console.print('[yellow]Tidak ada temuan runtime dari inspeksi DOM.[/yellow]')

            if mode == 'dom':
                if analyzer:
                    ai_choice = console.input('[bold magenta]Lanjutkan dengan analisis Gemini? (Y/n) > [/bold magenta]').strip().lower()
                    if ai_choice in {'', 'y', 'ya', 'yes'}:
                        ai_payload = {
                            **p,
                            'sanitizer_map': sanitizer_map,
                            'sanitizer_summary': sanitizer_summary,
                            'taint_flow': runtime_findings,
                            'vulns': [],
                        }
                        analyzer.perform_interactive_ai_for_parameter(ai_payload, interactive=False)
                else:
                    console.print('[yellow]Analisis AI tidak tersedia (set GENAI_API_KEY untuk mengaktifkan).[/yellow]')
                continue

            if mode == 'ai':
                if not analyzer:
                    console.print('[yellow]Analisis AI tidak tersedia karena tidak ada API key Gemini.[/yellow]')
                else:
                    ai_payload = {
                        **p,
                        'sanitizer_map': sanitizer_map,
                        'sanitizer_summary': sanitizer_summary,
                        'taint_flow': runtime_findings,
                        'vulns': [],
                    }
                    analyzer.perform_interactive_ai_for_parameter(ai_payload, interactive=False)
                continue

            template_for_test = dict(template)
            before = len(tester.vulns)
            tester.test_parameter(
                p['url'],
                p['method'],
                p['name'],
                template_for_test,
                p['is_form'],
                sanitizer_baseline=sanitizer_map if sanitizer_map else None,
                request_meta=p.get('request_meta')
            )
            after = len(tester.vulns)
            new_vulns = tester.vulns[before:after]
            if new_vulns:
                _render_vuln_summary(new_vulns)
            else:
                console.print('[yellow]Belum ada payload yang terbukti dieksekusi.[/yellow]')

            runtime_findings = runtime_findings or tester.last_runtime_findings
            if analyzer and not auto_full:
                ai_choice = console.input('[bold magenta]Perkuat dengan analisis Gemini? (Y/n) > [/bold magenta]').strip().lower()
                if ai_choice in {'', 'y', 'ya', 'yes'}:
                    ai_payload = {
                        **p,
                        'sanitizer_map': sanitizer_map,
                        'sanitizer_summary': sanitizer_summary,
                        'taint_flow': runtime_findings,
                        'vulns': new_vulns,
                    }
                    analyzer.perform_interactive_ai_for_parameter(ai_payload, interactive=False)

        # Uji JS eksternal
        if selected_js:
            metas = _prepare_js_overview(selected_js)
            if args.js_scope == 'dom':
                try:
                    metas = [m for m in metas if (m.get('sink_hits') or [])]
                except Exception:
                    pass
            if not metas:
                console.print('[yellow]Tidak ada file JavaScript yang dapat dianalisis.[/yellow]')
            else:
                if auto_full:
                    for meta in metas[:5]:
                        console.print(Panel(
                            f"Menganalisis File JS: [underline]{meta['url']}[/underline]",
                            title="[bold]Target JavaScript[/bold]",
                            border_style="cyan"
                        ))
                        _print_js_quick_summary(meta)
                else:
                    chosen_js = _prompt_js_selection(metas)
                    for meta in chosen_js:
                        console.print(Panel(
                            f"Menganalisis File JS: [underline]{meta['url']}[/underline]",
                            title="[bold]Target JavaScript[/bold]",
                            border_style="cyan"
                        ))
                        action = _prompt_js_action(analyzer is not None)
                        if action == 'skip':
                            console.print('[yellow]File JS dilewati sesuai permintaan pengguna.[/yellow]')
                            continue
                        if action == 'summary':
                            _print_js_quick_summary(meta)
                            if analyzer:
                                follow = console.input('[bold magenta]Jalankan analisis Gemini juga? (Y/n) > [/bold magenta]').strip().lower()
                                if follow in {'', 'y', 'ya', 'yes'}:
                                    analyzer.analyze_external_js(meta['url'], mode='ai', js_code=meta.get('code'))
                            else:
                                console.print('[yellow]Analisis AI tidak tersedia (set GENAI_API_KEY untuk mengaktifkan).[/yellow]')
                            continue
                        if action == 'ai':
                            if analyzer:
                                analyzer.analyze_external_js(meta['url'], mode='ai', js_code=meta.get('code'))
                            else:
                                console.print('[yellow]Analisis AI tidak tersedia karena tidak ada API key Gemini.[/yellow]')
                                _print_js_quick_summary(meta)
                            continue

        processed_once = True
        if auto_full:
            break

        again = console.input("\n[bold]Uji target lain? (y/n) > [/bold]").strip().lower()
        if again != 'y':
            break

    if tester.resilience_reports:
        summary = tester.resilience_summary()
        checklist_items = summary.get('checklist') or []
        checklist = "\n".join(f"- {item}" for item in checklist_items)
        panel_body = (
            f"Score: [bold]{summary.get('score', 0)}/100[/bold]\n"
            f"Confidence: {summary.get('confidence', 'unknown')}\n\n"
            f"{checklist or 'Tidak ada bukti terverifikasi.'}"
        )
        console.print(Panel(panel_body, title='[bold cyan]XSS Resilience Score[/bold cyan]', border_style='cyan'))
    else:
        console.print('[yellow]Tidak ada data resilience yang dapat dirangkum.[/yellow]')

    # 8.5) Final findings report
    try:
        findings = tester.build_findings_report()
        if findings:
            _render_final_report(findings)
        else:
            console.print('[yellow]Tidak ada XSS terverifikasi untuk dirangkum.[/yellow]')
    except Exception as exc:
        logger.debug(f'Final report generation failed: {exc}')

    # 8.6) Recommendations
    try:
        rec = tester.generate_recommendations()
        _render_recommendations(rec)
    except Exception as exc:
        logger.debug(f'Recommendation generation failed: {exc}')


    # 9) GraphQL XSS scan (opsional)
    if args.graphql:
        console.print(Rule("[bold magenta]🔍 GraphQL XSS Scan[/bold magenta]", style="magenta"))
        endpoints = graphql_scanner.discover_graphql_endpoints(args.url)
        if not endpoints:
            console.print("[yellow]Tidak ditemukan endpoint GraphQL umum.[/yellow]")
        else:
            for ep in endpoints:
                console.print(f"[blue]→ Introspecting {ep}…[/blue]")
                schema = graphql_scanner.introspect_schema(ep)
                if schema:
                    graphql_scanner.test_graphql_xss(ep, schema)
                else:
                    console.print(f"[bold red]✖ Gagal introspeksi di {ep}[/bold red]")


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        console.print("\n[bold red]Dibatalkan pengguna — keluar program.[/bold red]")
        sys.exit(1)
    except Exception:
        logger.error("Terjadi error tak terduga!", exc_info=True)








