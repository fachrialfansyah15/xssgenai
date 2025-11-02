from __future__ import annotations

from typing import Dict, List

from utils import contains_unescaped, decode_all


def sink_location_labels(contexts: List[str]) -> List[str]:
    """Derive high-level sink locations from low-level contexts."""
    try:
        ctx = set(contexts or [])
    except Exception:
        ctx = set()
    out: List[str] = []
    if ctx & {"attr_quoted", "attr_unquoted", "data_attribute", "srcdoc_attr", "css_inline"}:
        out.append("Attribute HTML")
    if "html_tag" in ctx or "tag_comment" in ctx:
        out.append("Body HTML")
    if ctx & {"script_tag", "js_string", "template_literal"}:
        out.append("JavaScript")
    if ctx & {"css_url", "css_expression"}:
        out.append("CSS")
    if "uri_scheme" in ctx:
        out.append("URL/Hash")
    return out


def summarize_filter_profile(
    sanitizer_map: Dict[str, str],
    mangling: Dict[str, Dict[str, str]] | None,
) -> Dict[str, object]:
    """Infer backend sanitization behaviour and resulting payload allowances."""

    def _status(ch: str) -> str | None:
        if isinstance(sanitizer_map, dict):
            val = sanitizer_map.get(ch)
            if val == "timeout":
                return "filtered"
            return val
        return None

    flags = {
        "allow_html": True,
        "allow_attr": True,
        "allow_event": True,
        "allow_url_scheme": True,
        "allow_js_string": True,
    }
    reasons: List[str] = []
    fingerprints: List[str] = []

    lt = _status("<")
    gt = _status(">")
    if lt in {"encoded", "filtered"} or gt in {"encoded", "filtered"}:
        flags["allow_html"] = False
        if lt == "encoded" or gt == "encoded":
            fingerprints.append("htmlspecialchars")
            reasons.append("Tanda sudut di-encode (indikasi htmlspecialchars/ENT_QUOTES).")
        else:
            fingerprints.append("strip_tags")
            reasons.append("Tanda sudut dihilangkan atau diganti (indikasi strip_tags/whitelist).")
    else:
        reasons.append("Tanda sudut tercermin utuh -> payload berbasis tag masih relevan.")

    dq = _status('"')
    sq = _status("'")
    bt = _status("`")
    if dq in {"filtered", "encoded"} and sq in {"filtered", "encoded"}:
        flags["allow_attr"] = False
        if bt == "reflected":
            flags["allow_js_string"] = True
            reasons.append("Kedua kutip diblokir, namun backtick (`) utuh -> coba template literal breakout.")
        else:
            flags["allow_js_string"] = False
            reasons.append("Kedua kutip diblokir/di-encode -> breakout atribut & JS string sulit.")
    else:
        reasons.append("Minimal satu jenis kutip utuh -> breakout atribut/JS string memungkinkan.")

    events = {}
    schemes = {}
    if isinstance(mangling, dict):
        events = mangling.get("events") or {}
        schemes = mangling.get("schemes") or {}

    if events:
        present = any((status or "").startswith("present") or status == "encoded" for status in events.values())
        if not present:
            flags["allow_event"] = False
            reasons.append("Event handler on* dimangling/dihapus server-side.")
        else:
            reasons.append("Event handler on* tetap tercermin.")

    if schemes:
        present = any((status or "").startswith("present") or status == "encoded" for status in schemes.values())
        if not present:
            flags["allow_url_scheme"] = False
            reasons.append("Skema javascript:/data: dibuang oleh backend.")
        else:
            reasons.append("Skema javascript:/data: tetap terlihat.")

    profile = {
        "flags": flags,
        "reasons": reasons,
        "fingerprints": sorted(set(filter(None, fingerprints))),
    }
    return profile


def get_xss_severity(contexts, payload, response_text):
    is_unescaped = contains_unescaped(response_text, payload)
    has_angle = ("<" in decode_all(response_text)) or (">" in decode_all(response_text))
    if any(c in contexts for c in ("script_tag", "event_handler", "attr_unquoted", "attr_quoted", "js_string")):
        return "[HIGH] Executable XSS" if is_unescaped and has_angle else "[INFO] Dangerous context, but no unescaped <>"
    if "html_tag" in contexts or "polyglot" in contexts:
        return "[INFO] Reflected in HTML context"
    return "[SAFE] Likely Not Exploitable"


__all__ = ["get_xss_severity", "sink_location_labels", "summarize_filter_profile"]
