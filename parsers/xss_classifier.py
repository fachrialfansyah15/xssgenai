"""
Lightweight classifier to map low-level context hints into high-level XSS
challenge categories for better guidance and reporting.

Categories covered:
 - inline        : direct HTML/script injection
 - attribute     : attribute/value breakout contexts
 - event         : inline event handlers (onload, onclick, ...)
 - js_uri        : javascript:/data:/vbscript: URI payloads
 - dom           : DOM-based sinks (innerHTML, document.write, eval, ...)
 - obfuscated    : obfuscated payloads or polyglot/encoding tricks

This module does not perform network I/O; it purely classifies based on
contexts and optional payload/code strings.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional


OBFUSCATION_PATTERNS = [
    # string building / dynamic property access
    re.compile(r"\bString\.fromCharCode\s*\(", re.I),
    re.compile(r"\b(unescape|escape|atob|btoa)\s*\(", re.I),
    re.compile(r"\b(?:window|self|this|top)\s*\[\s*['\"][^'\"]+['\"]\s*\]", re.I),
    # hex/unicode escapes that often indicate encoded script tokens
    re.compile(r"\\x[0-9A-Fa-f]{2}"),
    # Accept both cases explicitly to avoid bad range order
    re.compile(r"\\u[0-9A-Fa-f]{4}"),
    # arithmetic/number-base tricks like (8680439).toString(30)
    re.compile(r"\b\d+\s*\)\s*\.\s*toString\s*\(\s*\d+\s*\)", re.I),
    # split tag/script tokenization: <scr...ipt> or string concat
    re.compile(r"<\s*scr\s*ipt", re.I),
    re.compile(r"['\"][^'\"]+['\"]\s*\+\s*['\"][^'\"]+['\"]"),
]


SINK_CONTEXTS = {
    "innerHTML", "outerHTML", "textContent", "innerText", "outerText",
    "insertAdjacentHTML", "insertAdjacentText", "document.write",
    "document.writeln", "eval", "Function", "setTimeout-string",
    "setInterval-string",
}


def _detect_obfuscation(text: str | None, payload: str | None) -> List[str]:
    reasons: List[str] = []
    corpus = "\n".join([s for s in [payload or "", text or ""] if s])
    if not corpus:
        return reasons
    for rx in OBFUSCATION_PATTERNS:
        try:
            if rx.search(corpus):
                reasons.append(rx.pattern)
        except Exception:
            continue
    # Polyglot-like tokens
    if "--></" in corpus or "<!-->" in corpus or "</style>" in corpus:
        reasons.append("polyglot_comment_breakout")
    return reasons


def classify_categories(
    *,
    contexts: List[str] | None = None,
    payload: Optional[str] = None,
    code: Optional[str] = None,
    runtime_contexts: Optional[List[str]] = None,
) -> Dict[str, Dict[str, object]]:
    """
    Map low-level contexts into high-level categories.

    Returns a dict: {category: {match: bool, reasons: [..]}}
    Known categories: inline, attribute, event, js_uri, dom, obfuscated
    """
    ctx = set((contexts or []) + (runtime_contexts or []))
    out: Dict[str, Dict[str, object]] = {
        "inline":     {"match": False, "reasons": []},
        "attribute":  {"match": False, "reasons": []},
        "event":      {"match": False, "reasons": []},
        "js_uri":     {"match": False, "reasons": []},
        "dom":        {"match": False, "reasons": []},
        "obfuscated": {"match": False, "reasons": []},
    }

    def _mark(cat: str, reason: str) -> None:
        try:
            out[cat]["match"] = True
            reasons = out[cat].setdefault("reasons", [])
            if reason not in reasons:
                reasons.append(reason)
        except Exception:
            pass

    # Inline
    if "script_tag" in ctx:
        _mark("inline", "script_tag")
    if "html_tag" in ctx and not ({"attr_quoted", "attr_unquoted", "event_handler"} & ctx):
        _mark("inline", "html_tag_content")

    # Attribute-based
    for key in ("attr_quoted", "attr_unquoted", "data_attribute", "srcdoc_attr", "css_inline", "attr_src", "attr_href", "attr_value"):
        if key in ctx:
            _mark("attribute", key)

    # Event-based
    if "event_handler" in ctx or any(c.startswith("on") for c in ctx):
        _mark("event", "event_handler_or_on*")

    # JavaScript URI-based
    if "uri_javascript" in ctx or "uri_scheme" in ctx:
        _mark("js_uri", "uri_scheme")
    # Heuristic from payload/code
    if (payload and re.search(r"\b(?:javascript|data|vbscript)\s*:", payload, re.I)) or \
       (code and re.search(r"\b(?:javascript|data|vbscript)\s*:", code, re.I)):
        _mark("js_uri", "scheme_in_text")

    # DOM-based
    for s in SINK_CONTEXTS:
        if s in ctx:
            _mark("dom", s)
    # Rely on runtime contexts suggesting DOM sinks
    if runtime_contexts:
        if any(s in runtime_contexts for s in SINK_CONTEXTS):
            _mark("dom", "runtime_sink")

    # Obfuscated
    if "polyglot" in ctx:
        _mark("obfuscated", "polyglot")
    obf_reasons = _detect_obfuscation(code, payload)
    for r in obf_reasons:
        _mark("obfuscated", r)

    return out


def summarize_categories(result: Dict[str, Dict[str, object]]) -> List[str]:
    """Return a compact list of present category labels."""
    order = ["dom", "event", "attribute", "js_uri", "inline", "obfuscated"]
    labels = {
        "inline": "Inline XSS",
        "attribute": "Attribute-based XSS",
        "event": "Event-based XSS",
        "js_uri": "JavaScript URI XSS",
        "dom": "DOM-based XSS",
        "obfuscated": "Obfuscated XSS",
    }
    out: List[str] = []
    for cat in order:
        try:
            if result.get(cat, {}).get("match"):
                out.append(labels.get(cat, cat))
        except Exception:
            continue
    return out
